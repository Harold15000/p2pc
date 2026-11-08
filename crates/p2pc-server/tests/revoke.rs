// SPDX-License-Identifier: AGPL-3.0-only

//! Spec §5 revocation rules: revoke follows no-escalation, the last live unrestricted admin key cannot be revoked,
//! and `keys recover` is the offline way back.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{T0, TestApp, assert_problem};
use p2pc_server::clock::ManualClock;
use serde_json::{Value, json};
use time::Duration;

async fn revoke(app: &TestApp, by: &str, target: &str) -> common::Resp {
    app.call(Method::DELETE, &format!("/v1/keys/{target}"), Some(by), None)
        .await
}

fn key_id(key: &str) -> String {
    key["p2pc_sk_".len().."p2pc_sk_".len() + 12].to_string()
}

async fn create(app: &TestApp, by: &str, body: Value) -> String {
    let r = app.call(Method::POST, "/v1/keys", Some(by), Some(body)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.json()["key"].as_str().unwrap().to_string()
}

/// The review's lockout: the owner adds a limited admin key, then revokes the unrestricted init key. Once the limited
/// key expires, nobody can administer the account. Now the second step is refused.
#[tokio::test]
async fn the_last_unrestricted_admin_key_cannot_be_revoked() {
    let app = TestApp::new().await;
    let init_id = app.admin_key.key_id().to_string();
    for limits in [
        json!({"expires_at": "2026-11-06T00:00:00Z"}),
        json!({"daily_unit_cap": 1000}),
        json!({"allowed_images": ["ghcr.io/me/**"]}),
    ] {
        let mut body = json!({"scopes": ["admin"]});
        body.as_object_mut()
            .unwrap()
            .extend(limits.as_object().unwrap().clone());
        create(&app, &app.admin, body).await;
        let r = revoke(&app, &app.admin, &init_id).await;
        assert_problem(&r, StatusCode::CONFLICT, "last_admin_key");
    }
    assert_eq!(app.get("/v1/whoami", &app.admin).await.status, StatusCode::OK);
    // A second unrestricted admin key makes it possible.
    let second = create(&app, &app.admin, json!({"scopes": ["admin"]})).await;
    assert_eq!(revoke(&app, &app.admin, &init_id).await.status, StatusCode::NO_CONTENT);
    // And then the second one is the last.
    let r = revoke(&app, &second, &key_id(&second)).await;
    assert_problem(&r, StatusCode::CONFLICT, "last_admin_key");
}

#[tokio::test]
async fn a_limited_admin_cannot_revoke_a_more_powerful_key() {
    let app = TestApp::new().await;
    let limited = create(
        &app,
        &app.admin,
        json!({"scopes": ["admin"], "daily_unit_cap": 1000, "expires_at": "2026-12-01T00:00:00Z"}),
    )
    .await;
    // Not the init key.
    let r = revoke(&app, &limited, &app.admin_key.key_id().to_string()).await;
    let v = assert_problem(&r, StatusCode::FORBIDDEN, "escalation_denied");
    let fields: Vec<&str> = v["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["daily_unit_cap", "expires_at"]);
    // Not an uncapped key, nor one living longer than itself, even with fewer scopes.
    let uncapped = create(&app, &app.admin, json!({"scopes": ["jobs:read"]})).await;
    let longer = create(
        &app,
        &app.admin,
        json!({"scopes": ["jobs:read"], "daily_unit_cap": 10, "expires_at": "2027-01-01T00:00:00Z"}),
    )
    .await;
    for target in [&uncapped, &longer] {
        let r = revoke(&app, &limited, &key_id(target)).await;
        assert_problem(&r, StatusCode::FORBIDDEN, "escalation_denied");
        assert_eq!(app.get("/v1/whoami", target).await.status, StatusCode::OK);
    }
    // A key it could have created, even if another key created it: yes.
    let within = create(
        &app,
        &app.admin,
        json!({"scopes": ["jobs:read"], "daily_unit_cap": 1000, "expires_at": "2026-11-20T00:00:00Z"}),
    )
    .await;
    assert_eq!(
        revoke(&app, &limited, &key_id(&within)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(app.get("/v1/whoami", &within).await.status, StatusCode::UNAUTHORIZED);
    // Itself: yes.
    assert_eq!(
        revoke(&app, &limited, &key_id(&limited)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(app.get("/v1/whoami", &limited).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn recover_creates_a_working_unrestricted_admin_key_while_the_server_runs() {
    let app = TestApp::new().await;
    // The app keeps its pool open, like a running server.
    let clock = ManualClock::new(T0 + Duration::minutes(5));
    let out = p2pc_server::recover::recover(&app.data_dir(), &clock).await.unwrap();
    assert_eq!(out.account_id, app.account_id);
    assert_eq!(out.project_id, app.project_id);
    let key = out.admin_key.expose();
    let w = app.get("/v1/whoami", &key).await;
    assert_eq!(w.status, StatusCode::OK, "{:?}", w.body);
    assert_eq!(w.json()["scopes"], json!(["admin"]));
    // Unrestricted: it can revoke the init key, which is no longer the last unrestricted admin.
    let r = revoke(&app, &key, &app.admin_key.key_id().to_string()).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    // Audited as key_recovered, with no actor.
    let audit = app.get("/v1/audit?kind=key_recovered", &key).await.json();
    let items = audit["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{audit}");
    assert_eq!(items[0]["subject_id"], out.admin_key.key_id().to_string());
    assert_eq!(items[0]["actor_key_id"], json!(null));
    assert_eq!(items[0]["at"], "2026-11-05T10:05:00Z");
}

#[tokio::test]
async fn recover_needs_an_initialised_data_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let clock = ManualClock::new(T0);
    let err = p2pc_server::recover::recover(tmp.path(), &clock).await.unwrap_err();
    assert!(err.to_string().contains("p2pc-server init"), "{err}");
}
