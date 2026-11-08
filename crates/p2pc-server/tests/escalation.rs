// SPDX-License-Identifier: AGPL-3.0-only

//! Spec §5 "No escalation": a key can never create a more powerful key. `POST /v1/keys` checks the request against
//! its creator with `p2pc_proto::validate::check_no_escalation` and answers `403 escalation_denied`.
//!
//! `POST /v1/keys` needs the `admin` scope and `admin` covers every scope, so the scopes rule cannot fail through
//! HTTP; it is tested on `app::ensure_no_escalation` with a non-admin creator (last test).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{T0, TestApp, assert_problem};
use p2pc_proto::api::{ApiKeyInfo, CreateApiKey, Scope};
use p2pc_proto::units::Units;
use serde_json::{Value, json};

/// An admin key with limits, created by init's unrestricted admin key.
async fn limited_admin(app: &TestApp, limits: Value) -> String {
    let mut body = json!({"scopes": ["admin"], "label": "limited"});
    body.as_object_mut()
        .unwrap()
        .extend(limits.as_object().unwrap().clone());
    app.create_key(body).await.0
}

async fn create_with(app: &TestApp, creator: &str, body: Value) -> common::Resp {
    app.call(Method::POST, "/v1/keys", Some(creator), Some(body)).await
}

/// Asserts a `403 escalation_denied` naming exactly `fields`.
fn assert_denied(r: &common::Resp, fields: &[&str]) {
    let v = assert_problem(r, StatusCode::FORBIDDEN, "escalation_denied");
    let got: Vec<&str> = v["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            assert_eq!(e["code"], "not_allowed", "{e}");
            e["field"].as_str().unwrap()
        })
        .collect();
    assert_eq!(got, fields, "{v}");
    for f in fields {
        assert!(v["detail"].as_str().unwrap().contains(f), "{v}");
    }
}

async fn key_count(app: &TestApp) -> usize {
    app.get("/v1/keys?limit=100", &app.admin).await.json()["items"]
        .as_array()
        .unwrap()
        .len()
}

#[tokio::test]
async fn a_capped_creator_cannot_create_an_uncapped_or_bigger_cap() {
    let app = TestApp::new().await;
    let creator = limited_admin(&app, json!({"daily_unit_cap": 5000})).await;
    let before = key_count(&app).await;
    for body in [
        json!({"scopes": ["jobs:read"]}),
        json!({"scopes": ["jobs:read"], "daily_unit_cap": 5001}),
    ] {
        assert_denied(&create_with(&app, &creator, body).await, &["daily_unit_cap"]);
    }
    assert_eq!(key_count(&app).await, before, "nothing was created");
    for cap in [5000, 1] {
        let r = create_with(&app, &creator, json!({"scopes": ["jobs:read"], "daily_unit_cap": cap})).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    }
}

#[tokio::test]
async fn an_image_restricted_creator_can_only_hand_out_its_own_patterns() {
    let app = TestApp::new().await;
    let creator = limited_admin(
        &app,
        json!({"allowed_images": ["docker.io/library/python:*", "ghcr.io/me/**"]}),
    )
    .await;
    for images in [
        // No list means every image.
        Value::Null,
        // Narrower in effect, but not one of the creator's patterns: comparison is exact.
        json!(["ghcr.io/me/app:*"]),
        json!(["ghcr.io/me/**", "quay.io/x/y:1"]),
    ] {
        let mut body = json!({"scopes": ["jobs:write"]});
        if !images.is_null() {
            body["allowed_images"] = images.clone();
        }
        assert_denied(&create_with(&app, &creator, body).await, &["allowed_images"]);
    }
    for images in [
        json!(["ghcr.io/me/**"]),
        json!([]),
        json!(["docker.io/library/python:*", "ghcr.io/me/**"]),
    ] {
        let r = create_with(
            &app,
            &creator,
            json!({"scopes": ["jobs:write"], "allowed_images": images}),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{images}: {:?}", r.body);
    }
}

#[tokio::test]
async fn an_expiring_creator_cannot_create_a_longer_lived_key() {
    let app = TestApp::new().await;
    let creator = limited_admin(&app, json!({"expires_at": "2026-12-01T00:00:00Z"})).await;
    for body in [
        json!({"scopes": ["jobs:read"]}),
        json!({"scopes": ["jobs:read"], "expires_at": "2026-12-01T00:00:01Z"}),
    ] {
        assert_denied(&create_with(&app, &creator, body).await, &["expires_at"]);
    }
    for at in ["2026-12-01T00:00:00Z", "2026-11-06T00:00:00Z"] {
        let r = create_with(&app, &creator, json!({"scopes": ["jobs:read"], "expires_at": at})).await;
        assert_eq!(r.status, StatusCode::CREATED, "{at}: {:?}", r.body);
    }
}

#[tokio::test]
async fn every_violated_rule_is_listed_and_nothing_is_written() {
    let app = TestApp::new().await;
    let creator = limited_admin(
        &app,
        json!({"daily_unit_cap": 10, "allowed_images": ["ghcr.io/me/**"], "expires_at": "2026-12-01T00:00:00Z"}),
    )
    .await;
    let audit_before = app.get("/v1/audit?limit=100", &app.admin).await.json()["items"]
        .as_array()
        .unwrap()
        .len();
    let keys_before = key_count(&app).await;
    let r = create_with(&app, &creator, json!({"scopes": ["admin"]})).await;
    assert_denied(&r, &["daily_unit_cap", "allowed_images", "expires_at"]);
    assert_eq!(key_count(&app).await, keys_before);
    let audit_after = app.get("/v1/audit?limit=100", &app.admin).await.json()["items"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(audit_after, audit_before, "no key_created event");
    // A fully bounded request passes.
    let r = create_with(
        &app,
        &creator,
        json!({"scopes": ["admin"], "daily_unit_cap": 10, "allowed_images": ["ghcr.io/me/**"],
            "expires_at": "2026-12-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

#[tokio::test]
async fn validation_comes_before_escalation_and_an_unrestricted_admin_may_do_anything() {
    let app = TestApp::new().await;
    let creator = limited_admin(&app, json!({"daily_unit_cap": 5})).await;
    // Invalid and escalating: the 422 wins, so a client fixes its body first.
    let r = create_with(&app, &creator, json!({"scopes": []})).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    // init's admin key has no limits: no request is an escalation for it.
    let r = create_with(
        &app,
        &app.admin,
        json!({"scopes": ["admin", "jobs:write"], "daily_unit_cap": 999_999}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

#[test]
fn the_scopes_rule_maps_to_escalation_denied() {
    let creator = ApiKeyInfo {
        id: "abcdefgh2345".parse().unwrap(),
        project_id: p2pc_proto::ids::ProjectId::generate(),
        label: None,
        scopes: vec![Scope::JobsRead, Scope::JobsWrite],
        daily_unit_cap: Some(Units::from_milli(100)),
        allowed_images: None,
        created_at: T0,
        expires_at: None,
        last_used_at: None,
        revoked_at: None,
    };
    let request = |scopes: Vec<Scope>| CreateApiKey {
        label: None,
        scopes,
        expires_at: None,
        daily_unit_cap: Some(Units::from_milli(100)),
        allowed_images: None,
    };
    assert!(p2pc_server::app::ensure_no_escalation(&creator, &request(vec![Scope::JobsRead])).is_ok());
    assert!(
        p2pc_server::app::ensure_no_escalation(&creator, &request(vec![Scope::JobsRead, Scope::JobsWrite])).is_ok()
    );
    for scopes in [vec![Scope::Admin], vec![Scope::JobsRead, Scope::NodesWrite]] {
        let err = p2pc_server::app::ensure_no_escalation(&creator, &request(scopes)).unwrap_err();
        let p = err.problem();
        assert_eq!(p.status, 403);
        assert_eq!(p.code, "escalation_denied");
        assert_eq!(p.errors.len(), 1);
        assert_eq!(p.errors[0].field, "scopes");
    }
}
