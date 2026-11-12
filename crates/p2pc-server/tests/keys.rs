// SPDX-License-Identifier: AGPL-3.0-only

//! `/v1/keys` and `/v1/audit`, including cross-account isolation (SI-7).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode, header};
use common::{T0, TestApp, assert_problem, second_account};
use p2pc_proto::auth::ApiKey;
use serde_json::{Value, json};
use time::Duration;

#[tokio::test]
async fn create_returns_the_key_once_and_it_works() {
    let app = TestApp::new().await;
    let body = json!({
        "label": "ci", "scopes": ["jobs:read", "jobs:write"], "daily_unit_cap": 5000,
        "allowed_images": ["docker.io/library/python:*"], "expires_at": "2026-12-01T00:00:00Z"
    });
    let r = app.call(Method::POST, "/v1/keys", Some(&app.admin), Some(body)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let v = r.json();
    let key: ApiKey = v["key"].as_str().unwrap().parse().unwrap();
    // §5: the response is flat, the metadata next to `key`.
    assert!(v.get("info").is_none(), "{v}");
    let info = &v;
    assert_eq!(info["id"], key.key_id().to_string());
    assert_eq!(info["project_id"], app.project_id.to_string());
    assert_eq!(info["label"], "ci");
    assert_eq!(info["scopes"], json!(["jobs:read", "jobs:write"]));
    assert_eq!(info["daily_unit_cap"], 5000);
    assert_eq!(info["allowed_images"], json!(["docker.io/library/python:*"]));
    assert_eq!(info["expires_at"], "2026-12-01T00:00:00Z");
    assert_eq!(info["created_at"], "2026-11-05T10:00:00Z");
    assert_eq!(info["revoked_at"], json!(null));
    // The new key authenticates and carries its scopes.
    let w = app.get("/v1/whoami", &key.expose()).await.json();
    assert_eq!(w["key_id"], key.key_id().to_string());
    assert_eq!(w["scopes"], json!(["jobs:read", "jobs:write"]));
    // Listing never shows a secret.
    let list = app.get("/v1/keys", &app.admin).await;
    let secret = &key.expose()["p2pc_sk_".len() + 13..];
    assert!(!String::from_utf8_lossy(&list.body).contains(secret));
    assert!(!String::from_utf8_lossy(&list.body).contains("sha256:"));
}

/// Review P3-2: `create_key` reads the creator's row, then writes. In WAL mode a deferred transaction that has read
/// cannot wait for the write lock (SQLite answers `SQLITE_BUSY` at once), so concurrent creations would fail.
/// `BEGIN IMMEDIATE` takes the write lock first and lets `busy_timeout` queue them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_key_creations_all_succeed() {
    let app = TestApp::new().await;
    let mut set = tokio::task::JoinSet::new();
    for i in 0..32 {
        let router = app.router.clone();
        let admin = app.admin.clone();
        set.spawn(async move {
            let req = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v1/keys")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"scopes": ["jobs:read"], "label": format!("c{i}")}).to_string(),
                ))
                .unwrap();
            let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
            (status, body)
        });
    }
    while let Some(r) = set.join_next().await {
        let (status, body) = r.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body:?}");
    }
    let n = app.get("/v1/keys?limit=100", &app.admin).await.json()["items"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(n, 33);
}

#[tokio::test]
async fn create_validates_the_body() {
    let app = TestApp::new().await;
    let cases = [
        (json!({"scopes": []}), "scopes"),
        (
            json!({"scopes": ["jobs:read"], "expires_at": "2026-11-05T09:59:59Z"}),
            "expires_at",
        ),
        (
            json!({"scopes": ["jobs:read"], "expires_at": "2026-11-05T10:00:00Z"}),
            "expires_at",
        ),
        (
            json!({"scopes": ["jobs:read"], "allowed_images": ["python:[0-9]"]}),
            "allowed_images[0]",
        ),
        (json!({"scopes": ["jobs:read"], "label": "a\u{0}b"}), "label"),
    ];
    for (body, field) in cases {
        let r = app
            .call(Method::POST, "/v1/keys", Some(&app.admin), Some(body.clone()))
            .await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        let errors = v["errors"].as_array().unwrap();
        assert!(errors.iter().any(|e| e["field"] == field), "{body}: {v}");
        for e in errors {
            assert!(e["code"].is_string() && e["message"].is_string(), "{e}");
        }
    }
    // Shape errors: unknown scope, unknown field, wrong type.
    for body in [
        json!({"scopes": ["root"]}),
        json!({"scopes": ["jobs:read"], "name": "old spelling"}),
        json!({"scopes": "admin"}),
        json!({}),
    ] {
        let r = app
            .call(Method::POST, "/v1/keys", Some(&app.admin), Some(body.clone()))
            .await;
        assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "invalid_body");
    }
    // Not JSON at all.
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/v1/keys")
        .header(header::AUTHORIZATION, format!("Bearer {}", app.admin))
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{not json"))
        .unwrap();
    assert_problem(&app.send(req).await, StatusCode::BAD_REQUEST, "invalid_json");
    // Nothing was created.
    let list = app.get("/v1/keys", &app.admin).await.json();
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn list_is_cursor_paginated_in_creation_order() {
    let app = TestApp::new().await;
    let mut created = vec![app.admin_key.key_id().to_string()];
    for i in 0..4 {
        app.clock.set(T0 + Duration::seconds(i + 1));
        let (_, v) = app
            .create_key(json!({"scopes": ["jobs:read"], "label": format!("k{i}")}))
            .await;
        created.push(v["id"].as_str().unwrap().to_string());
    }
    let mut seen = Vec::new();
    let mut uri = "/v1/keys?limit=2".to_string();
    let mut pages = 0;
    loop {
        let v = app.get(&uri, &app.admin).await.json();
        pages += 1;
        let items = v["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|k| k["id"].as_str().unwrap().to_string()));
        match v["next_cursor"].as_str() {
            Some(c) => uri = format!("/v1/keys?limit=2&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(seen, created);
    assert_eq!(pages, 3);
    // Default and maximum limits.
    assert_eq!(
        app.get("/v1/keys", &app.admin).await.json()["items"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(app.get("/v1/keys?limit=100", &app.admin).await.status, StatusCode::OK);
    for bad in ["/v1/keys?limit=0", "/v1/keys?limit=101", "/v1/keys?cursor=nope"] {
        let r = app.get(bad, &app.admin).await;
        assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
    let r = app.get("/v1/keys?limit=abc", &app.admin).await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "invalid_query");
}

#[tokio::test]
async fn revoke_is_idempotent_and_audited() {
    let app = TestApp::new().await;
    let (key, v) = app.create_key(json!({"scopes": ["jobs:read"]})).await;
    let id = v["id"].as_str().unwrap().to_string();
    app.clock.set(T0 + Duration::minutes(5));
    for _ in 0..2 {
        let r = app
            .call(Method::DELETE, &format!("/v1/keys/{id}"), Some(&app.admin), None)
            .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    }
    assert_eq!(app.get("/v1/whoami", &key).await.status, StatusCode::UNAUTHORIZED);
    // The row stays, with revoked_at set.
    let list = app.get("/v1/keys", &app.admin).await.json();
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == id)
        .unwrap()
        .clone();
    assert_eq!(row["revoked_at"], "2026-11-05T10:05:00Z");
    // Audit, newest first: the revoked key's failed attempt, one key_revoked (not two), the key_created events and,
    // between them, the hub's own first start, which loaded its template bundle (H2 §7.6).
    app.flush_audit().await;
    let audit = app.get("/v1/audit", &app.admin).await.json();
    let kinds: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "auth_failed",
            "key_revoked",
            "key_created",
            "template_bundle_loaded",
            "key_created"
        ]
    );
    assert_eq!(audit["items"][0]["subject_id"], id);
    let revoked = &audit["items"][1];
    assert_eq!(revoked["subject_id"], id);
    assert_eq!(revoked["actor_key_id"], app.admin_key.key_id().to_string());
    assert!(revoked["id"].as_str().unwrap().starts_with("aud_"), "{revoked}");
    assert_eq!(revoked["detail"], json!({}));
    // Unknown and malformed key IDs are 404.
    for path in ["/v1/keys/abcdefgh2345", "/v1/keys/not-a-key-id"] {
        let r = app.call(Method::DELETE, path, Some(&app.admin), None).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
}

#[tokio::test]
async fn the_last_admin_key_cannot_revoke_itself() {
    let app = TestApp::new().await;
    let me = app.admin_key.key_id().to_string();
    let r = app
        .call(Method::DELETE, &format!("/v1/keys/{me}"), Some(&app.admin), None)
        .await;
    assert_problem(&r, StatusCode::CONFLICT, "last_admin_key");
    assert_eq!(app.get("/v1/whoami", &app.admin).await.status, StatusCode::OK);

    // An expired admin key does not count as another admin.
    app.create_key(json!({"scopes": ["admin"], "expires_at": "2026-11-05T10:30:00Z"}))
        .await;
    app.clock.set(T0 + Duration::hours(1));
    let r = app
        .call(Method::DELETE, &format!("/v1/keys/{me}"), Some(&app.admin), None)
        .await;
    assert_problem(&r, StatusCode::CONFLICT, "last_admin_key");

    // With a second live admin key, it can.
    let (second, _) = app.create_key(json!({"scopes": ["admin"]})).await;
    let r = app
        .call(Method::DELETE, &format!("/v1/keys/{me}"), Some(&app.admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(app.get("/v1/whoami", &app.admin).await.status, StatusCode::UNAUTHORIZED);
    // And now the second one is the last.
    let second_id = second["p2pc_sk_".len().."p2pc_sk_".len() + 12].to_string();
    let r = app
        .call(Method::DELETE, &format!("/v1/keys/{second_id}"), Some(&second), None)
        .await;
    assert_problem(&r, StatusCode::CONFLICT, "last_admin_key");
}

fn ids(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn accounts_cannot_see_or_revoke_each_others_keys() {
    let app = TestApp::new().await;
    let (other, other_id) = second_account(&app).await;
    let mine = app.admin_key.key_id().to_string();
    // A later creation time, so the list order (created_at, then key_id) is known.
    app.clock.set(T0 + Duration::seconds(1));
    let (_, v) = app.create_key(json!({"scopes": ["jobs:read"]})).await;
    let my_reader = v["id"].as_str().unwrap().to_string();

    let w = app.get("/v1/whoami", &other).await.json();
    assert_eq!(w["key_id"], other_id);
    assert_ne!(w["account_id"], app.account_id.to_string());

    assert_eq!(
        ids(&app.get("/v1/keys", &app.admin).await.json()),
        vec![mine.clone(), my_reader.clone()]
    );
    assert_eq!(ids(&app.get("/v1/keys", &other).await.json()), vec![other_id.clone()]);

    // Revoking across accounts is a 404, and nothing changes.
    for (key, target) in [(&other, &mine), (&other, &my_reader), (&app.admin, &other_id)] {
        let r = app
            .call(Method::DELETE, &format!("/v1/keys/{target}"), Some(key), None)
            .await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
    assert_eq!(app.get("/v1/whoami", &app.admin).await.status, StatusCode::OK);
    assert_eq!(app.get("/v1/whoami", &other).await.status, StatusCode::OK);

    // Audit is per account too: the other account sees none of ours.
    let theirs = app.get("/v1/audit", &other).await.json();
    assert_eq!(theirs["items"], json!([]));
    let ours = app.get("/v1/audit", &app.admin).await.json();
    assert!(!ours["items"].as_array().unwrap().is_empty());
    // A cursor from one account does not reveal the other's rows either.
    let r = app.get("/v1/audit?cursor=999999", &other).await.json();
    assert_eq!(r["items"], json!([]));
}

#[tokio::test]
async fn audit_is_paginated_newest_first_and_filters_by_kind() {
    let app = TestApp::new().await;
    // Subjects in creation order: init's admin key, the template bundle the hub loaded at its first start (H2 §7.6;
    // the subject is its version), then three more keys.
    let bundle_version = app.state.bundle.served().unwrap().version().to_string();
    let mut created = vec![app.admin_key.key_id().to_string(), bundle_version];
    for _ in 0..3 {
        let (_, v) = app.create_key(json!({"scopes": ["jobs:read"]})).await;
        created.push(v["id"].as_str().unwrap().to_string());
    }
    let mut subjects = Vec::new();
    let mut ids = Vec::new();
    let mut uri = "/v1/audit?limit=2".to_string();
    loop {
        let v = app.get(&uri, &app.admin).await.json();
        for e in v["items"].as_array().unwrap() {
            subjects.push(e["subject_id"].as_str().unwrap().to_string());
            ids.push(e["id"].as_str().unwrap().to_string());
        }
        match v["next_cursor"].as_str() {
            Some(c) => uri = format!("/v1/audit?limit=2&cursor={c}"),
            None => break,
        }
    }
    // Newest first, every event exactly once, with an `aud_` ID.
    created.reverse();
    assert_eq!(subjects, created);
    assert!(
        ids.iter().all(|i| i.parse::<p2pc_proto::ids::AuditEventId>().is_ok()),
        "{ids:?}"
    );
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), 5);
    let v = app.get("/v1/audit?kind=key_revoked", &app.admin).await.json();
    assert_eq!(v["items"], json!([]));
    let v = app.get("/v1/audit?kind=key_created&limit=1", &app.admin).await.json();
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert!(v["next_cursor"].is_string());
    let r = app.get("/v1/audit?kind=nope", &app.admin).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    // Detail never holds a secret or a digest.
    let all = app.get("/v1/audit", &app.admin).await;
    assert!(!String::from_utf8_lossy(&all.body).contains("sha256:"));
}
