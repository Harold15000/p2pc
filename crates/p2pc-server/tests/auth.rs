// SPDX-License-Identifier: AGPL-3.0-only

//! Authentication (spec §5) and scopes.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::{T0, TestApp, assert_problem};
use p2pc_proto::api::Scope;
use p2pc_proto::auth::{ApiKey, Secret};
use p2pc_proto::ids::KeyId;
use serde_json::json;
use time::Duration;

#[tokio::test]
async fn a_valid_key_authenticates() {
    let app = TestApp::new().await;
    let r = app.get("/v1/whoami", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        r.json(),
        json!({
            "account_id": app.account_id.to_string(),
            "project_id": app.project_id.to_string(),
            "key_id": app.admin_key.key_id().to_string(),
            "scopes": ["admin"],
            // The key's own limits (§7): init's key has a label and no limit.
            "label": "admin (init)",
            "daily_unit_cap": null,
            "allowed_images": null,
            "expires_at": null,
            // H2 §5.5: who the caller is (responses may grow, H1 §7).
            "principal": {"kind": "key", "id": app.admin_key.key_id().to_string()},
        })
    );
}

#[tokio::test]
async fn unknown_wrong_expired_and_revoked_keys_get_byte_identical_401s() {
    let app = TestApp::new().await;
    // Unknown key ID.
    let unknown = ApiKey::generate().expose();
    // Known key ID, wrong secret.
    let wrong = ApiKey::from_parts(app.admin_key.key_id(), Secret::generate()).expose();
    // Expired key.
    let (expiring, _) = app
        .create_key(json!({"scopes": ["jobs:read"], "expires_at": "2026-11-05T11:00:00Z"}))
        .await;
    assert_eq!(app.get("/v1/whoami", &expiring).await.status, StatusCode::OK);
    app.clock.set(T0 + Duration::hours(1));
    // Revoked key.
    let (revoked, v) = app.create_key(json!({"scopes": ["jobs:read"]})).await;
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(app.get("/v1/whoami", &revoked).await.status, StatusCode::OK);
    let r = app
        .call(Method::DELETE, &format!("/v1/keys/{id}"), Some(&app.admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    let mut bodies = Vec::new();
    for key in [&unknown, &wrong, &expiring, &revoked] {
        let r = app.get("/v1/whoami", key).await;
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
        assert_eq!(r.headers.get(header::WWW_AUTHENTICATE).unwrap(), "Bearer");
        bodies.push(r.body);
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
}

#[tokio::test]
async fn missing_and_malformed_headers_get_401() {
    let app = TestApp::new().await;
    let missing = app.call(Method::GET, "/v1/whoami", None, None).await;
    let body = assert_problem(&missing, StatusCode::UNAUTHORIZED, "unauthenticated");
    for value in [
        "Bearer".to_string(),
        "Bearer ".to_string(),
        "Bearer not-a-key".to_string(),
        format!("Basic {}", app.admin),
        format!("Bearer {}x", app.admin),
        format!("Bearer  {}", app.admin),
        app.admin.clone(),
    ] {
        let req = Request::builder()
            .uri("/v1/whoami")
            .header(header::AUTHORIZATION, value.as_str())
            .body(Body::empty())
            .unwrap();
        let r = app.send(req).await;
        assert_eq!(
            assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated"),
            body,
            "{value}"
        );
    }
    // The scheme is case-insensitive (RFC 9110 §11.1).
    let req = Request::builder()
        .uri("/v1/whoami")
        .header(header::AUTHORIZATION, format!("bearer {}", app.admin))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.send(req).await.status, StatusCode::OK);
}

#[tokio::test]
async fn there_is_no_localhost_bypass() {
    let app = TestApp::new().await;
    for host in ["127.0.0.1:7477", "localhost", "[::1]:7477"] {
        let req = Request::builder()
            .uri("/v1/keys")
            .header(header::HOST, host)
            .header("x-forwarded-for", "127.0.0.1")
            .body(Body::empty())
            .unwrap();
        assert_problem(&app.send(req).await, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
}

#[tokio::test]
async fn scopes_are_enforced_and_admin_implies_all() {
    let app = TestApp::new().await;
    let reader = app.key_with(&[Scope::JobsRead, Scope::NodesRead]).await;
    // Any valid key may call whoami.
    let r = app.get("/v1/whoami", &reader).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["scopes"], json!(["jobs:read", "nodes:read"]));
    // Admin-only endpoints refuse it with 403.
    for (method, path) in [
        (Method::GET, "/v1/keys"),
        (Method::POST, "/v1/keys"),
        (Method::DELETE, "/v1/keys/abcdefgh2345"),
        (Method::GET, "/v1/audit"),
    ] {
        let body = (method == Method::POST).then(|| json!({"scopes": ["jobs:read"]}));
        let r = app.call(method.clone(), path, Some(&reader), body).await;
        let v = assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
        assert!(v["detail"].as_str().unwrap().contains("admin"), "{v}");
    }
    // Admin passes every scope check.
    let p = principal_with(&[Scope::Admin]);
    for scope in [
        Scope::Admin,
        Scope::JobsRead,
        Scope::JobsWrite,
        Scope::NodesRead,
        Scope::NodesWrite,
    ] {
        assert!(p.has_scope(scope), "{scope:?}");
    }
    let p = principal_with(&[Scope::JobsRead]);
    assert!(p.has_scope(Scope::JobsRead));
    for scope in [Scope::Admin, Scope::JobsWrite, Scope::NodesRead, Scope::NodesWrite] {
        assert!(!p.has_scope(scope), "{scope:?}");
    }
}

fn principal_with(scopes: &[Scope]) -> p2pc_server::auth::Principal {
    p2pc_server::auth::Principal {
        account_id: p2pc_proto::ids::AccountId::generate(),
        project_id: p2pc_proto::ids::ProjectId::generate(),
        id: p2pc_proto::api::Principal::Key(KeyId::generate()),
        scopes: scopes.to_vec(),
        daily_unit_cap: None,
        allowed_images: None,
        label: None,
        expires_at: None,
        blobs_quota_mb: None,
    }
}

#[tokio::test]
async fn last_used_at_is_written_at_most_once_a_minute() {
    let app = TestApp::new().await;
    let (key, v) = app.create_key(json!({"scopes": ["jobs:read"]})).await;
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["last_used_at"], json!(null));
    let last_used = |app: &TestApp| {
        let id = id.clone();
        let db = app.db.clone();
        async move {
            sqlx::query_scalar::<_, Option<i64>>("SELECT last_used_at FROM api_keys WHERE key_id = ?")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    app.get("/v1/whoami", &key).await;
    assert_eq!(last_used(&app).await, Some(T0.unix_timestamp()));
    app.clock.set(T0 + Duration::seconds(59));
    app.get("/v1/whoami", &key).await;
    assert_eq!(last_used(&app).await, Some(T0.unix_timestamp()));
    app.clock.set(T0 + Duration::seconds(60));
    app.get("/v1/whoami", &key).await;
    assert_eq!(last_used(&app).await, Some(T0.unix_timestamp() + 60));
}

#[tokio::test]
async fn failed_authentications_are_aggregated_per_minute_and_key_id() {
    let app = TestApp::new().await;
    let wrong = ApiKey::from_parts(app.admin_key.key_id(), Secret::generate()).expose();
    for _ in 0..3 {
        app.get("/v1/whoami", &wrong).await;
    }
    for _ in 0..2 {
        app.get("/v1/whoami", &ApiKey::generate().expose()).await;
    }
    app.get("/v1/whoami", "garbage").await;
    // A missing header is not an authentication attempt.
    app.call(Method::GET, "/v1/whoami", None, None).await;
    app.clock.set(T0 + Duration::seconds(61));
    app.get("/v1/whoami", &wrong).await;

    // Failures are written off the request path; wait for the writer.
    app.flush_audit().await;
    let r = app.get("/v1/audit?kind=auth_failed", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let items = r.json()["items"].as_array().unwrap().clone();
    let mut rows: Vec<(String, String, u64)> = items
        .iter()
        .map(|e| {
            (
                e["at"].as_str().unwrap().to_string(),
                e["subject_id"].as_str().unwrap().to_string(),
                // The aggregated count lives in `detail` (proto `AuditKind::AuthFailed`).
                e["detail"]["count"].as_u64().unwrap(),
            )
        })
        .collect();
    // Rows of one batch have no defined order among themselves.
    rows.sort();
    let admin_id = app.admin_key.key_id().to_string();
    let mut want = vec![
        ("2026-11-05T10:01:00Z".to_string(), admin_id.clone(), 1),
        ("2026-11-05T10:00:00Z".to_string(), "unknown".to_string(), 3),
        ("2026-11-05T10:00:00Z".to_string(), admin_id, 3),
    ];
    want.sort();
    assert_eq!(rows, want);
    for e in &items {
        assert_eq!(e["kind"], "auth_failed");
        assert_eq!(e["actor_key_id"], json!(null));
    }
    assert_eq!(app.state.auth_failures.dropped(), 0);
}

/// Review P3-5: recording a failed attempt never makes the `401` wait for SQLite. With the database write-locked
/// by another connection, the writer task is stuck, the small queue fills, and extra events are dropped and counted,
/// while every `401` still answers at once.
#[tokio::test]
async fn a_401_never_waits_for_the_database() {
    let app = TestApp::with_auth_failure_queue(4).await;
    // Another writer holds the lock for longer than any 401 may take (busy_timeout is 5 s).
    let mut locker = app.db.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *locker).await.unwrap();
    let sent = 50u64;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for _ in 0..sent {
            let r = app.get("/v1/whoami", &ApiKey::generate().expose()).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        }
    })
    .await
    .expect("401s waited for the database");
    let dropped = app.state.auth_failures.dropped();
    assert!(dropped > 0, "the full queue must drop and count");
    sqlx::query("ROLLBACK").execute(&mut *locker).await.unwrap();
    drop(locker);
    app.flush_audit().await;
    let items = app.get("/v1/audit?kind=auth_failed", &app.admin).await.json()["items"]
        .as_array()
        .unwrap()
        .clone();
    let recorded: u64 = items.iter().map(|e| e["detail"]["count"].as_u64().unwrap()).sum();
    assert_eq!(
        recorded + dropped,
        sent,
        "every attempt is either recorded or counted as dropped"
    );
}
