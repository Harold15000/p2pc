// SPDX-License-Identifier: AGPL-3.0-only

//! Spec §5 "Re-checked at the point of use" (third review, P2): an operation that grants or removes power reloads
//! the caller's key inside its own transaction. A key revoked or expired after the request was authenticated gets
//! the same `401` as any other auth failure, and nothing changes.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::http::{Method, StatusCode};
use common::{T0, TestApp, assert_problem};
use p2pc_server::app::{AppState, router};
use p2pc_server::clock::Clock;
use p2pc_server::config::Config;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

fn key_id(key: &str) -> String {
    key["p2pc_sk_".len().."p2pc_sk_".len() + 12].to_string()
}

async fn key_ids(app: &TestApp) -> Vec<String> {
    app.get("/v1/keys?limit=100", &app.admin).await.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["id"].as_str().unwrap().to_string())
        .collect()
}

/// The body of the `401` every auth failure gets, for byte comparison.
async fn plain_401(app: &TestApp) -> axum::body::Bytes {
    let r = app.call(Method::GET, "/v1/whoami", None, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    r.body
}

/// Reads one HTTP/1.1 response head (and its `Content-Length` body) from a raw socket.
async fn read_response(s: &mut TcpStream) -> (u16, Vec<u8>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut byte).await.unwrap(), 1, "closed mid-head: {head:?}");
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let status = text[9..12].parse().unwrap();
    let len = text
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    s.read_exact(&mut body).await.unwrap();
    (status, body)
}

/// Over a real socket: the caller's headers are authenticated, then its key is revoked, then its body arrives. The
/// `100 Continue` (sent by hyper when the handler starts reading the body, so after the auth middleware passed) is
/// the synchronisation point; nothing sleeps.
#[tokio::test]
async fn a_key_revoked_after_its_headers_cannot_create_a_key() {
    let app = TestApp::new().await;
    // The caller: a second unrestricted admin key, which init's key may revoke.
    let (caller, _) = app.create_key(json!({"scopes": ["admin"]})).await;
    let before = key_ids(&app).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(p2pc_server::serve::serve_on(listener, app.state.clone(), async {
        let _ = stopped.await;
    }));

    let body = json!({"scopes": ["jobs:read"], "label": "should not exist"}).to_string();
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /v1/keys HTTP/1.1\r\nHost: p2pc.example.invalid\r\nAuthorization: Bearer {caller}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    let mut cont = [0u8; 25];
    tokio::time::timeout(StdDuration::from_secs(5), s.read_exact(&mut cont))
        .await
        .expect("no 100 Continue: the request did not get past authentication")
        .unwrap();
    assert_eq!(&cont, b"HTTP/1.1 100 Continue\r\n\r\n");

    // The request is now inside the handler, authenticated. Revoke its key from another connection.
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/keys/{}", key_id(&caller)),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);

    s.write_all(body.as_bytes()).await.unwrap();
    let (status, resp) = tokio::time::timeout(StdDuration::from_secs(5), read_response(&mut s))
        .await
        .unwrap();
    assert_eq!(status, 401, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(resp, plain_401(&app).await.to_vec(), "not the usual 401 body");

    // Nothing was created: same keys.
    assert_eq!(key_ids(&app).await, before);
    // The attempt with a revoked key is exactly what the owner wants to see (T04 ruling): the point-of-use 401
    // queues an `auth_failed` event, through the same off-path queue as a failed login, and nothing else was
    // recorded for it: no `key_created`.
    app.flush_audit().await;
    let audit = app.get("/v1/audit?limit=100", &app.admin).await.json();
    let kinds: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    // Between the two keys, the hub's own first start: it loaded its template bundle (H2 §7.6).
    assert_eq!(
        kinds,
        [
            "auth_failed",
            "key_revoked",
            "key_created",
            "template_bundle_loaded",
            "key_created"
        ],
        "{audit}"
    );
    assert_eq!(audit["items"][0]["subject_id"], key_id(&caller), "{audit}");
    assert_eq!(audit["items"][0]["detail"]["count"], 1, "{audit}");

    drop(s);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// A clock that answers a scripted sequence of times, then repeats the last one. It lets a test make the key
/// expire between the auth middleware (first `now()`) and the handler (second `now()`).
#[derive(Debug)]
struct ScriptedClock(Mutex<VecDeque<OffsetDateTime>>);

impl ScriptedClock {
    fn script(&self, times: &[OffsetDateTime]) {
        *self.0.lock().unwrap() = times.iter().copied().collect();
    }
}

impl Clock for ScriptedClock {
    fn now(&self) -> OffsetDateTime {
        let mut q = self.0.lock().unwrap();
        if q.len() > 1 {
            q.pop_front().unwrap()
        } else {
            *q.front().unwrap()
        }
    }
}

#[tokio::test]
async fn a_key_that_expires_mid_request_cannot_create_or_revoke() {
    let app = TestApp::new().await;
    let (caller, _) = app
        .create_key(json!({"scopes": ["admin"], "expires_at": "2026-11-05T11:00:00Z"}))
        .await;
    // A key the caller could have created (it expires before the caller), so only the expiry can stop the revoke.
    let (target, _) = app
        .create_key(json!({"scopes": ["jobs:read"], "expires_at": "2026-11-05T10:30:00Z"}))
        .await;
    let before = key_ids(&app).await;
    let expected_401 = plain_401(&app).await;

    // The same database, served with a scripted clock.
    let clock = Arc::new(ScriptedClock(Mutex::new(VecDeque::from([T0]))));
    let config = Config::load(&app.data_dir().join("server.toml")).unwrap();
    let state = AppState::load(app.db.clone(), config, clock.clone()).await.unwrap();
    let failures = state.auth_failures.clone();
    let router = router(state);
    let send = |method: Method, uri: String, body: Option<serde_json::Value>| {
        let router = router.clone();
        let caller = caller.clone();
        async move {
            let mut req = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {caller}"));
            let body = match body {
                Some(v) => {
                    req = req.header("content-type", "application/json");
                    axum::body::Body::from(v.to_string())
                }
                None => axum::body::Body::empty(),
            };
            let resp = router.oneshot(req.body(body).unwrap()).await.unwrap();
            let status = resp.status();
            (status, axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap())
        }
    };
    let late = T0 + Duration::hours(2);

    // Valid at authentication (10:00), expired in the handler (12:00).
    clock.script(&[T0, late]);
    let (status, body) = send(Method::POST, "/v1/keys".into(), Some(json!({"scopes": ["jobs:read"]}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, expected_401);

    clock.script(&[T0, late]);
    let (status, body) = send(Method::DELETE, format!("/v1/keys/{}", key_id(&target)), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, expected_401);

    // Revoking itself goes through the same re-check.
    clock.script(&[T0, late]);
    let (status, _) = send(Method::DELETE, format!("/v1/keys/{}", key_id(&caller)), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Nothing changed: no new key, nothing revoked.
    assert_eq!(key_ids(&app).await, before);
    for k in [&caller, &target] {
        let row = app.get("/v1/keys?limit=100", &app.admin).await.json()["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == key_id(k))
            .unwrap()
            .clone();
        assert_eq!(row["revoked_at"], json!(null), "{row}");
    }

    // Each of the three refused attempts was queued as an `auth_failed` event of the caller key, aggregated into one
    // row per minute (all three happened at the same minute).
    failures.flush().await;
    let audit = app.get("/v1/audit?kind=auth_failed", &app.admin).await.json();
    let items = audit["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{audit}");
    assert_eq!(items[0]["subject_id"], key_id(&caller), "{audit}");
    assert_eq!(items[0]["detail"]["count"], 3, "{audit}");

    // Control: with the clock steady at 10:00 the same revoke succeeds, so the 401s above came from the re-check.
    clock.script(&[T0]);
    let (status, body) = send(Method::DELETE, format!("/v1/keys/{}", key_id(&target)), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body:?}");
}

/// Third review, P3: a malformed token never waits for a pool connection.
#[tokio::test]
async fn a_malformed_token_is_refused_without_a_pool_connection() {
    let app = TestApp::new().await;
    // Hold every connection of the pool.
    let mut held = Vec::new();
    for _ in 0..app.db.options().get_max_connections() {
        held.push(app.db.acquire().await.unwrap());
    }
    for token in ["garbage", "p2pc_sk_short", ""] {
        let r = tokio::time::timeout(StdDuration::from_secs(2), app.get("/v1/whoami", token))
            .await
            .unwrap_or_else(|_| panic!("{token:?} waited for the pool"));
        assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    drop(held);
}

/// Third review, P3: `last_used_at` is bookkeeping. If writing it fails, the authenticated request still succeeds.
#[tokio::test]
async fn a_failed_last_used_write_does_not_fail_the_request() {
    let app = TestApp::new().await;
    sqlx::query(
        "CREATE TRIGGER force_last_used_failure BEFORE UPDATE OF last_used_at ON api_keys \
         BEGIN SELECT RAISE(ABORT, 'forced failure'); END",
    )
    .execute(&app.db)
    .await
    .unwrap();
    let r = app.get("/v1/whoami", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.json()["key_id"], app.admin_key.key_id().to_string());
    // The write really failed: last_used_at is still unset.
    let used: Option<i64> = sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE key_id = ?")
        .bind(app.admin_key.key_id().to_string())
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(used, None);
}
