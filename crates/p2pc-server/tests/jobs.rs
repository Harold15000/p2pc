// SPDX-License-Identifier: AGPL-3.0-only

//! The jobs API (spec §7, §11, SI-7): create, idempotency, caps, list, get, cancel and estimate.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::{Resp, T0, TestApp, assert_problem, second_account};
use p2pc_server::clock::Clock;
use serde_json::{Value, json};
use time::Duration;
use tower::ServiceExt;

const PYTHON: &str = "docker.io/library/python:3.12-slim";

/// A valid job body: 1 vCPU for the default hour is exactly 1 000 milli-units.
fn body() -> Value {
    json!({
        "image": "python:3.12-slim",
        "command": ["python", "-c", "print(6*7)"],
        "resources": {"cpu": 1, "memory_mb": 512},
    })
}

/// `body()` with `extra` merged over it (top-level keys).
fn body_with(extra: Value) -> Value {
    let mut b = body();
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    b
}

async fn post_job(app: &TestApp, key: &str, body: Value, idempotency_header: Option<&str>) -> Resp {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/v1/jobs")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(h) = idempotency_header {
        req = req.header("idempotency-key", h);
    }
    app.send(req.body(Body::from(body.to_string())).unwrap()).await
}

/// Creates a job with the admin key and returns its JSON, asserting `201`.
async fn create(app: &TestApp, body: Value) -> Value {
    let r = post_job(app, &app.admin, body, None).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", String::from_utf8_lossy(&r.body));
    r.json()
}

async fn cancel(app: &TestApp, key: &str, id: &str) -> Resp {
    app.call(Method::POST, &format!("/v1/jobs/{id}/cancel"), Some(key), None)
        .await
}

async fn rows(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap()
}

/// A key that can read and write jobs, with the given cap (milli-units) and image globs.
async fn job_key(app: &TestApp, cap: Option<u64>, images: Option<Vec<&str>>) -> String {
    let mut b = json!({"scopes": ["jobs:read", "jobs:write"]});
    if let Some(c) = cap {
        b["daily_unit_cap"] = json!(c);
    }
    if let Some(i) = images {
        b["allowed_images"] = json!(i);
    }
    app.create_key(b).await.0
}

// ── Create ────────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_job_is_created_queued_with_the_image_normalized() {
    let app = TestApp::new().await;
    let r = post_job(
        &app,
        &app.admin,
        body_with(json!({
            "name": "answer",
            "env": {"API_TOKEN": "s3cr3t-value"},
            "files": [{"path": "/inputs/a.txt", "content_b64": "aGk="}],
        })),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    let id = v["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("job_"), "{id}");
    assert_eq!(r.headers.get(header::LOCATION).unwrap(), &format!("/v1/jobs/{id}"));
    assert_eq!(v["status"], "queued");
    assert_eq!(v["attempt"], 1);
    assert_eq!(v["project_id"], app.project_id.to_string());
    assert_eq!(v["name"], "answer");
    assert_eq!(v["node_id"], Value::Null);
    assert_eq!(v["reason"], Value::Null);
    assert_eq!(v["cancel_requested_at"], Value::Null);
    assert_eq!(v["estimated_units"], 1000);
    assert_eq!(v["created_at"], "2026-11-05T10:00:00Z");
    assert_eq!(v["started_at"], Value::Null);
    assert_eq!(v["finished_at"], Value::Null);
    // The normalized image and the defaults are in the response.
    assert_eq!(v["spec"]["image"], PYTHON);
    assert_eq!(v["spec"]["timeout_s"], 3600);
    assert_eq!(v["spec"]["resources"]["disk_mb"], 2_048);
    assert_eq!(v["spec"]["retry"]["max_attempts"], 2);
    assert_eq!(v["spec"]["placement"]["pools"], json!(["mine"]));
    // §7 "Job representation in responses": env values redacted, files without content.
    assert_eq!(v["spec"]["env"], json!({"API_TOKEN": "<redacted>"}));
    let files = v["spec"]["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["path"], "/inputs/a.txt");
    assert_eq!(files[0]["size"], 2);
    assert!(files[0]["sha256"].as_str().unwrap().len() == 64, "{files:?}");
    assert!(files[0].get("content_b64").is_none(), "{files:?}");
    assert!(!String::from_utf8_lossy(&r.body).contains("s3cr3t-value"));

    // What is stored: the normalized spec (with the real env value, which only the agent will read), its hash and
    // the file metadata computed once.
    let row: (String, String, String, String, i64, i64, i64, String, String) = sqlx::query_as(
        "SELECT spec, files_meta, spec_hash, status, attempt, max_attempts, units_reserved, account_id, key_id \
         FROM jobs WHERE job_id = ?",
    )
    .bind(&id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    let spec: Value = serde_json::from_str(&row.0).unwrap();
    assert_eq!(spec["image"], PYTHON);
    assert_eq!(spec["env"]["API_TOKEN"], "s3cr3t-value");
    let meta: Value = serde_json::from_str(&row.1).unwrap();
    assert_eq!(meta[0]["path"], "/inputs/a.txt");
    assert_eq!(meta[0]["size"], 2);
    assert!(row.2.starts_with("sha256:") && row.2.len() == 71, "{}", row.2);
    assert_eq!((row.3.as_str(), row.4, row.5, row.6), ("queued", 1, 2, 1000));
    assert_eq!(row.7, app.account_id.to_string());
    assert_eq!(row.8, app.admin_key.key_id().to_string());
    // The creation is the first event of the job's history.
    let ev: Vec<(Option<String>, String, String)> =
        sqlx::query_as("SELECT from_status, to_status, reason FROM job_events WHERE job_id = ? ORDER BY seq")
            .bind(&id)
            .fetch_all(&app.db)
            .await
            .unwrap();
    assert_eq!(ev, [(None, "queued".to_string(), "created".to_string())]);
}

#[tokio::test]
async fn validation_errors_are_422_with_field_paths() {
    let app = TestApp::new().await;
    let cases = [
        (
            body_with(json!({"image": "NOT A VALID IMAGE"})),
            "image",
            "invalid_format",
        ),
        (
            body_with(json!({"image": "evil.example.invalid/x/y:1"})),
            "image",
            "not_allowed",
        ),
        (body_with(json!({"command": []})), "command", "out_of_range"),
        // A bad variable name is reported on `env` itself: the name is not echoed.
        (body_with(json!({"env": {"lower": "x"}})), "env", "invalid_format"),
        (body_with(json!({"env": {"P2PC_X": "x"}})), "env.P2PC_X", "reserved"),
        (
            body_with(json!({"files": [{"path": "/etc/passwd", "content_b64": "aGk="}]})),
            "files[0].path",
            "invalid_format",
        ),
        (
            body_with(json!({"resources": {"cpu": 0.1, "memory_mb": 512}})),
            "resources.cpu",
            "out_of_range",
        ),
        (
            body_with(json!({"resources": {"cpu": 1, "memory_mb": 64}})),
            "resources.memory_mb",
            "out_of_range",
        ),
        (
            body_with(json!({"resources": {"cpu": 1, "memory_mb": 512, "disk_mb": 0}})),
            "resources.disk_mb",
            "out_of_range",
        ),
        (
            body_with(json!({"resources": {"cpu": 1, "memory_mb": 512, "gpu": 2}})),
            "resources.gpu",
            "out_of_range",
        ),
        (body_with(json!({"timeout_s": 0})), "timeout_s", "out_of_range"),
        (body_with(json!({"timeout_s": 86_401})), "timeout_s", "out_of_range"),
        (
            body_with(json!({"egress": {"allow": ["*.example.invalid"]}})),
            "egress.allow[0]",
            "invalid_format",
        ),
        (
            body_with(json!({"retry": {"max_attempts": 6}})),
            "retry.max_attempts",
            "out_of_range",
        ),
    ];
    for (b, field, code) in cases {
        let r = post_job(&app, &app.admin, b.clone(), None).await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        assert!(
            v["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["field"] == field && e["code"] == code),
            "{field}/{code} not in {v}"
        );
    }
    // Every problem is reported at once.
    let r = post_job(
        &app,
        &app.admin,
        body_with(json!({"command": [], "timeout_s": 0, "resources": {"cpu": 0.1, "memory_mb": 512}})),
        None,
    )
    .await;
    let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert_eq!(v["errors"].as_array().unwrap().len(), 3, "{v}");
    // A typo is refused, not ignored (request bodies reject unknown fields).
    let r = post_job(&app, &app.admin, body_with(json!({"memroy_mb": 5})), None).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "invalid_body");
    assert_eq!(rows(&app).await, 0);
}

#[tokio::test]
async fn an_unsupported_pool_is_422_unsupported_pool() {
    let app = TestApp::new().await;
    let r = post_job(
        &app,
        &app.admin,
        body_with(json!({"placement": {"pools": ["public"]}})),
        None,
    )
    .await;
    let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "unsupported_pool");
    assert_eq!(v["errors"][0]["field"], "placement.pools", "{v}");
    assert_eq!(rows(&app).await, 0);
}

#[tokio::test]
async fn a_validation_error_never_echoes_an_env_value() {
    let app = TestApp::new().await;
    // A newline would inject a variable into Podman's `--env-file`: refused, and the value is not repeated.
    let r = post_job(
        &app,
        &app.admin,
        body_with(json!({"env": {"TOKEN": "line1-s3cr3t\nINJECTED=1"}})),
        None,
    )
    .await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    let text = String::from_utf8_lossy(&r.body);
    assert!(!text.contains("s3cr3t") && !text.contains("INJECTED"), "{text}");
}

#[tokio::test]
async fn jobs_need_the_right_scope() {
    let app = TestApp::new().await;
    let reader = app.key_with(&[p2pc_proto::api::Scope::JobsRead]).await;
    let writer = app.key_with(&[p2pc_proto::api::Scope::JobsWrite]).await;
    let nodes = app.key_with(&[p2pc_proto::api::Scope::NodesRead]).await;
    let id = create(&app, body()).await["id"].as_str().unwrap().to_string();
    // Write needs jobs:write.
    assert_problem(
        &post_job(&app, &reader, body(), None).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_problem(&cancel(&app, &reader, &id).await, StatusCode::FORBIDDEN, "forbidden");
    // Read needs jobs:read.
    for uri in ["/v1/jobs".to_string(), format!("/v1/jobs/{id}")] {
        assert_problem(&app.get(&uri, &writer).await, StatusCode::FORBIDDEN, "forbidden");
        assert_problem(&app.get(&uri, &nodes).await, StatusCode::FORBIDDEN, "forbidden");
        assert_eq!(app.get(&uri, &reader).await.status, StatusCode::OK);
    }
    // Estimate is a read.
    let est = async |key: &str| app.call(Method::POST, "/v1/estimate", Some(key), Some(body())).await;
    assert_eq!(est(&reader).await.status, StatusCode::OK);
    assert_problem(&est(&writer).await, StatusCode::FORBIDDEN, "forbidden");
    // No key at all.
    assert_problem(
        &app.call(Method::POST, "/v1/jobs", None, Some(body())).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
}

#[tokio::test]
async fn an_image_the_key_may_not_run_is_403_image_not_allowed() {
    let app = TestApp::new().await;
    let key = job_key(&app, None, Some(vec!["docker.io/library/python:*"])).await;
    // The glob applies to the normalized image: the short form `python:3.12-slim` is allowed.
    let ok = post_job(&app, &key, body(), None).await;
    assert_eq!(
        ok.status,
        StatusCode::CREATED,
        "{:?}",
        String::from_utf8_lossy(&ok.body)
    );
    let r = post_job(&app, &key, body_with(json!({"image": "alpine:3.20"})), None).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "image_not_allowed");
    // The unrestricted admin key may run it.
    assert_eq!(
        post_job(&app, &app.admin, body_with(json!({"image": "alpine:3.20"})), None)
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(rows(&app).await, 2);
}

#[tokio::test]
async fn the_daily_cap_is_enforced_to_the_milli_unit() {
    let app = TestApp::new().await;
    // Exactly at the cap is fine: 1 vCPU for 3600 s is 1 000 milli-units.
    let exact = job_key(&app, Some(1000), None).await;
    assert_eq!(post_job(&app, &exact, body(), None).await.status, StatusCode::CREATED);
    // One more milli-unit (1 millivCPU-hour above the cap) is not.
    let over = job_key(&app, Some(1000), None).await;
    let r = post_job(
        &app,
        &over,
        body_with(json!({"resources": {"cpu": 1.001, "memory_mb": 512}})),
        None,
    )
    .await;
    let v = assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    assert!(!v["detail"].as_str().unwrap().is_empty());
    // The cap counts what the key already reserved today: 1 000 + 500 = 1 500 is exact, one milli-unit more is not.
    let key = job_key(&app, Some(1500), None).await;
    assert_eq!(post_job(&app, &key, body(), None).await.status, StatusCode::CREATED);
    let half = body_with(json!({"resources": {"cpu": 0.5, "memory_mb": 512}}));
    assert_eq!(post_job(&app, &key, half, None).await.status, StatusCode::CREATED);
    // 0.25 vCPU for one second is 69.4 milli-vCPU-seconds: the estimate rounds up to 1 milli-unit, and 1 500 + 1
    // is over.
    let tiny = body_with(json!({"timeout_s": 1, "resources": {"cpu": 0.25, "memory_mb": 512}}));
    assert_problem(
        &post_job(&app, &key, tiny.clone(), None).await,
        StatusCode::PAYMENT_REQUIRED,
        "cap_exceeded",
    );
    // A refused job reserves nothing and creates nothing: the first key's job, and this key's two.
    assert_eq!(rows(&app).await, 3);
    // The next UTC day starts afresh.
    app.clock.set(T0 + Duration::days(1));
    assert_eq!(post_job(&app, &key, tiny, None).await.status, StatusCode::CREATED);
    // A key without a cap is not limited.
    for _ in 0..3 {
        assert_eq!(
            post_job(&app, &app.admin, body(), None).await.status,
            StatusCode::CREATED
        );
    }
}

#[tokio::test]
async fn a_cap_is_the_keys_own_and_cancelling_a_queued_job_releases_its_reservation() {
    let app = TestApp::new().await;
    let a = job_key(&app, Some(1000), None).await;
    let b = job_key(&app, Some(1000), None).await;
    let first = post_job(&app, &a, body(), None).await.json();
    // Another key's reservation does not count against `a`, nor the admin's.
    assert_eq!(post_job(&app, &b, body(), None).await.status, StatusCode::CREATED);
    assert_problem(
        &post_job(&app, &a, body(), None).await,
        StatusCode::PAYMENT_REQUIRED,
        "cap_exceeded",
    );
    // A job cancelled before it ever started never ran: its reservation is released.
    assert_eq!(
        cancel(&app, &a, first["id"].as_str().unwrap()).await.status,
        StatusCode::OK
    );
    assert_eq!(post_job(&app, &a, body(), None).await.status, StatusCode::CREATED);
}

// ── Idempotency ───────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_same_idempotency_key_and_body_return_the_existing_job() {
    let app = TestApp::new().await;
    let b = body_with(json!({"idempotency_key": "run-42"}));
    let first = post_job(&app, &app.admin, b.clone(), None).await;
    assert_eq!(first.status, StatusCode::CREATED);
    let second = post_job(&app, &app.admin, b, None).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(first.json()["id"], second.json()["id"]);
    assert_eq!(first.json(), second.json());
    assert_eq!(rows(&app).await, 1);
    // The key can arrive in the header instead of the field: the same key, the same job.
    let via_header = post_job(&app, &app.admin, body(), Some("run-42")).await;
    assert_eq!(via_header.status, StatusCode::OK, "{:?}", via_header.body);
    assert_eq!(via_header.json()["id"], first.json()["id"]);
    // Equal in both places is fine.
    let both = post_job(
        &app,
        &app.admin,
        body_with(json!({"idempotency_key": "run-42"})),
        Some("run-42"),
    )
    .await;
    assert_eq!(both.status, StatusCode::OK);
    assert_eq!(rows(&app).await, 1);
    // A header alone creates a job the first time.
    let fresh = post_job(&app, &app.admin, body(), Some("run-43")).await;
    assert_eq!(fresh.status, StatusCode::CREATED);
    // The key a client sent is never echoed back (§7, c47c0a5).
    assert!(
        fresh.json()["spec"].get("idempotency_key").is_none(),
        "{}",
        fresh.json()
    );
    assert_eq!(rows(&app).await, 2);
}

#[tokio::test]
async fn an_equal_body_is_equal_whatever_the_order_of_its_keys_or_how_the_numbers_are_written() {
    let app = TestApp::new().await;
    let a =
        r#"{"idempotency_key":"k","image":"python:3.12-slim","command":["x"],"resources":{"cpu":1,"memory_mb":512}}"#;
    let b = r#"{"resources":{"memory_mb":512,"cpu":1.0},"command":["x"],"image":"docker.io/library/python:3.12-slim","idempotency_key":"k"}"#;
    for (text, expected) in [(a, StatusCode::CREATED), (b, StatusCode::OK)] {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/jobs")
            .header(header::AUTHORIZATION, format!("Bearer {}", app.admin))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(text))
            .unwrap();
        assert_eq!(app.send(req).await.status, expected);
    }
    assert_eq!(rows(&app).await, 1);
}

#[tokio::test]
async fn the_same_idempotency_key_with_another_body_is_409() {
    let app = TestApp::new().await;
    let first = post_job(&app, &app.admin, body_with(json!({"idempotency_key": "k"})), None).await;
    assert_eq!(first.status, StatusCode::CREATED);
    let other = body_with(json!({"idempotency_key": "k", "command": ["echo", "different"]}));
    let r = post_job(&app, &app.admin, other, None).await;
    assert_problem(&r, StatusCode::CONFLICT, "idempotency_conflict");
    // The same through the header.
    let r = post_job(
        &app,
        &app.admin,
        body_with(json!({"command": ["echo", "different"]})),
        Some("k"),
    )
    .await;
    assert_problem(&r, StatusCode::CONFLICT, "idempotency_conflict");
    assert_eq!(rows(&app).await, 1);
}

#[tokio::test]
async fn a_header_and_a_field_that_disagree_are_422() {
    let app = TestApp::new().await;
    let r = post_job(&app, &app.admin, body_with(json!({"idempotency_key": "a"})), Some("b")).await;
    let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert_eq!(v["errors"][0]["field"], "idempotency_key", "{v}");
    // A header that is not a valid key is refused too.
    let r = post_job(&app, &app.admin, body(), Some("has space")).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert_eq!(rows(&app).await, 0);
}

#[tokio::test]
async fn a_replay_is_not_charged_again_and_is_not_blocked_by_the_cap() {
    let app = TestApp::new().await;
    let key = job_key(&app, Some(1000), None).await;
    let b = body_with(json!({"idempotency_key": "once"}));
    assert_eq!(post_job(&app, &key, b.clone(), None).await.status, StatusCode::CREATED);
    // The cap is used up, but a retry of the same request gets its job back instead of `402`.
    assert_eq!(post_job(&app, &key, b, None).await.status, StatusCode::OK);
    assert_eq!(rows(&app).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_parallel_creates_with_one_key_make_one_job() {
    let app = TestApp::new().await;
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let router = app.router.clone();
        let admin = app.admin.clone();
        set.spawn(async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body_with(json!({"idempotency_key": "race"})).to_string()))
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            (status, v["id"].as_str().unwrap_or("").to_string())
        });
    }
    let mut created = 0;
    let mut ids = std::collections::BTreeSet::new();
    while let Some(r) = set.join_next().await {
        let (status, id) = r.unwrap();
        match status {
            StatusCode::CREATED => created += 1,
            StatusCode::OK => {}
            other => panic!("unexpected {other}"),
        }
        ids.insert(id);
    }
    assert_eq!(created, 1);
    assert_eq!(ids.len(), 1, "every answer names the same job: {ids:?}");
    assert_eq!(rows(&app).await, 1);
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM job_events")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(events, 1);
}

// ── Re-check at the point of use ──────────────────────────────────────────────────────────────────────────────

/// A clock that answers a scripted sequence of times, then repeats the last one: a key can expire between the auth
/// middleware (the first reading) and the handler.
#[derive(Debug)]
struct ScriptedClock(std::sync::Mutex<std::collections::VecDeque<time::OffsetDateTime>>);

impl Clock for ScriptedClock {
    fn now(&self) -> time::OffsetDateTime {
        let mut q = self.0.lock().unwrap();
        if q.len() > 1 {
            q.pop_front().unwrap()
        } else {
            *q.front().unwrap()
        }
    }
}

#[tokio::test]
async fn a_key_that_expires_mid_request_creates_no_job_and_is_audited() {
    let mut app = TestApp::new().await;
    let (key, v) = app
        .create_key(json!({"scopes": ["jobs:write"], "expires_at": "2026-11-05T11:00:00Z"}))
        .await;
    let late = T0 + Duration::hours(2);
    let clock = std::sync::Arc::new(ScriptedClock(std::sync::Mutex::new([T0, late].into_iter().collect())));
    app.state.clock = clock;
    app.router = p2pc_server::app::router(app.state.clone());
    let r = post_job(&app, &key, body_with(json!({"idempotency_key": "x"})), None).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert_eq!(rows(&app).await, 0);
    // The refused attempt is queued as an `auth_failed` event of that key, like any failed login.
    app.flush_audit().await;
    let audit: Value = sqlx::query_scalar::<_, String>(
        "SELECT detail FROM audit_events WHERE kind = 'auth_failed' AND subject_id = ?",
    )
    .bind(v["id"].as_str().unwrap())
    .fetch_one(&app.db)
    .await
    .map(|s| serde_json::from_str(&s).unwrap())
    .unwrap();
    assert_eq!(audit["count"], 1);
}

// ── List ──────────────────────────────────────────────────────────────────────────────────────────────────────

fn ids_of(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn list_paginates_in_a_stable_order_across_three_pages() {
    let app = TestApp::new().await;
    // Two jobs in the first second, one in the next, two in the last: the order is created_at descending, then id.
    let mut jobs: Vec<(i64, String)> = Vec::new();
    for (offset, n) in [(0, 2), (1, 1), (2, 2)] {
        app.clock.set(T0 + Duration::seconds(offset));
        for _ in 0..n {
            let v = create(&app, body()).await;
            jobs.push((T0.unix_timestamp() + offset, v["id"].as_str().unwrap().to_string()));
        }
    }
    jobs.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let expected: Vec<String> = jobs.into_iter().map(|j| j.1).collect();

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut sizes = Vec::new();
    for _ in 0..3 {
        let uri = match &cursor {
            None => "/v1/jobs?limit=2".to_string(),
            Some(c) => format!("/v1/jobs?limit=2&cursor={c}"),
        };
        let page = app.get(&uri, &app.admin).await.json();
        sizes.push(ids_of(&page).len());
        seen.extend(ids_of(&page));
        cursor = page["next_cursor"].as_str().map(str::to_string);
    }
    assert_eq!(sizes, [2, 2, 1]);
    assert_eq!(cursor, None, "the last page has no next_cursor");
    assert_eq!(seen, expected);
    // The same listing without a limit gives the same order in one page.
    let all = app.get("/v1/jobs", &app.admin).await.json();
    assert_eq!(ids_of(&all), expected);
    assert_eq!(all["next_cursor"], Value::Null);
    // Repeating a page gives the same page (the order is stable).
    let again = app.get("/v1/jobs?limit=2", &app.admin).await.json();
    assert_eq!(ids_of(&again), expected[..2]);
}

#[tokio::test]
async fn list_filters_by_status_and_node() {
    let app = TestApp::new().await;
    let a = create(&app, body()).await["id"].as_str().unwrap().to_string();
    let b = create(&app, body()).await["id"].as_str().unwrap().to_string();
    let c = create(&app, body()).await["id"].as_str().unwrap().to_string();
    assert_eq!(cancel(&app, &app.admin, &b).await.status, StatusCode::OK);
    let node = p2pc_proto::ids::NodeId::generate().to_string();
    sqlx::query("UPDATE jobs SET status = 'running', node_id = ? WHERE job_id = ?")
        .bind(&node)
        .bind(&c)
        .execute(&app.db)
        .await
        .unwrap();

    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let by_status = |s: &str| {
        let uri = format!("/v1/jobs?status={s}");
        let app = &app;
        async move { ids_of(&app.get(&uri, &app.admin).await.json()) }
    };
    assert_eq!(by_status("queued").await, std::slice::from_ref(&a));
    assert_eq!(by_status("cancelled").await, std::slice::from_ref(&b));
    assert_eq!(by_status("running").await, std::slice::from_ref(&c));
    assert!(by_status("succeeded").await.is_empty());
    let on_node = app.get(&format!("/v1/jobs?node_id={node}"), &app.admin).await.json();
    assert_eq!(ids_of(&on_node), std::slice::from_ref(&c));
    let both = app
        .get(&format!("/v1/jobs?node_id={node}&status=queued"), &app.admin)
        .await
        .json();
    assert!(ids_of(&both).is_empty());
    assert_eq!(
        sorted(ids_of(&app.get("/v1/jobs", &app.admin).await.json())),
        sorted(vec![a, b, c])
    );
    // A filter that is not a value of its type is a 422, not an empty list.
    for bad in ["status=finished", "node_id=nope", "status="] {
        let r = app.get(&format!("/v1/jobs?{bad}"), &app.admin).await;
        assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
}

#[tokio::test]
async fn list_refuses_a_bad_cursor_or_limit() {
    let app = TestApp::new().await;
    create(&app, body()).await;
    // Not base64, base64 of something else, and a cursor with a bad job ID.
    let not_a_cursor = data_encoding::BASE64URL_NOPAD.encode(b"hello");
    let bad_id = data_encoding::BASE64URL_NOPAD.encode(b"1793872800.job_nope");
    for cursor in ["%%%", "garbage", &not_a_cursor, &bad_id, "1.2.3"] {
        let r = app.get(&format!("/v1/jobs?cursor={cursor}"), &app.admin).await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        assert_eq!(v["errors"][0]["field"], "cursor", "{cursor}: {v}");
    }
    for limit in ["0", "101", "abc"] {
        let r = app.get(&format!("/v1/jobs?limit={limit}"), &app.admin).await;
        assert!(
            r.status == StatusCode::UNPROCESSABLE_ENTITY || r.status == StatusCode::BAD_REQUEST,
            "{limit}: {}",
            r.status
        );
    }
    assert_eq!(app.get("/v1/jobs?limit=100", &app.admin).await.status, StatusCode::OK);
    // The cursor is opaque base64, never the raw `<time>.<id>`.
    let first = create(&app, body()).await;
    let page = app.get("/v1/jobs?limit=1", &app.admin).await.json();
    let cursor = page["next_cursor"].as_str().unwrap();
    assert!(!cursor.contains('.') && !cursor.contains("job_"), "{cursor}");
    assert!(data_encoding::BASE64URL_NOPAD.decode(cursor.as_bytes()).is_ok());
    drop(first);
}

// ── Get (SI-7) ────────────────────────────────────────────────────────────────────────────────────────────────

/// `GET /v1/jobs/{id}` is the one read that adds `attempts` (T06, §7); the other responses leave it out. These jobs
/// were never placed, so it is empty. Returns the job without it, to compare with the others.
fn without_attempts(mut v: Value) -> Value {
    let attempts = v.as_object_mut().unwrap().remove("attempts");
    assert_eq!(attempts, Some(json!([])), "{v}");
    v
}

#[tokio::test]
async fn get_returns_the_job_and_never_another_accounts() {
    let app = TestApp::new().await;
    let mine = create(&app, body_with(json!({"env": {"TOKEN": "abc"}}))).await;
    let id = mine["id"].as_str().unwrap();
    let r = app.get(&format!("/v1/jobs/{id}"), &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(without_attempts(r.json()), mine);

    // SI-7: another account gets a 404 for it, the same answer as for a job that does not exist: no 403, so the
    // job's existence is not leaked. Listing, getting and cancelling are all filtered by the principal.
    let (other, _) = second_account(&app).await;
    let theirs = post_job(&app, &other, body(), None).await;
    assert_eq!(theirs.status, StatusCode::CREATED, "{:?}", theirs.body);
    let theirs = theirs.json();
    let their_id = theirs["id"].as_str().unwrap();
    assert_ne!(theirs["project_id"], mine["project_id"]);

    let missing = app.get("/v1/jobs/job_01ARZ3NDEKTSV4RRFFQ69G5FAV", &other).await;
    assert_problem(&missing, StatusCode::NOT_FOUND, "not_found");
    let cross = app.get(&format!("/v1/jobs/{id}"), &other).await;
    assert_problem(&cross, StatusCode::NOT_FOUND, "not_found");
    assert_eq!(
        cross.body, missing.body,
        "a foreign job looks exactly like a missing one"
    );
    assert_problem(
        &app.get(&format!("/v1/jobs/{their_id}"), &app.admin).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    assert_problem(&cancel(&app, &other, id).await, StatusCode::NOT_FOUND, "not_found");
    assert_problem(
        &cancel(&app, &app.admin, their_id).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    assert_eq!(ids_of(&app.get("/v1/jobs", &app.admin).await.json()), [id]);
    assert_eq!(ids_of(&app.get("/v1/jobs", &other).await.json()), [their_id]);
    // Nothing happened to either job.
    let still: String = sqlx::query_scalar("SELECT status FROM jobs WHERE job_id = ?")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(still, "queued");
    // A malformed ID is a plain 404, too.
    assert_problem(
        &app.get("/v1/jobs/not-an-id", &app.admin).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
}

/// Spec §7 (c47c0a5): idempotency keys are scoped to the **API key** that sent them. Otherwise a second key could
/// resubmit a spec it can see, with a guessed `env` value, and learn from `200` versus `409` whether the guess was
/// right. Here key A's job has a secret env value; keys B and C, in the same project, each try one guess (B the
/// right value, C a wrong one) under A's idempotency key, and get the same answer: a new job, `201`.
#[tokio::test]
async fn another_key_reusing_an_idempotency_key_gets_its_own_job_and_learns_nothing() {
    let app = TestApp::new().await;
    let a = job_key(&app, None, None).await;
    let b = job_key(&app, None, None).await;
    let c = job_key(&app, None, None).await;
    let spec_with = |token: &str| body_with(json!({"env": {"TOKEN": token}, "idempotency_key": "shared-key"}));
    let first = post_job(&app, &a, spec_with("the-secret"), None).await;
    assert_eq!(first.status, StatusCode::CREATED);
    let a_id = first.json()["id"].as_str().unwrap().to_string();

    // B guesses right: not a `200` with A's job. C guesses wrong: not a `409`.
    let right = post_job(&app, &b, spec_with("the-secret"), None).await;
    assert_eq!(
        right.status,
        StatusCode::CREATED,
        "{:?}",
        String::from_utf8_lossy(&right.body)
    );
    let wrong = post_job(&app, &c, spec_with("a-wrong-guess"), None).await;
    assert_eq!(
        wrong.status,
        StatusCode::CREATED,
        "{:?}",
        String::from_utf8_lossy(&wrong.body)
    );
    let (right, wrong) = (right.json(), wrong.json());
    for new in [&right, &wrong] {
        assert_ne!(new["id"], a_id.as_str(), "someone was given A's job");
        assert!(!new.to_string().contains(&a_id));
    }
    assert_ne!(right["id"], wrong["id"]);
    // The two answers have the same shape: nothing tells the right guess from the wrong one.
    let shape = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(shape(&right), shape(&wrong));
    // The same through the header, with yet another body.
    let d = job_key(&app, None, None).await;
    let via_header = post_job(
        &app,
        &d,
        body_with(json!({"command": ["echo", "x"]})),
        Some("shared-key"),
    )
    .await;
    assert_eq!(via_header.status, StatusCode::CREATED);

    // A's own key keeps its behaviour: `200` for the same request, `409` for another one.
    let replay = post_job(&app, &a, spec_with("the-secret"), None).await;
    assert_eq!(
        (replay.status, replay.json()["id"].as_str()),
        (StatusCode::OK, Some(a_id.as_str()))
    );
    assert_problem(
        &post_job(&app, &a, spec_with("another-value"), None).await,
        StatusCode::CONFLICT,
        "idempotency_conflict",
    );
    // B's own replay finds B's own job, not A's; and B reusing its own key for another body is B's own `409`.
    let b_replay = post_job(&app, &b, spec_with("the-secret"), None).await;
    assert_eq!(b_replay.status, StatusCode::OK);
    assert_eq!(b_replay.json()["id"], right["id"]);
    assert_problem(
        &post_job(&app, &b, spec_with("a-wrong-guess"), None).await,
        StatusCode::CONFLICT,
        "idempotency_conflict",
    );
    assert_eq!(rows(&app).await, 4);
}

#[tokio::test]
async fn an_idempotency_key_means_nothing_to_another_account() {
    let app = TestApp::new().await;
    let (other, _) = second_account(&app).await;
    let b = body_with(json!({"idempotency_key": "same"}));
    let mine = post_job(&app, &app.admin, b.clone(), None).await;
    let theirs = post_job(&app, &other, b, None).await;
    assert_eq!(mine.status, StatusCode::CREATED);
    assert_eq!(theirs.status, StatusCode::CREATED);
    assert_ne!(mine.json()["id"], theirs.json()["id"]);
}

/// No response contains the idempotency key: not the creation, the replay, `GET`, the list, the cancel, nor the
/// listing of another page. It is stored (to make the replay work), never returned.
#[tokio::test]
async fn no_response_contains_the_idempotency_key() {
    let app = TestApp::new().await;
    let by_field = "k-field-5d0c1e7a";
    let by_header = "k-header-9b21f4c3";
    let created = post_job(&app, &app.admin, body_with(json!({"idempotency_key": by_field})), None).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let id = created.json()["id"].as_str().unwrap().to_string();
    let second = post_job(&app, &app.admin, body(), Some(by_header)).await;
    assert_eq!(second.status, StatusCode::CREATED);
    let mut responses = vec![created, second];
    responses.push(post_job(&app, &app.admin, body_with(json!({"idempotency_key": by_field})), None).await);
    responses.push(post_job(&app, &app.admin, body(), Some(by_header)).await);
    responses.push(app.get(&format!("/v1/jobs/{id}"), &app.admin).await);
    responses.push(app.get("/v1/jobs", &app.admin).await);
    responses.push(app.get("/v1/jobs?limit=1", &app.admin).await);
    responses.push(cancel(&app, &app.admin, &id).await);
    responses.push(
        app.call(
            Method::POST,
            "/v1/estimate",
            Some(&app.admin),
            Some(body_with(json!({"idempotency_key": by_field}))),
        )
        .await,
    );
    assert_eq!(responses.len(), 9);
    for (i, r) in responses.iter().enumerate() {
        let text = String::from_utf8_lossy(&r.body);
        assert!(r.status.is_success(), "{i}: {}", r.status);
        for needle in [by_field, by_header, "idempotency_key", "idempotency"] {
            assert!(!text.contains(needle), "response {i} contains {needle:?}: {text}");
        }
    }
    // It is stored, so a replay works: the field of the stored spec.
    let stored: String = sqlx::query_scalar("SELECT idempotency_key FROM jobs WHERE job_id = ?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(stored, by_field);
}

// ── Cancel ────────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cancelling_a_queued_job_ends_it_at_once_and_is_idempotent() {
    let app = TestApp::new().await;
    let id = create(&app, body()).await["id"].as_str().unwrap().to_string();
    app.clock.set(T0 + Duration::seconds(5));
    let r = cancel(&app, &app.admin, &id).await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["status"], "cancelled");
    assert_eq!(v["finished_at"], "2026-11-05T10:00:05Z");
    assert_eq!(v["cancel_requested_at"], Value::Null, "nothing to deliver to a node");
    // Cancelling twice is the same answer, with nothing changed.
    app.clock.set(T0 + Duration::seconds(50));
    let again = cancel(&app, &app.admin, &id).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json(), v);
    assert_eq!(
        without_attempts(app.get(&format!("/v1/jobs/{id}"), &app.admin).await.json()),
        v
    );
    // One transition event, with a reason, after the creation.
    let ev: Vec<(Option<String>, String, String)> =
        sqlx::query_as("SELECT from_status, to_status, reason FROM job_events WHERE job_id = ? ORDER BY seq")
            .bind(&id)
            .fetch_all(&app.db)
            .await
            .unwrap();
    assert_eq!(
        ev,
        [
            (None, "queued".to_string(), "created".to_string()),
            (
                Some("queued".to_string()),
                "cancelled".to_string(),
                "cancelled_by_user".to_string()
            ),
        ]
    );
}

#[tokio::test]
async fn a_terminal_job_is_unchanged_by_cancel() {
    let app = TestApp::new().await;
    for terminal in ["succeeded", "failed", "timed_out", "lost", "cancelled"] {
        let id = create(&app, body()).await["id"].as_str().unwrap().to_string();
        sqlx::query("UPDATE jobs SET status = ?, finished_at = ?, exit_code = 0 WHERE job_id = ?")
            .bind(terminal)
            .bind(T0.unix_timestamp())
            .bind(&id)
            .execute(&app.db)
            .await
            .unwrap();
        let before = without_attempts(app.get(&format!("/v1/jobs/{id}"), &app.admin).await.json());
        app.clock.advance(Duration::seconds(10));
        let r = cancel(&app, &app.admin, &id).await;
        assert_eq!(r.status, StatusCode::OK, "{terminal}");
        assert_eq!(r.json(), before, "{terminal}");
    }
}

#[tokio::test]
async fn cancelling_a_running_job_records_the_request_and_keeps_the_status() {
    let app = TestApp::new().await;
    for status in ["assigned", "running"] {
        let id = create(&app, body()).await["id"].as_str().unwrap().to_string();
        sqlx::query("UPDATE jobs SET status = ? WHERE job_id = ?")
            .bind(status)
            .bind(&id)
            .execute(&app.db)
            .await
            .unwrap();
        app.clock.advance(Duration::seconds(10));
        let asked_at = app.clock.now();
        let r = cancel(&app, &app.admin, &id).await;
        assert_eq!(r.status, StatusCode::OK);
        let v = r.json();
        assert_eq!(
            v["status"], status,
            "T06 delivers the Cancel; the job ends when the node reports"
        );
        assert_eq!(
            v["cancel_requested_at"],
            asked_at.format(&time::format_description::well_known::Rfc3339).unwrap()
        );
        assert_eq!(v["finished_at"], Value::Null);
        // Asking again changes nothing, not even the time of the first request.
        app.clock.advance(Duration::seconds(10));
        let again = cancel(&app, &app.admin, &id).await;
        assert_eq!(again.json(), v);
    }
}

// ── Estimate ──────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn estimate_with_no_nodes_is_not_feasible_and_says_why() {
    let app = TestApp::new().await;
    let r = app
        .call(Method::POST, "/v1/estimate", Some(&app.admin), Some(body()))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["feasible"], false);
    assert_eq!(v["matching_nodes"], 0);
    assert_eq!(v["would_queue"], true);
    assert_eq!(v["units_per_hour"], 1000);
    assert!(!v["reason"].as_str().unwrap().is_empty(), "{v}");
    // It created nothing.
    assert_eq!(rows(&app).await, 0);
    // A GPU is 10 units an hour on top of the CPUs: 2 + 10 vCPU-hour-equivalents.
    let gpu = body_with(json!({"resources": {"cpu": 2, "memory_mb": 512, "gpu": 1}}));
    let v = app
        .call(Method::POST, "/v1/estimate", Some(&app.admin), Some(gpu))
        .await
        .json();
    assert_eq!(v["units_per_hour"], 12_000);
}

#[tokio::test]
async fn estimate_validates_like_create() {
    let app = TestApp::new().await;
    let r = app
        .call(
            Method::POST,
            "/v1/estimate",
            Some(&app.admin),
            Some(body_with(json!({"timeout_s": 0}))),
        )
        .await;
    let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert_eq!(v["errors"][0]["field"], "timeout_s");
    let r = app
        .call(
            Method::POST,
            "/v1/estimate",
            Some(&app.admin),
            Some(body_with(json!({"placement": {"pools": ["public"]}}))),
        )
        .await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "unsupported_pool");
    // Header and field that disagree are refused here as well.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/estimate")
        .header(header::AUTHORIZATION, format!("Bearer {}", app.admin))
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", "a")
        .body(Body::from(body_with(json!({"idempotency_key": "b"})).to_string()))
        .unwrap();
    assert_problem(
        &app.send(req).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
    );
}

#[tokio::test]
async fn estimate_applies_the_keys_allowed_images_like_create() {
    let app = TestApp::new().await;
    let (key, _) = app
        .create_key(json!({
            "scopes": ["jobs:read"],
            "allowed_images": ["docker.io/library/python:*"],
        }))
        .await;
    let est = async |image: &str| {
        app.call(
            Method::POST,
            "/v1/estimate",
            Some(&key),
            Some(body_with(json!({"image": image}))),
        )
        .await
    };
    assert_eq!(est("python:3.12-slim").await.status, StatusCode::OK);
    assert_problem(&est("alpine:3.20").await, StatusCode::FORBIDDEN, "image_not_allowed");
}

/// A directory with `n` matching nodes, `free` of which have room now.
#[derive(Debug)]
struct FakeDirectory {
    matching: u32,
    free: u32,
}

impl p2pc_server::node_directory::NodeDirectory for FakeDirectory {
    fn match_job<'a>(
        &'a self,
        _account_id: p2pc_proto::ids::AccountId,
        _spec: &'a p2pc_proto::api::JobSpec,
    ) -> p2pc_server::node_directory::BoxFuture<'a, p2pc_server::node_directory::NodeMatch> {
        Box::pin(async move {
            p2pc_server::node_directory::NodeMatch {
                matching_nodes: self.matching,
                free_nodes: self.free,
            }
        })
    }
}

#[tokio::test]
async fn estimate_reads_the_node_directory() {
    let mut app = TestApp::new().await;
    for (matching, free, feasible, would_queue) in [(2, 1, true, false), (2, 0, true, true), (0, 0, false, true)] {
        app.state.nodes = std::sync::Arc::new(FakeDirectory { matching, free });
        app.router = p2pc_server::app::router(app.state.clone());
        let v = app
            .call(Method::POST, "/v1/estimate", Some(&app.admin), Some(body()))
            .await
            .json();
        assert_eq!(v["matching_nodes"], matching, "{v}");
        assert_eq!(v["feasible"], feasible, "{v}");
        assert_eq!(v["would_queue"], would_queue, "{v}");
        // A reason is given exactly when there is something to explain.
        assert_eq!(v.get("reason").is_some(), !feasible || would_queue, "{v}");
    }
}

// ── The read path never loads `spec` (T04 re-review, P2) ──────────────────────────────────────────────────────

/// Standard base64 of `n` bytes.
fn b64_of_len(n: usize) -> String {
    data_encoding::BASE64.encode(&vec![b'a'; n])
}

/// 50 jobs that each carry about 500 KiB of input files: a page of them is small, because the API serves the
/// redacted `spec_view` and never loads `spec`. (A page of 100 such jobs used to pull about 100 MiB out of SQLite.)
///
/// One job goes through `POST /v1/jobs`; the other 49 are inserted with the store's own `insert` (the same code the
/// handler calls), because validating, hashing and serializing 700 KB fifty times over HTTP in a debug build takes
/// half a minute and proves nothing more about the read path.
#[tokio::test]
async fn a_page_of_jobs_with_large_files_is_small() {
    use p2pc_proto::api::{FileMeta, JobSpec};
    use p2pc_proto::ids::JobId;
    use p2pc_proto::units::Units;
    use p2pc_server::store::jobs::{NewJob, insert};

    let app = TestApp::new().await;
    let content = b64_of_len(500 * 1024);
    let big = |i: usize| {
        body_with(json!({
            "name": format!("big-{i}"),
            "env": {"TOKEN": format!("secret-{i}")},
            "files": [{"path": "/inputs/data.bin", "content_b64": content}],
        }))
    };
    let r = post_job(&app, &app.admin, big(0), None).await;
    assert_eq!(r.status, StatusCode::CREATED);
    // The response to a create is small, whatever the files weigh.
    assert!(r.body.len() < 4096, "create response: {} bytes", r.body.len());
    let mut first: JobSpec = serde_json::from_value(big(1)).unwrap();
    first.image = PYTHON.to_string();
    let files_meta = FileMeta::compute_all(&first).unwrap();
    let mut conn = app.db.acquire().await.unwrap();
    for i in 1..50 {
        let mut spec = first.clone();
        spec.name = Some(format!("big-{i}"));
        spec.env.insert("TOKEN".into(), format!("secret-{i}"));
        let new = NewJob {
            job_id: JobId::generate(),
            account_id: app.account_id,
            project_id: app.project_id,
            key_id: app.admin_key.key_id(),
            spec,
            files_meta: files_meta.clone(),
            spec_hash: format!("sha256:{}", "0".repeat(64)),
            units_reserved: Units::from_milli(1000),
        };
        insert(&mut conn, &new, T0).await.unwrap();
    }
    drop(conn);
    assert_eq!(rows(&app).await, 50);
    // The files really are in the database: about 25 MiB of `spec` text.
    let stored: i64 = sqlx::query_scalar("SELECT SUM(length(spec)) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert!(stored > 25 * 1024 * 1024, "{stored} bytes of spec");
    let view_bytes: i64 = sqlx::query_scalar("SELECT SUM(length(spec_view)) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert!(view_bytes < 50 * 4096, "{view_bytes} bytes of spec_view");

    let r = app.get("/v1/jobs?limit=50", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.len() < 50 * 2048, "a page of 50 jobs is {} bytes", r.body.len());
    let page = r.json();
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 50);
    for item in items {
        let file = &item["spec"]["files"][0];
        assert_eq!(
            (file["path"].as_str(), file["size"].as_u64()),
            (Some("/inputs/data.bin"), Some(500 * 1024))
        );
        assert_eq!(file["sha256"].as_str().unwrap().len(), 64);
        assert!(item["spec"]["env"]["TOKEN"] == "<redacted>");
    }
    assert!(!String::from_utf8_lossy(&r.body).contains(&content[..64]));
}

/// The behavioural twin of the static `read_path_sql` check: with `jobs.spec` replaced by something that is not a
/// job spec at all, list, get, cancel and the idempotent replay still answer, with the same bodies. Only `load_spec`
/// (lease building, T06) reads the column, and it now fails, so it is the only thing that does.
#[tokio::test]
async fn list_get_cancel_and_replay_never_read_the_spec_column() {
    let app = TestApp::new().await;
    let b = body_with(json!({
        "env": {"TOKEN": "s3cr3t"},
        "files": [{"path": "/inputs/a.txt", "content_b64": "aGk="}],
        "idempotency_key": "never-read-spec",
    }));
    let created = post_job(&app, &app.admin, b.clone(), None).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let created = created.json();
    let id = created["id"].as_str().unwrap().to_string();
    let second = create(&app, body()).await["id"].as_str().unwrap().to_string();

    // The spec as the scheduler can still read it, then broken.
    let job_id: p2pc_proto::ids::JobId = id.parse().unwrap();
    let mut conn = app.db.acquire().await.unwrap();
    let spec = p2pc_server::store::jobs::load_spec(&mut conn, app.account_id, app.project_id, job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        spec.env["TOKEN"], "s3cr3t",
        "load_spec returns the real values: it is for leases"
    );
    assert_eq!(spec.files[0].content_b64, "aGk=");
    drop(conn);
    sqlx::query("UPDATE jobs SET spec = '{\"not\": \"a job spec\"}'")
        .execute(&app.db)
        .await
        .unwrap();
    let mut conn = app.db.acquire().await.unwrap();
    assert!(
        p2pc_server::store::jobs::load_spec(&mut conn, app.account_id, app.project_id, job_id)
            .await
            .is_err(),
        "the spec column is broken, and only load_spec notices"
    );
    drop(conn);

    // Every API read still works and says the same thing as before.
    assert_eq!(
        without_attempts(app.get(&format!("/v1/jobs/{id}"), &app.admin).await.json()),
        created
    );
    let list = app.get("/v1/jobs", &app.admin).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json()["items"].as_array().unwrap().len(), 2);
    let replay = post_job(&app, &app.admin, b, None).await;
    assert_eq!(
        replay.status,
        StatusCode::OK,
        "{:?}",
        String::from_utf8_lossy(&replay.body)
    );
    assert_eq!(replay.json(), created);
    let cancelled = cancel(&app, &app.admin, &second).await;
    assert_eq!(cancelled.status, StatusCode::OK);
    assert_eq!(cancelled.json()["status"], "cancelled");
}

/// The golden: `spec_view` is what the old read path produced from `spec` (`JobSpecView::from_stored`), and a fixed
/// literal. Env values are `<redacted>`, files are `{path, size, sha256}` with no content, and there is no
/// idempotency key.
#[tokio::test]
async fn the_stored_spec_view_is_what_the_old_code_made_from_the_spec() {
    let app = TestApp::new().await;
    let b = json!({
        "name": "answer",
        "image": "python:3.12-slim",
        "command": ["python", "-c", "print(6*7)"],
        "env": {"API_TOKEN": "s3cr3t-value", "B_SECOND": "another-secret"},
        "files": [
            {"path": "/inputs/a.txt", "content_b64": "aGk="},
            {"path": "/inputs/dir/b.bin", "content_b64": ""},
        ],
        "resources": {"cpu": 1.5, "memory_mb": 512},
        "timeout_s": 1800,
        "egress": {"allow": ["pypi.org"]},
        "idempotency_key": "golden-1",
    });
    let created = post_job(&app, &app.admin, b, None).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let id = created.json()["id"].as_str().unwrap().to_string();

    let (spec_text, view_text): (String, String) = sqlx::query_as("SELECT spec, spec_view FROM jobs WHERE job_id = ?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    // 1. The old code: build the view from the stored spec (decoding and hashing the files).
    let stored: p2pc_proto::api::JobSpec = serde_json::from_str(&spec_text).unwrap();
    let old = p2pc_proto::api::JobSpecView::from_stored(&stored).unwrap();
    let view: p2pc_proto::api::JobSpecView = serde_json::from_str(&view_text).unwrap();
    assert_eq!(view, old);
    // 2. A fixed literal (the SHA-256 of "hi" and of nothing).
    let golden = json!({
        "name": "answer",
        "image": "docker.io/library/python:3.12-slim",
        "command": ["python", "-c", "print(6*7)"],
        "env": {"API_TOKEN": "<redacted>", "B_SECOND": "<redacted>"},
        "files": [
            {"path": "/inputs/a.txt", "size": 2,
             "sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"},
            {"path": "/inputs/dir/b.bin", "size": 0,
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        ],
        "resources": {"cpu": 1.5, "memory_mb": 512, "gpu": 0, "disk_mb": 2048},
        "timeout_s": 1800,
        "egress": {"allow": ["pypi.org"]},
        "outputs": {"max_mb": 1024},
        "placement": {"pools": ["mine"], "node_id": null, "labels": {}},
        "retry": {"max_attempts": 2},
    });
    assert_eq!(serde_json::from_str::<Value>(&view_text).unwrap(), golden);
    // 3. It holds no secret and no content, and the API serves exactly it.
    for needle in ["s3cr3t-value", "another-secret", "content_b64", "golden-1", "aGk="] {
        assert!(!view_text.contains(needle), "{needle} in {view_text}");
    }
    assert_eq!(
        app.get(&format!("/v1/jobs/{id}"), &app.admin).await.json()["spec"],
        golden
    );
    // The spec itself keeps what the agent needs.
    assert!(spec_text.contains("s3cr3t-value") && spec_text.contains("aGk="));
}

// ── `too_large` through the API (spec §7 `files`) ─────────────────────────────────────────────────────────────

/// The largest job that validates, built like `largest_deliverable_spec()` of `p2pc-proto`: worst-case JSON
/// escaping (control characters are `\u00XX`, six bytes each) in `command` and `env`, and file content filling the
/// rest, so that its worst-case `Lease` is exactly `MAX_FRAME_LEN` bytes.
fn largest_deliverable_spec() -> p2pc_proto::api::JobSpec {
    use p2pc_proto::protocol::{MAX_FRAME_LEN, lease_frame_len};
    let mut s: p2pc_proto::api::JobSpec = serde_json::from_value(json!({
        "image": PYTHON,
        "command": ["python", "\u{1}".repeat(40 * 1024), ""],
        "env": {"A": "\u{1f}".repeat(30 * 1024)},
        "files": [{"path": "/inputs/data.bin", "content_b64": ""}],
        "resources": {"cpu": 1, "memory_mb": 512},
    }))
    .unwrap();
    let max = MAX_FRAME_LEN as usize;
    // Fill with file content, in whole base64 quanta, up to a little under the frame limit.
    let room = max - lease_frame_len(&s) - 64;
    s.files[0].content_b64 = b64_of_len(room / 4 * 3);
    // Then close the gap byte by byte: each plain ASCII character adds exactly one byte.
    let gap = max - lease_frame_len(&s);
    s.command[2] = "x".repeat(gap);
    assert_eq!(lease_frame_len(&s), max);
    s
}

/// The largest deliverable job is accepted (so a body that big gets through the HTTP body limit), and one byte more
/// is `422 too_large` on field `job`: the job would not fit one `Lease` frame.
#[tokio::test]
async fn a_job_that_would_not_fit_its_lease_frame_is_422_too_large() {
    let app = TestApp::new().await;
    let largest = largest_deliverable_spec();
    let at_the_limit = serde_json::to_value(&largest).unwrap();
    assert!(
        serde_json::to_vec(&at_the_limit).unwrap().len() > 700 * 1024,
        "the body is big, so the HTTP body limit is really exercised"
    );
    let r = post_job(&app, &app.admin, at_the_limit, None).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", String::from_utf8_lossy(&r.body));
    assert_eq!(rows(&app).await, 1);

    let mut bigger = largest;
    bigger.command[2].push('x');
    let r = post_job(&app, &app.admin, serde_json::to_value(&bigger).unwrap(), None).await;
    let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "too_large");
    let errors = v["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{v}");
    assert_eq!(
        (errors[0]["field"].as_str(), errors[0]["code"].as_str()),
        (Some("job"), Some("too_large"))
    );
    // The refusal says nothing about the content, and creates nothing.
    let text = String::from_utf8_lossy(&r.body);
    assert!(
        !text.contains('\u{1}') && !text.contains("xxxx"),
        "{} bytes",
        text.len()
    );
    assert_eq!(rows(&app).await, 1);
    // The estimate refuses it the same way.
    let r = app
        .call(
            Method::POST,
            "/v1/estimate",
            Some(&app.admin),
            Some(serde_json::to_value(&bigger).unwrap()),
        )
        .await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "too_large");
}
