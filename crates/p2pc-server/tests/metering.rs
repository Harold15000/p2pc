// SPDX-License-Identifier: AGPL-3.0-only

//! The metering additions seen from the REST API (H2 §7.2, §12): a capped principal's service reserves one UTC day
//! at `POST /v1/jobs` (`402 cap_exceeded` under 15 minutes of runtime, never its 30-day estimate), `cap_deadline` in
//! `GET /v1/jobs/{id}`, and the new `group_by` values of `GET /v1/usage`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{TestApp, assert_problem};
use serde_json::{Value, json};

/// A service of `cpu` vCPUs that may run 30 days.
fn service(cpu: f64) -> Value {
    json!({"kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
        "resources": {"cpu": cpu, "memory_mb": 256}, "timeout_s": 30 * 86_400,
        "service": {"ports": [{"port": 8080, "name": "http"}]}})
}

#[tokio::test]
async fn a_capped_service_reserves_one_day_not_its_whole_timeout() {
    let app = TestApp::new().await;
    // 2 units a day: a 30-day service of 1 vCPU would be 720 units by H1's estimate.
    let (key, _) = app
        .create_key(json!({"scopes": ["jobs:read", "jobs:write"], "daily_unit_cap": 2000}))
        .await;
    let r = app.call(Method::POST, "/v1/jobs", Some(&key), Some(service(1.0))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.json()["id"].as_str().unwrap().to_string();
    // Queued: no attempt runs, so no cap deadline yet.
    let got = app.get(&format!("/v1/jobs/{id}"), &key).await.json();
    assert_eq!(got["service"]["cap_deadline"], Value::Null);
    // Its day reservation took the whole cap (14 hours are left at 10:00 UTC): nothing is left for a batch job.
    let batch = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256}, "timeout_s": 60});
    let r = app.call(Method::POST, "/v1/jobs", Some(&key), Some(batch)).await;
    let p = assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    assert!(
        p["detail"].as_str().unwrap().contains("2.000 are already reserved"),
        "{p}"
    );
}

#[tokio::test]
async fn a_service_is_refused_when_the_cap_leaves_under_15_minutes() {
    let app = TestApp::new().await;
    // 0.2 units: 12 minutes of 1 vCPU.
    let (key, _) = app
        .create_key(json!({"scopes": ["jobs:read", "jobs:write"], "daily_unit_cap": 200}))
        .await;
    let r = app.call(Method::POST, "/v1/jobs", Some(&key), Some(service(1.0))).await;
    let p = assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    // The estimate it was refused for is 15 minutes of runtime.
    let detail = p["detail"].as_str().unwrap();
    assert!(
        detail.contains("needs 0.250 units") && detail.contains("cap is 0.200"),
        "{p}"
    );
    // Half the CPU fits: 0.2 units are 24 minutes of 0.5 vCPU.
    let r = app.call(Method::POST, "/v1/jobs", Some(&key), Some(service(0.5))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

#[tokio::test]
async fn an_uncapped_service_is_created_with_nothing_reserved() {
    let app = TestApp::new().await;
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&app.admin), Some(service(2.0)))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.json()["id"].as_str().unwrap().to_string();
    let (units, cap_day): (i64, Option<i64>) = sqlx::query_as(
        "SELECT j.units_reserved, s.cap_day FROM jobs j JOIN service_state s ON s.job_id = j.job_id WHERE j.job_id = ?",
    )
    .bind(&id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!((units, cap_day), (0, None));
}

#[tokio::test]
async fn usage_accepts_the_new_groupings() {
    let app = TestApp::new().await;
    for by in ["job", "node", "key", "device", "principal", "kind", "template"] {
        let r = app.get(&format!("/v1/usage?group_by={by}"), &app.admin).await;
        assert_eq!(r.status, StatusCode::OK, "{by}: {:?}", r.body);
        let v = r.json();
        assert_eq!(v["group_by"], json!(by));
        assert_eq!(v["total"]["attempts"], json!(0));
        // `estimated_slices` is additive: left out when 0, as an H1 client expects.
        assert!(v["total"].get("estimated_slices").is_none(), "{v}");
    }
    let r = app.get("/v1/usage?group_by=lease", &app.admin).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
}
