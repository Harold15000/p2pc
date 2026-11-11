// SPDX-License-Identifier: AGPL-3.0-only

//! Jobs of device principals (H2 spec §5.5, §5.6, SI-H2-18, SI-H2-20): idempotency deduplicates per principal, for
//! keys and devices alike, and a device's cap and image list bind its own submissions, never those of the key that
//! paired it.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{DeviceLimits, TestApp, assert_problem};
use p2pc_proto::api::Scope;
use p2pc_proto::ids::DeviceId;
use p2pc_proto::units::Units;
use serde_json::{Value, json};

fn job(idem: Option<&str>) -> Value {
    let mut v = json!({
        "image": "python:3.12-slim",
        "command": ["python", "-c", "print(6*7)"],
        "resources": {"cpu": 1, "memory_mb": 512},
        "timeout_s": 3600,
    });
    if let Some(k) = idem {
        v["idempotency_key"] = json!(k);
    }
    v
}

async fn submit_device(app: &TestApp, d: DeviceId, body: &Value) -> common::Resp {
    app.device_call(d, Method::POST, "/v1/jobs", Some(body.clone())).await
}

async fn jobs(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn idempotency_deduplicates_per_principal_for_keys_and_devices() {
    let app = TestApp::new().await;
    let writer = [Scope::JobsWrite, Scope::JobsRead];
    let d1 = app.add_device(&writer, DeviceLimits::default()).await;
    let d2 = app.add_device(&writer, DeviceLimits::default()).await;
    let key = app.key_with(&writer).await;
    let body = job(Some("same-key"));
    // One device, twice: one job, the replay answers 200 with it.
    let first = submit_device(&app, d1, &body).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    let again = submit_device(&app, d1, &body).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["id"], first.json()["id"]);
    assert_eq!(jobs(&app).await, 1);
    // The same idempotency key with another body from that device: a conflict, as for keys.
    let mut different = body.clone();
    different["command"] = json!(["true"]);
    let r = submit_device(&app, d1, &different).await;
    assert_problem(&r, StatusCode::CONFLICT, "idempotency_conflict");
    // Another device, and a key, with the same idempotency key: each its own job, learning nothing of the first.
    let second = submit_device(&app, d2, &body).await;
    assert_eq!(second.status, StatusCode::CREATED);
    let third = app.call(Method::POST, "/v1/jobs", Some(&key), Some(body.clone())).await;
    assert_eq!(third.status, StatusCode::CREATED);
    assert_eq!(jobs(&app).await, 3);
    // Each job names its principal, exactly one column set.
    let principals: Vec<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT key_id, device_id FROM jobs ORDER BY created_at, job_id")
            .fetch_all(&app.db)
            .await
            .unwrap();
    let devices = principals.iter().filter(|(k, d)| k.is_none() && d.is_some()).count();
    let keys = principals.iter().filter(|(k, d)| k.is_some() && d.is_none()).count();
    assert_eq!((devices, keys), (2, 1));
    // The key replays its own job.
    let r = app.call(Method::POST, "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["id"], third.json()["id"]);
    assert_eq!(jobs(&app).await, 3);
}

#[tokio::test]
async fn a_devices_cap_and_image_list_bind_its_own_jobs_only() {
    let app = TestApp::new().await;
    // 1 vCPU for 1 h is 1000 milli-units.
    let capped = app
        .add_device(
            &[Scope::JobsWrite],
            DeviceLimits {
                daily_unit_cap: Some(Units::from_milli(1500)),
                allowed_images: Some(vec!["docker.io/library/python:*".into()]),
                ..DeviceLimits::default()
            },
        )
        .await;
    // The admin key spends first: it is not the device's principal, so it does not count against the device.
    for _ in 0..3 {
        let r = app
            .call(Method::POST, "/v1/jobs", Some(&app.admin), Some(job(None)))
            .await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    assert_eq!(
        submit_device(&app, capped, &job(None)).await.status,
        StatusCode::CREATED
    );
    // The second job would bring the device to 2000 > 1500.
    let r = submit_device(&app, capped, &job(None)).await;
    assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    // An image outside the device's list.
    let mut other = job(None);
    other["image"] = json!("ghcr.io/example/tool:1");
    let r = submit_device(&app, capped, &other).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "image_not_allowed");
    // A device without `jobs:write` (the phone profile) cannot submit at all.
    let phone = app
        .add_device(&p2pc_proto::api::PHONE_PROFILE, DeviceLimits::default())
        .await;
    let r = submit_device(&app, phone, &job(None)).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
}
