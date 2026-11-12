// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /v1/server` and `PATCH /v1/server` (H2 spec §7.3): the H2 API generation, the hub's name and who may set it.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{DeviceLimits, TestApp, assert_problem};
use p2pc_proto::api::{PHONE_PROFILE, Scope};
use serde_json::{Value, json};

async fn patch(app: &TestApp, key: &str, body: Value) -> common::Resp {
    app.call(Method::PATCH, "/v1/server", Some(key), Some(body)).await
}

#[tokio::test]
async fn get_server_says_api_version_2_and_the_blob_limit() {
    let app = TestApp::new().await;
    let reader = app.key_with(&[Scope::JobsRead]).await;
    let v = app.get("/v1/server", &reader).await.json();
    assert_eq!(v["api_version"], 2, "{v}");
    assert_eq!(v["max_blob_mb"], app.state.config.blobs.max_blob_mb, "{v}");
    // No name until an `admin` sets one: the field is left out.
    assert!(v.get("hub_name").is_none(), "{v}");
}

#[tokio::test]
async fn an_admin_names_the_hub_and_every_principal_reads_the_name() {
    let app = TestApp::new().await;
    let r = patch(&app, &app.admin, json!({"hub_name": "My cloud"})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.json()["hub_name"], "My cloud");
    assert_eq!(r.json()["api_version"], 2);

    let reader = app.key_with(&[Scope::JobsRead]).await;
    assert_eq!(app.get("/v1/server", &reader).await.json()["hub_name"], "My cloud");
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let r = app.device_call(phone, Method::GET, "/v1/server", None).await;
    assert_eq!(r.json()["hub_name"], "My cloud");

    // An `admin` device renames it (the desktop app does it over its device connection, H2 §8.2), up to 64
    // characters of any script.
    let owner = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let name = "é".repeat(64);
    let r = app
        .device_call(owner, Method::PATCH, "/v1/server", Some(json!({"hub_name": name})))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(app.get("/v1/server", &reader).await.json()["hub_name"], name.as_str());
}

#[tokio::test]
async fn only_an_admin_names_the_hub() {
    let app = TestApp::new().await;
    let writer = app
        .key_with(&[Scope::JobsRead, Scope::JobsWrite, Scope::NodesRead, Scope::NodesWrite])
        .await;
    assert_problem(
        &patch(&app, &writer, json!({"hub_name": "Mine now"})).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let r = app
        .device_call(
            phone,
            Method::PATCH,
            "/v1/server",
            Some(json!({"hub_name": "Mine now"})),
        )
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    assert_problem(
        &app.call(Method::PATCH, "/v1/server", None, Some(json!({"hub_name": "x"})))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    assert!(app.get("/v1/server", &app.admin).await.json().get("hub_name").is_none());
}

#[tokio::test]
async fn a_name_that_is_not_1_to_64_printable_characters_is_refused() {
    let app = TestApp::new().await;
    patch(&app, &app.admin, json!({"hub_name": "Before"})).await;
    for bad in [
        String::new(),
        "x".repeat(65),
        "line\nbreak".into(),
        "tab\there".into(),
        // Invisible and bidirectional controls are not printable, and a device refuses them in `Paired` (§5.3).
        "abc\u{202e}cba".into(),
        "zero\u{200b}width".into(),
        // 64 characters, but more bytes than `Paired.hub_name` carries.
        "\u{1F600}".repeat(64),
    ] {
        let r = patch(&app, &app.admin, json!({"hub_name": bad})).await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        assert_eq!(v["errors"][0]["field"], "hub_name", "{bad:?}: {v}");
    }
    // The body rejects unknown fields; a read-only field is one of them.
    let r = patch(&app, &app.admin, json!({"hub_name": "x", "api_version": 3})).await;
    assert!(r.status.is_client_error(), "{:?}", r.body);
    assert_eq!(app.get("/v1/server", &app.admin).await.json()["hub_name"], "Before");
}
