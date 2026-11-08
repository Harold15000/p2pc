// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 9457 problem+json for every error class, and the unauthenticated endpoints.

mod common;

use axum::http::{Method, StatusCode};
use common::{TestApp, assert_problem};
use p2pc_proto::api::Scope;
use serde_json::json;

#[tokio::test]
async fn error_classes_render_problem_json() {
    let app = TestApp::new().await;
    // 401
    let r = app.call(Method::GET, "/v1/keys", None, None).await;
    let v = assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    assert_eq!(v["type"], "about:blank");
    assert_eq!(v["title"], "Unauthorized");
    // 403
    let reader = app.key_with(&[Scope::JobsRead]).await;
    let r = app.get("/v1/keys", &reader).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    // 404, with and without a key, inside and outside /v1.
    for (path, key) in [
        ("/v1/nope", Some(app.admin.as_str())),
        ("/v1/nope", None),
        ("/nope", None),
    ] {
        let r = app.call(Method::GET, path, key, None).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
    // 405
    let r = app.call(Method::PUT, "/healthz", None, None).await;
    assert_problem(&r, StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    // 422 with the `errors` extension.
    let r = app
        .call(Method::POST, "/v1/keys", Some(&app.admin), Some(json!({"scopes": []})))
        .await;
    let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert_eq!(
        v["errors"],
        json!([{"field": "scopes", "code": "out_of_range", "message": "must contain at least one scope"}])
    );
}

#[tokio::test]
async fn healthz_is_public_and_has_no_data() {
    let app = TestApp::new().await;
    let r = app.call(Method::GET, "/healthz", None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json(), json!({"status": "ok"}));
}

#[tokio::test]
async fn the_openapi_document_is_served_without_auth() {
    let app = TestApp::new().await;
    let r = app.call(Method::GET, "/v1/openapi.json", None, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.content_type(), "application/json");
    assert_eq!(r.body, p2pc_server::openapi::document());
}
