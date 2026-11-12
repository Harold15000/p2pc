// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /v1/templates` and `POST /v1/templates/{id}/launch` (H2 spec §7.3, §7.6; SI-H2-13, SI-H2-14): the listing,
//! the parameter targets, `422 invalid_params`, the singleton rule with `409 singleton_running`, the cap check of a
//! capped principal, and `503 templates_unavailable` when the hub may serve no bundle.
//!
//! The hub serves the repository's own templates (`private-chat` and `transcribe`), embedded at build time.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::bundles::{self, Signer};
use common::{DeviceLimits, Resp, TestApp, assert_problem, second_account};
use p2pc_proto::api::{BLOB_SHA256_HEADER, JobSpec, PHONE_PROFILE, Scope};
use p2pc_proto::ids::AccountId;
use p2pc_proto::units::Units;
use p2pc_server::node_directory::{BoxFuture, NodeDirectory, NodeMatch};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CHAT: &str = "/v1/templates/private-chat/launch";
const TRANSCRIBE: &str = "/v1/templates/transcribe/launch";

async fn launch(app: &TestApp, key: &str, uri: &str, body: Value) -> Resp {
    app.call(Method::POST, uri, Some(key), Some(body)).await
}

/// Uploads a small blob with `key` and returns its `sha256:<hex>` reference.
async fn blob(app: &TestApp, key: &str, bytes: &[u8]) -> String {
    let sha = data_encoding::HEXLOWER.encode(&Sha256::digest(bytes));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/blobs")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header(BLOB_SHA256_HEADER, &sha)
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    let r = app.send(req).await;
    assert!(r.status.is_success(), "{:?}", r.body);
    format!("sha256:{sha}")
}

/// A key with exactly `scopes` and, if given, a daily cap in milli-units.
async fn key(app: &TestApp, scopes: &[Scope], cap_milli: Option<u64>) -> String {
    let mut body = json!({ "scopes": scopes });
    if let Some(cap) = cap_milli {
        body["daily_unit_cap"] = json!(cap);
    }
    app.create_key(body).await.0
}

/// A node directory in which one GPU node of the account can run anything.
#[derive(Debug)]
struct OneGpuNode;

impl NodeDirectory for OneGpuNode {
    fn match_job<'a>(&'a self, _account_id: AccountId, _spec: &'a JobSpec) -> BoxFuture<'a, NodeMatch> {
        Box::pin(async {
            NodeMatch {
                matching_nodes: 1,
                free_nodes: 1,
            }
        })
    }
}

#[tokio::test]
async fn the_listing_shows_the_served_bundle_without_specs_or_routes() {
    let app = TestApp::new().await;
    let reader = key(&app, &[Scope::JobsRead], None).await;
    let launcher = key(&app, &[Scope::TemplatesLaunch], None).await;
    for k in [&app.admin, &reader, &launcher] {
        let r = app.get("/v1/templates", k).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let v = r.json();
        assert_eq!(v["bundle_version"], 1);
        assert_eq!(v["bundle_error"], Value::Null);
        let ids: Vec<&str> = v["templates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["private-chat", "transcribe"]);
        let chat = &v["templates"][0];
        assert_eq!(chat["singleton"], true);
        assert_eq!(chat["ui"], "chat");
        assert_eq!(chat["kind"], "service");
        assert_eq!(chat["requirements"]["gpu"], "preferred");
        assert_eq!(chat["params"][0]["name"], "model");
        assert_eq!(chat["params"][0]["target"], "pull");
        assert_eq!(chat["params"][0]["default"], "qwen3:4b-instruct");
        assert!(chat["download_mb"].as_u64().unwrap() > 0);
        assert!(!chat["licenses"].as_array().unwrap().is_empty());
        // What the UI needs, and nothing of the vetted JobSpec or the routes: those stay on the hub.
        for t in v["templates"].as_array().unwrap() {
            assert!(t.get("spec").is_none() && t.get("allowed_routes").is_none(), "{t}");
        }
    }
    // A device with the phone profile (`templates:launch`, no `jobs:read`).
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let r = app.device_call(phone, Method::GET, "/v1/templates", None).await;
    assert_eq!(r.status, StatusCode::OK);
    // Neither scope: `403`. No key: `401`.
    let nodes = key(&app, &[Scope::NodesRead, Scope::JobsWrite], None).await;
    assert_problem(
        &app.get("/v1/templates", &nodes).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let r = app.call(Method::GET, "/v1/templates", None, None).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[tokio::test]
async fn only_templates_launch_may_launch_and_only_a_template_of_the_bundle() {
    let app = TestApp::new().await;
    // `jobs:write` submits JobSpecs; it does not launch templates.
    let writer = key(&app, &[Scope::JobsWrite, Scope::JobsRead], None).await;
    let r = launch(&app, &writer, CHAT, json!({})).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = app.call(Method::POST, CHAT, None, Some(json!({}))).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");

    let launcher = key(&app, &[Scope::TemplatesLaunch], None).await;
    for unknown in [
        "/v1/templates/nope/launch",
        "/v1/templates/Private-Chat/launch",
        "/v1/templates/private-chat%2F..%2Fx/launch",
    ] {
        let r = launch(&app, &launcher, unknown, json!({})).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "unknown_template");
    }
    // The body rejects unknown fields, and its idempotency key follows the job rule.
    let r = launch(&app, &launcher, CHAT, json!({"params": {}, "spec": {}})).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.body);
    let r = launch(&app, &launcher, CHAT, json!({"idempotency_key": ""})).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.body);
    let none: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(none, 0, "nothing above created a job");
}

#[tokio::test]
async fn a_batch_template_launch_builds_the_job_through_the_parameter_targets() {
    let app = TestApp::new().await;
    let launcher = key(&app, &[Scope::TemplatesLaunch, Scope::BlobsWrite], None).await;
    let audio = blob(&app, &launcher, b"not really audio").await;
    let r = launch(
        &app,
        &launcher,
        TRANSCRIBE,
        json!({"params": {"audio": audio, "language": "es"}}),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let job = r.json();
    let id = job["id"].as_str().unwrap();
    assert_eq!(
        r.headers.get(header::LOCATION).unwrap().to_str().unwrap(),
        format!("/v1/jobs/{id}")
    );
    assert_eq!(job["status"], "queued");
    let spec = &job["spec"];
    // `template: {id, version, pull}`, set by the launch; `pull` is `null` without a `pull` parameter.
    assert_eq!(
        spec["template"],
        json!({"id": "transcribe", "version": 1, "pull": null})
    );
    assert!(spec.get("kind").is_none(), "a batch job, as H1 shows it");
    // `input:<path>`: one entry at the template's fixed path.
    assert_eq!(spec["inputs"], json!([{"path": "/inputs/audio", "blob": audio}]));
    // The template's own values: image by digest, fixed command, fixed egress, its `tpl:` volume, no GPU.
    assert!(spec["image"].as_str().unwrap().contains("@sha256:"), "{spec}");
    assert_eq!(spec["command"], json!(["/bin/sh", "/inputs/.template/transcribe.sh"]));
    assert_eq!(spec["egress"]["allow"], json!(["huggingface.co", "hf.co"]));
    assert_eq!(spec["volumes"][0]["name"], "tpl:transcribe/models");
    assert_eq!(spec["resources"]["gpu"], 0);
    assert_eq!(spec["timeout_s"], 3600);
    // `env:<NAME>`: the whole value (redacted in every response; read from the stored spec).
    let stored: String = sqlx::query_scalar("SELECT spec FROM jobs WHERE job_id = ?")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    let stored: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored["env"]["LANGUAGE"], "es");
    assert_eq!(
        stored["env"]["MODEL"], "small",
        "a parameter left out takes its default"
    );
    // The job belongs to the caller, as any job does.
    let (key_id, template_id): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT key_id, template_id FROM jobs WHERE job_id = ?")
            .bind(id)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert!(launcher.contains(&key_id.unwrap()));
    assert_eq!(template_id.as_deref(), Some("transcribe"));

    // A blob the caller's account does not hold.
    let missing = format!("sha256:{}", "a".repeat(64));
    let r = launch(&app, &launcher, TRANSCRIBE, json!({"params": {"audio": missing}})).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "unknown_blob");
    // A blob of another account is unknown too.
    let (other, _) = second_account(&app).await;
    let theirs = blob(&app, &other, b"their audio").await;
    let r = launch(&app, &launcher, TRANSCRIBE, json!({"params": {"audio": theirs}})).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "unknown_blob");
}

#[tokio::test]
async fn unknown_out_of_type_and_out_of_bounds_parameters_get_invalid_params() {
    let app = TestApp::new().await;
    let launcher = key(&app, &[Scope::TemplatesLaunch, Scope::BlobsWrite], None).await;
    let audio = blob(&app, &launcher, b"audio").await;
    let bad_transcribe = [
        json!({}),                                                    // the blob is required
        json!({"audio": audio, "nope": "x"}),                         // unknown parameter
        json!({"audio": audio, "language": 5}),                       // wrong type
        json!({"audio": audio, "language": "klingon"}),               // not one of the template's values
        json!({"audio": audio, "model": true}),                       // wrong type
        json!({"audio": "sha256:short"}),                             // not a digest
        json!({"audio": 7}),                                          // wrong type
        json!({"audio": audio, "language": "auto; rm -rf /volumes"}), // never a value of its own
    ];
    for params in bad_transcribe {
        let r = launch(&app, &launcher, TRANSCRIBE, json!({ "params": params })).await;
        let problem = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "invalid_params");
        // The answer names the template's parameter, never the value the caller sent.
        let text = problem.to_string();
        assert!(!text.contains("klingon") && !text.contains("rm -rf"), "{text}");
    }
    let bad_chat = [
        json!({"idle_timeout_s": 899}),    // below the template's bounds
        json!({"idle_timeout_s": 86401}),  // above them
        json!({"idle_timeout_s": "3600"}), // wrong type
        json!({"idle_timeout_s": 3600.5}), // not an integer
        json!({"model": "llama3:70b"}),    // not one of the template's values
        json!({"model": 4}),               // wrong type
        json!({"timeout_s": 60}),          // not a parameter of the template
        json!({"resources": {"cpu": 64}}), // no parameter reaches the resources
    ];
    for params in bad_chat {
        let r = launch(&app, &launcher, CHAT, json!({ "params": params })).await;
        // A value that is not a bool, an integer or a string is not a parameter value at all (`invalid_body`).
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{params}: {:?}", r.body);
        let code = r.json()["code"].as_str().unwrap().to_string();
        assert!(code == "invalid_params" || code == "invalid_body", "{params}: {code}");
    }
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(jobs, 0, "a refused launch creates nothing");
}

/// SI-H2-13, on the hub: whatever a caller sends as a parameter value, the job is either refused or built from the
/// template's own words. Shell metacharacters never reach a spec.
#[tokio::test]
async fn shell_metacharacters_as_parameter_values_never_reach_a_job() {
    let app = TestApp::new().await;
    let launcher = key(&app, &[Scope::TemplatesLaunch, Scope::BlobsWrite], None).await;
    let audio = blob(&app, &launcher, b"audio").await;
    let hostile = [
        "$(reboot)",
        "`id`",
        "a;b",
        "a|b",
        "a&&b",
        "a b",
        "-o",
        "--model=x",
        "../../etc/passwd",
        "small\nmedium",
        "small\0",
        "'small'",
        "\"small\"",
        "${MODEL}",
        "small*",
        "small>out",
        "",
    ];
    for value in hostile {
        for (uri, params) in [
            (TRANSCRIBE, json!({"audio": audio, "language": value})),
            (TRANSCRIBE, json!({"audio": audio, "model": value})),
            (TRANSCRIBE, json!({"audio": value})),
            (CHAT, json!({"model": value})),
            (CHAT, json!({"idle_timeout_s": value})),
        ] {
            let r = launch(&app, &launcher, uri, json!({ "params": params })).await;
            assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "invalid_params");
        }
    }
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(jobs, 0);
}

#[tokio::test]
async fn a_service_template_launch_sets_the_field_target_the_pull_model_and_the_gpu_hint() {
    let mut app = TestApp::new().await;
    let launcher = key(&app, &[Scope::TemplatesLaunch], None).await;
    // No node of the account has a GPU: `requirements.gpu = "preferred"` launches with `gpu: 0`.
    let r = launch(&app, &launcher, CHAT, json!({"params": {"idle_timeout_s": 900}})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let job = r.json();
    let spec = &job["spec"];
    assert_eq!(spec["kind"], "service");
    assert_eq!(spec["name"], "Private AI chat");
    assert_eq!(spec["resources"]["gpu"], 0);
    // `field:service.idle_timeout_s`, inside the template's bounds.
    assert_eq!(spec["service"]["idle_timeout_s"], 900);
    assert_eq!(
        spec["timeout_s"], 2_592_000,
        "no parameter of this template reaches timeout_s"
    );
    // `pull`: the model the hub downloads, stored with the job. The default is the spec's.
    assert_eq!(
        spec["template"],
        json!({"id": "private-chat", "version": 1, "pull": "qwen3:4b-instruct"})
    );
    assert_eq!(spec["volumes"][0]["name"], "tpl:private-chat/models");
    assert_eq!(spec["volumes"][0]["mount"], "/volumes/models/blobs");
    assert_eq!(
        spec["egress"]["allow"],
        json!([
            "registry.ollama.ai",
            "ollama.com",
            "dd20bb891979d25aebc8bec07b2b3bbc.r2.cloudflarestorage.com"
        ])
    );
    // A service reserves nothing at creation (H2 §12).
    assert_eq!(job["estimated_units"], 0);
    // Stop it, so the next launch is a new instance.
    let id = job["id"].as_str().unwrap().to_string();
    let r = app
        .call(Method::POST, &format!("/v1/jobs/{id}/cancel"), Some(&app.admin), None)
        .await;
    assert_eq!(r.json()["status"], "cancelled");

    // With an eligible GPU node in the account, the same launch asks for the GPU.
    app.state.nodes = Arc::new(OneGpuNode);
    app.router = p2pc_server::app::router(app.state.clone());
    let r = launch(&app, &launcher, CHAT, json!({"params": {"model": "qwen3:1.7b"}})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let spec = &r.json()["spec"];
    assert_eq!(spec["resources"]["gpu"], 1);
    assert_eq!(spec["template"]["pull"], "qwen3:1.7b");
    assert_eq!(spec["service"]["idle_timeout_s"], 3600, "the default");
}

#[tokio::test]
async fn a_singleton_launch_returns_the_running_instance_and_another_model_gets_singleton_running() {
    let app = TestApp::new().await;
    let owner = key(&app, &[Scope::TemplatesLaunch], None).await;
    let r = launch(&app, &owner, CHAT, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.json()["id"].as_str().unwrap().to_string();

    // Any principal with `templates:launch` in the account and project gets the same instance: `200`.
    let other = key(&app, &[Scope::TemplatesLaunch], None).await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    for r in [
        launch(&app, &owner, CHAT, json!({})).await,
        launch(&app, &other, CHAT, json!({"params": {"idle_timeout_s": 7200}})).await,
        // The same model, said out loud.
        launch(&app, &other, CHAT, json!({"params": {"model": "qwen3:4b-instruct"}})).await,
        app.device_call(phone, Method::POST, CHAT, Some(json!({}))).await,
    ] {
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        assert_eq!(r.json()["id"], id.as_str());
        assert_eq!(
            r.json()["spec"]["service"]["idle_timeout_s"],
            3600,
            "the instance as it runs"
        );
    }
    // Another model while the instance is live: `409`, naming the instance and its model.
    for r in [
        launch(&app, &owner, CHAT, json!({"params": {"model": "qwen3:1.7b"}})).await,
        app.device_call(
            phone,
            Method::POST,
            CHAT,
            Some(json!({"params": {"model": "qwen3:1.7b"}})),
        )
        .await,
    ] {
        let problem = assert_problem(&r, StatusCode::CONFLICT, "singleton_running");
        let detail = problem["detail"].as_str().unwrap();
        assert!(detail.contains(&id) && detail.contains("qwen3:4b-instruct"), "{detail}");
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Any of them may stop it (H2 §7.2); once it is terminal, a launch creates a new instance, with any model.
    let r = app
        .device_call(phone, Method::POST, &format!("/v1/jobs/{id}/cancel"), None)
        .await;
    assert_eq!(r.json()["status"], "cancelled", "{:?}", r.body);
    let r = app
        .device_call(
            phone,
            Method::POST,
            CHAT,
            Some(json!({"params": {"model": "qwen3:1.7b"}})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_ne!(r.json()["id"], id.as_str());
    assert_eq!(r.json()["spec"]["template"]["pull"], "qwen3:1.7b");

    // An instance of another account is never returned: that account gets its own.
    let (theirs, _) = second_account(&app).await;
    let r = launch(&app, &theirs, CHAT, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    // `transcribe` is not a singleton: every launch is a new job.
    let batch = key(&app, &[Scope::TemplatesLaunch, Scope::BlobsWrite], None).await;
    let audio = blob(&app, &batch, b"audio").await;
    let mut ids = Vec::new();
    for _ in 0..2 {
        let r = launch(&app, &batch, TRANSCRIBE, json!({"params": {"audio": audio}})).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        ids.push(r.json()["id"].as_str().unwrap().to_string());
    }
    assert_ne!(ids[0], ids[1]);
}

#[tokio::test]
async fn a_launch_is_idempotent_per_principal() {
    let app = TestApp::new().await;
    let launcher = key(&app, &[Scope::TemplatesLaunch, Scope::BlobsWrite], None).await;
    let audio = blob(&app, &launcher, b"audio").await;
    let body = json!({"params": {"audio": audio, "language": "en"}, "idempotency_key": "launch-1"});
    let first = launch(&app, &launcher, TRANSCRIBE, body.clone()).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    let again = launch(&app, &launcher, TRANSCRIBE, body.clone()).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(again.json()["id"], first.json()["id"]);
    // No response ever shows the key.
    assert!(!String::from_utf8_lossy(&again.body).contains("launch-1"));
    // The same key with another request.
    let mut other = body.clone();
    other["params"]["language"] = json!("es");
    let r = launch(&app, &launcher, TRANSCRIBE, other).await;
    assert_problem(&r, StatusCode::CONFLICT, "idempotency_conflict");
    // The same key with another template is another request too.
    let r = launch(&app, &launcher, CHAT, json!({"idempotency_key": "launch-1"})).await;
    assert_problem(&r, StatusCode::CONFLICT, "idempotency_conflict");
    // Another principal reusing the key gets its own job.
    let second = key(&app, &[Scope::TemplatesLaunch], None).await;
    let r = launch(&app, &second, TRANSCRIBE, body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_ne!(r.json()["id"], first.json()["id"]);
}

#[tokio::test]
async fn the_image_allowlist_of_the_caller_applies_to_a_launch() {
    let app = TestApp::new().await;
    let (narrow, _) = app
        .create_key(json!({"scopes": ["templates:launch"], "allowed_images": ["ghcr.io/ggml-org/*"]}))
        .await;
    // `private-chat` runs an image the key may not run: refused, also while an instance is live.
    let r = launch(&app, &narrow, CHAT, json!({})).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "image_not_allowed");
    let r = launch(&app, &app.admin, CHAT, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = launch(&app, &narrow, CHAT, json!({})).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "image_not_allowed");
    // `transcribe` runs one it may.
    let (uploader, _) = app.create_key(json!({"scopes": ["blobs:write"]})).await;
    let audio = blob(&app, &uploader, b"audio").await;
    let r = launch(&app, &narrow, TRANSCRIBE, json!({"params": {"audio": audio}})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

/// H2 §7.6 "Launch by a capped principal": checked before the job exists, refused with `402 cap_exceeded` and a
/// detail that names the template, the units it needs and the units left today.
#[tokio::test]
async fn a_capped_principal_launches_only_what_its_daily_cap_allows() {
    let app = TestApp::new().await;
    let (uploader, _) = app.create_key(json!({"scopes": ["blobs:write"]})).await;
    let audio = blob(&app, &uploader, b"audio").await;
    let params = json!({"params": {"audio": audio}});
    // `transcribe`: 4 vCPUs for its `timeout_s` of 3,600 s, that is 4 units.
    let short = key(&app, &[Scope::TemplatesLaunch], Some(3_999)).await;
    let r = launch(&app, &short, TRANSCRIBE, params.clone()).await;
    let problem = assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("transcribe") && detail.contains("4.000") && detail.contains("3.999"),
        "{detail}"
    );
    // Exactly at the cap is allowed; then nothing is left.
    let exact = key(&app, &[Scope::TemplatesLaunch], Some(4_000)).await;
    let r = launch(&app, &exact, TRANSCRIBE, params.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.json()["estimated_units"], 4_000);
    let r = launch(&app, &exact, TRANSCRIBE, params.clone()).await;
    let detail = assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded")["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(detail.contains("4.000") && detail.contains("0.000"), "{detail}");

    // `private-chat` (4 vCPUs, no GPU here): the first day's reservation must buy 15 minutes, that is 1 unit.
    let short = key(&app, &[Scope::TemplatesLaunch], Some(999)).await;
    let r = launch(&app, &short, CHAT, json!({})).await;
    let detail = assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded")["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        detail.contains("private-chat") && detail.contains("1.000") && detail.contains("0.999"),
        "{detail}"
    );
    let jobs_of_short: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE kind = 'service'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(jobs_of_short, 0, "the cap is checked before the job exists");
    // With 15 minutes or more it starts, holding the day's reservation of T2-16 (never a 30-day estimate).
    let enough = key(&app, &[Scope::TemplatesLaunch], Some(2_000)).await;
    let r = launch(&app, &enough, CHAT, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.json()["estimated_units"], 0);
    let id = r.json()["id"].as_str().unwrap().to_string();
    let (cap_day, reserved): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT cap_day, cap_reserved_units FROM service_state WHERE job_id = ?")
            .bind(&id)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert!(cap_day.is_some());
    assert_eq!(reserved, Some(2_000), "bounded by the cap, not by the day");
    // The singleton is live: a capped launcher with nothing left still gets the instance, since nothing new starts.
    let r = launch(&app, &short, CHAT, json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.json()["id"], id.as_str());
}

/// A device's cap is its own (SI-H2-18): the launch of a capped phone is checked against the phone, not against the
/// uncapped owner.
#[tokio::test]
async fn a_capped_device_is_checked_against_its_own_cap() {
    let app = TestApp::new().await;
    let limits = DeviceLimits {
        daily_unit_cap: Some(Units::from_milli(500)),
        ..DeviceLimits::default()
    };
    let phone = app.add_device(&PHONE_PROFILE, limits).await;
    let r = app.device_call(phone, Method::POST, CHAT, Some(json!({}))).await;
    assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    // The owner is uncapped and launches it; the phone then reaches the shared instance.
    let r = launch(&app, &app.admin, CHAT, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = app.device_call(phone, Method::POST, CHAT, Some(json!({}))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

/// SI-H2-14, at the API: with the bundle at the mark gone, the hub serves no template rather than the older
/// embedded one.
#[tokio::test]
async fn without_a_servable_bundle_the_listing_is_empty_and_a_launch_gets_templates_unavailable() {
    let mut app = TestApp::new().await;
    let signer = Signer::new();
    let (v3, signature) = signer.sign(&bundles::bundle(3));
    bundles::put(&app, &v3, Some(&signature));
    let store = bundles::start(&app, signer.trust(1)).await;
    bundles::serve(&mut app, store.clone());
    let r = app.get("/v1/templates", &app.admin).await;
    assert_eq!(r.json()["bundle_version"], 3);
    let r = launch(&app, &app.admin, CHAT, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.json()["id"].as_str().unwrap().to_string();

    bundles::remove(&app);
    store.reload().await.unwrap();
    let r = app.get("/v1/templates", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["bundle_version"], Value::Null);
    assert_eq!(v["templates"], json!([]));
    assert!(v["bundle_error"].as_str().unwrap().contains("version 3"), "{v}");
    for uri in [CHAT, TRANSCRIBE, "/v1/templates/nope/launch"] {
        let r = launch(&app, &app.admin, uri, json!({})).await;
        assert_problem(&r, StatusCode::SERVICE_UNAVAILABLE, "templates_unavailable");
    }
    // The instance that runs is still a job of the project; only launching is off.
    let r = app.get(&format!("/v1/jobs/{id}"), &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
}

/// T2-15 turns volumes on for `POST /v1/jobs` (H2 §7.1): a service may have plain volumes; `tpl:` names and volumes
/// of a batch job stay for template launches.
#[tokio::test]
async fn a_service_job_may_have_plain_volumes_and_tpl_names_stay_for_launches() {
    let app = TestApp::new().await;
    let service = json!({"kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
        "resources": {"cpu": 1, "memory_mb": 256}, "service": {"ports": [{"port": 8080, "name": "http"}]},
        "volumes": [{"name": "data", "mount": "/volumes/data", "max_mb": 64}]});
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&app.admin), Some(service.clone()))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.json()["spec"]["volumes"][0]["name"], "data");
    // A `tpl:` name only through a launch (SI-H2-9).
    let mut tpl = service.clone();
    tpl["volumes"][0]["name"] = json!("tpl:private-chat/models");
    let r = app.call(Method::POST, "/v1/jobs", Some(&app.admin), Some(tpl)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.body);
    // A batch job that is not a template launch has no volumes.
    let batch = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256},
        "volumes": [{"name": "data", "mount": "/volumes/data", "max_mb": 64}]});
    let r = app.call(Method::POST, "/v1/jobs", Some(&app.admin), Some(batch)).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "volumes_not_allowed");
    // And a client never sets `template` itself.
    let mut forged = service;
    forged["template"] = json!({"id": "private-chat", "version": 1});
    let r = app.call(Method::POST, "/v1/jobs", Some(&app.admin), Some(forged)).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "read_only_field");
}
