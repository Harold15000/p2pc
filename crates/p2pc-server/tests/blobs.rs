// SPDX-License-Identifier: AGPL-3.0-only

//! Blobs (H2 §7.5, §13, SI-H2-8): the REST routes, the quotas and upload limits, blob `inputs` at job creation, the
//! tombstone GC with its per-`(account, digest)` lock, and the staging sweep.
//!
//! Blobs are small (at most a few hundred KiB) and every wait is bounded.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration as StdDuration, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Method, Request, StatusCode, header};
use common::{DeviceLimits, Resp, TestApp, assert_problem, second_account};
use p2pc_proto::api::{BLOB_SHA256_HEADER, Scope, Sha256Digest};
use p2pc_proto::ids::{AccountId, DeviceId};
use p2pc_server::app::{device_router, router};
use p2pc_server::auth::DeviceConnection;
use p2pc_server::blobs::UploadLimits;
use p2pc_server::gc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::Duration;
use tokio::sync::{mpsc, oneshot};
use tower::ServiceExt;

/// The bound for anything that should happen promptly. Only reached when something is broken.
const WAIT: StdDuration = StdDuration::from_secs(20);

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn hex(bytes: &[u8]) -> String {
    digest(bytes).to_string()
}

/// Who sends a request: an API key (TCP router) or a device (device router, H2 §6.3).
#[derive(Clone, Copy)]
enum Who<'a> {
    Key(&'a str),
    Device(DeviceId),
}

fn request(who: Who<'_>, method: Method, uri: &str, headers: &[(&str, String)], body: Body) -> (Request<Body>, bool) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Who::Key(key) = who {
        req = req.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    for (name, value) in headers {
        req = req.header(*name, value);
    }
    let mut req = req.body(body).unwrap();
    let device = match who {
        Who::Device(d) => {
            req.extensions_mut().insert(DeviceConnection { device_id: d });
            true
        }
        Who::Key(_) => false,
    };
    (req, device)
}

async fn send(app: &TestApp, who: Who<'_>, method: Method, uri: &str, headers: &[(&str, String)], body: Body) -> Resp {
    let (req, device) = request(who, method, uri, headers, body);
    if device {
        app.send_on(device_router(app.state.clone()), req).await
    } else {
        app.send(req).await
    }
}

fn upload_headers(len: u64, sha: &str) -> Vec<(&'static str, String)> {
    vec![
        (header::CONTENT_LENGTH.as_str(), len.to_string()),
        (BLOB_SHA256_HEADER, sha.to_string()),
    ]
}

async fn upload(app: &TestApp, who: Who<'_>, bytes: &[u8]) -> Resp {
    send(
        app,
        who,
        Method::POST,
        "/v1/blobs",
        &upload_headers(bytes.len() as u64, &hex(bytes)),
        Body::from(bytes.to_vec()),
    )
    .await
}

async fn head(app: &TestApp, who: Who<'_>, sha: &str) -> Resp {
    send(app, who, Method::HEAD, &format!("/v1/blobs/{sha}"), &[], Body::empty()).await
}

async fn delete(app: &TestApp, who: Who<'_>, sha: &str) -> Resp {
    send(
        app,
        who,
        Method::DELETE,
        &format!("/v1/blobs/{sha}"),
        &[],
        Body::empty(),
    )
    .await
}

fn blob_file(app: &TestApp, account: &str, sha: &str) -> PathBuf {
    app.data_dir()
        .join("blobs")
        .join(account)
        .join("sha256")
        .join(&sha[..2])
        .join(&sha[2..4])
        .join(sha)
}

fn staging_files(app: &TestApp) -> Vec<PathBuf> {
    match std::fs::read_dir(app.state.blobs.staging_dir()) {
        Ok(entries) => entries.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

fn job_body(inputs: &[(&str, &str)], disk_mb: u64) -> Value {
    let inputs: Vec<Value> = inputs
        .iter()
        .map(|(path, sha)| json!({"path": path, "blob": format!("sha256:{sha}")}))
        .collect();
    json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": disk_mb}, "inputs": inputs})
}

async fn account_of_key(app: &TestApp, key_id: &str) -> String {
    sqlx::query_scalar("SELECT account_id FROM api_keys WHERE key_id = ?")
        .bind(key_id)
        .fetch_one(&app.db)
        .await
        .unwrap()
}

async fn rows(app: &TestApp, sha: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE sha256 = ?")
        .bind(sha)
        .fetch_one(&app.db)
        .await
        .unwrap()
}

/// A request body fed from a channel, which says when the handler first reads it: the upload is then in progress
/// (its reservation and its staging file exist).
struct ChanBody {
    rx: mpsc::Receiver<Bytes>,
    polled: Option<oneshot::Sender<()>>,
}

impl axum::body::HttpBody for ChanBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
        if let Some(tx) = self.polled.take() {
            let _ = tx.send(());
        }
        self.rx
            .poll_recv(cx)
            .map(|o| o.map(|b| Ok(hyper::body::Frame::data(b))))
    }
}

/// An upload of `bytes` whose body is held open after its first chunk until the returned sender sends the rest (or
/// is dropped). Returns once the handler has started reading the body.
async fn held_upload(
    router: Router,
    who: Who<'_>,
    bytes: &[u8],
) -> (mpsc::Sender<Bytes>, tokio::task::JoinHandle<StatusCode>) {
    let (tx, rx) = mpsc::channel(4);
    let (polled_tx, polled_rx) = oneshot::channel();
    let body = Body::new(ChanBody {
        rx,
        polled: Some(polled_tx),
    });
    let (req, _) = request(
        who,
        Method::POST,
        "/v1/blobs",
        &upload_headers(bytes.len() as u64, &hex(bytes)),
        body,
    );
    tx.send(Bytes::copy_from_slice(&bytes[..1])).await.unwrap();
    let task = tokio::spawn(async move { router.oneshot(req).await.unwrap().status() });
    tokio::time::timeout(WAIT, polled_rx).await.unwrap().unwrap();
    (tx, task)
}

#[tokio::test]
async fn an_upload_is_stored_per_account_and_deduplicated() {
    let app = TestApp::new().await;
    let bytes = b"hello blob".repeat(100);
    let sha = hex(&bytes);
    let r = upload(&app, Who::Key(&app.admin), &bytes).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let v = r.json();
    assert_eq!(v["sha256"], sha.as_str());
    assert_eq!(v["size"], bytes.len());
    assert_eq!(v["created_at"], "2026-11-05T10:00:00Z");
    // Unreferenced: 24 h after the upload.
    assert_eq!(v["expires_at"], "2026-11-06T10:00:00Z");
    // The file, under the account's own directory; nothing is left in staging.
    let path = blob_file(&app, &app.account_id.to_string(), &sha);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(staging_files(&app).is_empty());

    // Again, later: `200` with the same blob (the body is read and discarded).
    app.clock.advance(Duration::minutes(5));
    let again = upload(&app, Who::Key(&app.admin), &bytes).await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(again.json()["created_at"], "2026-11-05T10:00:00Z");
    assert_eq!(rows(&app, &sha).await, 1);
    assert!(staging_files(&app).is_empty());

    let h = head(&app, Who::Key(&app.admin), &sha).await;
    assert_eq!(h.status, StatusCode::OK);
    assert_eq!(h.headers[header::CONTENT_LENGTH], bytes.len().to_string().as_str());
    assert!(h.body.is_empty());
    assert_eq!(
        head(&app, Who::Key(&app.admin), &hex(b"other")).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        head(&app, Who::Key(&app.admin), "not-a-digest").await.status,
        StatusCode::NOT_FOUND
    );

    let list = app.get("/v1/blobs", &app.admin).await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    let l = list.json();
    assert_eq!(l["items"].as_array().unwrap().len(), 1);
    assert_eq!(l["items"][0]["sha256"], sha.as_str());
    assert_eq!(l["items"][0]["referenced_by"], 0);
    assert_eq!(l["items"][0]["expires_at"], "2026-11-06T10:00:00Z");
    assert_eq!(l["total_bytes"], bytes.len());
    assert_eq!(l["quota_mb"], 20_480);
}

#[tokio::test]
async fn the_list_is_paginated() {
    let app = TestApp::new().await;
    for i in 0..3u8 {
        assert_eq!(
            upload(&app, Who::Key(&app.admin), &[i; 10]).await.status,
            StatusCode::CREATED
        );
        app.clock.advance(Duration::seconds(1));
    }
    let first = app.get("/v1/blobs?limit=2", &app.admin).await.json();
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let cursor = first["next_cursor"].as_str().unwrap().to_string();
    let second = app
        .get(&format!("/v1/blobs?limit=2&cursor={cursor}"), &app.admin)
        .await
        .json();
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert!(second["next_cursor"].is_null());
    assert_eq!(second["items"][0]["sha256"], hex(&[2; 10]).as_str());
    let bad = app.get("/v1/blobs?cursor=nope", &app.admin).await;
    assert_problem(&bad, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[tokio::test]
async fn the_declared_size_and_digest_are_checked_before_the_body() {
    let app = TestApp::with_config(|c| {
        c.blobs.max_blob_mb = 1;
        c.blobs.blobs_quota_mb = 1;
    })
    .await;
    let who = Who::Key(&app.admin);
    // No Content-Length (a chunked upload): 411.
    let sha = hex(b"x");
    let r = send(
        &app,
        who,
        Method::POST,
        "/v1/blobs",
        &[(BLOB_SHA256_HEADER, sha.clone())],
        Body::from("x"),
    )
    .await;
    assert_problem(&r, StatusCode::LENGTH_REQUIRED, "length_required");
    // No digest, or not 64 lowercase hex: 422.
    for bad in [None, Some("ABC"), Some(&*sha.to_uppercase())] {
        let mut headers = vec![(header::CONTENT_LENGTH.as_str(), "1".to_string())];
        if let Some(b) = bad {
            headers.push((BLOB_SHA256_HEADER, b.to_string()));
        }
        let r = send(&app, who, Method::POST, "/v1/blobs", &headers, Body::from("x")).await;
        assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
    // Over `max_blob_mb`: 413, without reading the body (it has 1 byte).
    let r = send(
        &app,
        who,
        Method::POST,
        "/v1/blobs",
        &upload_headers(1024 * 1024 + 1, &sha),
        Body::from("x"),
    )
    .await;
    assert_problem(&r, StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    // Over the account's quota with what it stores: 507.
    let big = vec![7u8; 600 * 1024];
    assert_eq!(upload(&app, who, &big).await.status, StatusCode::CREATED);
    let r = send(
        &app,
        who,
        Method::POST,
        "/v1/blobs",
        &upload_headers(600 * 1024, &hex(b"other")),
        Body::from("x"),
    )
    .await;
    assert_problem(&r, StatusCode::INSUFFICIENT_STORAGE, "quota_exceeded");
    assert!(staging_files(&app).is_empty());
}

#[tokio::test]
async fn a_mismatch_or_a_short_or_long_body_leaves_nothing() {
    let app = TestApp::new().await;
    let who = Who::Key(&app.admin);
    let bytes = b"some bytes".to_vec();
    let wrong = hex(b"not these bytes");
    let r = send(
        &app,
        who,
        Method::POST,
        "/v1/blobs",
        &upload_headers(bytes.len() as u64, &wrong),
        Body::from(bytes.clone()),
    )
    .await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "digest_mismatch");
    assert_eq!(rows(&app, &wrong).await, 0);
    // A body shorter, then longer, than its Content-Length.
    for declared in [bytes.len() as u64 + 5, bytes.len() as u64 - 2] {
        let r = send(
            &app,
            who,
            Method::POST,
            "/v1/blobs",
            &upload_headers(declared, &hex(&bytes)),
            Body::from(bytes.clone()),
        )
        .await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "body_length_mismatch");
    }
    assert_eq!(rows(&app, &hex(&bytes)).await, 0);
    assert!(staging_files(&app).is_empty());
    assert!(!blob_file(&app, &app.account_id.to_string(), &wrong).exists());
}

#[tokio::test]
async fn an_idle_upload_ends_and_frees_its_slot() {
    let mut app = TestApp::new().await;
    app.state.blobs = app.state.blobs.clone().with_upload_limits(UploadLimits {
        idle: StdDuration::from_millis(200),
        ..UploadLimits::default()
    });
    app.router = router(app.state.clone());
    let bytes = vec![3u8; 100];
    let (tx, task) = held_upload(app.router.clone(), Who::Key(&app.admin), &bytes).await;
    let status = tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    drop(tx);
    assert!(staging_files(&app).is_empty());
    assert_eq!(rows(&app, &hex(&bytes)).await, 0);
}

#[tokio::test]
async fn a_third_concurrent_upload_of_one_principal_gets_429() {
    let app = TestApp::new().await;
    let phone = app
        .add_device(
            &[
                Scope::NodesRead,
                Scope::TemplatesLaunch,
                Scope::BlobsWrite,
                Scope::NodesInvite,
            ],
            DeviceLimits::default(),
        )
        .await;
    let router = device_router(app.state.clone());
    let (a, b) = (vec![1u8; 64], vec![2u8; 64]);
    let (tx_a, task_a) = held_upload(router.clone(), Who::Device(phone), &a).await;
    let (tx_b, task_b) = held_upload(router.clone(), Who::Device(phone), &b).await;
    let r = upload(&app, Who::Device(phone), &[9u8; 64]).await;
    assert_problem(&r, StatusCode::TOO_MANY_REQUESTS, "too_many_uploads");
    // Another principal is not counted with the phone.
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &[9u8; 64]).await.status,
        StatusCode::CREATED
    );
    tx_a.send(Bytes::copy_from_slice(&a[1..])).await.unwrap();
    drop(tx_a);
    tx_b.send(Bytes::copy_from_slice(&b[1..])).await.unwrap();
    drop(tx_b);
    assert_eq!(
        tokio::time::timeout(WAIT, task_a).await.unwrap().unwrap(),
        StatusCode::CREATED
    );
    assert_eq!(
        tokio::time::timeout(WAIT, task_b).await.unwrap().unwrap(),
        StatusCode::CREATED
    );
    // Both slots are free again.
    assert_eq!(
        upload(&app, Who::Device(phone), &[8u8; 64]).await.status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn a_device_quota_counts_the_blobs_it_holds_a_claim_on() {
    let app = TestApp::with_config(|c| c.blobs.blobs_quota_mb = 8).await;
    let phone = app
        .add_device(
            &[Scope::BlobsWrite],
            DeviceLimits {
                blobs_quota_mb: Some(1),
                ..DeviceLimits::default()
            },
        )
        .await;
    let (owner_blob, own, more) = (vec![1u8; 600 * 1024], vec![2u8; 600 * 1024], vec![3u8; 600 * 1024]);
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &owner_blob).await.status,
        StatusCode::CREATED
    );
    assert_eq!(upload(&app, Who::Device(phone), &own).await.status, StatusCode::CREATED);
    // A new blob beyond its quota, and a claim on the owner's blob beyond it too.
    assert_problem(
        &upload(&app, Who::Device(phone), &more).await,
        StatusCode::INSUFFICIENT_STORAGE,
        "quota_exceeded",
    );
    assert_problem(
        &upload(&app, Who::Device(phone), &owner_blob).await,
        StatusCode::INSUFFICIENT_STORAGE,
        "quota_exceeded",
    );
    // The account still has room for the owner.
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &more).await.status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn delete_removes_the_callers_claim_and_the_blob_with_the_last_one() {
    let app = TestApp::new().await;
    let phone = app
        .add_device(
            &[
                Scope::NodesRead,
                Scope::TemplatesLaunch,
                Scope::BlobsWrite,
                Scope::NodesInvite,
            ],
            DeviceLimits::default(),
        )
        .await;
    let writer = app.key_with(&[Scope::BlobsWrite]).await;
    let (shared, owners) = (b"shared".to_vec(), b"owner only".to_vec());
    // The phone first, then the owner: two claims on one blob.
    assert_eq!(
        upload(&app, Who::Device(phone), &shared).await.status,
        StatusCode::CREATED
    );
    assert_eq!(upload(&app, Who::Key(&app.admin), &shared).await.status, StatusCode::OK);
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &owners).await.status,
        StatusCode::CREATED
    );
    let account = app.account_id.to_string();

    // A caller without a claim, not admin: 403 (the phone, and a `blobs:write` key).
    assert_problem(
        &delete(&app, Who::Device(phone), &hex(&owners)).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_problem(
        &delete(&app, Who::Key(&writer), &hex(&owners)).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    // Unknown: 404.
    assert_eq!(
        delete(&app, Who::Device(phone), &hex(b"nothing")).await.status,
        StatusCode::NOT_FOUND
    );

    // The phone's `DELETE` removes only its own claim; the owner's job still finds the blob.
    assert_eq!(
        delete(&app, Who::Device(phone), &hex(&shared)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        head(&app, Who::Key(&app.admin), &hex(&shared)).await.status,
        StatusCode::OK
    );
    assert!(blob_file(&app, &account, &hex(&shared)).exists());
    let r = app
        .call(
            Method::POST,
            "/v1/jobs",
            Some(&app.admin),
            Some(job_body(&[("/inputs/a", &hex(&shared))], 1024)),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let job = r.json()["id"].as_str().unwrap().to_string();

    // While a non-terminal job references it: 409.
    assert_problem(
        &delete(&app, Who::Key(&app.admin), &hex(&shared)).await,
        StatusCode::CONFLICT,
        "blob_in_use",
    );
    let c = app
        .call(Method::POST, &format!("/v1/jobs/{job}/cancel"), Some(&app.admin), None)
        .await;
    assert_eq!(c.status, StatusCode::OK);
    // The last claim goes: the blob goes too, row and file.
    assert_eq!(
        delete(&app, Who::Key(&app.admin), &hex(&shared)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        head(&app, Who::Key(&app.admin), &hex(&shared)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(rows(&app, &hex(&shared)).await, 0);
    assert!(!blob_file(&app, &account, &hex(&shared)).exists());

    // An admin removes every claim, even without one of its own.
    assert_eq!(
        upload(&app, Who::Device(phone), b"phone's").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        delete(&app, Who::Key(&app.admin), &hex(b"phone's")).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(rows(&app, &hex(b"phone's")).await, 0);
}

#[tokio::test]
async fn the_routes_check_their_scopes() {
    let app = TestApp::new().await;
    let bytes = b"scoped".to_vec();
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    let nodes = app.key_with(&[Scope::NodesRead]).await;
    let reader = app.key_with(&[Scope::JobsRead]).await;
    let writer = app.key_with(&[Scope::BlobsWrite]).await;
    assert_problem(
        &upload(&app, Who::Key(&reader), b"x").await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    // A `HEAD` answer has no body, so only its status says why.
    assert_eq!(
        head(&app, Who::Key(&nodes), &hex(&bytes)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(head(&app, Who::Key(&reader), &hex(&bytes)).await.status, StatusCode::OK);
    assert_eq!(head(&app, Who::Key(&writer), &hex(&bytes)).await.status, StatusCode::OK);
    assert_problem(&app.get("/v1/blobs", &writer).await, StatusCode::FORBIDDEN, "forbidden");
    assert_eq!(app.get("/v1/blobs", &reader).await.status, StatusCode::OK);
    assert_problem(
        &delete(&app, Who::Key(&reader), &hex(&bytes)).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    // No credentials at all.
    let r = send(
        &app,
        Who::Key("p2pc_sk_notakey"),
        Method::HEAD,
        "/v1/blobs/x",
        &[],
        Body::empty(),
    )
    .await; // gitleaks:allow
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn job_inputs_must_name_live_blobs_of_the_callers_account_that_fit_the_disk() {
    let app = TestApp::new().await;
    let (other_key, other_id) = second_account(&app).await;
    let bytes = b"input bytes".to_vec();
    let sha = hex(&bytes);
    let create = |key: String, body: Value| {
        let app = &app;
        async move { app.call(Method::POST, "/v1/jobs", Some(&key), Some(body)).await }
    };
    // Not uploaded yet.
    let r = create(app.admin.clone(), job_body(&[("/inputs/a", &sha)], 1024)).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "unknown_blob");
    // Uploaded in another account only: unknown here (SI-H2-8).
    assert_eq!(
        upload(&app, Who::Key(&other_key), &bytes).await.status,
        StatusCode::CREATED
    );
    let r = create(app.admin.clone(), job_body(&[("/inputs/a", &sha)], 1024)).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "unknown_blob");
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    // 64 MiB of disk leaves no room for any input.
    let r = create(app.admin.clone(), job_body(&[("/inputs/a", &sha)], 64)).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "inputs_exceed_disk");
    let r = create(
        app.admin.clone(),
        job_body(&[("/inputs/a", &sha), ("/inputs/b", &sha)], 1024),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    // The reference keeps it alive, counted once per job.
    let l = app.get("/v1/blobs", &app.admin).await.json();
    assert_eq!(l["items"][0]["referenced_by"], 1);
    assert!(l["items"][0]["expires_at"].is_null());
    let refs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_refs WHERE sha256 = ? AND account_id = ?")
        .bind(&sha)
        .bind(app.account_id.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(refs, 2);
    // A tombstoned blob is absent to job creation.
    sqlx::query("UPDATE blobs SET deleting_at = 1 WHERE sha256 = ? AND account_id = ?")
        .bind(&sha)
        .bind(account_of_key(&app, &other_id).await)
        .execute(&app.db)
        .await
        .unwrap();
    let r = create(other_key.clone(), job_body(&[("/inputs/a", &sha)], 1024)).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "unknown_blob");
}

#[tokio::test]
async fn gc_deletes_an_unreferenced_blob_24_h_after_its_upload() {
    let app = TestApp::new().await;
    let bytes = b"short-lived".to_vec();
    let sha = hex(&bytes);
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    app.clock.advance(Duration::hours(24) - Duration::seconds(1));
    assert_eq!(gc::run_pass(&app.state, 100).await, gc::GcReport::default());
    assert_eq!(rows(&app, &sha).await, 1);
    app.clock.advance(Duration::seconds(1));
    let r = gc::run_pass(&app.state, 100).await;
    assert_eq!((r.blobs_removed, r.errors), (1, 0), "{r:?}");
    assert_eq!(rows(&app, &sha).await, 0);
    assert!(!blob_file(&app, &app.account_id.to_string(), &sha).exists());
    let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploaders WHERE sha256 = ?")
        .bind(&sha)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(claims, 0);
}

#[tokio::test]
async fn a_referenced_blob_lives_until_its_last_job_ended_plus_24_h_and_the_retention() {
    let app = TestApp::new().await;
    let bytes = b"referenced".to_vec();
    let sha = hex(&bytes);
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    let r = app
        .call(
            Method::POST,
            "/v1/jobs",
            Some(&app.admin),
            Some(job_body(&[("/inputs/a", &sha)], 1024)),
        )
        .await;
    let job = r.json()["id"].as_str().unwrap().to_string();
    // A queued job keeps it alive however long it waits.
    app.clock.advance(Duration::days(30));
    assert_eq!(gc::run_pass(&app.state, 100).await.blobs_removed, 0);
    let c = app
        .call(Method::POST, &format!("/v1/jobs/{job}/cancel"), Some(&app.admin), None)
        .await;
    assert_eq!(c.json()["status"], "cancelled");
    // 24 h plus the 7-day retention after the job became terminal.
    app.clock.advance(Duration::days(8) - Duration::seconds(1));
    assert_eq!(gc::run_pass(&app.state, 100).await.blobs_removed, 0);
    let l = app.get("/v1/blobs", &app.admin).await.json();
    assert_eq!(l["items"][0]["expires_at"], "2026-12-13T10:00:00Z");
    app.clock.advance(Duration::seconds(1));
    assert_eq!(gc::run_pass(&app.state, 100).await.blobs_removed, 1);
    assert_eq!(rows(&app, &sha).await, 0);
}

#[tokio::test]
async fn a_tombstoned_blob_is_absent_and_an_upload_stores_it_as_new() {
    let app = TestApp::new().await;
    let bytes = b"tombstoned".to_vec();
    let sha = hex(&bytes);
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    // A GC that stopped after step 1.
    sqlx::query("UPDATE blobs SET deleting_at = ? WHERE sha256 = ?")
        .bind(common::T0.unix_timestamp())
        .bind(&sha)
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(
        head(&app, Who::Key(&app.admin), &sha).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(
        app.get("/v1/blobs", &app.admin).await.json()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        delete(&app, Who::Key(&app.admin), &sha).await.status,
        StatusCode::NOT_FOUND
    );
    // The upload finishes the deletion, then stores the blob as new.
    app.clock.advance(Duration::hours(1));
    let r = upload(&app, Who::Key(&app.admin), &bytes).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.json()["created_at"], "2026-11-05T11:00:00Z");
    assert_eq!(
        std::fs::read(blob_file(&app, &app.account_id.to_string(), &sha)).unwrap(),
        bytes
    );
    assert_eq!(head(&app, Who::Key(&app.admin), &sha).await.status, StatusCode::OK);
}

#[tokio::test]
async fn gc_resumes_from_a_tombstone_and_retries_a_file_it_could_not_delete() {
    let app = TestApp::new().await;
    let bytes = b"stubborn".to_vec();
    let sha = hex(&bytes);
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    // The file cannot be deleted: something replaced it with a non-empty directory.
    let path = blob_file(&app, &app.account_id.to_string(), &sha);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("inside"), b"x").unwrap();
    app.clock.advance(Duration::hours(25));
    let r = gc::run_pass(&app.state, 100).await;
    assert_eq!((r.blobs_removed, r.errors), (0, 1), "{r:?}");
    // Step 1 happened: absent to every reader, row kept, the attempt stamped.
    assert_eq!(
        head(&app, Who::Key(&app.admin), &sha).await.status,
        StatusCode::NOT_FOUND
    );
    let (deleting, attempt): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT deleting_at, last_attempt_at FROM blobs WHERE sha256 = ?")
            .bind(&sha)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert!(deleting.is_some() && attempt.is_some());
    std::fs::remove_dir_all(&path).unwrap();
    let r = gc::run_pass(&app.state, 100).await;
    assert_eq!((r.blobs_removed, r.errors), (1, 0), "{r:?}");
    assert_eq!(rows(&app, &sha).await, 0);
}

/// SI-H2-8: the same digest in two accounts is two blobs, two files and two locks.
#[tokio::test]
async fn the_same_digest_in_two_accounts_is_two_independent_blobs() {
    let app = TestApp::new().await;
    let (other_key, other_id) = second_account(&app).await;
    let other_account = account_of_key(&app, &other_id).await;
    let owner_account = app.account_id.to_string();
    let bytes = b"same digest, two accounts".to_vec();
    let sha = hex(&bytes);
    assert_eq!(
        upload(&app, Who::Key(&other_key), &bytes).await.status,
        StatusCode::CREATED
    );
    // Deduplication never crosses accounts: the owner's upload creates its own blob.
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    assert!(blob_file(&app, &owner_account, &sha).exists());
    assert!(blob_file(&app, &other_account, &sha).exists());
    // The other account's job references its own copy.
    let r = app
        .call(
            Method::POST,
            "/v1/jobs",
            Some(&other_key),
            Some(job_body(&[("/inputs/a", &sha)], 1024)),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    // `DELETE` in the owner's account leaves the other's file and row.
    assert_eq!(
        delete(&app, Who::Key(&app.admin), &sha).await.status,
        StatusCode::NO_CONTENT
    );
    assert!(!blob_file(&app, &owner_account, &sha).exists());
    assert_eq!(std::fs::read(blob_file(&app, &other_account, &sha)).unwrap(), bytes);
    assert_eq!(head(&app, Who::Key(&other_key), &sha).await.status, StatusCode::OK);

    // GC in the owner's account (a new, expired copy) leaves the other's, which its job keeps alive.
    assert_eq!(
        upload(&app, Who::Key(&app.admin), &bytes).await.status,
        StatusCode::CREATED
    );
    app.clock.advance(Duration::days(40));
    assert_eq!(gc::run_pass(&app.state, 100).await.blobs_removed, 1);
    assert!(!blob_file(&app, &owner_account, &sha).exists());
    assert_eq!(std::fs::read(blob_file(&app, &other_account, &sha)).unwrap(), bytes);
    assert_eq!(head(&app, Who::Key(&other_key), &sha).await.status, StatusCode::OK);
}

/// SI-H2-8: an upload in one account and GC in the other do not wait on each other's lock; within one account the
/// lock is shared.
#[tokio::test]
async fn the_digest_lock_is_per_account() {
    let app = TestApp::new().await;
    let (other_key, other_id) = second_account(&app).await;
    let other: AccountId = account_of_key(&app, &other_id).await.parse().unwrap();
    let bytes = b"locked digest".to_vec();
    let d = digest(&bytes);

    // The owner's lock is held (as a GC between its steps would hold it).
    let held = app.state.blobs.lock(app.account_id, d).await;
    // The other account uploads the same digest without waiting.
    let r = tokio::time::timeout(WAIT, upload(&app, Who::Key(&other_key), &bytes))
        .await
        .unwrap();
    assert_eq!(r.status, StatusCode::CREATED);
    // GC of the other account's (expired) blob does not wait either.
    app.clock.advance(Duration::hours(25));
    let r = tokio::time::timeout(WAIT, gc::run_pass(&app.state, 100)).await.unwrap();
    assert_eq!(r.blobs_removed, 1);
    // An upload of that digest in the owner's account waits for the lock.
    let router = app.router.clone();
    let (req, _) = request(
        Who::Key(&app.admin),
        Method::POST,
        "/v1/blobs",
        &upload_headers(bytes.len() as u64, &hex(&bytes)),
        Body::from(bytes.clone()),
    );
    let mut task = tokio::spawn(async move { router.oneshot(req).await.unwrap().status() });
    assert!(
        tokio::time::timeout(StdDuration::from_millis(300), &mut task)
            .await
            .is_err(),
        "the upload did not wait for its account's lock"
    );
    drop(held);
    assert_eq!(
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap(),
        StatusCode::CREATED
    );
    // And the other account's lock is independent of it.
    let _other_held = tokio::time::timeout(WAIT, app.state.blobs.lock(other, d))
        .await
        .unwrap();
}

fn set_mtime(path: &std::path::Path, at: time::OffsetDateTime) {
    let when = SystemTime::UNIX_EPOCH + StdDuration::from_secs(u64::try_from(at.unix_timestamp()).unwrap());
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

#[tokio::test]
async fn the_staging_sweep_goes_by_last_write_and_skips_uploads_in_progress() {
    let app = TestApp::new().await;
    let staging = app.state.blobs.staging_dir();
    std::fs::create_dir_all(&staging).unwrap();
    let (old, recent) = (staging.join("old-orphan"), staging.join("recent-orphan"));
    std::fs::write(&old, b"o").unwrap();
    std::fs::write(&recent, b"r").unwrap();
    set_mtime(&old, common::T0 - Duration::hours(2));
    set_mtime(&recent, common::T0 - Duration::minutes(10));
    // An upload in progress, whose last write is old too.
    let bytes = vec![5u8; 32];
    let (tx, task) = held_upload(app.router.clone(), Who::Key(&app.admin), &bytes).await;
    let in_progress: Vec<PathBuf> = staging_files(&app)
        .into_iter()
        .filter(|p| p != &old && p != &recent)
        .collect();
    assert_eq!(in_progress.len(), 1);
    set_mtime(&in_progress[0], common::T0 - Duration::hours(3));

    let r = gc::run_pass(&app.state, 100).await;
    assert_eq!(r.staging_swept, 1, "{r:?}");
    assert!(!old.exists() && recent.exists() && in_progress[0].exists());
    // At start every staging file no upload holds goes, whatever its age.
    assert_eq!(gc::sweep_staging_at_start(&app.state).await, 1);
    assert!(!recent.exists() && in_progress[0].exists());

    tx.send(Bytes::copy_from_slice(&bytes[1..])).await.unwrap();
    drop(tx);
    assert_eq!(
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap(),
        StatusCode::CREATED
    );
    assert!(staging_files(&app).is_empty());
}
