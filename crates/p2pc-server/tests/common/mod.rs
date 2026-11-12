// SPDX-License-Identifier: AGPL-3.0-only

//! Shared harness: a fresh data dir and SQLite database per test, initialised with `init`, and the in-process
//! router driven with `tower::ServiceExt::oneshot`.

// Not every test file uses every helper. Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not
// cover them.
#![allow(dead_code, clippy::unwrap_used)]

pub mod fleet;
pub mod h2;
pub mod ports;
pub mod sql;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use p2pc_proto::api::Scope;
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{AccountId, DeviceId, ProjectId};
use p2pc_server::app::{AppState, device_router, router};
use p2pc_server::auth::DeviceConnection;
use p2pc_server::clock::Clock;
use p2pc_server::clock::ManualClock;
use p2pc_server::config::Config;
use p2pc_server::store::{self, Db};
use serde_json::Value;
use time::OffsetDateTime;
use time::macros::datetime;
use tower::ServiceExt;

/// Fixed start time for every test.
pub const T0: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);

pub struct TestApp {
    pub dir: tempfile::TempDir,
    pub db: Db,
    pub clock: Arc<ManualClock>,
    pub state: AppState,
    pub router: Router,
    /// The admin key printed by `init`, in full.
    pub admin: String,
    pub admin_key: ApiKey,
    pub account_id: AccountId,
    pub project_id: ProjectId,
}

#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
    }

    pub fn content_type(&self) -> &str {
        self.headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

impl TestApp {
    /// The data dir `init` created.
    pub fn data_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("data")
    }

    pub async fn new() -> Self {
        Self::with_auth_failure_queue(p2pc_server::audit_queue::DEFAULT_CAPACITY).await
    }

    /// A test app whose failed-authentication queue holds `capacity` events.
    pub async fn with_auth_failure_queue(capacity: usize) -> Self {
        Self::build(capacity, |_| {}).await
    }

    /// A test app whose config is edited before the state is built.
    pub async fn with_config(edit: impl FnOnce(&mut Config)) -> Self {
        Self::build(p2pc_server::audit_queue::DEFAULT_CAPACITY, edit).await
    }

    async fn build(capacity: usize, edit: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let clock = Arc::new(ManualClock::new(T0));
        let out = p2pc_server::init::init(&data_dir, clock.as_ref()).await.unwrap();
        let mut config = Config::load(&out.config_path).unwrap();
        edit(&mut config);
        let db = store::open(&config.db_path(), store::OpenMode::Existing).await.unwrap();
        let state = AppState::load_with_queue(db.clone(), config, clock.clone(), capacity)
            .await
            .unwrap();
        Self {
            dir,
            db,
            clock,
            state: state.clone(),
            router: router(state),
            admin: out.admin_key.expose(),
            admin_key: out.admin_key,
            account_id: out.account_id,
            project_id: out.project_id,
        }
    }

    pub async fn call(&self, method: Method, uri: &str, key: Option<&str>, body: Option<Value>) -> Resp {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(key) = key {
            req = req.header(header::AUTHORIZATION, format!("Bearer {key}"));
        }
        let body = match body {
            Some(v) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        self.send(req.body(body).unwrap()).await
    }

    pub async fn send(&self, req: Request<Body>) -> Resp {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        Resp { status, headers, body }
    }

    /// Waits until every failed authentication queued so far is in the audit log.
    pub async fn flush_audit(&self) {
        self.state.auth_failures.flush().await;
    }

    pub async fn get(&self, uri: &str, key: &str) -> Resp {
        self.call(Method::GET, uri, Some(key), None).await
    }

    /// Creates a key through the API with the admin key and returns `(full key, response JSON)`.
    pub async fn create_key(&self, body: Value) -> (String, Value) {
        let r = self.call(Method::POST, "/v1/keys", Some(&self.admin), Some(body)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let v = r.json();
        (v["key"].as_str().unwrap().to_string(), v)
    }

    pub async fn key_with(&self, scopes: &[Scope]) -> String {
        self.create_key(serde_json::json!({ "scopes": scopes })).await.0
    }

    /// A request on the device router (H2 §6.3), as the `p2pc/device/1` transport serves it: the device the
    /// transport authenticated is attached as a request extension, never as a header.
    pub async fn device_call(&self, device: DeviceId, method: Method, uri: &str, body: Option<Value>) -> Resp {
        let mut req = Request::builder().method(method).uri(uri);
        let body = match body {
            Some(v) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        let mut req = req.body(body).unwrap();
        req.extensions_mut().insert(DeviceConnection { device_id: device });
        self.send_on(device_router(self.state.clone()), req).await
    }

    /// Sends `req` through `router`.
    pub async fn send_on(&self, router: Router, req: Request<Body>) -> Resp {
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        Resp { status, headers, body }
    }

    /// Registers a device straight in the store (as `devices add` does) in the default project, with `limits`.
    pub async fn add_device(&self, scopes: &[Scope], limits: DeviceLimits) -> DeviceId {
        let mut tx = store::begin_immediate(&self.db).await.unwrap();
        let new = store::devices::NewDevice {
            device_id: DeviceId::generate(),
            project_id: self.project_id,
            iroh_node_id: node_key(),
            label: Some("test device".into()),
            platform: "test".into(),
            scopes: scopes.to_vec(),
            daily_unit_cap: limits.daily_unit_cap,
            allowed_images: limits.allowed_images,
            blobs_quota_mb: limits.blobs_quota_mb,
            expires_at: limits.expires_at,
            paired_by: None,
        };
        let row = store::devices::insert(&mut tx, self.account_id, &new, self.clock.now())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        row.device_id
    }
}

/// Limits of a test device.
#[derive(Debug, Clone, Default)]
pub struct DeviceLimits {
    pub daily_unit_cap: Option<p2pc_proto::units::Units>,
    pub allowed_images: Option<Vec<String>>,
    pub blobs_quota_mb: Option<u64>,
    pub expires_at: Option<OffsetDateTime>,
}

/// A fresh iroh NodeId: 64 lowercase hex characters of a valid Ed25519 public key.
pub fn node_key() -> String {
    loop {
        let bytes = *p2pc_proto::invite::HubNonce::generate().as_bytes();
        if iroh::PublicKey::from_bytes(&bytes).is_ok() {
            return data_encoding::HEXLOWER.encode(&bytes);
        }
    }
}

/// 64 hex characters that are **not** an Ed25519 point (some 32-byte strings do not decompress).
pub fn not_a_point() -> String {
    loop {
        let bytes = *p2pc_proto::invite::HubNonce::generate().as_bytes();
        if iroh::PublicKey::from_bytes(&bytes).is_err() {
            return data_encoding::HEXLOWER.encode(&bytes);
        }
    }
}

/// Asserts the RFC 9457 shape and returns the body.
pub fn assert_problem(r: &Resp, status: StatusCode, code: &str) -> Value {
    assert_eq!(r.status, status, "{:?}", r.body);
    assert_eq!(r.content_type(), "application/problem+json");
    let v = r.json();
    assert_eq!(v["status"], status.as_u16());
    assert_eq!(v["code"], code, "{v}");
    assert!(v["type"].is_string(), "{v}");
    assert!(v["title"].is_string(), "{v}");
    assert!(v["detail"].is_string(), "{v}");
    v
}

/// A valid node inventory for `hostname`: 8 CPUs, 16 GiB, no GPU, Podman ready, offering 6 CPUs and 12 GiB.
///
/// Built from JSON rather than a struct literal, so that a field added to `Inventory` (with a serde default) does
/// not break the tests (CONTRIBUTING "Shared types grow").
pub fn inventory(hostname: &str) -> p2pc_proto::api::Inventory {
    serde_json::from_value(serde_json::json!({
        "hostname": hostname,
        "platform": "linux",
        "cpu": {"model": "Example CPU", "cores": 8},
        "memory_mb": 16384,
        "os": "Ubuntu 24.04",
        "arch": "x86_64",
        "gpus": [],
        "gpu_status": {"status": "not_found"},
        "sandbox": [{"driver": "podman", "class": "container", "runtimes": ["crun"], "ready": true}],
        "offered": {"cpu": 6.0, "memory_mb": 12288, "gpu": 0},
        "agent_version": "0.1.0",
    }))
    .unwrap()
}

/// Inserts a second account with its own project and admin key straight into the database. Returns the key in full
/// and its key ID.
pub async fn second_account(app: &TestApp) -> (String, String) {
    let account = AccountId::generate().to_string();
    let project = ProjectId::generate().to_string();
    let key = ApiKey::generate();
    let digest = key.hash().to_stored();
    let now = T0.unix_timestamp();
    sqlx::query("INSERT INTO accounts (account_id, is_owner, created_at) VALUES (?, 0, ?)")
        .bind(&account)
        .bind(now)
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO projects (project_id, account_id, name, created_at) VALUES (?, ?, 'default', ?)")
        .bind(&project)
        .bind(&account)
        .bind(now)
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO api_keys (key_id, account_id, project_id, secret_digest, scopes, created_at) \
         VALUES (?, ?, ?, ?, '[\"admin\"]', ?)",
    )
    .bind(key.key_id().to_string())
    .bind(&account)
    .bind(&project)
    .bind(digest)
    .bind(now)
    .execute(&app.db)
    .await
    .unwrap();
    (key.expose(), key.key_id().to_string())
}
