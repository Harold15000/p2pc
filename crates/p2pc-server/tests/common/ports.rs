// SPDX-License-Identifier: AGPL-3.0-only

//! Service ports end to end (H2 spec §6.1, §7.4): the server as `serve` wires it (REST listener, gateway, scheduler),
//! a fake agent that also plays the service behind a port, and clients on every transport: devices over
//! `p2pc/device/1`, API keys over TCP and over `p2pc/http/1`. Everything runs over loopback, relays disabled.
//!
//! The fake service **records every byte** that reaches it, per connection, and every `PortOpen` the hub sends, so a
//! test can say exactly what a connection carried, and that a refused request opened nothing at all.
//!
//! Nothing here sleeps to synchronise: a test waits for what the hub or the service does, under [`WAIT`].

// Helpers are not `#[test]` functions: a failed `expect` here is a test failure with its message.
#![allow(clippy::expect_used)]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use iroh::SecretKey;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use p2pc_proto::api::{AllowedRoute, FileMeta, JobSpec, Principal, Scope};
use p2pc_proto::ids::{DeviceId, JobId, LeaseId};
use p2pc_proto::protocol::{
    AgentMsg, HealthState, HubStreamHeader, PortOpen, PortOpenAck, ServiceHealth, read_frame_with_limit, write_frame,
};
use p2pc_proto::units::Units;
use p2pc_proto::{PROTOCOL_ALPN_DEVICE, PROTOCOL_ALPN_HTTP};
use p2pc_server::clock::Clock;
use p2pc_server::config::Config;
use p2pc_server::gateway::GatewayLimits;
use p2pc_server::jobs_api::TemplateCatalog;
use p2pc_server::store::{self, jobs};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};

use super::fleet::{FakeAgent, Fleet, NowForTests};
use super::h2::Peer;
pub use super::h2::WAIT;
use super::{DeviceLimits, TestApp};

/// The port of the template services of these tests (Ollama's).
pub const CHAT_PORT: u16 = 11434;

/// The bundle of the tests: `private-chat` is a singleton whose port takes `POST /api/chat` and `GET /api/tags`
/// (the beta's routes, H2 §7.6); `notes` is a template without routes.
#[derive(Debug)]
pub struct Bundle;

impl TemplateCatalog for Bundle {
    fn singleton_ids(&self) -> Vec<String> {
        vec!["private-chat".to_string()]
    }

    fn allowed_routes(&self, template_id: &str) -> Vec<AllowedRoute> {
        if template_id != "private-chat" {
            return Vec::new();
        }
        serde_json::from_value(json!([
            {"port": CHAT_PORT, "method": "POST", "path": "/api/chat"},
            {"port": CHAT_PORT, "method": "GET", "path": "/api/tags"},
        ]))
        .expect("routes")
    }
}

/// What the fake service does with a connection the hub opens.
#[derive(Clone)]
pub enum Act {
    /// Sends every byte back, and ends when the hub ends its side.
    Echo,
    /// Reads one HTTP request (its head, then `Content-Length` bytes), answers `first`, waits for a permit of `gate`
    /// if there is one, answers `second` and ends its side. It keeps reading: whatever else arrives is recorded.
    Http {
        first: Vec<u8>,
        second: Vec<u8>,
        gate: Option<Arc<Semaphore>>,
    },
    /// Answers `PortOpenAck{ok: false}` with this reason.
    Refuse(&'static str),
    /// Accepts the connection and never sends a byte.
    Silent,
    /// Tells the test a `PortOpen` arrived, and accepts it only once `gate` gives a permit.
    AckLate(Arc<Semaphore>),
}

/// One connection, as the fake service saw it until it ended.
#[derive(Debug)]
pub struct Seen {
    /// The `PortOpen` that opened it.
    pub open: PortOpen,
    /// Every byte that reached the service.
    pub bytes: Vec<u8>,
    /// Whether the hub ended it cleanly (a stream finish) rather than with a reset.
    pub clean: bool,
}

/// The service behind the ports of a fake agent.
pub struct Service {
    act: Mutex<Act>,
    opens: Mutex<Vec<PortOpen>>,
    seen: mpsc::Sender<Seen>,
    asked: mpsc::Sender<()>,
}

impl Service {
    pub fn set(&self, act: Act) {
        *self.act.lock().expect("act") = act;
    }

    /// Every `PortOpen` the hub sent so far.
    pub fn opens(&self) -> Vec<PortOpen> {
        self.opens.lock().expect("opens").clone()
    }
}

/// A fake agent that declared `service_jobs`, with the service behind its ports.
pub struct Node {
    pub agent: FakeAgent,
    pub service: Arc<Service>,
    seen: mpsc::Receiver<Seen>,
    asked: mpsc::Receiver<()>,
}

impl Node {
    pub async fn join(fleet: &Fleet) -> Self {
        let agent = fleet.agent().await;
        let agent = fleet.restart_with(agent, &["service_jobs"]).await;
        let (seen_tx, seen) = mpsc::channel(256);
        let (asked_tx, asked) = mpsc::channel(256);
        let service = Arc::new(Service {
            act: Mutex::new(Act::Echo),
            opens: Mutex::new(Vec::new()),
            seen: seen_tx,
            asked: asked_tx,
        });
        tokio::spawn(accept(agent.conn.clone(), service.clone()));
        Self {
            agent,
            service,
            seen,
            asked,
        }
    }

    /// The agent restarts (§6 "Reconnects"): a new connection whose `Hello` lists no lease, so the hub loses its
    /// leases at once. The service behind it is the same.
    pub async fn restart(self, fleet: &Fleet) -> Self {
        let agent = fleet.restart_with(self.agent, &["service_jobs"]).await;
        tokio::spawn(accept(agent.conn.clone(), self.service.clone()));
        Self { agent, ..self }
    }

    /// The next connection that ended at the service.
    pub async fn seen(&mut self) -> Seen {
        tokio::time::timeout(WAIT, self.seen.recv())
            .await
            .expect("no connection ended at the service")
            .expect("the service is gone")
    }

    /// Waits for a `PortOpen` that an [`Act::AckLate`] service holds.
    pub async fn asked(&mut self) {
        tokio::time::timeout(WAIT, self.asked.recv())
            .await
            .expect("no PortOpen reached the service")
            .expect("the service is gone");
    }

    /// The next lease of this node, accepted, started and reported `healthy`.
    pub async fn start_next(&mut self, fleet: &Fleet) -> (LeaseId, u64) {
        let (lease_id, epoch) = self.start_next_unready(fleet).await;
        self.health(fleet, lease_id, epoch, HealthState::Healthy).await;
        (lease_id, epoch)
    }

    /// The next lease of this node, accepted and started: its service is still `starting`.
    pub async fn start_next_unready(&mut self, fleet: &Fleet) -> (LeaseId, u64) {
        assert_eq!(fleet.scheduler.tick().await.errors, 0);
        let (lease_id, epoch) = self.agent.next_lease().await;
        self.agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
        self.agent
            .send(&AgentMsg::JobStarted {
                lease_id,
                epoch,
                started_at: fleet.app.clock.now_for_tests(),
            })
            .await;
        self.agent.sync().await;
        (lease_id, epoch)
    }

    pub async fn health(&mut self, fleet: &Fleet, lease_id: LeaseId, epoch: u64, state: HealthState) {
        self.agent
            .send(&AgentMsg::ServiceHealth(ServiceHealth {
                lease_id,
                epoch,
                state,
                since: fleet.app.clock.now_for_tests(),
                detail: None,
            }))
            .await;
        self.agent.sync().await;
    }
}

/// Serves the streams the hub opens on `conn` until the connection is gone.
async fn accept(conn: Connection, service: Arc<Service>) {
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(connection(send, recv, service.clone()));
    }
}

/// Reads from `recv` into `bytes` until the hub ends the stream. `true` for a clean end, `false` for a reset.
async fn drain(recv: &mut RecvStream, bytes: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 4096];
    loop {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => bytes.extend_from_slice(&chunk[..n]),
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// Reads one HTTP request into `bytes`: its head, then `Content-Length` bytes. `false` if the stream ended first.
async fn read_request(recv: &mut RecvStream, bytes: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return true;
            }
        }
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => bytes.extend_from_slice(&chunk[..n]),
            _ => return false,
        }
    }
}

async fn connection(mut send: SendStream, mut recv: RecvStream, service: Arc<Service>) {
    let header = read_frame_with_limit::<HubStreamHeader, _>(&mut recv, 4096).await;
    let Ok(Some(HubStreamHeader::PortOpen(open))) = header else {
        return;
    };
    service.opens.lock().expect("opens").push(open.clone());
    let act = service.act.lock().expect("act").clone();
    let mut bytes = Vec::new();
    let accepted = PortOpenAck::accepted();
    let clean = match act {
        Act::Refuse(reason) => {
            let _ = write_frame(&mut send, &PortOpenAck::refused(reason)).await;
            let _ = send.finish();
            drain(&mut recv, &mut bytes).await
        }
        Act::AckLate(gate) => {
            let _ = service.asked.send(()).await;
            gate.acquire().await.expect("gate").forget();
            let _ = write_frame(&mut send, &accepted).await;
            drain(&mut recv, &mut bytes).await
        }
        Act::Silent => {
            let _ = write_frame(&mut send, &accepted).await;
            drain(&mut recv, &mut bytes).await
        }
        Act::Echo => {
            let _ = write_frame(&mut send, &accepted).await;
            let mut chunk = [0u8; 4096];
            let clean = loop {
                match recv.read(&mut chunk).await {
                    Ok(Some(n)) => {
                        bytes.extend_from_slice(&chunk[..n]);
                        if send.write_all(&chunk[..n]).await.is_err() {
                            break false;
                        }
                    }
                    Ok(None) => break true,
                    Err(_) => break false,
                }
            };
            let _ = send.finish();
            clean
        }
        Act::Http { first, second, gate } => {
            let _ = write_frame(&mut send, &accepted).await;
            if read_request(&mut recv, &mut bytes).await {
                let _ = send.write_all(&first).await;
                if let Some(gate) = gate {
                    gate.acquire().await.expect("gate").forget();
                }
                let _ = send.write_all(&second).await;
                let _ = send.finish();
                drain(&mut recv, &mut bytes).await
            } else {
                false
            }
        }
    };
    let _ = service.seen.send(Seen { open, bytes, clean }).await;
}

/// The hub with its REST listener, and one node.
pub struct World {
    pub fleet: Fleet,
    /// The REST listener, which API-key clients connect to.
    pub rest: SocketAddr,
    pub node: Node,
}

impl World {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(edit: impl FnOnce(&mut Config)) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let rest = listener.local_addr().expect("an address");
        let fleet = Fleet::start_full(
            edit,
            |state| state.templates = Arc::new(Bundle),
            GatewayLimits::default(),
            rest,
        )
        .await;
        tokio::spawn(p2pc_server::serve::serve_on(
            listener,
            fleet.app.state.clone(),
            std::future::pending(),
        ));
        let node = Node::join(&fleet).await;
        Self { fleet, rest, node }
    }

    pub fn app(&self) -> &TestApp {
        &self.fleet.app
    }

    /// The admin API key, as a principal.
    pub fn owner(&self) -> Principal {
        Principal::Key(self.app().admin_key.key_id())
    }

    /// Stores a job as a submission or a template launch stores it, with `by` as its principal.
    pub async fn store_job(&self, by: Principal, spec: Value) -> JobId {
        let app = self.app();
        let spec: JobSpec = serde_json::from_value(spec).expect("a job spec");
        let mut tx = store::begin_immediate(&app.db).await.expect("a transaction");
        let new = jobs::NewJob {
            job_id: JobId::generate(),
            account_id: app.account_id,
            project_id: app.project_id,
            principal: by,
            files_meta: FileMeta::compute_all(&spec).expect("file metadata"),
            spec,
            spec_hash: format!("sha256:{}", "0".repeat(64)),
            units_reserved: Units::ZERO,
        };
        let row = jobs::insert(&mut tx, &new, app.clock.now()).await.expect("the job");
        tx.commit().await.expect("commit");
        row.job_id
    }

    /// A service of `by`, running and healthy on the node. Returns the job and its lease.
    pub async fn running(&mut self, by: Principal, spec: Value) -> (JobId, LeaseId, u64) {
        let job = self.store_job(by, spec).await;
        let (lease_id, epoch) = self.node.start_next(&self.fleet).await;
        (job, lease_id, epoch)
    }

    /// Registers `key` as a device with `scopes`, as `devices add` does.
    pub async fn add_device(&self, key: &SecretKey, scopes: &[Scope], limits: DeviceLimits) -> DeviceId {
        let app = self.app();
        let mut tx = store::begin_immediate(&app.db).await.expect("a transaction");
        let new = store::devices::NewDevice {
            device_id: DeviceId::generate(),
            project_id: app.project_id,
            iroh_node_id: key.public().to_string(),
            label: Some("test device".into()),
            platform: "test".into(),
            scopes: scopes.to_vec(),
            daily_unit_cap: limits.daily_unit_cap,
            allowed_images: limits.allowed_images,
            blobs_quota_mb: limits.blobs_quota_mb,
            expires_at: limits.expires_at,
            paired_by: None,
        };
        let row = store::devices::insert(&mut tx, app.account_id, &new, app.clock.now())
            .await
            .expect("the device");
        tx.commit().await.expect("commit");
        row.device_id
    }

    /// A `p2pc/device/1` connection of `key`.
    pub async fn device(&self, key: &SecretKey) -> Peer {
        Peer::connect(self.fleet.addr(), key, PROTOCOL_ALPN_DEVICE)
            .await
            .expect("p2pc/device/1 is served")
    }

    /// A `p2pc/http/1` connection of a new NodeId.
    pub async fn tunnel(&self) -> Peer {
        Peer::connect(self.fleet.addr(), &SecretKey::generate(), PROTOCOL_ALPN_HTTP)
            .await
            .expect("p2pc/http/1 is served")
    }

    /// `GET /v1/jobs/{id}` with the admin key.
    pub async fn job(&self, job: JobId) -> Value {
        let app = self.app();
        let r = app.get(&format!("/v1/jobs/{job}"), &app.admin).await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        r.json()
    }

    /// `service_state.last_activity_at` of `job`, in Unix seconds.
    pub async fn last_activity(&self, job: JobId) -> Option<i64> {
        sqlx::query_scalar("SELECT last_activity_at FROM service_state WHERE job_id = ?")
            .bind(job.to_string())
            .fetch_one(&self.app().db)
            .await
            .expect("the service state")
    }
}

/// A service that came from no template (`p2pc service run`), with `CHAT_PORT` and port 8080.
pub fn plain_service() -> Value {
    json!({"kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
        "resources": {"cpu": 1, "memory_mb": 256},
        "service": {"ports": [{"port": CHAT_PORT, "name": "api"}, {"port": 8080, "name": "http"}]}})
}

/// A service of the template `id`, as its launch stores it.
pub fn template_service(id: &str) -> Value {
    let mut spec = plain_service();
    spec["template"] = json!({"id": id, "version": 1});
    spec
}

/// A response the hub or the service wrote, as far as these tests read one.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
    }

    /// The problem `code`, for an error of the hub.
    pub fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_string()
    }
}

/// One client connection, on any transport: a device stream, a TCP connection or a `p2pc/http/1` stream.
pub struct Wire {
    read: Box<dyn AsyncRead + Send + Unpin>,
    write: Box<dyn AsyncWrite + Send + Unpin>,
    buf: Vec<u8>,
}

impl Wire {
    /// A new stream of `peer` (a device connection, or a `p2pc/http/1` tunnel).
    pub async fn stream(peer: &Peer) -> Self {
        let (send, recv) = peer.conn.open_bi().await.expect("a stream");
        Self {
            read: Box::new(recv),
            write: Box::new(send),
            buf: Vec::new(),
        }
    }

    /// A new TCP connection to the REST listener.
    pub async fn tcp(rest: SocketAddr) -> Self {
        let tcp = tokio::net::TcpStream::connect(rest).await.expect("the REST listener");
        let (read, write) = tcp.into_split();
        Self {
            read: Box::new(read),
            write: Box::new(write),
            buf: Vec::new(),
        }
    }

    /// Writes `bytes`. `false` when the hub no longer takes them (it answered already and closed).
    pub async fn send(&mut self, bytes: &[u8]) -> bool {
        self.write.write_all(bytes).await.is_ok() && self.write.flush().await.is_ok()
    }

    /// Ends this side of the connection.
    pub async fn finish(&mut self) {
        let _ = self.write.shutdown().await;
    }

    async fn more(&mut self) -> Result<(), String> {
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(WAIT, self.read.read(&mut chunk)).await {
            Err(_) => Err("no answer".to_string()),
            Ok(Ok(0)) => Err("the connection ended".to_string()),
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(())
            }
            Ok(Err(e)) => Err(e.to_string()),
        }
    }

    /// Reads one response: its head, then `Content-Length` bytes of body (none for a `101`).
    pub async fn answer(&mut self) -> Result<Answer, String> {
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..end]).to_string();
                let status: u16 = head
                    .split(' ')
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| format!("not an HTTP response: {head:?}"))?;
                let length: usize = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse().ok())
                    .unwrap_or(0);
                if self.buf.len() >= end + 4 + length {
                    let body = self.buf[end + 4..end + 4 + length].to_vec();
                    self.buf.drain(..end + 4 + length);
                    return Ok(Answer { status, head, body });
                }
            }
            self.more().await?;
        }
    }

    /// Reads exactly `n` bytes.
    pub async fn exactly(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.buf.len() < n {
            self.more().await?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// Reads to the end of the connection: everything that came, and whether the end was clean.
    pub async fn rest(&mut self) -> (Vec<u8>, bool) {
        let mut chunk = [0u8; 4096];
        let clean = loop {
            match tokio::time::timeout(WAIT, self.read.read(&mut chunk)).await {
                Err(_) => panic!("the connection is still open"),
                Ok(Ok(0)) => break true,
                Ok(Ok(n)) => self.buf.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) => break false,
            }
        };
        (std::mem::take(&mut self.buf), clean)
    }

    /// Asks for the port connection (H2 §7.4) and reads the hub's answer: `101`, or a problem. `auth` is an API
    /// key for the TCP listener and `p2pc/http/1`; a device sends none.
    pub async fn connect(&mut self, job: JobId, port: u16, auth: Option<&str>, query: &str) -> Answer {
        let auth = auth.map_or_else(String::new, |key| format!("Authorization: Bearer {key}\r\n"));
        let request = format!(
            "POST /v1/jobs/{job}/ports/{port}/connect{query} HTTP/1.1\r\nHost: hub\r\nConnection: Upgrade\r\n\
             Upgrade: p2pc-port/1\r\n{auth}\r\n"
        );
        assert!(self.send(request.as_bytes()).await, "the request is sent");
        self.answer().await.expect("an answer to the connect")
    }

    /// [`Wire::connect`] that must be upgraded.
    pub async fn upgraded(&mut self, job: JobId, port: u16, auth: Option<&str>) {
        let r = self.connect(job, port, auth, "").await;
        assert_eq!(r.status, 101, "{} {:?}", r.head, String::from_utf8_lossy(&r.body));
        assert!(
            r.head.to_ascii_lowercase().contains("upgrade: p2pc-port/1"),
            "{}",
            r.head
        );
    }
}

/// Retries `attempt` until it gives a value. For what the hub does after a client can observe it (a slot given
/// back, a row written): the test looks again, as a client would, and nothing sleeps.
pub async fn eventually<T, F: Future<Output = Option<T>>>(what: &str, mut attempt: impl FnMut() -> F) -> T {
    let retry = async {
        loop {
            if let Some(value) = attempt().await {
                return value;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(WAIT, retry)
        .await
        .unwrap_or_else(|_| panic!("never: {what}"))
}
