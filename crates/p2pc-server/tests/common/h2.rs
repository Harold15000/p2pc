// SPDX-License-Identifier: AGPL-3.0-only

//! The hub's H2 protocols over real iroh connections on loopback, relays disabled (H2 §5.3, §6.3, §10.5): a hub with
//! its gateway, and peers that pair (`p2pc/pair/1`) or speak HTTP/1.1 over device streams (`p2pc/device/1`).
//!
//! Nothing here sleeps to synchronise. A test waits for what the hub does (an answer, a reset, a close) under
//! [`WAIT`], which is only reached when something is broken, and moves the injected clock for everything the hub
//! reads the time for.

// Helpers are not `#[test]` functions: a failed `expect` here is a test failure with its message.
#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration as StdDuration;

use axum::Router;
use axum::http::{Method, StatusCode};
use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use p2pc_proto::api::Scope;
use p2pc_proto::ids::DeviceId;
use p2pc_proto::pair::{PAIR_MAX_FRAME_LEN, PairRequest, PairResponse, PairingTicket};
use p2pc_proto::protocol::{read_frame_with_limit, write_frame};
use p2pc_proto::{PROTOCOL_ALPN_DEVICE, PROTOCOL_ALPN_PAIR};
use p2pc_server::app::AppState;
use p2pc_server::clock::Clock;
use p2pc_server::config::Config;
use p2pc_server::gateway::endpoint::bind;
use p2pc_server::gateway::{EndpointOptions, Gateway, GatewayConfig, GatewayLimits};
use p2pc_server::store;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{DeviceLimits, TestApp};

/// The bound for anything that should happen promptly. Only reached when something is broken.
pub const WAIT: StdDuration = StdDuration::from_secs(20);

/// The web app origin of the test hubs: pairing tickets need one.
pub const ORIGIN: &str = "https://app.example.invalid";

/// The QUIC close code of a connection the hub closes with no detail (H1: "closed by the server").
pub const CLOSE_BY_SERVER: u64 = 1;

/// A hub: the app state and its gateway on loopback.
pub struct Hub {
    pub app: TestApp,
    pub gw: Gateway,
}

/// The spec's limits; the background sweep never runs during a test (the tests call what it would).
pub fn limits() -> GatewayLimits {
    GatewayLimits {
        sweep_interval: StdDuration::from_secs(3600),
        ..GatewayLimits::default()
    }
}

impl Hub {
    pub async fn start() -> Self {
        Self::start_with(|_| {}, limits()).await
    }

    /// With the config edited before the state is built, and gateway limits.
    pub async fn start_with(edit: impl FnOnce(&mut Config), limits: GatewayLimits) -> Self {
        Self::start_full(edit, limits, |_| None, "127.0.0.1:9".parse().expect("an address")).await
    }

    /// [`Hub::start_with`], with a router for the device streams (`None`: the API's own) and the REST listener the
    /// `p2pc/http/1` tunnel relays to. The default REST target is unreachable: nothing a device stream does may
    /// depend on it (SI-H2-3: device requests are served in-process).
    pub async fn start_full(
        edit: impl FnOnce(&mut Config),
        limits: GatewayLimits,
        device_router: impl FnOnce(&AppState) -> Option<Router>,
        rest: SocketAddr,
    ) -> Self {
        let app = TestApp::with_config(|c| {
            c.devices.web_app_origin = Some(ORIGIN.into());
            edit(c);
        })
        .await;
        let mut config = GatewayConfig::new(EndpointOptions::loopback_without_relays(), rest);
        config.limits = limits;
        config.device_router = device_router(&app.state);
        let gw = Gateway::start(app.state.clone(), config)
            .await
            .expect("the gateway starts");
        Self { app, gw }
    }

    pub fn addr(&self) -> EndpointAddr {
        let ep = self.gw.endpoint();
        EndpointAddr::new(ep.id()).with_ip_addr(ep.bound_sockets()[0])
    }

    /// Creates a pairing ticket with the admin key and lets the gateway see it (what its sweep does each second).
    /// Returns the ticket and the response body.
    pub async fn ticket(&self, body: Value) -> (PairingTicket, Value) {
        let r = self
            .app
            .call(
                Method::POST,
                "/v1/devices/pairing-tickets",
                Some(&self.app.admin),
                Some(body),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let v = r.json();
        let ticket = PairingTicket::decode(v["ticket"].as_str().expect("a ticket")).expect("a valid ticket");
        assert!(self.gw.refresh_pair_serving().await, "a ticket is open");
        (ticket, v)
    }

    /// A ticket the hub never issued: this hub's NodeId and relays, a fresh random code.
    pub fn forged_ticket(&self) -> PairingTicket {
        let hub = self.gw.endpoint().id().to_string().parse().expect("a NodeId");
        PairingTicket::generate(hub, Vec::new(), time::Duration::seconds(600), self.app.clock.now()).expect("a ticket")
    }

    /// A forged ticket whose code hashes into the same 16-bit prefix as `like`'s.
    pub fn forged_ticket_in_prefix_of(&self, like: &PairingTicket) -> PairingTicket {
        let mut t = self.forged_ticket();
        // Walk the codes from a random start until one hashes into the prefix (65,536 tries on average).
        loop {
            for byte in &mut t.code {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
            if t.hash_prefix() == like.hash_prefix() && t.code != like.code {
                return t;
            }
        }
    }

    /// Connects `key` on `alpn`. `Err` when the handshake fails (the hub does not accept the ALPN).
    pub async fn connect(&self, key: &SecretKey, alpn: &[u8]) -> Result<Peer, String> {
        Peer::connect(self.addr(), key, alpn).await
    }

    /// One `Pair` from `key` on a new connection. `None` means the hub closed without an answer.
    pub async fn pair(&self, key: &SecretKey, ticket: &PairingTicket) -> Option<PairResponse> {
        let peer = self
            .connect(key, PROTOCOL_ALPN_PAIR)
            .await
            .expect("p2pc/pair/1 is served");
        peer.pair(ticket).await
    }

    /// Pairs `key` with a new ticket made from `body` and returns its device ID.
    pub async fn paired(&self, key: &SecretKey, body: Value) -> DeviceId {
        let (ticket, _) = self.ticket(body).await;
        match self.pair(key, &ticket).await {
            Some(PairResponse::Paired { device_id, .. }) => device_id.parse().expect("a device ID"),
            other => panic!("not paired: {other:?}"),
        }
    }

    /// Registers `key` as a device straight in the store (as `devices add` does), in the default project.
    pub async fn add_device(&self, key: &SecretKey, scopes: &[Scope], limits: DeviceLimits) -> DeviceId {
        let mut tx = store::begin_immediate(&self.app.db).await.expect("a transaction");
        let new = store::devices::NewDevice {
            device_id: DeviceId::generate(),
            project_id: self.app.project_id,
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
        let row = store::devices::insert(&mut tx, self.app.account_id, &new, self.app.clock.now())
            .await
            .expect("the device is inserted");
        tx.commit().await.expect("commit");
        row.device_id
    }

    /// A `p2pc/device/1` connection of `key`. The handshake always succeeds; what the hub does next is the test's
    /// to check.
    pub async fn device(&self, key: &SecretKey) -> Peer {
        self.connect(key, PROTOCOL_ALPN_DEVICE)
            .await
            .expect("p2pc/device/1 is always served")
    }

    /// The count of the one aggregated `auth_failed` audit row of `subject` (`pair`, `device`), 0 when there is none.
    pub async fn failures_audited(&self, subject: &str) -> u64 {
        self.app.flush_audit().await;
        let audit = self.app.get("/v1/audit?kind=auth_failed", &self.app.admin).await.json();
        let rows: Vec<&Value> = audit["items"]
            .as_array()
            .expect("items")
            .iter()
            .filter(|e| e["subject_id"] == subject)
            .collect();
        assert!(rows.len() <= 1, "one aggregated row a minute: {audit}");
        rows.first()
            .map_or(0, |e| e["detail"]["count"].as_u64().expect("a count"))
    }
}

/// A peer of the hub: its own endpoint and one connection.
pub struct Peer {
    pub ep: Endpoint,
    pub conn: Connection,
}

impl Peer {
    pub async fn connect(addr: EndpointAddr, key: &SecretKey, alpn: &[u8]) -> Result<Peer, String> {
        let ep = bind(key.clone(), &EndpointOptions::loopback_without_relays())
            .await
            .expect("a client endpoint");
        match tokio::time::timeout(WAIT, ep.connect(addr, alpn)).await {
            Ok(Ok(conn)) => Ok(Peer { ep, conn }),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("the handshake neither completed nor failed".into()),
        }
    }

    /// Waits for the hub to close the connection: its application close code and reason.
    pub async fn closed(&self) -> (u64, String) {
        match tokio::time::timeout(WAIT, self.conn.closed())
            .await
            .expect("the connection is still open")
        {
            ConnectionError::ApplicationClosed(close) => (
                close.error_code.into_inner(),
                String::from_utf8_lossy(&close.reason).to_string(),
            ),
            other => panic!("not closed by the hub: {other:?}"),
        }
    }

    /// Asserts the hub closes the connection with no detail: H1's "closed by the server" and an empty reason.
    pub async fn closed_with_no_detail(&self) {
        assert_eq!(self.closed().await, (CLOSE_BY_SERVER, String::new()));
    }

    /// Asserts the hub closes the connection with `not_paired` (H2 §5.5).
    pub async fn closed_not_paired(&self) {
        assert_eq!(
            self.closed().await,
            (
                u64::from(p2pc_proto::device::CLOSE_NOT_PAIRED),
                p2pc_proto::device::NOT_PAIRED.to_string()
            )
        );
    }

    /// Whether the connection is still open.
    pub fn is_open(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    /// Sends one `Pair` on a new stream and reads the answer. `None` means the hub closed without one.
    pub async fn pair(&self, ticket: &PairingTicket) -> Option<PairResponse> {
        self.pair_as(ticket, "Phone", "iOS Safari").await
    }

    pub async fn pair_as(&self, ticket: &PairingTicket, label: &str, platform: &str) -> Option<PairResponse> {
        let (mut send, mut recv) = self.conn.open_bi().await.ok()?;
        let msg = PairRequest::Pair {
            ticket: ticket.clone(),
            label: label.into(),
            platform: platform.into(),
        };
        // The hub may already have closed the connection: then there is no answer either.
        write_frame(&mut send, &msg).await.ok()?;
        read_answer(&mut recv).await
    }

    /// Sends raw bytes as the one frame of a pair connection and reads the answer.
    pub async fn pair_raw(&self, frame: &[u8]) -> Option<PairResponse> {
        let (mut send, mut recv) = self.conn.open_bi().await.ok()?;
        send.write_all(frame).await.ok()?;
        read_answer(&mut recv).await
    }

    /// A new stream of this connection.
    pub async fn stream(&self) -> HttpStream {
        let (send, recv) = self.conn.open_bi().await.expect("a stream");
        HttpStream {
            send,
            recv,
            buf: Vec::new(),
        }
    }

    /// One request on a new stream, read to the end of the stream. `Err` when the hub reset the stream or closed
    /// the connection instead of answering.
    pub async fn request(&self, method: &str, path: &str, headers: &str, body: &str) -> Result<HttpResp, String> {
        // The hub may have closed the connection: then there is no stream to ask on.
        let (send, recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        let mut s = HttpStream {
            send,
            recv,
            buf: Vec::new(),
        };
        s.send_request(method, path, &format!("Connection: close\r\n{headers}"), body)
            .await?;
        s.send.finish().map_err(|e| e.to_string())?;
        let out = tokio::time::timeout(WAIT, s.recv.read_to_end(1 << 20))
            .await
            .map_err(|_| "no answer".to_string())?
            .map_err(|e| e.to_string())?;
        HttpResp::parse(&out).ok_or_else(|| format!("not an HTTP response: {:?}", String::from_utf8_lossy(&out)))
    }

    pub async fn get(&self, path: &str) -> Result<HttpResp, String> {
        self.request("GET", path, "", "").await
    }

    pub async fn close(self) {
        self.conn.close(0u32.into(), b"bye");
        self.ep.close().await;
    }
}

async fn read_answer(recv: &mut RecvStream) -> Option<PairResponse> {
    tokio::time::timeout(WAIT, read_frame_with_limit::<PairResponse, _>(recv, PAIR_MAX_FRAME_LEN))
        .await
        .expect("no answer and no close")
        .ok()
        .flatten()
}

/// One device stream: an HTTP/1.1 connection to the hub's API.
pub struct HttpStream {
    pub send: SendStream,
    pub recv: RecvStream,
    buf: Vec<u8>,
}

/// An HTTP/1.1 response, as far as these tests read one.
#[derive(Debug)]
pub struct HttpResp {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl HttpResp {
    fn parse(raw: &[u8]) -> Option<Self> {
        let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&raw[..end]).to_string();
        let status = head.split(' ').nth(1)?.parse().ok()?;
        Some(Self {
            status,
            head,
            body: raw[end + 4..].to_vec(),
        })
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
    }

    fn content_length(&self) -> usize {
        self.head
            .lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse().ok())
            .unwrap_or(0)
    }
}

impl HttpStream {
    pub async fn send_request(&mut self, method: &str, path: &str, headers: &str, body: &str) -> Result<(), String> {
        let length = if body.is_empty() {
            String::new()
        } else {
            format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len())
        };
        let request = format!("{method} {path} HTTP/1.1\r\nHost: hub\r\n{headers}{length}\r\n{body}");
        self.send.write_all(request.as_bytes()).await.map_err(|e| e.to_string())
    }

    /// Reads one response: its head, then `Content-Length` bytes. `Err` when the stream ended first.
    pub async fn response(&mut self) -> Result<HttpResp, String> {
        let read = async {
            loop {
                if let Some(mut resp) = HttpResp::parse(&self.buf) {
                    let need = resp.content_length();
                    if resp.body.len() >= need {
                        let used = self.buf.len() - (resp.body.len() - need);
                        resp.body.truncate(need);
                        self.buf.drain(..used);
                        return Ok(resp);
                    }
                }
                let mut chunk = [0u8; 4096];
                match self.recv.read(&mut chunk).await {
                    Ok(Some(n)) => self.buf.extend_from_slice(&chunk[..n]),
                    Ok(None) => return Err("the stream ended".to_string()),
                    Err(e) => return Err(e.to_string()),
                }
            }
        };
        tokio::time::timeout(WAIT, read)
            .await
            .map_err(|_| "no answer".to_string())?
    }

    /// One keep-alive request and its response; the stream stays open, holding its slot of the device budget.
    pub async fn roundtrip(&mut self, method: &str, path: &str, body: &str) -> Result<HttpResp, String> {
        self.send_request(method, path, "", body).await?;
        self.response().await
    }

    /// Opens the stream for real (a QUIC stream exists for the hub once it carries data) and holds it: one
    /// keep-alive `GET /v1/whoami`, answered `200`.
    pub async fn hold(&mut self) {
        let r = self.roundtrip("GET", "/v1/whoami", "").await.expect("an answer");
        assert_eq!(r.status, 200, "{}", r.head);
    }

    /// Waits for the hub to end the stream (finished, reset or its connection closed). Bytes still buffered are
    /// dropped.
    pub async fn ended(&mut self) {
        let end = async {
            let mut chunk = [0u8; 4096];
            while let Ok(Some(_)) = self.recv.read(&mut chunk).await {}
        };
        tokio::time::timeout(WAIT, end).await.expect("the stream is still open");
    }

    /// Whether the hub reset this stream instead of serving it: sends a request and reads the outcome.
    pub async fn is_refused(&mut self) -> bool {
        let _ = self.send_request("GET", "/v1/whoami", "", "").await;
        self.response().await.is_err()
    }

    /// Raw bytes after an upgrade: writes `bytes` and reads exactly as many back (the test route echoes).
    pub async fn echo(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.send.write_all(bytes).await.map_err(|e| e.to_string())?;
        let mut back = vec![0u8; bytes.len()];
        let mut have = self.buf.len().min(back.len());
        back[..have].copy_from_slice(&self.buf[..have]);
        self.buf.drain(..have);
        let read = async {
            while have < back.len() {
                match self.recv.read(&mut back[have..]).await {
                    Ok(Some(n)) => have += n,
                    Ok(None) => return Err("the stream ended".to_string()),
                    Err(e) => return Err(e.to_string()),
                }
            }
            Ok(())
        };
        tokio::time::timeout(WAIT, read)
            .await
            .map_err(|_| "no echo".to_string())??;
        assert_eq!(back, bytes);
        Ok(())
    }
}

/// A raw HTTP/1.1 request over TCP to the REST listener, read to the end of the connection.
pub async fn tcp_request(addr: SocketAddr, request: String) -> HttpResp {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.expect("the REST listener");
    tcp.write_all(request.as_bytes()).await.expect("the request is sent");
    let mut out = Vec::new();
    tokio::time::timeout(WAIT, tcp.read_to_end(&mut out))
        .await
        .expect("no answer")
        .expect("the response is read");
    HttpResp::parse(&out).expect("an HTTP response")
}
