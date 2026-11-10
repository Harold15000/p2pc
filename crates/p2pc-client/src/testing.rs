// SPDX-License-Identifier: Apache-2.0

//! A tiny in-process HTTP/1.1 mock server for tests (feature `test-util`).
//!
//! It binds `127.0.0.1:0`, records every request and answers with whatever a handler closure returns. It exists so
//! that the client, the CLI and later the MCP server are tested without the real server (which is AGPL and which
//! these Apache-2.0 crates never depend on, not even in tests). It speaks just enough HTTP for `reqwest`: keep-alive,
//! `Content-Length` bodies, no chunked requests, no TLS.
//!
//! The handler runs on a server thread, so it is plain synchronous code that can keep counters in a `Mutex`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test support: a panic here fails the test that uses it"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A request as the mock server received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// `GET`, `POST`, `DELETE`, …
    pub method: String,
    /// The path without the query, for example `/v1/jobs`.
    pub path: String,
    /// The raw query string, without the `?`.
    pub query: Option<String>,
    /// Header names (lowercase) and values.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// The value of a header, by lowercase name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The body parsed as JSON. Panics if it is not JSON.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("the request body is JSON")
    }

    /// `METHOD /path`, the usual route key.
    #[must_use]
    pub fn route(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

/// What a handler answers.
#[derive(Debug, Clone)]
pub struct MockResponse {
    /// HTTP status.
    pub status: u16,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl MockResponse {
    /// A JSON body.
    #[must_use]
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(value).expect("serializable"),
        }
    }

    /// A `application/problem+json` error.
    #[must_use]
    pub fn problem(status: u16, code: &str, detail: &str) -> Self {
        Self::problem_with(status, code, detail, &serde_json::json!([]))
    }

    /// A problem with per-field errors.
    #[must_use]
    pub fn problem_with(status: u16, code: &str, detail: &str, errors: &serde_json::Value) -> Self {
        let mut r = Self::json(
            status,
            &serde_json::json!({
                "type": "about:blank", "title": "Error", "status": status,
                "detail": detail, "code": code, "errors": errors,
            }),
        );
        r.headers[0].1 = "application/problem+json".into();
        r
    }

    /// No body (`204`, or a bare status).
    #[must_use]
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A plain-text body, for example a proxy's error page.
    #[must_use]
    pub fn text(status: u16, text: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: text.as_bytes().to_vec(),
        }
    }

    /// Makes the connection drop in the middle of the body: the response announces one more byte than it sends and
    /// then the server closes the connection, as a network that fails mid-stream does. The client sees a broken
    /// body, not a clean end. Only [`MockServer`] drops the connection; the tunnel mock sends the whole response.
    #[must_use]
    pub fn cut(self) -> Self {
        self.with_header(CUT_HEADER, "1")
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// The marker header of [`MockResponse::cut`]. It is not sent.
const CUT_HEADER: &str = "x-mock-cut";

type Handler = dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static;

/// A running mock server. It stops when dropped.
#[derive(Debug)]
pub struct MockServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
}

impl MockServer {
    /// Starts a server on `127.0.0.1` and an OS-chosen port. `handler` is called for every request, in the order
    /// requests arrive; the request is already recorded when it runs.
    pub fn start(handler: impl Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let addr = listener.local_addr().expect("local address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        {
            let (requests, stop) = (Arc::clone(&requests), Arc::clone(&stop));
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let (handler, requests) = (Arc::clone(&handler), Arc::clone(&requests));
                    thread::spawn(move || serve(stream, &handler, &requests));
                }
            });
        }
        Self { addr, requests, stop }
    }

    /// The base URL, `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request received so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("lock").clone()
    }

    /// The requests that match `METHOD /path`.
    #[must_use]
    pub fn requests_to(&self, route: &str) -> Vec<RecordedRequest> {
        self.requests().into_iter().filter(|r| r.route() == route).collect()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so its thread ends.
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve(stream: TcpStream, handler: &Arc<Handler>, requests: &Arc<Mutex<Vec<RecordedRequest>>>) {
    // A silent peer must not keep the thread alive forever.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    while let Some(request) = read_request(&mut reader) {
        // Refused before the handler, as the real server refuses it before anything else.
        if let Some(refusal) = refuse_fractional_timestamps(&request.body) {
            if write_response(&mut writer, &refusal).is_err() {
                return;
            }
            continue;
        }
        requests.lock().expect("lock").push(request.clone());
        let response = handler(&request);
        if write_response(&mut writer, &response).is_err() {
            return;
        }
        if response.headers.iter().any(|(k, _)| k == CUT_HEADER) {
            // Dropping the stream closes the connection with the body unfinished.
            return;
        }
    }
}

/// The real server's rule for every timestamp in a request body: whole seconds only (it stores Unix seconds and
/// refuses a fraction with `422 validation_failed`). Both mock servers apply it to every request before the handler,
/// so a client that sends `now + duration` straight from a clock fails its tests, as it would fail in production.
fn refuse_fractional_timestamps(body: &[u8]) -> Option<MockResponse> {
    fn walk(value: &serde_json::Value, path: &str) -> Option<String> {
        match value {
            serde_json::Value::String(text) => {
                let at = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()?;
                (at.nanosecond() != 0).then(|| path.to_string())
            }
            serde_json::Value::Array(items) => items
                .iter()
                .enumerate()
                .find_map(|(i, v)| walk(v, &format!("{path}[{i}]"))),
            serde_json::Value::Object(map) => map.iter().find_map(|(k, v)| {
                let field = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                walk(v, &field)
            }),
            _ => None,
        }
    }
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let field = walk(&value, "")?;
    Some(MockResponse::problem_with(
        422,
        "validation_failed",
        "the request is not valid",
        &serde_json::json!([{
            "field": field, "code": "invalid_format",
            "message": "must be a whole number of seconds (no fractional part)",
        }]),
    ))
}

fn read_request(reader: &mut BufReader<TcpStream>) -> Option<RecordedRequest> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let len = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    Some(RecordedRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn write_response(writer: &mut TcpStream, r: &MockResponse) -> std::io::Result<()> {
    let cut = r.headers.iter().any(|(k, _)| k == CUT_HEADER);
    let announced = r.body.len() + usize::from(cut);
    let mut head = format!("HTTP/1.1 {} Mock\r\ncontent-length: {announced}\r\n", r.status);
    for (k, v) in r.headers.iter().filter(|(k, _)| k != CUT_HEADER) {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    writer.write_all(head.as_bytes())?;
    writer.write_all(&r.body)?;
    writer.flush()
}

#[cfg(feature = "tunnel")]
pub use tunnel_mock::MockTunnelServer;

/// A fake `p2pc/http/1` server: an iroh endpoint on loopback, relays disabled, that serves HTTP/1.1 with hyper on
/// every bidirectional stream, as the real server's tunnel does (it relays each stream to its REST listener as one
/// TCP connection, and does not pass the client's end of stream on). It never depends on the server crate.
#[cfg(feature = "tunnel")]
mod tunnel_mock {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, Limited};
    use iroh::endpoint::{PortmapperConfig, presets};
    use iroh::{Endpoint, RelayMode, SecretKey};
    use p2pc_proto::PROTOCOL_ALPN_HTTP;
    use p2pc_proto::auth::ServerAddress;
    use tokio::io::{AsyncRead, ReadBuf};

    use super::{Handler, MockResponse, RecordedRequest};

    /// Shared with the server's thread.
    #[derive(Default)]
    struct Seen {
        requests: Vec<RecordedRequest>,
        /// NodeIds of every connection, in order.
        connections: Vec<String>,
        /// The connections, to close them from the test.
        live: Vec<iroh::endpoint::Connection>,
    }

    /// A running fake tunnel server. It stops when dropped.
    #[derive(Debug)]
    pub struct MockTunnelServer {
        address: ServerAddress,
        addrs: Vec<SocketAddr>,
        seen: Arc<Mutex<SeenBox>>,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    /// `Seen` behind a `Debug` that prints nothing (requests hold keys).
    struct SeenBox(Seen);

    impl std::fmt::Debug for SeenBox {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Seen")
        }
    }

    impl MockTunnelServer {
        /// Starts the server on its own thread. `handler` answers every request, as for [`super::MockServer`].
        pub fn start(handler: impl Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static) -> Self {
            let handler: Arc<Handler> = Arc::new(handler);
            let seen = Arc::new(Mutex::new(SeenBox(Seen::default())));
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let thread = {
                let seen = Arc::clone(&seen);
                std::thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("runtime");
                    runtime.block_on(serve(handler, seen, ready_tx, stopped));
                })
            };
            let (id, addrs) = ready_rx.recv().expect("the mock tunnel server started");
            Self {
                address: ServerAddress::new(id, Vec::new()),
                addrs,
                seen,
                stop: Some(stop),
                thread: Some(thread),
            }
        }

        /// The server address: its NodeId and no relays.
        #[must_use]
        pub fn address(&self) -> ServerAddress {
            self.address.clone()
        }

        /// The server address as text, `p2pc_srv_…`.
        #[must_use]
        pub fn address_text(&self) -> String {
            self.address.encode().expect("a valid address")
        }

        /// Its loopback sockets: the direct-address hints a client needs, since there is no relay.
        #[must_use]
        pub fn addrs(&self) -> Vec<SocketAddr> {
            self.addrs.clone()
        }

        /// Every request received so far, oldest first.
        #[must_use]
        pub fn requests(&self) -> Vec<RecordedRequest> {
            self.seen.lock().expect("lock").0.requests.clone()
        }

        /// The requests that match `METHOD /path`.
        #[must_use]
        pub fn requests_to(&self, route: &str) -> Vec<RecordedRequest> {
            self.requests().into_iter().filter(|r| r.route() == route).collect()
        }

        /// How many `p2pc/http/1` connections were accepted.
        #[must_use]
        pub fn connections(&self) -> usize {
            self.seen.lock().expect("lock").0.connections.len()
        }

        /// Closes every connection from the server's side, as a restart or a network change would.
        pub fn close_connections(&self) {
            let live = std::mem::take(&mut self.seen.lock().expect("lock").0.live);
            for conn in live {
                conn.close(0u32.into(), b"closed by the test");
            }
        }

        /// The distinct NodeIds that connected.
        #[must_use]
        pub fn peers(&self) -> HashSet<String> {
            self.seen.lock().expect("lock").0.connections.iter().cloned().collect()
        }
    }

    impl Drop for MockTunnelServer {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    async fn serve(
        handler: Arc<Handler>,
        seen: Arc<Mutex<SeenBox>>,
        ready: std::sync::mpsc::Sender<(String, Vec<SocketAddr>)>,
        mut stopped: tokio::sync::oneshot::Receiver<()>,
    ) {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![PROTOCOL_ALPN_HTTP.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .portmapper_config(PortmapperConfig::Disabled)
            .clear_address_lookup()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .expect("a loopback address")
            .bind()
            .await
            .expect("bind the mock tunnel endpoint");
        ready
            .send((endpoint.id().to_string(), endpoint.bound_sockets()))
            .expect("the test is waiting");
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let (handler, seen) = (Arc::clone(&handler), Arc::clone(&seen));
                    tokio::spawn(async move {
                        let Ok(conn) = incoming.await else { return };
                        if conn.alpn() != PROTOCOL_ALPN_HTTP {
                            return;
                        }
                        {
                            let mut seen = seen.lock().expect("lock");
                            seen.0.connections.push(conn.remote_id().to_string());
                            seen.0.live.push(conn.clone());
                        }
                        while let Ok((send, recv)) = conn.accept_bi().await {
                            let (handler, seen) = (Arc::clone(&handler), Arc::clone(&seen));
                            tokio::spawn(async move {
                                let io = hyper_util::rt::TokioIo::new(tokio::io::join(NoHalfClose(recv), send));
                                let service = hyper::service::service_fn(move |req| {
                                    let (handler, seen) = (Arc::clone(&handler), Arc::clone(&seen));
                                    async move { Ok::<_, std::convert::Infallible>(answer(req, &handler, &seen).await) }
                                });
                                let _ = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await;
                            });
                        }
                    });
                }
            }
        }
        endpoint.close().await;
    }

    async fn answer(
        req: hyper::Request<hyper::body::Incoming>,
        handler: &Arc<Handler>,
        seen: &Arc<Mutex<SeenBox>>,
    ) -> hyper::Response<Full<Bytes>> {
        let (parts, body) = req.into_parts();
        let body = Limited::new(body, 64 * 1024 * 1024)
            .collect()
            .await
            .map(|b| b.to_bytes().to_vec())
            .unwrap_or_default();
        let recorded = RecordedRequest {
            method: parts.method.to_string(),
            path: parts.uri.path().to_string(),
            query: parts.uri.query().map(str::to_string),
            headers: parts
                .headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body,
        };
        let r = match super::refuse_fractional_timestamps(&recorded.body) {
            Some(refusal) => refusal,
            None => {
                seen.lock().expect("lock").0.requests.push(recorded.clone());
                handler(&recorded)
            }
        };
        let mut builder = hyper::Response::builder().status(r.status);
        for (k, v) in &r.headers {
            builder = builder.header(k, v);
        }
        builder.body(Full::new(Bytes::from(r.body))).expect("a valid response")
    }

    /// Hides the client's end of stream from hyper, as the real tunnel does (hyper would otherwise drop a connection
    /// whose client half-closes, possibly before the response).
    struct NoHalfClose<R>(R);

    impl<R: AsyncRead + Unpin> AsyncRead for NoHalfClose<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            match Pin::new(&mut self.0).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => Poll::Pending,
                other => other,
            }
        }
    }
}

/// Ready-made API objects for mock answers, built from the real `p2pc-proto` types so they stay valid.
pub mod fixtures {
    use std::collections::BTreeMap;

    use p2pc_proto::api::{
        ApiKeyInfo, AuditEvent, AuditKind, Capacity, CpuInfo, GpuStatus, GpuStatusKind, Inventory, Job, JobSpec,
        JobSpecView, JobStatus, Node, NodeState, Platform, Resources, Scope, WhoAmI,
    };
    use p2pc_proto::ids::{AccountId, AuditEventId, JobId, KeyId, NodeId, ProjectId};
    use p2pc_proto::units::Units;
    use time::OffsetDateTime;

    /// A fixed instant, so fixtures are reproducible: 2023-11-14T22:13:20Z.
    #[must_use]
    pub fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid timestamp")
    }

    /// A job in `status`, with a spec that has one env variable and no files. `exit_code` is set as given.
    #[must_use]
    pub fn job(id: JobId, status: JobStatus, exit_code: Option<i32>) -> Job {
        let spec = JobSpec {
            name: Some("fixture".into()),
            image: "docker.io/library/python:3.12-slim".into(),
            command: vec!["python".into(), "-c".into(), "print(6*7)".into()],
            env: BTreeMap::from([("TOKEN".into(), "never-shown".into())]),
            files: Vec::new(),
            resources: Resources {
                cpu: 1.0,
                memory_mb: 2048,
                gpu: 0,
                disk_mb: 10_240,
            },
            timeout_s: 3600,
            egress: Default::default(),
            outputs: Default::default(),
            placement: Default::default(),
            retry: Default::default(),
            idempotency_key: None,
            kind: p2pc_proto::api::JobKind::Batch,
            service: None,
            volumes: Vec::new(),
            inputs: Vec::new(),
            template: None,
        };
        // A constructor, then the fields: a field added to the shared type does not break this (CONTRIBUTING rule 7).
        let mut job = Job::new(
            id,
            ProjectId::generate(),
            status,
            u32::from(status != JobStatus::Queued),
            JobSpecView::from_stored(&spec).expect("a valid spec"),
            Units::from_milli(1000),
            t0(),
        );
        job.name = Some("fixture".into());
        job.exit_code = exit_code;
        job.finished_at = status.is_terminal().then(t0);
        job
    }

    /// An online node with 4 vCPUs, 8 GiB and no GPU.
    #[must_use]
    pub fn node(id: NodeId, name: &str) -> Node {
        Node {
            id,
            name: name.into(),
            hostname: name.into(),
            state: NodeState::Online,
            draining: false,
            inventory: Inventory {
                hostname: name.into(),
                platform: Platform::Linux,
                cpu: CpuInfo {
                    model: "Test CPU".into(),
                    cores: 4,
                },
                memory_mb: 8192,
                os: "Ubuntu 24.04".into(),
                arch: "x86_64".into(),
                gpus: Vec::new(),
                gpu_status: GpuStatus {
                    status: GpuStatusKind::NotFound,
                    reason: None,
                },
                dxg: false,
                wsl2: None,
                sandbox: Vec::new(),
                offered: Capacity {
                    cpu: 4.0,
                    memory_mb: 8192,
                    gpu: 0,
                    ..Capacity::default()
                },
                disk_total_mb: None,
                agent_version: "0.1.0".into(),
            },
            free: Capacity {
                cpu: 3.5,
                memory_mb: 6144,
                gpu: 0,
                ..Capacity::default()
            },
            labels: BTreeMap::new(),
            last_seen: Some(t0()),
            created_at: t0(),
            approval: p2pc_proto::api::NodeApproval::Approved,
            enrolled_by: None,
            node_phrase: None,
        }
    }

    /// What `GET /v1/whoami` answers for an **unrestricted** key with the given scopes: no label, no cap, no image
    /// list, no expiry.
    ///
    /// Serialized, this **sends the four limit members as explicit `null`s** (`label`, `daily_unit_cap`,
    /// `allowed_images`, `expires_at`), exactly like the real server: `"daily_unit_cap": null` means *uncapped*
    /// (§7), and `p2pc mcp` relies on it. To model a server older than those fields, whose answer leaves the members
    /// out, use [`whoami_legacy`].
    #[must_use]
    pub fn whoami(key_id: KeyId, scopes: Vec<Scope>) -> WhoAmI {
        WhoAmI {
            account_id: AccountId::generate(),
            project_id: ProjectId::generate(),
            key_id,
            scopes,
            label: None,
            daily_unit_cap: None,
            allowed_images: None,
            expires_at: None,
            principal: None,
        }
    }

    /// What `GET /v1/whoami` answers for a **capped** key, like the one an AI agent gets for `p2pc mcp` (§7): labelled
    /// `agent`, with `daily_unit_cap`, a python-only image list and no expiry.
    #[must_use]
    pub fn whoami_capped(key_id: KeyId, scopes: Vec<Scope>, daily_unit_cap: Units) -> WhoAmI {
        WhoAmI {
            label: Some("agent".into()),
            daily_unit_cap: Some(daily_unit_cap),
            allowed_images: Some(vec!["docker.io/library/python:*".into()]),
            ..whoami(key_id, scopes)
        }
    }

    /// What `GET /v1/whoami` answers on a **legacy server**, one older than the limit fields: only `account_id`,
    /// `project_id`, `key_id` and `scopes`, with `label`, `daily_unit_cap`, `allowed_images` and `expires_at`
    /// **absent** (not `null`).
    ///
    /// The distinction matters: `p2pc mcp` reads the raw JSON and treats an absent `daily_unit_cap` as "the server did
    /// not report it" (refused unless `--allow-uncapped`), and a `null` one as "uncapped". [`whoami`] serializes the
    /// proto struct, whose `Option` fields always come out as `null` (the contract: the real server never omits
    /// them), so it cannot model the legacy case; this fixture removes the members from the JSON instead.
    #[must_use]
    pub fn whoami_legacy(key_id: KeyId, scopes: Vec<Scope>) -> serde_json::Value {
        let mut body = serde_json::to_value(whoami(key_id, scopes)).unwrap_or_default();
        if let Some(object) = body.as_object_mut() {
            for member in ["label", "daily_unit_cap", "allowed_images", "expires_at"] {
                object.remove(member);
            }
        }
        body
    }

    /// A live key with the `jobs:read` scope.
    #[must_use]
    pub fn key_info(id: KeyId) -> ApiKeyInfo {
        ApiKeyInfo {
            id,
            project_id: ProjectId::generate(),
            label: Some("ci".into()),
            scopes: vec![Scope::JobsRead],
            daily_unit_cap: None,
            allowed_images: None,
            created_at: t0(),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    /// A `key_created` audit event.
    #[must_use]
    pub fn audit_event() -> AuditEvent {
        AuditEvent {
            id: AuditEventId::generate(),
            at: t0(),
            kind: AuditKind::KeyCreated,
            actor_key_id: Some(KeyId::generate()),
            actor_device_id: None,
            subject_id: Some("subject".into()),
            detail: serde_json::Map::new(),
        }
    }
}
