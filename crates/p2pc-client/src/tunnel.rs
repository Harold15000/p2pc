// SPDX-License-Identifier: Apache-2.0

//! The `p2pc/http/1` tunnel (spec §10, option B): the REST API of a server that opens no port, reached by its server
//! address `p2pc_srv_…` over iroh (QUIC, NAT traversal, relays).
//!
//! # How it works
//!
//! - One iroh endpoint and **one connection per process** to the server's NodeId, on ALPN `p2pc/http/1`. A lost
//!   connection is re-established on the next request, with a capped backoff between failed attempts (250 ms,
//!   doubling, at most 10 s). Each connection attempt has a 15 s timeout ([`TUNNEL_CONNECT_TIMEOUT`]).
//! - **Each HTTP request gets its own QUIC bidirectional stream**, which the server relays to its REST listener as
//!   one TCP connection. Requests carry `Connection: close`, so the server ends the stream as soon as the response
//!   is out and never holds a stream slot for an idle keep-alive connection.
//! - Everything above the stream is the client's usual code ([`crate::Client`]): the same headers, retries, size
//!   caps and errors as over TCP, and the key only in a sensitive `Authorization` header (SI-6).
//! - [`relay_tcp`] splices one local TCP connection onto one stream, for `p2pc proxy`.
//!
//! # Address hygiene (§10, experiment E4)
//!
//! The client endpoint is bound by **`p2pc_net`**, the Apache-2.0 crate the server and the agent share, so the three
//! ends follow the same rules in one implementation (this crate never depends on the AGPL server):
//!
//! - **no port mapping** (no UPnP or NAT-PMP): iroh is built without `portmapper`, and the builder disables it too;
//! - **no third-party discovery**: the `Minimal` preset with address lookup cleared; the server is reached with the
//!   relays of its address and, if given, direct address hints;
//! - **only the chosen addresses**: one socket per address that [`p2pc_proto::net::select_addresses`] picks (by
//!   default those of the default-route interface; never CGNAT/Tailscale, link-local or a container or VM bridge).
//!   An unspecified bind would advertise every interface. With nothing selected the endpoint is relay-only;
//! - **network changes**: long-running commands call [`Tunnel::watch_network`] ([`p2pc_net::watch_network`]) and bind
//!   a new endpoint when the selection changes; two failures in a row also re-bind, as a fallback.
//!
//! The relay sees only encrypted QUIC: the TLS session is end to end with the server's NodeId.

use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use p2pc_net::BindSpec;
use p2pc_proto::PROTOCOL_ALPN_HTTP;
use p2pc_proto::auth::ServerAddress;
use p2pc_proto::net::{AddressChange, DirectAddresses, Interface, SelectedAddr, select_addresses};
use reqwest::header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;
use url::Url;

use crate::client::Response;
use crate::error::{Error, LocalError, NetworkError, NetworkKind};

/// How long establishing the tunnel connection may take.
pub const TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The `Host` of requests sent through the tunnel. The server ignores it; HTTP/1.1 requires one.
pub const TUNNEL_HOST: &str = "p2pc-tunnel.invalid";
/// The first wait after a failed connection attempt. It doubles at every failure.
pub const RECONNECT_BASE: Duration = Duration::from_millis(250);
/// The longest wait between connection attempts.
pub const RECONNECT_MAX: Duration = Duration::from_secs(10);

/// The base URL the client builds request paths on. It never reaches the network: only its path and query do.
pub(crate) fn base_url() -> Url {
    #[allow(clippy::expect_used, reason = "a constant URL that always parses")]
    Url::parse(&format!("http://{TUNNEL_HOST}/")).expect("a valid constant URL")
}

/// How to reach a server through the tunnel.
#[derive(Debug, Clone)]
pub struct TunnelOptions {
    /// The server's address: its NodeId and relay hints.
    pub address: ServerAddress,
    /// Which local addresses the client endpoint binds, and so advertises (§10). Default: the default-route
    /// interface's. `DirectAddresses::None` is relay only.
    pub bind: DirectAddresses,
    /// Direct addresses of the server, when known (a server on the same LAN, tests). Usually empty: the relay
    /// introduces the two ends.
    pub server_addrs: Vec<SocketAddr>,
    /// The timeout of one connection attempt, and of opening a stream. Default 15 s.
    pub connect_timeout: Duration,
    /// The wait after a first failed connection attempt; it doubles at every further failure, up to
    /// [`RECONNECT_MAX`]. Default [`RECONNECT_BASE`] (250 ms).
    pub reconnect_base: Duration,
}

impl TunnelOptions {
    /// The defaults for `address`.
    #[must_use]
    pub fn new(address: ServerAddress) -> Self {
        Self {
            address,
            bind: DirectAddresses::DefaultRoute,
            server_addrs: Vec::new(),
            connect_timeout: TUNNEL_CONNECT_TIMEOUT,
            reconnect_base: RECONNECT_BASE,
        }
    }
}

/// What the client endpoint is bound with: the result of the §10 rules for one interface snapshot.
///
/// Only what varies is here. The rest is fixed by [`p2pc_net::bind_endpoint`], shared with the server and the agent:
/// **no port mapping** (iroh is compiled without its `portmapper` feature, which `scripts/check-iroh-features.sh` and a
/// test over `Cargo.lock` keep that way, and the builder disables it on top) and **no address lookup or publishing**
/// (the `Minimal` preset, and the lookup list cleared).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPlan {
    /// The relays: those of the server address, and nothing else.
    pub relays: Vec<Url>,
    /// One IP socket per address (port 0). Empty means relay only.
    pub bind: Vec<SelectedAddr>,
}

impl EndpointPlan {
    /// What [`p2pc_net::bind_endpoint`] binds for this plan: the plan's relays and sockets, and no ALPN (a client
    /// accepts no connection).
    #[must_use]
    pub fn bind_spec(&self) -> BindSpec {
        BindSpec {
            relay_mode: p2pc_net::relay_mode(self.relays.iter().cloned().map(RelayUrl::from)),
            addrs: self.bind.clone(),
            port: 0,
            alpns: Vec::new(),
        }
    }
}

/// The endpoint plan for `options` on a host with `interfaces`, whose default route goes through `default_route`.
#[must_use]
pub fn endpoint_plan(options: &TunnelOptions, interfaces: &[Interface], default_route: Option<&str>) -> EndpointPlan {
    EndpointPlan {
        relays: options.address.relays.clone(),
        bind: select_addresses(interfaces, default_route, &options.bind),
    }
}

/// Why a tunnel could not be set up.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TunnelError {
    /// The server address does not hold a valid NodeId or relay list.
    #[error("the server address is not valid")]
    InvalidAddress,
}

/// The tunnel to one server: one endpoint, one connection, a stream per request. Cloning shares them.
#[derive(Clone)]
pub struct Tunnel {
    inner: Arc<Inner>,
}

struct Inner {
    options: TunnelOptions,
    server: EndpointId,
    /// The endpoint and the connection. Held across a connection attempt, so that only one runs at a time.
    state: tokio::sync::Mutex<State>,
    /// The backoff. A plain mutex: a stream that proves its connection updates it from `poll_read`.
    backoff: std::sync::Mutex<Backoff>,
    /// Set by [`Tunnel::close`] before it takes the state lock, and never cleared: a connection task that a caller
    /// started and abandoned must not bind or connect after the tunnel was closed.
    closed: AtomicBool,
    /// Wakes the connection attempt that is in flight when the tunnel is closed, so `close()` does not wait it out.
    closing: tokio::sync::Notify,
}

#[derive(Default)]
struct State {
    endpoint: Option<Endpoint>,
    conn: Option<Live>,
    /// Connection attempts and endpoint binds so far (diagnostics and tests).
    attempts: u32,
    binds: u32,
}

/// The current connection, and whether a stream has worked on it yet.
struct Live {
    conn: Connection,
    proven: Arc<AtomicBool>,
}

#[derive(Default)]
struct Backoff {
    /// Failures in a row: attempts that failed, and connections that ended before any stream worked on them.
    failures: u32,
    /// No new attempt before this instant: until then a request fails at once with `last_error`.
    retry_at: Option<Instant>,
    /// The error of the last failure, as (kind, message).
    last_error: Option<(NetworkKind, String)>,
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunnel")
            .field("server", &self.inner.server.fmt_short().to_string())
            .finish_non_exhaustive()
    }
}

/// The wait after `failures` failed attempts in a row: `base` (250 ms by default), doubling, at most 10 s.
#[must_use]
pub fn reconnect_delay(base: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let factor = 1u32.checked_shl((failures - 1).min(16)).unwrap_or(u32::MAX);
    base.saturating_mul(factor).min(RECONNECT_MAX)
}

/// Failures in a row after which the endpoint is dropped and bound again, on the addresses the interfaces have now.
/// The fallback for a network change that [`Tunnel::watch_network`] did not see (or a command that does not watch).
pub const REBIND_AFTER_FAILURES: u32 = 2;

impl Inner {
    /// Records a failure: the backoff grows, and after [`REBIND_AFTER_FAILURES`] the endpoint is dropped.
    fn fail(&self, state: &mut State, error: &NetworkError) {
        let failures = {
            let mut backoff = lock(&self.backoff);
            backoff.failures = backoff.failures.saturating_add(1);
            backoff.retry_at = Some(Instant::now() + reconnect_delay(self.options.reconnect_base, backoff.failures));
            backoff.last_error = Some((error.kind(), error.message().to_string()));
            backoff.failures
        };
        if failures >= REBIND_AFTER_FAILURES {
            drop_endpoint(state, "repeated failures");
        }
    }

    /// The last error, while the backoff window is open.
    fn backing_off(&self) -> Option<NetworkError> {
        let backoff = lock(&self.backoff);
        match (backoff.retry_at, &backoff.last_error) {
            (Some(at), Some((kind, message))) if Instant::now() < at => Some(NetworkError::new(*kind, message.clone())),
            _ => None,
        }
    }

    /// A stream worked: the server is reachable and answers. The backoff starts over.
    fn proven(&self) {
        let mut backoff = lock(&self.backoff);
        *backoff = Backoff::default();
    }
}

fn closed_error() -> NetworkError {
    NetworkError::new(NetworkKind::Other, "tunnel closed")
}

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Drops the endpoint and its connection; the next attempt binds a new one. The old one is closed in the background
/// (a graceful close must not hold up requests), bounded like the server's.
fn drop_endpoint(state: &mut State, why: &str) {
    state.conn = None;
    if let Some(endpoint) = state.endpoint.take() {
        tracing::debug!(why, "tunnel: binding a new endpoint");
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.close()).await;
        });
    }
}

impl Tunnel {
    /// A tunnel to the server of `options`. Nothing is bound or connected until the first request.
    pub fn new(options: TunnelOptions) -> Result<Self, TunnelError> {
        options.address.validate().map_err(|_| TunnelError::InvalidAddress)?;
        let server: EndpointId = options
            .address
            .server
            .parse()
            .map_err(|_| TunnelError::InvalidAddress)?;
        Ok(Self {
            inner: Arc::new(Inner {
                options,
                server,
                state: tokio::sync::Mutex::new(State::default()),
                backoff: std::sync::Mutex::new(Backoff::default()),
                closed: AtomicBool::new(false),
                closing: tokio::sync::Notify::new(),
            }),
        })
    }

    /// The server's NodeId, shortened, for messages.
    #[must_use]
    pub fn server_short(&self) -> String {
        self.inner.server.fmt_short().to_string()
    }

    fn short(&self) -> String {
        self.server_short()
    }

    /// The live connection, or a new one.
    ///
    /// The work runs in a task of its own that every caller shares through the state lock: a caller that gives up
    /// (a timeout, a cancelled MCP tool call) does not cancel a connection attempt halfway, so its outcome, success
    /// or failure, is always recorded, and the callers behind it see it.
    ///
    /// A failure opens a backoff window. Within it every request fails **at once** with the last error, so that
    /// requests waiting for the tunnel do not each make a full attempt while the server is unreachable, and the server
    /// (which rate-limits new connections per NodeId) is not hammered. A connection counts as working only once a
    /// stream has received data on it: a server that accepts and then closes at once is a failure too.
    async fn connection(&self) -> Result<(Connection, Arc<AtomicBool>), NetworkError> {
        let this = self.clone();
        match tokio::spawn(async move { this.connection_task().await }).await {
            Ok(result) => result,
            Err(_) => Err(NetworkError::new(
                NetworkKind::Other,
                "the tunnel's connection task ended unexpectedly",
            )),
        }
    }

    async fn connection_task(&self) -> Result<(Connection, Arc<AtomicBool>), NetworkError> {
        let mut state = self.inner.state.lock().await;
        // After the lock: `close()` sets the flag first and then waits for this very lock.
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        if let Some(live) = &state.conn {
            if live.conn.close_reason().is_none() {
                return Ok((live.conn.clone(), live.proven.clone()));
            }
            let proven = live.proven.load(Ordering::Acquire);
            state.conn = None;
            if proven {
                tracing::debug!(server = %self.short(), "tunnel connection lost; reconnecting");
            } else {
                let error = NetworkError::new(
                    NetworkKind::Connect,
                    format!(
                        "the server {} closed the tunnel connection before answering",
                        self.short()
                    ),
                );
                self.inner.fail(&mut state, &error);
            }
        }
        if let Some(error) = self.inner.backing_off() {
            return Err(error);
        }
        state.attempts = state.attempts.saturating_add(1);
        match self.connect(&mut state).await {
            Ok(conn) => {
                // Not a reset of the backoff yet: that waits for a stream that works on this connection.
                let proven = Arc::new(AtomicBool::new(false));
                state.conn = Some(Live {
                    conn: conn.clone(),
                    proven: proven.clone(),
                });
                Ok((conn, proven))
            }
            Err(e) => {
                self.inner.fail(&mut state, &e);
                Err(e)
            }
        }
    }

    /// How many connection attempts were made, and how many times the endpoint was bound. For diagnostics and tests.
    pub async fn counters(&self) -> (u32, u32) {
        let state = self.inner.state.lock().await;
        (state.attempts, state.binds)
    }

    /// Drops the endpoint, and with it the connection: the next request binds a new endpoint on the addresses the
    /// interfaces have then, and reconnects. A request in flight on the old connection may fail once.
    pub async fn rebind(&self) {
        let mut state = self.inner.state.lock().await;
        drop_endpoint(&mut state, "the network changed");
    }

    /// Watches the network with [`p2pc_net::watch_network`] (the same watcher as the server and the agent) and calls
    /// [`Tunnel::rebind`] when the selected addresses change. For long-running commands (`p2pc proxy`, `p2pc mcp`).
    /// The watch stops when the returned handle is dropped.
    pub async fn watch_network(&self) -> NetworkWatch {
        let policy = self.inner.options.bind.clone();
        let initial = p2pc_net::current_selection(&policy).await;
        let (changes, mut received) = tokio::sync::mpsc::channel::<AddressChange>(4);
        let watcher = tokio::spawn(p2pc_net::watch_network(policy, initial, changes));
        let tunnel = self.clone();
        let rebinder = tokio::spawn(async move {
            while let Some(change) = received.recv().await {
                // Interface names only, never addresses (§10).
                tracing::info!(interfaces = %change, "network changed: the tunnel binds a new endpoint");
                tunnel.rebind().await;
            }
        });
        NetworkWatch {
            _tasks: [AbortOnDrop(watcher), AbortOnDrop(rebinder)],
        }
    }

    async fn connect(&self, state: &mut State) -> Result<Connection, NetworkError> {
        let endpoint = match &state.endpoint {
            Some(ep) => ep.clone(),
            None => {
                let ep = self.bind().await?;
                state.binds = state.binds.saturating_add(1);
                state.endpoint = Some(ep.clone());
                ep
            }
        };
        let mut addr = EndpointAddr::new(self.inner.server);
        for relay in &self.inner.options.address.relays {
            addr = addr.with_relay_url(RelayUrl::from(relay.clone()));
        }
        for hint in &self.inner.options.server_addrs {
            addr = addr.with_ip_addr(*hint);
        }
        let timeout = self.inner.options.connect_timeout;
        // Registered before the flag is read, so a `close()` between the two is not missed.
        let closing = self.inner.closing.notified();
        tokio::pin!(closing);
        closing.as_mut().enable();
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let attempt = tokio::time::timeout(timeout, endpoint.connect(addr, PROTOCOL_ALPN_HTTP));
        let outcome = tokio::select! {
            () = &mut closing => return Err(closed_error()),
            outcome = attempt => outcome,
        };
        match outcome {
            Ok(Ok(conn)) => {
                tracing::debug!(server = %self.short(), "tunnel connected");
                Ok(conn)
            }
            Ok(Err(e)) => Err(NetworkError::new(
                NetworkKind::Connect,
                format!("could not open the tunnel to server {}: {e}", self.short()),
            )),
            Err(_) => Err(NetworkError::new(
                NetworkKind::Timeout,
                format!(
                    "could not open the tunnel to server {} within {} s",
                    self.short(),
                    timeout.as_secs()
                ),
            )),
        }
    }

    /// Binds a fresh endpoint (a new, ephemeral identity) on the addresses the §10 rules select now.
    async fn bind(&self) -> Result<Endpoint, NetworkError> {
        let options = &self.inner.options;
        let (interfaces, default_route) = match options.bind {
            DirectAddresses::None => (Vec::new(), None),
            _ => p2pc_net::host_interfaces().await,
        };
        let plan = endpoint_plan(options, &interfaces, default_route.as_deref());
        p2pc_net::bind_endpoint(SecretKey::generate(), &plan.bind_spec())
            .await
            .map_err(|e| NetworkError::new(NetworkKind::Connect, e.to_string()))
    }

    /// Opens a new bidirectional stream to the server, connecting (or reconnecting) first if needed.
    pub async fn open_stream(&self) -> Result<TunnelStream, NetworkError> {
        let timeout = self.inner.options.connect_timeout;
        let mut last = None;
        // Twice: a connection that died quietly is only noticed when a stream is refused on it.
        for _ in 0..2 {
            let (conn, proven) = self.connection().await?;
            match tokio::time::timeout(timeout, conn.open_bi()).await {
                Ok(Ok((send, recv))) => {
                    return Ok(TunnelStream {
                        send,
                        recv,
                        proof: Proof {
                            inner: self.inner.clone(),
                            proven,
                        },
                    });
                }
                Ok(Err(e)) => last = Some(e.to_string()),
                Err(_) => {
                    return Err(NetworkError::new(
                        NetworkKind::Timeout,
                        "the server accepted no new stream in time (too many requests at once?)",
                    ));
                }
            }
        }
        Err(NetworkError::new(
            NetworkKind::Other,
            format!(
                "the tunnel connection was lost: {}",
                last.unwrap_or_else(|| "unknown reason".into())
            ),
        ))
    }

    /// Sends one request over its own stream and returns the response once its headers are in.
    pub(crate) async fn send(&self, request: TunnelRequest<'_>) -> Result<Response, Error> {
        let deadline = Instant::now() + request.timeout;
        let mut builder = hyper::Request::builder()
            .method(request.method)
            .uri(request.path_and_query);
        if let Some(headers) = builder.headers_mut() {
            *headers = request.headers;
            headers.insert(HOST, HeaderValue::from_static(TUNNEL_HOST));
            // One request per stream: the server ends the stream when the response is out.
            headers.insert(CONNECTION, HeaderValue::from_static("close"));
        }
        let body: BoxBody<Bytes, std::io::Error> = match request.upload {
            Some(file) => file.boxed(),
            None => Full::new(Bytes::from(request.body.unwrap_or_default()))
                .map_err(|never| match never {})
                .boxed(),
        };
        let http_request = builder
            .body(body)
            .map_err(|_| Error::Local(LocalError::new("the request is not valid")))?;
        let exchange = async {
            let stream = self.open_stream().await?;
            let io = hyper_util::rt::TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| NetworkError::new(NetworkKind::Other, format!("tunnel: {e}")))?;
            let driver = AbortOnDrop(tokio::spawn(async move {
                let _ = conn.await;
            }));
            let response = sender
                .send_request(http_request)
                .await
                .map_err(|e| NetworkError::new(NetworkKind::Other, format!("tunnel: {e}")))?;
            Ok::<_, NetworkError>((response, driver))
        };
        let (response, driver) = match tokio::time::timeout_at(deadline, exchange).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(Error::Network(NetworkError::new(
                    NetworkKind::Timeout,
                    "the request through the tunnel timed out",
                )));
            }
        };
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let body = TunnelBody {
            body: response.into_body(),
            deadline,
            read_timeout: request.read_timeout,
            _driver: driver,
        };
        Ok(Response::from_tunnel(status, content_length, body))
    }

    /// Sends a request that asks to switch protocols (`Connection: Upgrade`) on a stream of its own. On `101` the
    /// stream is handed over as it is: raw bytes both ways. Any other answer is returned as a response, for the caller
    /// to turn into the hub's error.
    pub(crate) async fn upgrade(&self, request: TunnelRequest<'_>) -> Result<Upgrade, Error> {
        let deadline = Instant::now() + request.timeout;
        let mut builder = hyper::Request::builder()
            .method(request.method)
            .uri(request.path_and_query);
        if let Some(headers) = builder.headers_mut() {
            *headers = request.headers;
            headers.insert(HOST, HeaderValue::from_static(TUNNEL_HOST));
        }
        let http_request = builder
            .body(Full::new(Bytes::new()))
            .map_err(|_| Error::Local(LocalError::new("the request is not valid")))?;
        let exchange = async {
            let stream = self.open_stream().await?;
            let io = hyper_util::rt::TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| NetworkError::new(NetworkKind::Other, format!("tunnel: {e}")))?;
            // `with_upgrades` keeps the connection task alive until the upgrade has been handed over.
            let driver = tokio::spawn(async move {
                let _ = conn.with_upgrades().await;
            });
            let driver = AbortOnDrop(driver);
            let response = sender
                .send_request(http_request)
                .await
                .map_err(|e| NetworkError::new(NetworkKind::Other, format!("tunnel: {e}")))?;
            Ok::<_, NetworkError>((response, driver))
        };
        let (response, driver) = match tokio::time::timeout_at(deadline, exchange).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(Error::Network(NetworkError::new(
                    NetworkKind::Timeout,
                    "the request through the tunnel timed out",
                )));
            }
        };
        if response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
            let upgraded = hyper::upgrade::on(response)
                .await
                .map_err(|e| Error::Network(NetworkError::new(NetworkKind::Other, format!("tunnel: {e}"))))?;
            // The connection task ends by itself once the upgrade is handed over; it must not be aborted with it.
            std::mem::forget(driver);
            return Ok(Upgrade::Upgraded(hyper_util::rt::TokioIo::new(upgraded)));
        }
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let body = TunnelBody {
            body: response.into_body(),
            deadline,
            read_timeout: request.read_timeout,
            _driver: driver,
        };
        Ok(Upgrade::Refused(Response::from_tunnel(status, content_length, body)))
    }

    /// Closes the connection and the endpoint, telling the server at once instead of letting it time out.
    ///
    /// The tunnel stays closed: a request made after this, or a connection task still waiting for the lock, fails
    /// with "tunnel closed" instead of binding a new endpoint. A connection attempt in flight is cut short.
    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.closing.notify_waiters();
        let mut state = self.inner.state.lock().await;
        if let Some(conn) = state.conn.take() {
            conn.conn.close(VarInt::from_u32(0), b"");
        }
        if let Some(endpoint) = state.endpoint.take() {
            endpoint.close().await;
        }
    }

    /// The local sockets of the endpoint, once it is bound (empty before the first request). For tests of the
    /// address hygiene.
    pub async fn bound_sockets(&self) -> Vec<SocketAddr> {
        let state = self.inner.state.lock().await;
        state.endpoint.as_ref().map(Endpoint::bound_sockets).unwrap_or_default()
    }
}

/// A request for [`Tunnel::send`], built by the client.
pub(crate) struct TunnelRequest<'a> {
    pub(crate) method: Method,
    pub(crate) path_and_query: &'a str,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Vec<u8>>,
    /// A file streamed as the body instead of `body` (a blob upload).
    pub(crate) upload: Option<crate::upload::FileBody>,
    /// The whole-request timeout.
    pub(crate) timeout: Duration,
    /// The longest wait for the next piece of the body.
    pub(crate) read_timeout: Duration,
}

/// What [`Tunnel::upgrade`] got.
pub(crate) enum Upgrade {
    /// `101`: the raw stream.
    Upgraded(hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>),
    /// Anything else, with its body unread.
    Refused(Response),
}

/// Aborts a task when dropped: the HTTP connection task of a request does not outlive its response.
#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The body of a response received through the tunnel.
pub(crate) struct TunnelBody {
    body: hyper::body::Incoming,
    deadline: Instant,
    read_timeout: Duration,
    _driver: AbortOnDrop,
}

impl TunnelBody {
    /// The next piece of the body, `None` at its end. Bounded by the request's deadline and the read timeout.
    pub(crate) async fn chunk(&mut self) -> Result<Option<Bytes>, NetworkError> {
        loop {
            let limit = (Instant::now() + self.read_timeout).min(self.deadline);
            match tokio::time::timeout_at(limit, self.body.frame()).await {
                Err(_) => {
                    return Err(NetworkError::new(
                        NetworkKind::Timeout,
                        "the response through the tunnel stalled or took too long",
                    ));
                }
                Ok(None) => return Ok(None),
                Ok(Some(Err(e))) => return Err(NetworkError::new(NetworkKind::Other, format!("tunnel: {e}"))),
                Ok(Some(Ok(frame))) => {
                    // Trailers carry nothing the API uses.
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }
}

/// One bidirectional QUIC stream of the tunnel, as a byte pipe.
pub struct TunnelStream {
    send: SendStream,
    recv: RecvStream,
    proof: Proof,
}

/// Marks the stream's connection as working when the first byte arrives from the server, which resets the backoff.
struct Proof {
    inner: Arc<Inner>,
    proven: Arc<AtomicBool>,
}

impl Proof {
    fn data_received(&self) {
        if !self.proven.swap(true, Ordering::AcqRel) {
            self.inner.proven();
        }
    }
}

/// Stops a background task when dropped: the network watch of [`Tunnel::watch_network`].
#[derive(Debug)]
pub struct NetworkWatch {
    _tasks: [AbortOnDrop; 2],
}

impl fmt::Debug for TunnelStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelStream").finish_non_exhaustive()
    }
}

impl TunnelStream {
    /// Abandons the stream both ways: the server's relay ends at once instead of waiting for its REST side.
    pub fn abort(mut self) {
        let _ = self.send.reset(VarInt::from_u32(0));
        let _ = self.recv.stop(VarInt::from_u32(0));
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.recv).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.proof.data_received();
        }
        polled
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// The limits of [`relay_tcp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// No byte either way for this long ends the relay. Default 5 minutes.
    pub idle: Duration,
    /// After the local client closes its side, how long the server's answer may stay silent before the relay ends.
    /// Default 2 s. A client that half-closes and then waits for a slow answer loses it after this; ordinary HTTP
    /// clients close only once they are done, and this frees the server's stream slot soon after.
    pub after_local_close: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(300),
            after_local_close: Duration::from_secs(2),
        }
    }
}

/// How a [`relay_tcp`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// The server ended the stream (its REST side closed the connection).
    ServerClosed,
    /// The local client went away.
    ClientClosed,
    /// Nothing moved for too long.
    Idle,
    /// The stream broke.
    StreamError,
}

/// Splices one local TCP connection onto one tunnel stream until either side is done, then resets the stream so the
/// server's relay ends at once. Bytes are copied as they are; nothing is added (in particular, never an API key).
pub async fn relay_tcp(stream: TunnelStream, tcp: tokio::net::TcpStream, limits: RelayLimits) -> RelayEnd {
    let _ = tcp.set_nodelay(true);
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let TunnelStream {
        mut send,
        mut recv,
        proof,
    } = stream;
    let mut up = vec![0u8; 16 * 1024];
    let mut down = vec![0u8; 16 * 1024];
    // Whether bytes still go up; once not, why: the client closed its side, or the upload failed.
    let mut uploading = true;
    let mut upload_failed = false;
    let end = loop {
        let quiet = if uploading {
            limits.idle
        } else {
            limits.after_local_close
        };
        tokio::select! {
            read = tcp_read.read(&mut up), if uploading => match read {
                // The client's end of stream is not passed on (the server does not pass it on either): its answer
                // may still come, for a short while.
                Ok(0) => uploading = false,
                Ok(n) => {
                    match tokio::time::timeout(limits.idle, send.write_all(&up[..n])).await {
                        Ok(Ok(())) => {}
                        // The server stopped reading (its REST side is done, for example). What it already sent
                        // back is still delivered: stop uploading and keep reading, as after a local close.
                        Ok(Err(_)) => {
                            uploading = false;
                            upload_failed = true;
                        }
                        Err(_) => break RelayEnd::Idle,
                    }
                }
                Err(_) => break RelayEnd::ClientClosed,
            },
            read = recv.read(&mut down) => match read {
                Ok(Some(n)) => {
                    proof.data_received();
                    match tokio::time::timeout(limits.idle, tcp_write.write_all(&down[..n])).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => break RelayEnd::ClientClosed,
                        Err(_) => break RelayEnd::Idle,
                    }
                }
                Ok(None) => {
                    let _ = tcp_write.shutdown().await;
                    break RelayEnd::ServerClosed;
                }
                Err(_) => break RelayEnd::StreamError,
            },
            () = tokio::time::sleep(quiet) => {
                break match (uploading, upload_failed) {
                    (true, _) => RelayEnd::Idle,
                    (false, true) => RelayEnd::StreamError,
                    (false, false) => RelayEnd::ClientClosed,
                };
            }
        }
    };
    let _ = send.reset(VarInt::from_u32(0));
    let _ = recv.stop(VarInt::from_u32(0));
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delays_double_up_to_the_cap() {
        let base = RECONNECT_BASE;
        assert_eq!(reconnect_delay(base, 0), Duration::ZERO);
        assert_eq!(reconnect_delay(base, 1), Duration::from_millis(250));
        assert_eq!(reconnect_delay(base, 2), Duration::from_millis(500));
        assert_eq!(reconnect_delay(base, 3), Duration::from_secs(1));
        assert_eq!(reconnect_delay(base, 7), Duration::from_secs(10));
        assert_eq!(reconnect_delay(base, u32::MAX), Duration::from_secs(10));
        assert_eq!(reconnect_delay(Duration::ZERO, 5), Duration::ZERO);
    }

    #[test]
    fn the_base_url_is_a_reserved_name() {
        assert_eq!(base_url().as_str(), "http://p2pc-tunnel.invalid/");
    }
}
