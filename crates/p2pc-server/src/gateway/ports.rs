// SPDX-License-Identifier: AGPL-3.0-only

//! The port relay (H2 spec §6.1, §7.4, §12): hub-opened `PortOpen` streams toward the node that runs a service, and
//! the bytes relayed between such a stream and a client's upgraded connection.
//!
//! - **One stream per client connection** ([`open`]). The hub opens a bidirectional stream on the node's agent
//!   connection, sends `PortOpen{lease_id, epoch, port, conn_id}` and reads the agent's `PortOpenAck`. The lease is
//!   the job's current one, read when the stream is opened and read again after the agent's answer (SI-H2-6); the hub
//!   opens streams only toward agents that declared `service_jobs`, and at most 256 at once per agent connection.
//! - **Raw connections** ([`Plan::Raw`]): bytes are copied both ways until both sides ended. A clean end of one side
//!   is passed on as a clean end, an error as a reset.
//! - **Filtered connections** ([`Plan::Filtered`], every principal that is not `admin` on a template service): the
//!   hub reads **one** HTTP/1.1 request, checks it with [`crate::ports_api::filter`], and only then opens the stream
//!   and sends the request, re-serialized, with exactly its `Content-Length` bytes of body. A refused request is
//!   answered by the hub itself, inside the upgraded connection, and no stream is opened: nothing reaches the
//!   service, not even a connection. The response is relayed as it comes until the service closes; then the hub
//!   closes the connection. Whatever the client sends after its request is read and dropped.
//! - **Limits** ([`PortRelay::acquire`]): 64 open connections per service, 16 per principal per service, and for
//!   API-key clients (the TCP listener and `p2pc/http/1`) `port_conn_budget` in total. A device's connection holds a
//!   stream of the device budget instead (§6.3).
//! - **Idle.** A connection closes after `port_idle_s` with no byte in either direction, on every transport: the
//!   relay keeps the time itself, so it also ends a connection nobody is reading. A device's connections end when the
//!   device is revoked or expires (SI-H2-4): each registers with [`crate::devices_api::DeviceSessions`].
//! - **Accounting** (§7.4 "Idle accounting", §12). The relay moves the service's `last_activity_at` at most once
//!   every 10 s per service, when a byte is relayed or a connection closes, and adds the bytes and connections to
//!   `service_traffic` of the UTC day. Byte counts are never logged, and nothing here logs or keeps a byte of what
//!   the connections carry.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration as StdDuration;

use axum::http::StatusCode;
use iroh::endpoint::{RecvStream, SendStream, VarInt};
use p2pc_proto::api::{AllowedRoute, H2ErrorCode, Principal};
use p2pc_proto::ids::JobId;
use p2pc_proto::protocol::{
    HubStreamHeader, MAX_PORT_STREAMS_PER_LEASE, PortOpen, PortOpenAck, capability, port_open_reason,
    read_frame_with_limit, write_frame,
};
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use super::hub::PortStreamError;
use crate::app::AppState;
use crate::config::Config;
use crate::devices_api::DeviceSession;
use crate::error::ApiError;
use crate::ports_api::filter::{self, Refusal};
use crate::scheduler::OpenConnections;
use crate::store::ports::TrafficDelta;
use crate::store::{self, StoreError};

/// Most open port connections per principal per service (H2 §7.4).
pub const MAX_CONNECTIONS_PER_PRINCIPAL: u32 = 16;
/// Most open port connections per service (H2 §7.4), the agent's limit per lease.
pub const MAX_CONNECTIONS_PER_SERVICE: u32 = MAX_PORT_STREAMS_PER_LEASE as u32;
/// How often, at most, the relay moves a service's `last_activity_at` (H2 §7.4).
pub const ACTIVITY_INTERVAL: Duration = Duration::seconds(10);
/// How long `?wait_ready=true` waits for a service that is still `starting` (H2 §7.4).
pub const READY_WAIT: Duration = Duration::seconds(30);
/// Largest `PortOpenAck` frame the hub reads.
pub const ACK_FRAME_LIMIT: u32 = 4 * 1024;
/// QUIC error code of a port stream the hub abandons (a refused or failed open, a client that went away, an idle
/// limit).
pub const STREAM_RESET_BY_HUB: u32 = 0;
/// Bytes copied at a time, per direction of a connection.
const COPY_BUFFER: usize = 16 * 1024;
/// How long the hub keeps reading from a client after it answered it itself, so the answer is not lost to a reset.
const LINGER: StdDuration = StdDuration::from_secs(1);

/// The limits of the port relay. The defaults are the spec's; tests shorten the waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortLimits {
    /// Open connections per service.
    pub per_service: u32,
    /// Open connections per principal per service.
    pub per_principal: u32,
    /// A connection closes after this long with no byte in either direction (`services.port_idle_s`).
    pub idle: StdDuration,
    /// Time for the head of a filtered request (H1's header limit).
    pub head_timeout: StdDuration,
    /// Time for the body of a filtered request (H1's body limit).
    pub body_timeout: StdDuration,
    /// Time for the node to answer a `PortOpen`. The agent bounds its own dial below this.
    pub open_timeout: StdDuration,
    /// How long `?wait_ready=true` waits, on the hub's clock.
    pub ready_wait: Duration,
    /// How often a waiting connect looks at the service again.
    pub ready_poll: StdDuration,
    /// The least time between two writes of a service's `last_activity_at`.
    pub activity_interval: Duration,
}

impl PortLimits {
    /// The limits of `config`.
    #[must_use]
    pub fn of(config: &Config) -> Self {
        Self {
            per_service: MAX_CONNECTIONS_PER_SERVICE,
            per_principal: MAX_CONNECTIONS_PER_PRINCIPAL,
            idle: StdDuration::from_secs(u64::from(config.services.port_idle_s)),
            head_timeout: config.http.header_read_timeout(),
            body_timeout: config.http.body_read_timeout(),
            open_timeout: StdDuration::from_secs(45),
            ready_wait: READY_WAIT,
            ready_poll: StdDuration::from_millis(200),
            activity_interval: ACTIVITY_INTERVAL,
        }
    }
}

/// The state of the port relay, shared by every port connection. Cheap to clone.
#[derive(Debug, Clone)]
pub struct PortRelay {
    inner: Arc<RelayInner>,
}

#[derive(Debug)]
struct RelayInner {
    limits: RwLock<PortLimits>,
    /// The open connections per service, shared with the scheduler's idle cancel and `GET /v1/jobs/{id}`.
    connections: OpenConnections,
    /// The open connections of each principal, per service.
    principals: Mutex<HashMap<JobId, HashMap<Principal, u32>>>,
    /// When each service's `last_activity_at` was last written.
    activity: Mutex<HashMap<JobId, OffsetDateTime>>,
    /// `port_conn_budget`: the upgraded connections of API-key clients.
    key_budget: Arc<Semaphore>,
    next_conn_id: AtomicU64,
}

/// Why [`PortRelay::acquire`] gave no slot. Each is `429 too_many_connections`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SlotRefused {
    /// The service has its most open connections.
    #[error("this service already has its most open connections")]
    Service,
    /// The principal has its most open connections to the service.
    #[error("this principal already has its most open connections to this service")]
    Principal,
    /// `port_conn_budget` is in use.
    #[error("the hub's budget of port connections for API keys is in use")]
    Budget,
}

/// One open port connection, counted until dropped.
#[derive(Debug)]
pub struct PortSlot {
    relay: PortRelay,
    job_id: JobId,
    principal: Principal,
    _budget: Option<OwnedSemaphorePermit>,
}

impl Drop for PortSlot {
    fn drop(&mut self) {
        let inner = &self.relay.inner;
        let mut principals = inner.principals.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(of_job) = principals.get_mut(&self.job_id) {
            if let Some(n) = of_job.get_mut(&self.principal) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    of_job.remove(&self.principal);
                }
            }
            if of_job.is_empty() {
                principals.remove(&self.job_id);
            }
        }
        inner.connections.closed(self.job_id);
    }
}

impl PortRelay {
    /// The relay of a hub with `config`, counting its connections in `connections`.
    #[must_use]
    pub fn new(config: &Config, connections: OpenConnections) -> Self {
        Self::with_limits(PortLimits::of(config), config.port_conn_budget() as usize, connections)
    }

    /// A relay with given limits and `port_conn_budget`.
    #[must_use]
    pub fn with_limits(limits: PortLimits, key_budget: usize, connections: OpenConnections) -> Self {
        Self {
            inner: Arc::new(RelayInner {
                limits: RwLock::new(limits),
                connections,
                principals: Mutex::new(HashMap::new()),
                activity: Mutex::new(HashMap::new()),
                key_budget: Arc::new(Semaphore::new(key_budget)),
                next_conn_id: AtomicU64::new(1),
            }),
        }
    }

    /// The limits in force.
    #[must_use]
    pub fn limits(&self) -> PortLimits {
        *self.inner.limits.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the limits, for every clone of the relay. Tests shorten the waits with it.
    #[doc(hidden)]
    pub fn set_limits(&self, limits: PortLimits) {
        *self.inner.limits.write().unwrap_or_else(PoisonError::into_inner) = limits;
    }

    /// How many slots of `port_conn_budget` are free.
    #[must_use]
    pub fn key_budget_free(&self) -> usize {
        self.inner.key_budget.available_permits()
    }

    /// Counts a new connection of `principal` to `job_id` (H2 §7.4 "Limits"): at most 64 per service, 16 per
    /// principal per service and, with `key_client` (an API key, on the TCP listener or `p2pc/http/1`),
    /// `port_conn_budget` in total. The connection is counted until the slot is dropped.
    pub fn acquire(&self, job_id: JobId, principal: Principal, key_client: bool) -> Result<PortSlot, SlotRefused> {
        let limits = self.limits();
        let inner = &self.inner;
        // Under one lock, so two connects cannot both take the last place.
        let mut principals = inner.principals.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.connections.count(job_id) >= limits.per_service {
            return Err(SlotRefused::Service);
        }
        let held = principals
            .get(&job_id)
            .and_then(|of_job| of_job.get(&principal))
            .copied()
            .unwrap_or(0);
        if held >= limits.per_principal {
            return Err(SlotRefused::Principal);
        }
        let budget = if key_client {
            Some(
                inner
                    .key_budget
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| SlotRefused::Budget)?,
            )
        } else {
            None
        };
        *principals.entry(job_id).or_default().entry(principal).or_insert(0) += 1;
        inner.connections.opened(job_id);
        Ok(PortSlot {
            relay: self.clone(),
            job_id,
            principal,
            _budget: budget,
        })
    }

    /// Whether the `last_activity_at` of `job_id` is due for a write at `now`: none was made in the last
    /// `activity_interval`. A `true` counts as the write, so the caller makes it.
    fn activity_due(&self, job_id: JobId, now: OffsetDateTime) -> bool {
        let interval = self.limits().activity_interval;
        let mut written = self.inner.activity.lock().unwrap_or_else(PoisonError::into_inner);
        if written.get(&job_id).is_some_and(|at| (now - *at).abs() < interval) {
            return false;
        }
        // An entry older than the interval says nothing: dropping it keeps the map as small as the services with
        // traffic in the last interval.
        if written.len() >= 256 {
            written.retain(|_, at| (now - *at).abs() < interval);
        }
        written.insert(job_id, now);
        true
    }
}

/// Why no stream to a service's port could be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The service is not running on a current lease: `409 service_not_running`.
    NotRunning,
    /// The node's connection carries its most port streams: `429 too_many_connections`.
    TooManyStreams,
    /// The hub could not open the stream, or the agent refused it: `502 node_unreachable`, with why.
    Unreachable(String),
    /// The hub's database failed: `500`.
    Internal,
}

impl From<StoreError> for OpenError {
    fn from(e: StoreError) -> Self {
        tracing::error!(error = %e, "storage error while opening a port stream");
        OpenError::Internal
    }
}

impl From<sqlx::Error> for OpenError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::from(e).into()
    }
}

impl From<OpenError> for ApiError {
    fn from(e: OpenError) -> Self {
        match e {
            OpenError::NotRunning => service_not_running(),
            OpenError::TooManyStreams => ApiError::too_many_requests(
                H2ErrorCode::TooManyConnections.as_str(),
                "The node of this service already carries its most port connections.",
            ),
            OpenError::Unreachable(why) => {
                ApiError::with_status(StatusCode::BAD_GATEWAY, H2ErrorCode::NodeUnreachable.as_str(), why)
            }
            OpenError::Internal => ApiError::internal(),
        }
    }
}

/// `409 service_not_running`.
#[must_use]
pub fn service_not_running() -> ApiError {
    ApiError::conflict(H2ErrorCode::ServiceNotRunning.as_str(), "The service is not running.")
}

/// A stream the hub opened to a port of a service, after the agent's `PortOpenAck{ok: true}`. Dropped before it
/// ended cleanly, it is reset in both directions, so the agent drops its side of the connection too.
#[derive(Debug)]
pub struct PortStream {
    send: SendStream,
    recv: RecvStream,
    /// Whether both directions ended cleanly.
    ended: bool,
    _place: OwnedSemaphorePermit,
}

impl Drop for PortStream {
    fn drop(&mut self) {
        if !self.ended {
            // An error means that direction already ended.
            let _ = self.send.reset(VarInt::from_u32(STREAM_RESET_BY_HUB));
            let _ = self.recv.stop(VarInt::from_u32(STREAM_RESET_BY_HUB));
        }
    }
}

/// What the agent's refusal says, as one of the spec's codes; anything else an agent sends is not repeated.
fn refusal_reason(ack: &PortOpenAck) -> &'static str {
    port_open_reason::ALL
        .into_iter()
        .find(|known| ack.reason.as_deref() == Some(*known))
        .unwrap_or("refused")
}

/// Opens a stream to `port` of the service `job_id` on the node that runs it (H2 §6.1).
///
/// The `PortOpen` names the job's current lease, read here; when the agent has answered, the lease is read again, and
/// a stream for a lease that was replaced meanwhile is dropped (SI-H2-6).
pub async fn open(state: &AppState, job_id: JobId, port: u16) -> Result<PortStream, OpenError> {
    let limits = state.ports.limits();
    let lease = {
        let mut conn = state.db.acquire().await?;
        let lease = store::ports::current_lease(&mut conn, job_id)
            .await?
            .ok_or(OpenError::NotRunning)?;
        // §6.1 "Who opens what": only toward agents that declared `service_jobs`.
        let serves_ports = store::nodes::by_id(&mut conn, lease.node_id)
            .await?
            .is_some_and(|node| node.features.iter().any(|f| f == capability::SERVICE_JOBS));
        if !serves_ports {
            return Err(OpenError::Unreachable(
                "The node's agent does not serve service ports.".into(),
            ));
        }
        lease
    };
    let (conn, place) = state.hub.port_stream(lease.node_id).map_err(|e| match e {
        PortStreamError::NotConnected => OpenError::Unreachable("The node is not connected.".into()),
        PortStreamError::TooMany => OpenError::TooManyStreams,
    })?;
    let header = HubStreamHeader::PortOpen(PortOpen {
        lease_id: lease.id,
        epoch: lease.epoch,
        port,
        conn_id: state.ports.inner.next_conn_id.fetch_add(1, Ordering::Relaxed),
    });
    let deadline = Instant::now() + limits.open_timeout;
    let no_answer = || OpenError::Unreachable("The node did not answer in time.".into());
    let (send, recv) = tokio::time::timeout_at(deadline, conn.open_bi())
        .await
        .map_err(|_| no_answer())?
        .map_err(|_| OpenError::Unreachable("The connection to the node was lost.".into()))?;
    // From here the stream is reset unless it is handed over open.
    let mut stream = PortStream {
        send,
        recv,
        ended: false,
        _place: place,
    };
    let exchange = async {
        write_frame(&mut stream.send, &header).await.ok()?;
        read_frame_with_limit::<PortOpenAck, _>(&mut stream.recv, ACK_FRAME_LIMIT)
            .await
            .ok()
            .flatten()
    };
    let ack = tokio::time::timeout_at(deadline, exchange)
        .await
        .map_err(|_| no_answer())?
        .filter(|ack| ack.validate().is_ok())
        .ok_or_else(|| OpenError::Unreachable("The node did not answer the port connection.".into()))?;
    if !ack.ok {
        return Err(OpenError::Unreachable(format!(
            "The node refused the connection: {}.",
            refusal_reason(&ack)
        )));
    }
    // SI-H2-6, on the hub: the lease may have been replaced while the agent answered.
    let mut conn = state.db.acquire().await?;
    if !store::ports::still_current(&mut conn, lease.id, lease.epoch).await? {
        return Err(OpenError::NotRunning);
    }
    Ok(stream)
}

/// What a port connection does once it is upgraded.
#[derive(Debug)]
pub enum Plan {
    /// Raw bytes both ways, on a stream opened before the upgrade.
    Raw(PortStream),
    /// One HTTP request, forwarded only if these routes of the template allow it (H2 §7.4).
    Filtered(Vec<AllowedRoute>),
}

/// An upgraded port connection, with what it holds for its life.
#[derive(Debug)]
pub struct Accepted {
    /// The service.
    pub job_id: JobId,
    /// The port of the service.
    pub port: u16,
    /// Its place in the connection limits.
    pub slot: PortSlot,
    /// For a device: its registration, which tells the connection to close when the device is revoked or expires.
    /// `None` for an API key, whose connection is a TCP connection to the REST listener.
    pub session: Option<DeviceSession>,
    /// Raw, or filtered.
    pub plan: Plan,
}

/// Runs an upgraded port connection to its end: relays `client` as `accepted.plan` says, then records what is left
/// of its traffic and gives its slot back.
pub async fn serve<C>(state: AppState, client: C, accepted: Accepted)
where
    C: AsyncRead + AsyncWrite + Send + Unpin,
{
    let Accepted {
        job_id,
        port,
        slot,
        session,
        plan,
    } = accepted;
    let meter = Meter::new(&state, job_id);
    let idle = Idle::new(state.ports.limits().idle);
    // Only a TCP connection can lose an answer to a reset when it is closed with bytes unread.
    let linger = session.is_none();
    let relayed = async {
        match plan {
            Plan::Raw(stream) => {
                meter.opened();
                splice(client, stream, &meter, &idle).await;
            }
            Plan::Filtered(routes) => {
                let target = Target {
                    job_id,
                    port,
                    routes: &routes,
                    linger,
                };
                filtered(&state, client, &target, &meter, &idle).await;
            }
        }
    };
    match session {
        Some(mut session) => {
            tokio::select! {
                // SI-H2-4: the device was revoked or has expired. Dropping the relay resets the stream to the node.
                () = session.closed() => {
                    tracing::debug!(%job_id, "port connection closed: its device is no longer live");
                }
                () = relayed => {}
            }
        }
        None => relayed.await,
    }
    // Before the slot goes: the idle cancel must not see "no open connection" with the activity still unwritten.
    meter.close().await;
    drop(slot);
}

/// Bytes from the client to the service, or back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    In,
    Out,
}

/// The time since the last byte of a connection, in either direction.
#[derive(Debug)]
struct Idle {
    limit: StdDuration,
    last: Mutex<Instant>,
}

impl Idle {
    fn new(limit: StdDuration) -> Self {
        Self {
            limit,
            last: Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    /// Completes once `limit` has passed since the last byte.
    async fn expired(&self) {
        loop {
            let due = *self.last.lock().unwrap_or_else(PoisonError::into_inner) + self.limit;
            if Instant::now() >= due {
                return;
            }
            tokio::time::sleep_until(due).await;
        }
    }
}

/// The traffic of one connection not yet written, and the writes of its service's activity (H2 §7.4, §12).
#[derive(Debug)]
struct Meter {
    state: AppState,
    job_id: JobId,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    connections: AtomicU64,
    /// When this connection's traffic was last written.
    written: Mutex<OffsetDateTime>,
}

impl Meter {
    fn new(state: &AppState, job_id: JobId) -> Self {
        Self {
            state: state.clone(),
            job_id,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            written: Mutex::new(state.clock.now()),
        }
    }

    /// A stream to the port is open: one more connection in the day's traffic.
    fn opened(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// `n` bytes were relayed. At most once every `activity_interval` per service this moves `last_activity_at`,
    /// and at most as often per connection it writes the connection's traffic.
    async fn bytes(&self, direction: Direction, n: u64) {
        let counter = match direction {
            Direction::In => &self.bytes_in,
            Direction::Out => &self.bytes_out,
        };
        counter.fetch_add(n, Ordering::Relaxed);
        let now = self.state.clock.now();
        let activity = self.state.ports.activity_due(self.job_id, now);
        let interval = self.state.ports.limits().activity_interval;
        let traffic = (now - *self.written.lock().unwrap_or_else(PoisonError::into_inner)).abs() >= interval;
        if activity || traffic {
            self.write(now, activity).await;
        }
    }

    /// The connection is closing: the activity, if a write is due, and whatever traffic is left.
    async fn close(&self) {
        let now = self.state.clock.now();
        let activity = self.state.ports.activity_due(self.job_id, now);
        self.write(now, activity).await;
    }

    fn take(&self) -> TrafficDelta {
        TrafficDelta {
            bytes_in: self.bytes_in.swap(0, Ordering::Relaxed),
            bytes_out: self.bytes_out.swap(0, Ordering::Relaxed),
            connections: self.connections.swap(0, Ordering::Relaxed),
        }
    }

    async fn write(&self, now: OffsetDateTime, activity: bool) {
        let delta = self.take();
        if !activity && delta.is_empty() {
            return;
        }
        *self.written.lock().unwrap_or_else(PoisonError::into_inner) = now;
        if let Err(e) = self.store(now, activity, delta).await {
            // Kept for the next write. The counts themselves are never logged.
            self.bytes_in.fetch_add(delta.bytes_in, Ordering::Relaxed);
            self.bytes_out.fetch_add(delta.bytes_out, Ordering::Relaxed);
            self.connections.fetch_add(delta.connections, Ordering::Relaxed);
            tracing::debug!(error = %e, job_id = %self.job_id, "cannot record the activity of a service");
        }
    }

    async fn store(&self, now: OffsetDateTime, activity: bool, delta: TrafficDelta) -> Result<(), StoreError> {
        let mut tx = store::begin_immediate(&self.state.db).await?;
        if activity {
            store::ports::touch_activity(&mut tx, self.job_id, now).await?;
        }
        if !delta.is_empty() {
            store::ports::add_traffic(&mut tx, self.job_id, now, delta).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Copies `from` to `to` until `from` ends cleanly, counting the bytes.
async fn pump<R, W>(from: &mut R, to: &mut W, direction: Direction, meter: &Meter, idle: &Idle) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; COPY_BUFFER];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        idle.touch();
        to.write_all(&buf[..n]).await?;
        to.flush().await?;
        idle.touch();
        meter.bytes(direction, n as u64).await;
    }
}

/// A raw connection: copies both ways until both directions ended.
///
/// A clean end of one side ends the other side's direction cleanly (a stream finish toward the node, a half-close
/// toward the client) and the other direction goes on. An error on either side, or `port_idle_s` with no byte, ends
/// everything: the stream to the node is reset and the client's connection dropped.
async fn splice<C>(client: C, mut stream: PortStream, meter: &Meter, idle: &Idle)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_client, mut to_client) = tokio::io::split(client);
    let clean = {
        let (send, recv) = (&mut stream.send, &mut stream.recv);
        let up = async {
            pump(&mut from_client, &mut *send, Direction::In, meter, idle).await?;
            send.shutdown().await
        };
        let down = async {
            pump(&mut *recv, &mut to_client, Direction::Out, meter, idle).await?;
            to_client.shutdown().await
        };
        tokio::pin!(up, down);
        let (mut up_done, mut down_done) = (false, false);
        loop {
            if up_done && down_done {
                break true;
            }
            tokio::select! {
                ended = &mut up, if !up_done => match ended {
                    Ok(()) => up_done = true,
                    Err(_) => break false,
                },
                ended = &mut down, if !down_done => match ended {
                    Ok(()) => down_done = true,
                    Err(_) => break false,
                },
                () = idle.expired() => break false,
            }
        }
    };
    stream.ended = clean;
}

/// Why a filtered connection forwards nothing.
enum Rejected {
    /// The hub answers the client itself.
    Answer(ApiError),
    /// The client went away: there is nobody to answer.
    Gone,
}

/// The answer of the hub itself to a request the filter refused (H2 §7.4).
fn refused(refusal: Refusal) -> ApiError {
    match refusal {
        Refusal::BadRequest(why) => {
            ApiError::bad_request(INVALID_REQUEST, format!("The request is not forwarded: {why}."))
        }
        Refusal::HeadersTooLarge => ApiError::with_status(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            H2ErrorCode::HeadersTooLarge.as_str(),
            format!(
                "The request line and headers must fit in {} bytes and {} header lines.",
                filter::MAX_HEAD_BYTES,
                filter::MAX_HEADERS
            ),
        ),
        Refusal::TooLarge => ApiError::with_status(
            StatusCode::PAYLOAD_TOO_LARGE,
            TOO_LARGE,
            format!("The request body must be at most {} bytes.", filter::MAX_BODY_BYTES),
        ),
        Refusal::RouteNotAllowed => route_not_allowed(),
    }
}

/// The `code` of the hub's `400` to a request the filter never forwards (H2 §7.4).
pub const INVALID_REQUEST: &str = "invalid_request";
/// The `code` of the hub's `413` to a request body over 1 MiB (H2 §7.4).
pub const TOO_LARGE: &str = "too_large";

/// `403 route_not_allowed`.
#[must_use]
pub fn route_not_allowed() -> ApiError {
    ApiError::with_status(
        StatusCode::FORBIDDEN,
        H2ErrorCode::RouteNotAllowed.as_str(),
        "This template does not allow this request: only the method and path of one of its allowed routes is \
         forwarded.",
    )
}

/// `error` as an HTTP/1.1 response, for the hub's own answers inside an upgraded connection.
fn inner_response(error: &ApiError) -> Vec<u8> {
    let status = error.status();
    let body = serde_json::to_vec(error.problem()).unwrap_or_default();
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error"),
        crate::error::PROBLEM_JSON,
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out
}

/// Answers the client with `error` and ends the connection. With `linger` (a TCP connection), the hub then reads
/// what the client still sends for a moment, so that closing does not reset the connection before the client read
/// the answer.
async fn answer<C>(client: &mut C, error: &ApiError, limits: &PortLimits, linger: bool)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let response = inner_response(error);
    let written = tokio::time::timeout(limits.head_timeout, async {
        client.write_all(&response).await?;
        client.flush().await?;
        client.shutdown().await
    })
    .await;
    if linger && matches!(written, Ok(Ok(()))) {
        let drained = async {
            let mut sink = [0u8; 2048];
            while matches!(client.read(&mut sink).await, Ok(n) if n > 0) {}
        };
        let _ = tokio::time::timeout(LINGER, drained).await;
    }
}

/// Reads one request from `client` and admits it against `routes`: the parsed request and exactly its body.
async fn read_request<C>(
    client: &mut C,
    routes: &[AllowedRoute],
    port: u16,
    limits: &PortLimits,
) -> Result<(filter::Request, Vec<u8>), Rejected>
where
    C: AsyncRead + Unpin,
{
    let timed_out = || Rejected::Answer(ApiError::request_timeout());
    let mut buf = Vec::with_capacity(1024);
    let mut scanned = 0;
    let head = async {
        loop {
            match filter::head_end(&buf, &mut scanned) {
                Ok(Some(end)) => return Ok(end),
                Ok(None) => {}
                Err(refusal) => return Err(Rejected::Answer(refused(refusal))),
            }
            let mut chunk = [0u8; 2048];
            match client.read(&mut chunk).await {
                Ok(0) if buf.is_empty() => return Err(Rejected::Gone),
                Ok(0) => {
                    return Err(Rejected::Answer(refused(Refusal::BadRequest(
                        "the request ended before its head was complete",
                    ))));
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return Err(Rejected::Gone),
            }
        }
    };
    let end = tokio::time::timeout(limits.head_timeout, head)
        .await
        .map_err(|_| timed_out())??;
    let request = filter::admit(&buf[..end], routes, port).map_err(|refusal| Rejected::Answer(refused(refusal)))?;
    // `admit` bounds the body by 1 MiB.
    let need = usize::try_from(request.body_len()).map_err(|_| Rejected::Answer(refused(Refusal::TooLarge)))?;
    let mut body = buf.split_off(end);
    // Whatever came after the body is dropped here, and nothing after it is read into `body`.
    body.truncate(need);
    let rest = async {
        while body.len() < need {
            let mut chunk = [0u8; 8192];
            let want = (need - body.len()).min(chunk.len());
            match client.read(&mut chunk[..want]).await {
                Ok(0) => {
                    return Err(Rejected::Answer(refused(Refusal::BadRequest(
                        "the body is shorter than its Content-Length",
                    ))));
                }
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => return Err(Rejected::Gone),
            }
        }
        Ok(())
    };
    tokio::time::timeout(limits.body_timeout, rest)
        .await
        .map_err(|_| timed_out())??;
    Ok((request, body))
}

/// Where a filtered connection goes, and what it may send there.
struct Target<'a> {
    job_id: JobId,
    port: u16,
    /// The template's `allowed_routes` on `port`.
    routes: &'a [AllowedRoute],
    /// Whether the hub lingers after an answer of its own ([`answer`]).
    linger: bool,
}

/// A filtered connection (H2 §7.4): one request, forwarded re-serialized if the template's routes allow it, and its
/// response relayed until the service closes.
async fn filtered<C>(state: &AppState, mut client: C, target: &Target<'_>, meter: &Meter, idle: &Idle)
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let limits = state.ports.limits();
    let linger = target.linger;
    let (request, body) = match read_request(&mut client, target.routes, target.port, &limits).await {
        Ok(admitted) => admitted,
        Err(Rejected::Answer(error)) => return answer(&mut client, &error, &limits, linger).await,
        Err(Rejected::Gone) => return,
    };
    // Only now: a request the filter refused opens nothing on the node.
    let mut stream = match open(state, target.job_id, target.port).await {
        Ok(stream) => stream,
        Err(e) => return answer(&mut client, &e.into(), &limits, linger).await,
    };
    meter.opened();
    // The request the service gets: written from its parsed form, then exactly `Content-Length` bytes of body.
    let head = request.head();
    let sent = tokio::time::timeout(limits.body_timeout, async {
        stream.send.write_all(&head).await?;
        stream.send.write_all(&body).await?;
        stream.send.flush().await
    })
    .await;
    if !matches!(sent, Ok(Ok(()))) {
        let error = OpenError::Unreachable("The request could not be sent to the node.".into());
        return answer(&mut client, &error.into(), &limits, linger).await;
    }
    idle.touch();
    meter.bytes(Direction::In, (head.len() + body.len()) as u64).await;
    drop(body);
    // The stream toward the service stays open while the response comes: a server may take the end of the request
    // side for a client that went away.
    let (mut from_client, mut to_client) = tokio::io::split(client);
    let clean = {
        let response = pump(&mut stream.recv, &mut to_client, Direction::Out, meter, idle);
        // What the client still sends is read and dropped: nothing after the request's body is forwarded. A client
        // that ended its side still gets the response; one that broke the connection ends it.
        let client_gone = async {
            let mut sink = [0u8; 2048];
            loop {
                match from_client.read(&mut sink).await {
                    Ok(0) => std::future::pending::<()>().await,
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        };
        tokio::select! {
            ended = response => ended.is_ok(),
            () = client_gone => false,
            () = idle.expired() => false,
        }
    };
    if clean {
        // The service closed: the hub closes the connection (H2 §7.4).
        let _ = tokio::time::timeout(limits.head_timeout, to_client.shutdown()).await;
        let _ = stream.send.finish();
        stream.ended = true;
    }
}

#[cfg(test)]
mod tests {
    use p2pc_proto::ids::{DeviceId, KeyId};

    use super::*;

    fn limits() -> PortLimits {
        PortLimits {
            per_service: 3,
            per_principal: 2,
            idle: StdDuration::from_secs(600),
            head_timeout: StdDuration::from_secs(10),
            body_timeout: StdDuration::from_secs(30),
            open_timeout: StdDuration::from_secs(45),
            ready_wait: READY_WAIT,
            ready_poll: StdDuration::from_millis(200),
            activity_interval: ACTIVITY_INTERVAL,
        }
    }

    #[test]
    fn the_spec_limits() {
        assert_eq!(MAX_CONNECTIONS_PER_SERVICE, 64);
        assert_eq!(MAX_CONNECTIONS_PER_PRINCIPAL, 16);
        assert_eq!(ACTIVITY_INTERVAL, Duration::seconds(10));
        assert_eq!(READY_WAIT, Duration::seconds(30));
    }

    #[test]
    fn connections_are_capped_per_service_per_principal_and_for_api_keys() {
        let open = OpenConnections::default();
        let relay = PortRelay::with_limits(limits(), 2, open.clone());
        let (job, other) = (JobId::generate(), JobId::generate());
        let phone = Principal::Device(DeviceId::generate());
        let key = Principal::Key(KeyId::generate());
        // Two per principal per service; another service has its own count.
        let a = relay.acquire(job, phone, false).unwrap();
        let _b = relay.acquire(job, phone, false).unwrap();
        assert_eq!(relay.acquire(job, phone, false).unwrap_err(), SlotRefused::Principal);
        let _c = relay.acquire(other, phone, false).unwrap();
        // Three per service, whoever holds them; the scheduler's count is the same count.
        let _d = relay.acquire(job, key, true).unwrap();
        assert_eq!(open.count(job), 3);
        assert_eq!(relay.acquire(job, key, true).unwrap_err(), SlotRefused::Service);
        // A slot given back is free again, for the service and for its principal.
        drop(a);
        assert_eq!(open.count(job), 2);
        let _e = relay.acquire(job, phone, false).unwrap();
        // API keys share `port_conn_budget` over every service; devices never take from it.
        assert_eq!(relay.key_budget_free(), 1);
        let f = relay.acquire(other, key, true).unwrap();
        assert_eq!(relay.acquire(other, key, true).unwrap_err(), SlotRefused::Budget);
        assert_eq!(open.count(other), 2, "a refused connection is not counted");
        let _g = relay
            .acquire(other, Principal::Device(DeviceId::generate()), false)
            .unwrap();
        drop(f);
        assert_eq!(relay.key_budget_free(), 1);
        // The hub's own model pull counts in the scheduler's count, so it takes a place of the service too.
        let third = JobId::generate();
        open.opened(third);
        open.opened(third);
        let _h = relay.acquire(third, key, false).unwrap();
        assert_eq!(relay.acquire(third, phone, false).unwrap_err(), SlotRefused::Service);
    }

    #[test]
    fn the_activity_of_a_service_is_written_at_most_once_per_interval() {
        let relay = PortRelay::with_limits(limits(), 1, OpenConnections::default());
        let (job, other) = (JobId::generate(), JobId::generate());
        let t = OffsetDateTime::UNIX_EPOCH + Duration::days(20_000);
        assert!(relay.activity_due(job, t));
        assert!(!relay.activity_due(job, t));
        assert!(!relay.activity_due(job, t + Duration::seconds(9)));
        assert!(relay.activity_due(other, t + Duration::seconds(9)), "per service");
        assert!(relay.activity_due(job, t + Duration::seconds(10)));
        assert!(!relay.activity_due(job, t + Duration::seconds(19)));
        assert!(relay.activity_due(job, t + Duration::seconds(20)));
        // The map does not grow with the services that had traffic long ago.
        for _ in 0..1000 {
            assert!(relay.activity_due(JobId::generate(), t + Duration::seconds(20)));
        }
        assert!(relay.activity_due(JobId::generate(), t + Duration::seconds(60)));
        assert!(relay.inner.activity.lock().unwrap().len() <= 256);
    }

    #[test]
    fn the_hubs_own_answers_are_complete_http_responses() {
        let text = String::from_utf8(inner_response(&route_not_allowed())).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
        assert!(head.contains("Content-Type: application/problem+json\r\n"));
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(head.ends_with("Connection: close"));
        let problem: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(problem["code"], "route_not_allowed");
        assert_eq!(problem["status"], 403);
        for (refusal, status, code) in [
            (Refusal::BadRequest("x"), 400, "invalid_request"),
            (Refusal::HeadersTooLarge, 431, "headers_too_large"),
            (Refusal::TooLarge, 413, "too_large"),
            (Refusal::RouteNotAllowed, 403, "route_not_allowed"),
        ] {
            let error = refused(refusal);
            assert_eq!((error.status().as_u16(), error.problem().code.as_str()), (status, code));
        }
        let error: ApiError = OpenError::Unreachable("The node is not connected.".into()).into();
        assert_eq!(
            (error.status().as_u16(), error.problem().code.as_str()),
            (502, "node_unreachable")
        );
        assert_eq!(
            ApiError::from(OpenError::NotRunning).problem().code,
            "service_not_running"
        );
        assert_eq!(ApiError::from(OpenError::TooManyStreams).status().as_u16(), 429);
    }

    #[test]
    fn an_agents_refusal_is_repeated_only_as_a_known_code() {
        for known in port_open_reason::ALL {
            assert_eq!(refusal_reason(&PortOpenAck::refused(known)), known);
        }
        assert_eq!(refusal_reason(&PortOpenAck::refused("<script>")), "refused");
    }
}
