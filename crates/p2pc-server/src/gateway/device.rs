// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc/device/1` (H2 spec §5.5, §6.3, §10.5): the REST API for paired devices.
//!
//! Each bidirectional stream carries one HTTP/1.1 connection, served **in-process** by the device router
//! ([`crate::app::device_router`]) with a [`DeviceConnection`] attached to every request. Nothing is relayed to the
//! TCP listener, and the device principal is a Rust value this transport sets after iroh's TLS authenticated the
//! NodeId, so no header can make one (SI-H2-3).
//!
//! **Before the device check** any NodeId can complete the handshake, so that part is unauthenticated surface
//! (§6.3):
//! - the NodeId is looked up (one indexed lookup) right after the handshake, before any stream is accepted, and a
//!   NodeId that is not a live device is closed with `not_paired`, the same for a NodeId never paired, a revoked
//!   device and an expired one (§5.5);
//! - at most 32 connections at once have not passed the check, each checked within 5 s; beyond that, or when the
//!   check cannot be made in time, the connection is closed with no detail (never `not_paired`: the hub does not
//!   know);
//! - `not_paired` closes are counted per NodeId (10 a minute), and a NodeId over its limit is closed at connect
//!   without the lookup. There is no global failure bucket, so a live device that gets a slot always passes. Beyond
//!   the aggregate failure cap (§5.3) a close carries no detail and is not logged one by one. Every `not_paired`
//!   close is counted into one aggregated `auth_failed` audit row a minute (`subject_id` `device`).
//!
//! **After it**, the device budget (§6.3), apart from the REST connection cap and the tunnel budget:
//! - at most 2 connections per device, and `device_streams_per_device` streams across them;
//! - `device_stream_budget` streams in total, of which `device_stream_admin_reserve` only for `admin` devices
//!   ([`super::limits::DeviceBudget`]). A stream over a cap is reset with [`STREAM_REFUSED`]; the connection stays;
//! - the REST listener's slow-client limits on every stream (header, keep-alive idle; the body and whole-request
//!   limits are layers of the router), and `port_idle_s` on an upgraded connection ([`DeviceIo`]). A stream holds its
//!   slot for its whole life, an upgraded port connection or a log follow included.
//!
//! **A device is checked at connection time and on every request** ([`crate::auth::require_device`] re-reads its
//! row), and its connections are closed actively: `DELETE /v1/devices/{id}` and the 2 s liveness sweep
//! ([`crate::devices_api::sweep_once`]) close the [`DeviceSession`] this module registers, which closes the QUIC
//! connection with `not_paired` and so every stream of it, upgraded ones with traffic included (SI-H2-4).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::Service as _;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use p2pc_proto::api::Scope;
use p2pc_proto::device::{CLOSE_NOT_PAIRED, NOT_PAIRED};
use p2pc_proto::ids::DeviceId;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

use super::Inner;
use super::hub::CLOSE_BY_SERVER;
use super::limits::StreamSlot;
use crate::auth::DeviceConnection;
use crate::config::Config;
use crate::devices_api::DeviceSession;
use crate::store::devices::DeviceRow;
use crate::store::{self, StoreError};

/// Subject of the aggregated `auth_failed` audit rows of `not_paired` closes (H2 §5.6).
pub const DEVICE_FAILURE_SUBJECT: &str = "device";

/// QUIC stream error code of a device stream refused over the device stream budget (the same number as a
/// `p2pc/http/1` stream refused over the tunnel budget).
pub const STREAM_REFUSED: u32 = 1;

/// Closes with no detail.
fn close(conn: &Connection) {
    conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
}

/// Closes with `not_paired` (§5.5).
fn close_not_paired(conn: &Connection) {
    conn.close(VarInt::from_u32(CLOSE_NOT_PAIRED), NOT_PAIRED.as_bytes());
}

/// Handles one `p2pc/device/1` connection until it ends.
pub(super) async fn handle(inner: Arc<Inner>, conn: Connection) {
    let iroh_id = conn.remote_id().to_string();
    let now = inner.state.clock.now();
    // §6.3: a NodeId over its own `not_paired` limit is closed at connect, without the lookup. Only its own closes
    // count, and nobody else holds its key.
    let (key_ok, total_ok) = {
        let mut failures = inner.device_failures();
        (failures.key_allows(&iroh_id, now), failures.total_allows(now))
    };
    if !key_ok {
        // Beyond the aggregate cap, refusals are not logged one by one.
        if total_ok {
            tracing::debug!("device connection refused: not_paired rate limit of this NodeId");
        }
        return close(&conn);
    }
    // §6.3: at most this many connections at once that have not passed the check, apart from the other ALPNs.
    let Ok(unchecked) = inner.device_unchecked.clone().try_acquire_owned() else {
        return close(&conn);
    };
    // §6.3: the check, within its deadline, counted from the handshake. No stream is accepted before it passes.
    let deadline = Instant::now() + inner.limits.device_check_deadline;
    let Some(device) = check(&inner, &conn, &iroh_id, deadline).await else {
        return;
    };
    let device_id = device.device_id;
    // §6.3: from here the connection counts against its device's connections.
    let Some(_connection) = ConnectionSlot::take(&inner, device_id) else {
        tracing::debug!(%device_id, "device connection refused: too many for this device");
        return close(&conn);
    };
    // Registered, then checked once more: a revocation that committed between the first check and the registration
    // closed nothing of this connection, and is seen here. One after the registration closes it through the
    // session.
    let session = inner.state.devices.register(device_id);
    match check(&inner, &conn, &iroh_id, deadline).await {
        Some(again) if again.device_id == device_id => {}
        Some(_) => return close(&conn),
        None => return,
    }
    drop(unchecked);
    serve(&inner, &conn, &device, session).await;
}

/// The device check (§6.3): the live device of `iroh_id`, or `None` after closing the connection: with
/// `not_paired` for a NodeId that is not a live device, with no detail when the hub could not tell in time.
async fn check(inner: &Inner, conn: &Connection, iroh_id: &str, deadline: Instant) -> Option<DeviceRow> {
    match tokio::time::timeout_at(deadline, lookup(inner, iroh_id)).await {
        Ok(Ok(Some(device))) => Some(device),
        Ok(Ok(None)) => {
            not_paired(inner, conn, iroh_id);
            None
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "cannot look up a device");
            close(conn);
            None
        }
        Err(_) => {
            tracing::debug!("device connection closed: not checked within the deadline");
            close(conn);
            None
        }
    }
}

async fn lookup(inner: &Inner, iroh_id: &str) -> Result<Option<DeviceRow>, StoreError> {
    let mut conn = inner.state.db.acquire().await?;
    let now = inner.state.clock.now();
    store::devices::live_by_iroh_node_id(&mut conn, iroh_id, now).await
}

/// Closes a connection whose NodeId is not a live device, and counts the close: per NodeId, into the aggregate
/// failure cap and into the aggregated audit row. Beyond the aggregate cap the close carries no detail and is not
/// logged (§5.3).
fn not_paired(inner: &Inner, conn: &Connection, iroh_id: &str) {
    let now = inner.state.clock.now();
    // Counted against the NodeId even beyond the aggregate cap, so its own limit keeps applying.
    let within_total = inner.device_failures().record(iroh_id, now);
    record_audit(inner, now);
    if within_total {
        tracing::debug!("device connection closed: not_paired");
        close_not_paired(conn);
    } else {
        close(conn);
    }
}

fn record_audit(inner: &Inner, now: OffsetDateTime) {
    if let Some(owner) = inner.state.owner_account {
        inner
            .state
            .auth_failures
            .record(owner, DEVICE_FAILURE_SUBJECT.to_string(), now);
    }
}

/// One open connection of a device, counted in `Inner::device_connections` until it is dropped.
struct ConnectionSlot<'a> {
    inner: &'a Inner,
    device_id: DeviceId,
}

impl<'a> ConnectionSlot<'a> {
    fn take(inner: &'a Inner, device_id: DeviceId) -> Option<Self> {
        let mut map = inner.device_connections();
        let count = map.entry(device_id).or_insert(0);
        if *count >= inner.limits.device_connections_per_device {
            return None;
        }
        *count += 1;
        drop(map);
        Some(Self { inner, device_id })
    }
}

impl Drop for ConnectionSlot<'_> {
    fn drop(&mut self) {
        let mut map = self.inner.device_connections();
        if let Some(count) = map.get_mut(&self.device_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.device_id);
            }
        }
    }
}

/// Serves the streams of a checked device connection until the peer closes it or the device stops being live.
async fn serve(inner: &Inner, conn: &Connection, device: &DeviceRow, mut session: DeviceSession) {
    let device_id = device.device_id;
    let admin = device.scopes.contains(&Scope::Admin);
    // A connection never needs more streams than its device may hold; the budget below is what decides. The
    // protocol has no unidirectional stream.
    let per_device = u32::try_from(inner.device_budget.limits().streams_per_device).unwrap_or(u32::MAX);
    conn.set_max_concurrent_bi_streams(VarInt::from_u32(per_device));
    conn.set_max_concurrent_uni_streams(VarInt::from_u32(0));
    let limits = StreamLimits::of(&inner.state.config);
    let attach = DeviceConnection { device_id };
    loop {
        tokio::select! {
            biased;
            // §5.5: revoked (by `DELETE` or, seen by the liveness sweep, by another process) or past its expiry.
            // Closing the connection ends every stream of it, upgraded ones included.
            () = session.closed() => {
                tracing::info!(%device_id, "device connection closed: the device is no longer live");
                return close_not_paired(conn);
            }
            stream = conn.accept_bi() => {
                let Ok((mut send, mut recv)) = stream else { return };
                let Some(slot) = inner.device_budget.try_acquire(device_id, admin) else {
                    tracing::debug!(%device_id, "device stream refused: over the device stream budget");
                    let _ = send.reset(VarInt::from_u32(STREAM_REFUSED));
                    let _ = recv.stop(VarInt::from_u32(STREAM_REFUSED));
                    continue;
                };
                let io = DeviceIo::new(send, recv, limits, slot);
                tokio::spawn(serve_stream(io, inner.device_router.clone(), attach));
            }
        }
    }
}

/// Serves one device stream as an HTTP/1.1 connection, in-process, until it ends. Every request gets `attach`
/// before the router sees it.
async fn serve_stream(io: DeviceIo, router: Router, attach: DeviceConnection) {
    let state = io.state.clone();
    let router = TowerToHyperService::new(router);
    let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
        // The device principal: this value, set here, and nothing the request carries (SI-H2-3).
        request.extensions_mut().insert(attach);
        let busy = InFlight::enter(&state);
        let response = router.call(request);
        let state = state.clone();
        async move {
            let response = response.await;
            if let Ok(response) = &response
                && response.status() == StatusCode::SWITCHING_PROTOCOLS
            {
                // From here the stream is a port connection (§7.4): `port_idle_s` replaces the HTTP limits.
                state.upgraded.store(true, Ordering::Release);
            }
            drop(busy);
            response
        }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        // `DeviceIo` enforces the header limit, counted from a request's first byte, as `ConnIo` does on TCP.
        .header_read_timeout(None)
        .keep_alive(true)
        // A device may finish its side of the stream once its request is sent; the response is still written.
        .half_close(true);
    if let Err(e) = builder
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades()
        .await
    {
        tracing::debug!(error = %e, "device stream closed with an error");
    }
}

/// The time limits of a device stream (§6.3): the REST listener's, and `port_idle_s` once upgraded.
#[derive(Debug, Clone, Copy)]
struct StreamLimits {
    /// Time for a request head, from its first byte (or from the stream's start).
    header: Duration,
    /// Time between two requests on a keep-alive stream.
    idle: Duration,
    /// Time with no byte in either direction on an upgraded stream.
    port_idle: Duration,
}

impl StreamLimits {
    fn of(config: &Config) -> Self {
        Self {
            header: config.http.header_read_timeout(),
            idle: config.http.keepalive_idle(),
            port_idle: Duration::from_secs(u64::from(config.services.port_idle_s)),
        }
    }
}

/// What the service and the IO of one stream share: the requests being handled, and whether the stream was
/// upgraded.
#[derive(Debug, Default)]
struct StreamState {
    in_flight: AtomicUsize,
    /// Requests whose response head was produced, ever. The IO compares it with what it last saw, so it learns that
    /// a request ended even if it was never polled while that request was handled (hyper does not read the stream
    /// mid-request when half-close is allowed).
    finished: AtomicUsize,
    upgraded: AtomicBool,
    /// hyper may already be waiting on the stream while a request is handled. When the last request ends, this
    /// read must be woken, or the idle deadline would never be armed.
    busy_reader: Mutex<Option<Waker>>,
}

impl StreamState {
    fn park_reader(&self, waker: &Waker) {
        let mut slot = self.busy_reader.lock().unwrap_or_else(PoisonError::into_inner);
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    fn wake_reader(&self) {
        let waker = self.busy_reader.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// Counts a request as in flight until dropped.
struct InFlight(Arc<StreamState>);

impl InFlight {
    fn enter(state: &Arc<StreamState>) -> Self {
        state.in_flight.fetch_add(1, Ordering::AcqRel);
        Self(state.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.finished.fetch_add(1, Ordering::AcqRel);
        if self.0.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            // The stream goes idle (or was upgraded): let the pending read re-evaluate its deadline.
            self.0.wake_reader();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// A request head is due within the header limit.
    Head,
    /// A request is being handled: no deadline here (the router bounds the request).
    Busy,
    /// Between two requests: the next one is due within the keep-alive idle limit.
    Idle,
    /// Upgraded: closed after `port_idle` with no byte in either direction.
    Upgraded,
}

/// One device stream as the IO of an HTTP/1.1 connection, with its deadlines and its slot of the device budget.
///
/// It is [`crate::conn::ConnIo`]'s rule for a QUIC stream (head, busy, idle: see there for why hyper's own header
/// timer is not used), plus what only a device stream has: once the service answers `101`, the stream is a port
/// connection and the only limit is `port_idle` since the last byte read or written. The slot is given back when
/// this value is dropped, which for an upgraded stream is when whoever holds the upgraded connection drops it.
struct DeviceIo {
    send: SendStream,
    recv: RecvStream,
    state: Arc<StreamState>,
    limits: StreamLimits,
    phase: Phase,
    deadline: Pin<Box<Sleep>>,
    /// [`StreamState::finished`] as of the last poll.
    seen_finished: usize,
    /// Set when a deadline passed: every later read and write fails too, so both directions end.
    timed_out: bool,
    _slot: StreamSlot,
}

impl DeviceIo {
    /// A newly accepted stream: its first request head is due within the header limit.
    fn new(send: SendStream, recv: RecvStream, limits: StreamLimits, slot: StreamSlot) -> Self {
        Self {
            send,
            recv,
            state: Arc::default(),
            limits,
            phase: Phase::Head,
            deadline: Box::pin(tokio::time::sleep(limits.header)),
            seen_finished: 0,
            timed_out: false,
            _slot: slot,
        }
    }

    fn arm(&mut self, after: Duration) {
        self.deadline.as_mut().reset(Instant::now() + after);
    }

    /// Follows what the service did since the last poll: an upgrade, a request that began or ended.
    fn follow_service(&mut self) {
        if self.state.upgraded.load(Ordering::Acquire) {
            if self.phase != Phase::Upgraded {
                self.phase = Phase::Upgraded;
                self.arm(self.limits.port_idle);
            }
        } else if self.state.in_flight.load(Ordering::Acquire) > 0 {
            self.phase = Phase::Busy;
        } else {
            let finished = self.state.finished.load(Ordering::Acquire);
            if self.phase == Phase::Busy || finished != self.seen_finished {
                // A response is done since the last poll: wait for the next request, at most the idle limit.
                self.phase = Phase::Idle;
                self.arm(self.limits.idle);
            }
            self.seen_finished = finished;
        }
    }

    /// The deadline of the current phase passed, or it is not due yet.
    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        if self.deadline.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.timed_out = true;
        Poll::Ready(self.expired())
    }

    fn expired(&self) -> io::Error {
        let what = match self.phase {
            Phase::Head => "request headers not received in time",
            Phase::Upgraded => "port connection idle for too long",
            Phase::Busy | Phase::Idle => "keep-alive stream idle for too long",
        };
        io::Error::new(io::ErrorKind::TimedOut, what)
    }
}

impl AsyncRead for DeviceIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Err(this.expired()));
        }
        this.follow_service();
        let before = buf.filled().len();
        match AsyncRead::poll_read(Pin::new(&mut this.recv), cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    match this.phase {
                        // The first byte of the next request: its head is due within the header limit.
                        Phase::Idle => {
                            this.phase = Phase::Head;
                            this.arm(this.limits.header);
                        }
                        Phase::Upgraded => this.arm(this.limits.port_idle),
                        Phase::Head | Phase::Busy => {}
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if this.phase == Phase::Busy {
                    this.state.park_reader(cx.waker());
                    // The request may have ended between the check above and now.
                    if this.state.in_flight.load(Ordering::Acquire) == 0 {
                        cx.waker().wake_by_ref();
                    }
                    return Poll::Pending;
                }
                this.poll_deadline(cx).map(Err)
            }
        }
    }
}

impl AsyncWrite for DeviceIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Err(this.expired()));
        }
        this.follow_service();
        match AsyncWrite::poll_write(Pin::new(&mut this.send), cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 && this.phase == Phase::Upgraded {
                    this.arm(this.limits.port_idle);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // A write that cannot progress on an upgraded stream is no byte either: the idle limit applies. Before
            // an upgrade, the router's request limits bound a response the peer does not read.
            Poll::Pending if this.phase == Phase::Upgraded => this.poll_deadline(cx).map(Err),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
