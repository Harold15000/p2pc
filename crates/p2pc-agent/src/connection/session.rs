// SPDX-License-Identifier: Apache-2.0

//! One control connection, from `Hello` to its end (§6).
//!
//! 1. **Handshake.** `Hello{agent_version, features, inventory, running}` right after the dial, with the
//!    inventory the daemon detected just before it (fresh for every connection) and the supervisor's leases. The first answer must be `Welcome` (or `Error`), within [`WELCOME_TIMEOUT`].
//!    - `account_id` must be the enrolled owner (SI-1). Otherwise the connection is closed, an error is logged, and
//!      the daemon backs off: no lease is ever taken from it.
//!    - `agent_lease_ttl_s + 10 <= lease_ttl_s`, otherwise the agent's own timer is lowered to `lease_ttl_s - 10`,
//!      with a warning (SI-13).
//! 2. **Heartbeats** every `heartbeat_interval_s` (at most a third of the agent's lease timer, so the acks can keep
//!    it alive): `Heartbeat{seq, load, running}`, `seq` increasing. `running` lists the leases that still hold
//!    resources ([`LeaseSupervisor::holding`]), not `Hello`'s list. One more heartbeat goes out at once each time a
//!    lease frees its resources ([`LeaseSupervisor::released`]), with the same `seq` counter (§6, amended 2026-11-08).
//! 3. **Inventory** re-detected every 10 minutes on its own task; `InventoryUpdate` only when the normalized result
//!    changed.
//! 4. **Every server message** restarts the lease timer ([`super::watchdog`]), then is routed:
//!    - `Lease`: owner check (`not_owner`), strict job parse (`invalid_job`, the connection stays), then the
//!      [`LeaseHandler`]; at most [`MAX_PENDING_DECISIONS`] at once, each answered within [`DECISION_TIMEOUT`]. The
//!      decisions belong to the session: when it ends, those still in progress are aborted, and waited for, before
//!      [`run`] returns, so none outlives it or runs after the daemon's `stop_all` (T05b review, carry-over to T10a);
//!    - `Cancel` to the handler; `Drain` and `Resume` to the [`LeaseSupervisor`];
//!    - `Error{not_enrolled}` and `Error{agent_too_old}` end the agent; other errors are logged;
//!    - `Unknown` (a newer server's message): logged at debug level and ignored.
//!
//! Once welcomed, the session publishes its job queue and stream opener on the [`Uplink`], for the jobs' own messages
//! and uploads (T10a); it withdraws them when it ends.
//!
//! **Service ports** (H2 §6.1). A session with a [`PortOpener`] (the node's ingress bridge, [`Shared::ports`])
//! declares the `service_jobs` capability in `Hello.features`, accepts leases of service jobs, and, once welcomed,
//! serves the streams the server opens on the connection ([`super::streams`]) until it ends. Without one it is an H1
//! session: no capability, service leases are `invalid_job`, and no stream of the server is ever accepted.
//!
//! **Control frames first** (T10a review, P2-1). Job messages (`JobStarted`, `LogChunk`, `JobFinished`) have their
//! own queue of [`JOB_QUEUE`] frames, and the writer always takes a waiting control frame (heartbeat, lease answer,
//! inventory update) before the next job frame: a job logging at full speed delays a heartbeat by at most the frame
//! being written. The loop never waits to queue a control frame either (`try_send`): inbound frames, `Cancel`
//! included, are always read. A control frame that finds its queue full is dropped with a warning, never silently.
//!
//! A frame that is oversized, malformed or invalid closes the connection (SI-10). So does a server that stays
//! silent for [`silence_limit`]: the daemon then reconnects at once.
//!
//! Reading and writing run on their own tasks, through bounded queues: the codec is not cancellation-safe, and a
//! slow peer gets back-pressure, never unbounded buffering.

use std::sync::Arc;
use std::time::Duration;

use p2pc_proto::api::Inventory;
use p2pc_proto::ids::AccountId;
use p2pc_proto::net::{AddressChange, SelectedAddr};
use p2pc_proto::protocol::{
    AGENT_LEASE_TTL_MARGIN_S, AgentMsg, FrameError, LeaseRejectReason, MAX_FRAME_LEN, ServerMsg, capability,
    error_code, read_frame, write_frame,
};
use p2pc_proto::validate::{H2Features, Limits};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};

use super::BoxFuture;
use super::lease::{LeaseDecision, LeaseHandler, LeaseOffer, LeaseSupervisor};
use super::load::LoadSource;
use super::streams::{self, PortOpener, StreamAcceptor};
use super::transport::{Link, StreamOpener};
use super::uplink::{Acks, JOB_QUEUE, JobFrame, Port, Uplink};
use super::watchdog::Watchdog;
use crate::inventory::AGENT_VERSION;

/// How long the server has to answer `Hello`.
pub const WELCOME_TIMEOUT: Duration = Duration::from_secs(15);
/// Longest write of one frame. A peer that does not read for this long is dropped.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the inventory is detected again (§6).
pub const INVENTORY_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Most lease decisions in progress at once; beyond it a lease is refused with `insufficient_capacity`.
pub const MAX_PENDING_DECISIONS: usize = 16;
/// The handler's budget for one decision: under the server's 10 s (§6 "Two-phase assignment").
pub const DECISION_TIMEOUT: Duration = Duration::from_secs(8);
/// The budget of `cancel`, `drain` and `resume`, which run on the connection's task.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Frames queued in each direction.
const QUEUE: usize = 64;
/// How long the end of a session waits for queued frames to go out.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Where `Hello` and the periodic re-detection get the inventory.
pub trait InventorySource: Send + Sync + std::fmt::Debug + 'static {
    /// A fresh detection. Never cached.
    fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>>;
}

/// What tells a session the network changed (T10l).
#[derive(Debug)]
pub struct NetworkEvents {
    /// The network watcher's new selections of addresses.
    pub changes: mpsc::Receiver<AddressChange>,
    /// The connector's request to bind its endpoint again with the same addresses ([`super::Connector::rebind_signal`]).
    pub rebind: Arc<Notify>,
}

/// Everything a session needs; owned by the daemon and shared by its sessions.
#[derive(Debug, Clone)]
pub struct Shared {
    /// The enrolled owner, from `[server] account_id` (SI-1).
    pub owner: AccountId,
    /// `agent_lease_ttl_s` from the config.
    pub agent_lease_ttl: Duration,
    /// The lease timer.
    pub watchdog: Watchdog,
    /// Running leases, drain, stop.
    pub supervisor: Arc<dyn LeaseSupervisor>,
    /// Leases and cancels.
    pub handler: Arc<dyn LeaseHandler>,
    /// The inventory.
    pub inventory: Arc<dyn InventorySource>,
    /// The heartbeats' load.
    pub load: Arc<dyn LoadSource>,
    /// How often to re-detect the inventory.
    pub inventory_interval: Duration,
    /// Bounds the lease decisions in progress.
    pub decisions: Arc<Semaphore>,
    /// Where the welcomed session publishes its outbox and streams for the jobs (T10a).
    pub uplink: Uplink,
    /// Opens the service ports the server asks for with `PortOpen` streams (H2 §6.1): the node's ingress bridge.
    /// `None` is an H1 agent: it declares no `service_jobs`, takes no service lease and accepts no stream.
    pub ports: Option<Arc<dyn PortOpener>>,
}

impl Shared {
    /// `Hello.features`: `service_jobs` exactly when this node can serve the ports of a service.
    #[must_use]
    pub fn features(&self) -> Vec<String> {
        match self.ports {
            Some(_) => vec![capability::SERVICE_JOBS.to_string()],
            None => Vec::new(),
        }
    }

    /// The limits a lease's job is parsed with: the agent's, with service jobs understood exactly when the
    /// capability is declared (H2 §6.1: a job this agent does not understand is `invalid_job`).
    fn lease_limits(&self) -> Limits {
        Limits {
            h2: H2Features {
                services: self.ports.is_some(),
                ..H2Features::default()
            },
            ..Limits::agent()
        }
    }
}

/// What the `Welcome` said, once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcomed {
    /// The agent-side lease timer in force for this connection.
    pub agent_lease_ttl: Duration,
    /// The heartbeat interval in force.
    pub heartbeat_interval: Duration,
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// SIGTERM or SIGINT.
    Shutdown,
    /// The network changed: re-bind to these addresses and reconnect at once.
    AddressesChanged(Vec<SelectedAddr>),
    /// The connector asked for a new endpoint with the same addresses (T10l): re-bind and reconnect at once.
    Rebind,
    /// The connection dropped, the server went silent, or a frame was bad. `welcomed` tells whether the
    /// `Welcome` had arrived (the backoff starts again from 1 s then).
    Lost {
        /// Whether a `Welcome` was received on this connection.
        welcomed: bool,
    },
    /// The `Welcome` named another account than the owner (SI-1).
    WrongOwner,
    /// `Error{not_enrolled}`.
    NotEnrolled,
    /// `Error{agent_too_old}`.
    AgentTooOld,
    /// Something on our side failed before `Hello` (for example the inventory).
    Failed(String),
}

/// How long a welcomed connection may stay silent before it is dropped: three heartbeats (each gets an ack), at
/// least 10 s, and never more than half the agent's lease timer, so a reconnect has time to land before it fires.
#[must_use]
pub fn silence_limit(heartbeat: Duration, agent_lease_ttl: Duration) -> Duration {
    (heartbeat * 3)
        .max(Duration::from_secs(10))
        .min(agent_lease_ttl / 2)
        .max(Duration::from_secs(1))
}

/// The agent's lease timer for a server's `lease_ttl_s`: the configured one, or `lease_ttl_s - 10` when that is
/// shorter (§6, SI-13). Returns the timer and whether it was lowered.
#[must_use]
pub fn effective_agent_ttl(configured: Duration, lease_ttl_s: u32) -> (Duration, bool) {
    let max = Duration::from_secs(u64::from(lease_ttl_s.saturating_sub(AGENT_LEASE_TTL_MARGIN_S)).max(1));
    if configured > max {
        (max, true)
    } else {
        (configured, false)
    }
}

/// An inventory in a form where only real changes differ: lists sorted.
#[must_use]
pub fn normalized(inventory: &Inventory) -> serde_json::Value {
    let mut inv = inventory.clone();
    inv.gpus.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    for sb in &mut inv.sandbox {
        sb.runtimes.sort();
        sb.problems.sort();
    }
    inv.sandbox.sort_by(|a, b| a.driver.cmp(&b.driver));
    serde_json::to_value(&inv).unwrap_or(serde_json::Value::Null)
}

/// Writes one frame within [`WRITE_TIMEOUT`]; false when the connection is no good any more.
async fn write_one(send: &mut (dyn AsyncWrite + Send + Unpin), msg: &AgentMsg) -> bool {
    match tokio::time::timeout(WRITE_TIMEOUT, write_frame(send, msg)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, kind = msg.kind(), "cannot write to the server");
            false
        }
        Err(_) => {
            tracing::warn!(kind = msg.kind(), "the server does not read; dropping the connection");
            false
        }
    }
}

/// The control stream's only writer: control frames first, then job frames. Heartbeats and confirmable reports
/// are noted in `acks` as they are written (§6 "A `JobFinished` is confirmed"). A job frame it cannot write is
/// dropped, which reports it lost to its run.
async fn writer(
    mut send: Box<dyn AsyncWrite + Send + Unpin>,
    mut control: mpsc::Receiver<AgentMsg>,
    mut jobs: mpsc::Receiver<JobFrame>,
    acks: Arc<Acks>,
) {
    loop {
        tokio::select! {
            biased;
            Some(msg) = control.recv() => {
                if !write_one(&mut *send, &msg).await {
                    return;
                }
                if let AgentMsg::Heartbeat { seq, .. } = msg {
                    acks.heartbeat_written(seq);
                }
            }
            Some(frame) = jobs.recv() => {
                let Some(msg) = frame.msg() else { continue };
                if !write_one(&mut *send, msg).await {
                    return;
                }
                if let Some(confirm) = frame.written() {
                    acks.report_written(confirm);
                }
            }
            else => break,
        }
    }
    let _ = tokio::time::timeout(WRITE_TIMEOUT, send.shutdown()).await;
}

/// Why the reader of a control stream stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadEnd {
    /// The server finished the stream cleanly, or the session no longer reads.
    Closed,
    /// The connection was lost or closed under us: an I/O error, or a stream cut inside a frame. Not a protocol
    /// violation (the T05b real run logged a server restart as one).
    Lost(String),
    /// A frame that is oversized, not UTF-8 or not valid JSON, or a message that fails `validate()` (SI-10).
    Violation(String),
}

/// Classifies a frame error: transport failures are [`ReadEnd::Lost`], content failures [`ReadEnd::Violation`].
#[must_use]
pub fn classify(err: &FrameError) -> ReadEnd {
    match err {
        FrameError::Io(_) | FrameError::Truncated => ReadEnd::Lost(err.to_string()),
        FrameError::TooLarge { .. } | FrameError::InvalidUtf8 | FrameError::InvalidJson { .. } | FrameError::Encode => {
            ReadEnd::Violation(err.to_string())
        }
    }
}

/// Reads server messages into `tx` until the stream ends, and logs why: a lost connection at info level, a real
/// decode or validation failure as an SI-10 warning.
pub async fn read_loop(mut recv: impl AsyncRead + Unpin, tx: mpsc::Sender<ServerMsg>) -> ReadEnd {
    let end = loop {
        match read_frame::<ServerMsg, _>(&mut recv, MAX_FRAME_LEN).await {
            Ok(Some(msg)) => {
                if let Err(e) = msg.validate() {
                    break ReadEnd::Violation(format!("`{}`: {e}", msg.kind()));
                }
                if tx.send(msg).await.is_err() {
                    break ReadEnd::Closed;
                }
            }
            Ok(None) => break ReadEnd::Closed,
            Err(e) => break classify(&e),
        }
    };
    match &end {
        ReadEnd::Closed => tracing::debug!("the server closed the control stream"),
        ReadEnd::Lost(e) => tracing::info!(error = %e, "connection to the server lost"),
        ReadEnd::Violation(e) => {
            tracing::warn!(error = %e, "malformed or invalid message from the server; closing (SI-10)");
        }
    }
    end
}

async fn reader(recv: Box<dyn AsyncRead + Send + Unpin>, tx: mpsc::Sender<ServerMsg>) {
    let _ = read_loop(recv, tx).await;
}

/// A running session's tasks and queues.
struct Io {
    /// Control frames.
    outbox: mpsc::Sender<AgentMsg>,
    /// Job frames, behind the control frames.
    jobs: mpsc::Sender<JobFrame>,
    /// Which heartbeats and reports were written, for the confirmations.
    acks: Arc<Acks>,
    inbound: mpsc::Receiver<ServerMsg>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
    close: Option<Box<dyn FnOnce() + Send + Sync>>,
    streams: Arc<dyn StreamOpener>,
    /// Where the streams the server opens arrive, until the dispatcher takes it.
    incoming: Option<Arc<dyn StreamAcceptor>>,
    /// Serves the streams the server opens (H2 §6.1), once welcomed.
    dispatcher: Option<JoinHandle<()>>,
    /// The number of this session's port on the [`Uplink`], once welcomed.
    port: Option<u64>,
}

impl Io {
    fn new(link: Link) -> Self {
        let (out_tx, out_rx) = mpsc::channel(QUEUE);
        let (jobs_tx, jobs_rx) = mpsc::channel(JOB_QUEUE);
        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        let acks = Arc::new(Acks::default());
        let Link {
            send,
            recv,
            close,
            streams,
            incoming,
        } = link;
        Self {
            outbox: out_tx,
            jobs: jobs_tx,
            acks: acks.clone(),
            inbound: in_rx,
            reader: tokio::spawn(reader(recv, in_tx)),
            writer: tokio::spawn(writer(send, out_rx, jobs_rx, acks)),
            close: Some(close),
            streams,
            incoming,
            dispatcher: None,
            port: None,
        }
    }

    /// Stops serving the server's streams and waits until every one of them is gone.
    async fn stop_dispatcher(&mut self) {
        if let Some(dispatcher) = self.dispatcher.take() {
            dispatcher.abort();
            let _ = dispatcher.await;
        }
    }

    /// Lets the writer flush what is queued (bounded), then closes the connection.
    async fn finish(mut self) {
        self.reader.abort();
        let Io {
            outbox, jobs, writer, ..
        } = &mut self;
        drop(std::mem::replace(outbox, mpsc::channel(1).0));
        drop(std::mem::replace(jobs, mpsc::channel(1).0));
        let _ = tokio::time::timeout(FLUSH_TIMEOUT, writer).await;
        if let Some(close) = self.close.take() {
            close();
        }
    }
}

impl Drop for Io {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher.abort();
        }
        if let Some(close) = self.close.take() {
            close();
        }
    }
}

/// Runs one session over `link` until it ends. `inventory` was detected just **before** the dial (T05b review,
/// P2-1): the server allows 10 s from the handshake to the first message, and a detection can take longer, so
/// `Hello` goes out at once with it. Each connection gets its own fresh detection (§6).
pub async fn run(
    shared: &Shared,
    link: Link,
    inventory: Inventory,
    shutdown: &mut watch::Receiver<bool>,
    network: &mut NetworkEvents,
    on_welcome: impl FnOnce(&Welcomed),
) -> SessionEnd {
    let mut io = Io::new(link);
    let mut decisions = JoinSet::new();
    let end = drive(
        shared,
        &mut io,
        &mut decisions,
        inventory,
        shutdown,
        network,
        on_welcome,
    )
    .await;
    // The jobs lose their way to the server first, then the decisions still in progress are aborted and waited
    // for: none outlives the session (a job must never start after the daemon's `stop_all`).
    if let Some(port) = io.port.take() {
        shared.uplink.disconnect(port);
    }
    // The port streams of this connection end with it.
    io.stop_dispatcher().await;
    decisions.shutdown().await;
    io.finish().await;
    end
}

async fn drive(
    shared: &Shared,
    io: &mut Io,
    decisions: &mut JoinSet<()>,
    inventory: Inventory,
    shutdown: &mut watch::Receiver<bool>,
    network: &mut NetworkEvents,
    on_welcome: impl FnOnce(&Welcomed),
) -> SessionEnd {
    // 1. Hello at once, with the inventory detected just before the dial.
    let mut last_inventory = normalized(&inventory);
    let hello = AgentMsg::Hello {
        agent_version: AGENT_VERSION.to_string(),
        inventory,
        running: shared.supervisor.running(),
        features: shared.features(),
    };
    if io.outbox.send(hello).await.is_err() {
        return SessionEnd::Lost { welcomed: false };
    }
    // 2. Welcome.
    let first = tokio::select! {
        r = tokio::time::timeout(WELCOME_TIMEOUT, io.inbound.recv()) => r,
        _ = shutdown.changed() => return SessionEnd::Shutdown,
    };
    let welcomed = match first {
        Err(_) => {
            tracing::warn!("the server did not answer Hello in time");
            return SessionEnd::Lost { welcomed: false };
        }
        Ok(None) => return SessionEnd::Lost { welcomed: false },
        Ok(Some(msg)) => {
            // In the handshake, only a Welcome for the owner is contact: a Welcome for another account (SI-1), or an
            // Error, keeps no job alive (T05b review P3).
            if matches!(&msg, ServerMsg::Welcome { account_id, .. } if *account_id == shared.owner) {
                shared.watchdog.heard();
            }
            match msg {
                ServerMsg::Welcome {
                    server_version,
                    node_id,
                    account_id,
                    heartbeat_interval_s,
                    lease_ttl_s,
                    // `pending_approval` (H2 §5.5) is not used yet (T2-23).
                    ..
                } => {
                    if account_id != shared.owner {
                        tracing::error!(
                            welcome_account = %account_id,
                            owner = %shared.owner,
                            "the server's Welcome names another account than this node's owner: refusing it, and \
                             every lease from it (SI-1)"
                        );
                        return SessionEnd::WrongOwner;
                    }
                    let (ttl, lowered) = effective_agent_ttl(shared.agent_lease_ttl, lease_ttl_s);
                    if lowered {
                        tracing::warn!(
                            agent_lease_ttl_s = shared.agent_lease_ttl.as_secs(),
                            lease_ttl_s,
                            lowered_to_s = ttl.as_secs(),
                            "agent_lease_ttl_s + 10 > the server's lease_ttl_s: lowering the agent's lease timer \
                             so it always stops jobs before the server requeues them (SI-13)"
                        );
                    }
                    shared.watchdog.set_ttl(ttl);
                    let asked = Duration::from_secs(u64::from(heartbeat_interval_s));
                    let most = (ttl / 3).max(Duration::from_secs(1));
                    if asked > most {
                        tracing::warn!(
                            heartbeat_interval_s,
                            used_s = most.as_secs(),
                            "the server's heartbeat interval is too long for the agent's lease timer; heartbeating \
                             more often"
                        );
                    }
                    let w = Welcomed {
                        agent_lease_ttl: ttl,
                        heartbeat_interval: asked.min(most),
                    };
                    tracing::info!(%node_id, %server_version, "connected to the server");
                    on_welcome(&w);
                    io.port = Some(shared.uplink.connect(Port::new(&io.jobs, io.streams.clone())));
                    // Only now, and only with a bridge: before the Welcome no stream of the server is accepted.
                    if let (Some(ports), Some(incoming)) = (&shared.ports, io.incoming.take()) {
                        io.dispatcher = Some(tokio::spawn(streams::serve(incoming, Arc::clone(ports))));
                    }
                    w
                }
                ServerMsg::Error { code, .. } if code == error_code::NOT_ENROLLED => return SessionEnd::NotEnrolled,
                ServerMsg::Error { code, .. } if code == error_code::AGENT_TOO_OLD => return SessionEnd::AgentTooOld,
                ServerMsg::Error { code, message } => {
                    tracing::warn!(%code, %message, "the server refused Hello");
                    return SessionEnd::Lost { welcomed: false };
                }
                other => {
                    tracing::warn!(
                        kind = other.kind(),
                        "the server answered Hello with something else than Welcome"
                    );
                    return SessionEnd::Lost { welcomed: false };
                }
            }
        }
    };
    // 3. The loop.
    let hb_every = welcomed.heartbeat_interval;
    let silence = silence_limit(hb_every, welcomed.agent_lease_ttl);
    let mut heartbeat = tokio::time::interval_at(Instant::now() + hb_every, hb_every);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let every = shared.inventory_interval;
    let mut redetect = tokio::time::interval_at(Instant::now() + every, every);
    redetect.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut detection: Option<JoinHandle<Result<Inventory, String>>> = None;
    let mut seq: u64 = 0;
    let mut last_heard = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return SessionEnd::Shutdown,
            Some(change) = network.changes.recv() => return SessionEnd::AddressesChanged(change.addrs),
            () = network.rebind.notified() => return SessionEnd::Rebind,
            msg = io.inbound.recv() => {
                let Some(msg) = msg else {
                    return SessionEnd::Lost { welcomed: true };
                };
                shared.watchdog.heard();
                last_heard = Instant::now();
                if let Some(end) = route(shared, io, decisions, msg).await {
                    return end;
                }
            }
            // Reap the answered decisions, so the set stays as small as the decisions in progress.
            Some(_) = decisions.join_next(), if !decisions.is_empty() => {}
            () = tokio::time::sleep_until(last_heard + silence) => {
                tracing::warn!(silent_s = silence.as_secs(), "no message from the server; reconnecting");
                return SessionEnd::Lost { welcomed: true };
            }
            _ = heartbeat.tick() => {
                if let Some(end) = send_heartbeat(shared, io, &mut seq).await {
                    return end;
                }
            }
            // A lease freed its resources (its cleanup ended): tell the server at once, so it can offer the slot
            // again without waiting for the tick (§6 "Heartbeat"). The tick keeps its own rhythm.
            () = shared.supervisor.released() => {
                if let Some(end) = send_heartbeat(shared, io, &mut seq).await {
                    return end;
                }
            }
            _ = redetect.tick(), if detection.is_none() => {
                let source = shared.inventory.clone();
                detection = Some(tokio::spawn(async move { source.detect().await }));
            }
            result = async {
                match detection.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            }, if detection.is_some() => {
                detection = None;
                match result {
                    Ok(Ok(inventory)) => {
                        let now = normalized(&inventory);
                        if now != last_inventory {
                            tracing::info!("the inventory changed; sending InventoryUpdate");
                            last_inventory = now;
                            if let Some(end) = queue(io, AgentMsg::InventoryUpdate { inventory }) {
                                return end;
                            }
                        }
                    }
                    Ok(Err(e)) => tracing::warn!(error = %e, "inventory re-detection failed; keeping the last one"),
                    Err(_) => tracing::warn!("inventory re-detection panicked; keeping the last one"),
                }
            }
        }
    }
}

/// Queues the next `Heartbeat`, numbered after the last one, with the load now and the leases that still hold resources
/// on the node (`LeaseSupervisor::holding`, not `Hello`'s list). `Some` ends the session.
async fn send_heartbeat(shared: &Shared, io: &Io, seq: &mut u64) -> Option<SessionEnd> {
    *seq += 1;
    let load = shared.load.sample().await;
    // Read after the load sample: a lease released meanwhile is already off the list.
    let running = shared.supervisor.holding();
    queue(
        io,
        AgentMsg::Heartbeat {
            seq: *seq,
            load,
            running,
        },
    )
}

/// Routes one message. `Some` ends the session.
async fn route(shared: &Shared, io: &Io, decisions: &mut JoinSet<()>, msg: ServerMsg) -> Option<SessionEnd> {
    match msg {
        ServerMsg::HeartbeatAck { seq } => {
            tracing::trace!(seq, "heartbeat acknowledged");
            io.acks.acked(seq);
        }
        ServerMsg::Lease {
            lease_id,
            epoch,
            job,
            account_id,
            deadline,
        } => {
            let reject = |reason| AgentMsg::LeaseRejected {
                lease_id,
                epoch,
                reason,
            };
            // SI-1: only the owner's jobs, checked before anything else sees the lease.
            if account_id != shared.owner {
                tracing::warn!(%lease_id, %account_id, "lease for another account refused (not_owner, SI-1)");
                return queue(io, reject(LeaseRejectReason::NotOwner));
            }
            // §6 "must understand": strict parse; a failure is a rejected offer, never a closed connection.
            let job = match job.parse_strict_with(&shared.lease_limits()) {
                Ok(job) => job,
                Err(errors) => {
                    let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
                    tracing::warn!(%lease_id, ?fields, "lease with a job this agent does not accept (invalid_job)");
                    return queue(io, reject(LeaseRejectReason::InvalidJob));
                }
            };
            let Ok(permit) = shared.decisions.clone().try_acquire_owned() else {
                tracing::warn!(%lease_id, "too many lease decisions in progress; refusing");
                return queue(io, reject(LeaseRejectReason::InsufficientCapacity));
            };
            let handler = shared.handler.clone();
            let outbox = io.outbox.clone();
            let offer = LeaseOffer {
                lease_id,
                epoch,
                job,
                account_id,
                deadline,
            };
            decisions.spawn(async move {
                let decision = tokio::time::timeout(DECISION_TIMEOUT, handler.lease(offer))
                    .await
                    .unwrap_or(LeaseDecision::Reject(LeaseRejectReason::AgentNotReady));
                let answer = match decision {
                    LeaseDecision::Accept => AgentMsg::LeaseAccepted { lease_id, epoch },
                    LeaseDecision::Reject(reason) => AgentMsg::LeaseRejected {
                        lease_id,
                        epoch,
                        reason,
                    },
                };
                let _ = outbox.send(answer).await;
                drop(permit);
            });
        }
        // Bounded: a slow implementation must never stall the connection's reads (T05b review, P3-1).
        ServerMsg::Cancel {
            lease_id,
            epoch,
            reason,
        } => bounded("cancel", shared.handler.cancel(lease_id, epoch, reason)).await,
        ServerMsg::Drain {} => bounded("drain", shared.supervisor.drain()).await,
        ServerMsg::Resume {} => bounded("resume", shared.supervisor.resume()).await,
        ServerMsg::Error { code, .. } if code == error_code::NOT_ENROLLED => return Some(SessionEnd::NotEnrolled),
        ServerMsg::Error { code, .. } if code == error_code::AGENT_TOO_OLD => return Some(SessionEnd::AgentTooOld),
        ServerMsg::Error { code, message } => tracing::warn!(%code, %message, "error from the server"),
        ServerMsg::Welcome { .. } => tracing::warn!("a second Welcome on one connection; ignored"),
        ServerMsg::Unknown => tracing::debug!("a message type this agent does not know; ignored"),
        // H2 §6.1: sent only to agents that declared `volumes` or `approval`, which this one does not yet.
        msg @ (ServerMsg::VolumeDelete(_) | ServerMsg::NodeApproved(_)) => {
            tracing::debug!(kind = msg.kind(), "a message this agent does not use yet; ignored");
        }
    }
    None
}

/// Runs a `LeaseHandler` or `LeaseSupervisor` call with [`CALL_TIMEOUT`]; past it, the call is dropped with a
/// warning (implementations hand long work to their own tasks).
async fn bounded(what: &'static str, call: BoxFuture<'_, ()>) {
    if tokio::time::timeout(CALL_TIMEOUT, call).await.is_err() {
        tracing::warn!(
            call = what,
            timeout_s = CALL_TIMEOUT.as_secs(),
            "a lease call took too long; abandoned"
        );
    }
}

/// Queues a control frame without waiting, so the loop always goes back to reading. A full queue (64 control
/// frames the server has not taken) drops the frame with a warning; the writer's own timeout ends such a connection.
fn queue(io: &Io, msg: AgentMsg) -> Option<SessionEnd> {
    match io.outbox.try_send(msg) {
        Ok(()) => None,
        Err(mpsc::error::TrySendError::Full(msg)) => {
            tracing::warn!(kind = msg.kind(), "the control queue is full; this frame is dropped");
            None
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Some(SessionEnd::Lost { welcomed: true }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_timer_is_lowered_only_when_it_must_be() {
        let s = Duration::from_secs;
        assert_eq!(
            effective_agent_ttl(s(45), 60),
            (s(45), false),
            "the defaults fit (SI-13)"
        );
        assert_eq!(effective_agent_ttl(s(45), 55), (s(45), false), "45 + 10 <= 55");
        assert_eq!(effective_agent_ttl(s(45), 50), (s(40), true));
        assert_eq!(effective_agent_ttl(s(45), 11), (s(1), true));
        assert_eq!(effective_agent_ttl(s(45), 3), (s(1), true), "never zero");
    }

    #[tokio::test]
    async fn a_lost_connection_is_not_an_si10_violation() {
        use tokio::io::AsyncWriteExt as _;
        // The peer goes away in the middle of a frame (a server restart, a removed node's closed connection).
        let (mut server, agent) = tokio::io::duplex(1024);
        let (tx, _rx) = mpsc::channel(4);
        server.write_all(&[0, 0, 0, 50, b'{']).await.unwrap();
        drop(server);
        assert!(matches!(read_loop(agent, tx).await, ReadEnd::Lost(_)));
        // An I/O error is a lost connection too.
        let reset = FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection lost",
        ));
        assert!(matches!(classify(&reset), ReadEnd::Lost(_)));
        // A clean end is just closed.
        let (server, agent) = tokio::io::duplex(1024);
        drop(server);
        let (tx, _rx) = mpsc::channel(4);
        assert_eq!(read_loop(agent, tx).await, ReadEnd::Closed);
    }

    #[tokio::test]
    async fn bad_frames_and_invalid_messages_are_si10_violations() {
        use tokio::io::AsyncWriteExt as _;
        for frame in [
            b"\x00\x00\x00\x03{{{".to_vec(),
            b"\x00\x00\x00\x02\xff\xfe".to_vec(),
            // Decodes, but fails validate(): heartbeat_interval_s is 0.
            {
                let body = br#"{"type":"welcome","server_version":"0.1.0","node_id":"node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4","account_id":"acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4","heartbeat_interval_s":0,"lease_ttl_s":60}"#;
                let mut f = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                f.extend_from_slice(body);
                f
            },
        ] {
            let (mut server, agent) = tokio::io::duplex(4096);
            server.write_all(&frame).await.unwrap();
            let (tx, mut rx) = mpsc::channel(4);
            assert!(matches!(read_loop(agent, tx).await, ReadEnd::Violation(_)), "{frame:?}");
            assert!(rx.try_recv().is_err(), "nothing invalid is passed on");
        }
        let too_big = FrameError::TooLarge {
            len: u32::MAX,
            max: MAX_FRAME_LEN,
        };
        assert!(matches!(classify(&too_big), ReadEnd::Violation(_)));
    }

    #[test]
    fn silence_limit_bounds() {
        let s = Duration::from_secs;
        assert_eq!(silence_limit(s(5), s(45)), s(15));
        assert_eq!(silence_limit(s(1), s(45)), s(10));
        assert_eq!(silence_limit(s(20), s(45)), s(22) + Duration::from_millis(500));
    }
}
