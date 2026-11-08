// SPDX-License-Identifier: AGPL-3.0-only

//! The node gateway (spec §6, §10): the server's iroh endpoint and its two protocols.
//!
//! - `p2pc/agent/1` ([`agent`]): `Join`, `Hello`, heartbeats and the routing of lease and job messages to
//!   [`NodeEvents`]; live connections in the [`NodeHub`].
//! - uploads ([`upload`]): every bidirectional stream after an agent's control stream carries one output file;
//! - `p2pc/http/1` ([`tunnel`]): each bidirectional stream relayed to the local REST listener, where the API key is
//!   checked as for any other request.
//! - Liveness: a node with no contact for `lease_ttl_s` becomes `offline` ([`Gateway::sweep_liveness`], run every
//!   second); at boot, every node that was online gets `lease_ttl_s` from the boot (§6 "Server restart"), a grace
//!   that is never recorded as a contact.
//!
//! Later tasks plug in through [`LeaseReconciler`] (T06) and [`NodeEvents`] (T06, T10).

mod agent;
pub mod endpoint;
pub mod hub;
pub mod limits;
mod tunnel;
mod upload;

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use iroh::Endpoint;
use iroh::endpoint::VarInt;
use p2pc_proto::ids::NodeId;
use p2pc_proto::protocol::{AgentMsg, RunningLease, ServerMsg};
use p2pc_proto::{PROTOCOL_ALPN_AGENT, PROTOCOL_ALPN_HTTP};
use time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

pub use self::endpoint::{EndpointOptions, ServerIdentity};
pub use self::hub::{Expired, HubEvent, NodeHub, OfflineReason, SendError};
pub use self::limits::GatewayLimits;
use self::limits::MinuteLimiter;
use crate::app::AppState;
use crate::store::{self, StoreError};

/// A boxed, sendable future, for the object-safe hook traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Reconciles the leases an agent lists in `Hello.running` (§6 "Reconnects"). T06 implements it.
pub trait LeaseReconciler: Send + Sync + fmt::Debug + 'static {
    /// The messages to send after the `Welcome`: typically `Cancel` for every lease that is not current.
    ///
    /// [`ReconcileFailed`] when the reconciliation could not be decided (for example a database error): the session
    /// is then closed with nothing sent, so the agent reconnects and reconciles again. Its leases are never cancelled
    /// for a server-side failure (§6 "Server restart": healthy jobs are never cancelled).
    fn reconcile<'a>(
        &'a self,
        node_id: NodeId,
        running: &'a [RunningLease],
    ) -> BoxFuture<'a, Result<Vec<ServerMsg>, ReconcileFailed>>;
}

/// A reconciliation that could not be decided; the session is closed and the agent retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the leases of a Hello could not be reconciled")]
pub struct ReconcileFailed;

/// Before T06 no lease exists, so every lease an agent reports is cancelled.
#[derive(Debug, Default, Clone, Copy)]
pub struct CancelAllLeases;

/// The `reason` of the `Cancel`s [`CancelAllLeases`] sends.
pub const UNKNOWN_LEASE: &str = "unknown_lease";

impl LeaseReconciler for CancelAllLeases {
    fn reconcile<'a>(
        &'a self,
        _node_id: NodeId,
        running: &'a [RunningLease],
    ) -> BoxFuture<'a, Result<Vec<ServerMsg>, ReconcileFailed>> {
        Box::pin(async move {
            Ok(running
                .iter()
                .map(|l| ServerMsg::Cancel {
                    lease_id: l.lease_id,
                    epoch: l.epoch,
                    reason: UNKNOWN_LEASE.to_string(),
                })
                .collect())
        })
    }
}

/// Lease and job messages from agents, and node loss. T06 (leases) and T10 (logs, outputs) implement it.
pub trait NodeEvents: Send + Sync + fmt::Debug + 'static {
    /// `LeaseAccepted`, `LeaseRejected`, `JobStarted`, `LogChunk` or `JobFinished` from `node_id`, validated.
    fn on_message(&self, node_id: NodeId, msg: AgentMsg) -> BoxFuture<'_, ()>;
    /// A `Heartbeat` from `node_id` with its `running` list: every lease that still holds resources on the node
    /// (§6). Called before the `HeartbeatAck`, so a node that sees the ack knows it was handled. Nothing by default.
    fn on_heartbeat<'a>(&'a self, node_id: NodeId, running: &'a [RunningLease]) -> BoxFuture<'a, ()> {
        let _ = (node_id, running);
        Box::pin(async {})
    }
    /// `node_id` went `offline`: no contact for `lease_ttl_s` ([`OfflineReason::Lost`]), or the owner deleted it
    /// ([`OfflineReason::Deleted`]). T06 requeues the node's leases in both cases.
    fn on_node_offline(&self, node_id: NodeId, reason: OfflineReason) -> BoxFuture<'_, ()>;
}

/// Logs at debug level and drops everything (before T06 and T10).
#[derive(Debug, Default, Clone, Copy)]
pub struct DropNodeEvents;

impl NodeEvents for DropNodeEvents {
    fn on_message(&self, node_id: NodeId, msg: AgentMsg) -> BoxFuture<'_, ()> {
        // The kind only: a LogChunk's data or a JobFinished's error could hold anything.
        tracing::debug!(%node_id, kind = msg.kind(), "agent message dropped (no handler yet)");
        Box::pin(async {})
    }

    fn on_node_offline(&self, node_id: NodeId, reason: OfflineReason) -> BoxFuture<'_, ()> {
        tracing::debug!(%node_id, ?reason, "node offline");
        Box::pin(async {})
    }
}

/// What the gateway needs besides the app state.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// How to bind the endpoint.
    pub endpoint: EndpointOptions,
    /// Where `p2pc/http/1` streams go: the REST listener.
    pub rest_addr: SocketAddr,
    /// The limits.
    pub limits: GatewayLimits,
    /// Lease reconciliation (T06).
    pub reconciler: Arc<dyn LeaseReconciler>,
    /// Lease and job messages and node loss (T06, T10). Installed in the hub at start, so `DELETE /v1/nodes/{id}`
    /// reaches it too.
    pub events: Arc<dyn NodeEvents>,
}

impl GatewayConfig {
    /// The defaults for `endpoint` and `rest_addr`: spec limits, [`CancelAllLeases`], [`DropNodeEvents`]. `serve`
    /// replaces both with the scheduler (T06).
    #[must_use]
    pub fn new(endpoint: EndpointOptions, rest_addr: SocketAddr) -> Self {
        Self {
            endpoint,
            rest_addr,
            limits: GatewayLimits::default(),
            reconciler: Arc::new(CancelAllLeases),
            events: Arc::new(DropNodeEvents),
        }
    }
}

/// Shared by every connection task.
#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) state: AppState,
    /// The endpoint in use. It is replaced when the network changes ([`rebind`]).
    endpoint: Mutex<Endpoint>,
    /// Bumped at each replacement, so the accept loop tells "replaced" from "closed".
    generation: AtomicU64,
    /// Set by [`Gateway::shutdown`].
    closing: AtomicBool,
    /// How the endpoint was bound (relays, port), for a re-bind.
    options: EndpointOptions,
    pub(crate) limits: GatewayLimits,
    pub(crate) reconciler: Arc<dyn LeaseReconciler>,
    pub(crate) events: Arc<dyn NodeEvents>,
    pub(crate) rest_addr: SocketAddr,
    pub(crate) unknown_connections: Arc<Semaphore>,
    pub(crate) pending_joins: Arc<Semaphore>,
    pub(crate) decodes: limits::DecodeGate,
    pub(crate) handshakes: Arc<Semaphore>,
    pub(crate) http_streams: Arc<Semaphore>,
    pub(crate) http_connections_open: Arc<Semaphore>,
    pub(crate) join_failures: Mutex<MinuteLimiter>,
    pub(crate) http_connections: Mutex<MinuteLimiter>,
    /// `p2pc/http/1` connections open per NodeId (at most `http_connections_per_node`).
    pub(crate) http_peers: Mutex<std::collections::HashMap<String, usize>>,
    pub(crate) min_agent_version: semver::Version,
    /// Agent connections in progress per enrolled node (at most `max_connections_per_node`).
    pub(crate) agent_connections: Mutex<std::collections::HashMap<NodeId, usize>>,
    /// Per node: the upload streams whose header is being read (at most `uploads.headers_per_node`).
    pub(crate) upload_headers: Mutex<std::collections::HashMap<NodeId, Arc<Semaphore>>>,
}

impl Inner {
    /// The endpoint in use now.
    pub(crate) fn endpoint(&self) -> Endpoint {
        self.endpoint.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub(crate) fn hub(&self) -> &NodeHub {
        &self.state.hub
    }

    pub(crate) fn ttl(&self) -> Duration {
        Duration::seconds(i64::from(self.state.config.nodes.lease_ttl_s))
    }

    pub(crate) fn join_failures(&self) -> std::sync::MutexGuard<'_, MinuteLimiter> {
        self.join_failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn http_connections(&self) -> std::sync::MutexGuard<'_, MinuteLimiter> {
        self.http_connections.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn http_peers(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, usize>> {
        self.http_peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn agent_connections(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<NodeId, usize>> {
        self.agent_connections.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The node's semaphore of upload header reads, shared by all its connections. One entry per enrolled node that
    /// connected, so the map is bounded by the nodes.
    pub(crate) fn upload_headers(&self, node_id: NodeId) -> Arc<Semaphore> {
        self.upload_headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(node_id)
            .or_insert_with(|| Arc::new(Semaphore::new(self.limits.uploads.headers_per_node)))
            .clone()
    }
}

/// Why the gateway could not start.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The endpoint could not be bound.
    #[error(transparent)]
    Endpoint(#[from] endpoint::EndpointError),
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The running gateway. Dropping it does not stop it; call [`Gateway::shutdown`].
#[derive(Debug)]
pub struct Gateway {
    inner: Arc<Inner>,
    accept: JoinHandle<()>,
    sweep: JoinHandle<()>,
    network: Option<JoinHandle<()>>,
}

impl Gateway {
    /// Binds the endpoint, applies the restart grace and starts accepting connections.
    pub async fn start(state: AppState, config: GatewayConfig) -> Result<Self, GatewayError> {
        let endpoint = endpoint::bind(state.server.secret_key().clone(), &config.endpoint).await?;
        // §6 "Server restart": nodes that were online get lease_ttl_s from now, so none expires before it. A grace,
        // not a contact: their `last_seen_at` stays the real one. They are listed `offline` until their agent's
        // `Hello` (T05b real run): no session exists yet, and the scheduler offers leases only to connected nodes.
        let boot = state.clock.now();
        let mut tx = store::begin_immediate(&state.db).await?;
        let online = store::nodes::offline_at_boot(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        state.hub.seen_at_boot(&online, boot);
        state.hub.set_node_events(config.events.clone());
        let limits = config.limits;
        let inner = Arc::new(Inner {
            min_agent_version: state.config.nodes.min_agent_version(),
            agent_connections: Mutex::new(std::collections::HashMap::new()),
            upload_headers: Mutex::new(std::collections::HashMap::new()),
            http_peers: Mutex::new(std::collections::HashMap::new()),
            unknown_connections: Arc::new(Semaphore::new(limits.max_unknown_connections)),
            pending_joins: Arc::new(Semaphore::new(limits.max_pending_joins)),
            decodes: limits::DecodeGate::new(limits.max_concurrent_decodes),
            handshakes: Arc::new(Semaphore::new(limits.max_handshakes)),
            http_streams: Arc::new(Semaphore::new(limits.http_streams_total)),
            http_connections_open: Arc::new(Semaphore::new(limits.http_connections_total)),
            join_failures: Mutex::new(MinuteLimiter::new(
                limits.join_failures_per_node_per_minute,
                limits.join_failures_per_minute,
            )),
            http_connections: Mutex::new(MinuteLimiter::new(
                limits.http_connections_per_node_per_minute,
                u32::MAX,
            )),
            state,
            endpoint: Mutex::new(endpoint),
            generation: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            options: config.endpoint.clone(),
            limits,
            reconciler: config.reconciler,
            events: config.events,
            rest_addr: config.rest_addr,
        });
        tracing::info!(
            node_id = %inner.endpoint().id(),
            sockets = ?inner.endpoint().bound_sockets(),
            "node gateway listening"
        );
        let accept = tokio::spawn(accept_loop(inner.clone()));
        let sweep = tokio::spawn(sweep_loop(inner.clone()));
        let network = inner
            .options
            .reselect
            .clone()
            .map(|policy| tokio::spawn(network_loop(inner.clone(), policy)));
        Ok(Self {
            inner,
            accept,
            sweep,
            network,
        })
    }

    /// The endpoint in use (tests read its address).
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        self.inner.endpoint()
    }

    /// Binds a new endpoint on `bind`, then closes the old one: what a network change does. Live connections are
    /// closed, and agents reconnect. If the new endpoint cannot be bound, the old one stays.
    pub async fn rebind_to(&self, bind: Vec<p2pc_proto::net::SelectedAddr>) {
        rebind(&self.inner, bind).await;
    }

    /// The hub of live connections.
    #[must_use]
    pub fn hub(&self) -> &NodeHub {
        self.inner.hub()
    }

    /// Turns every node with no contact for `lease_ttl_s` `offline`: closes its connection, writes its
    /// `node_disconnections` row and calls [`NodeEvents::on_node_offline`] with [`OfflineReason::Lost`]. Runs every second; tests call it after
    /// moving the clock.
    pub async fn sweep_liveness(&self) {
        sweep(&self.inner).await;
    }

    /// The first half of [`Gateway::sweep_liveness`]: takes the expired nodes out of the hub. Tests use it, with
    /// [`Gateway::sweep_finish`], to interleave a reconnect between the two halves.
    #[doc(hidden)]
    pub fn sweep_take_expired(&self) -> Vec<Expired> {
        self.inner
            .hub()
            .take_expired(self.inner.state.clock.now(), self.inner.ttl())
    }

    /// The second half of [`Gateway::sweep_liveness`]: records `expired` offline and calls the hook.
    #[doc(hidden)]
    pub async fn sweep_finish(&self, expired: Vec<Expired>) {
        finish_sweep(&self.inner, expired).await;
    }

    /// Stops accepting, closes every connection and the endpoint.
    pub async fn shutdown(self) {
        self.inner.closing.store(true, Ordering::SeqCst);
        self.sweep.abort();
        if let Some(network) = &self.network {
            network.abort();
        }
        close_bounded(self.inner.endpoint()).await;
        let _ = self.accept.await;
    }
}

/// The longest a clean close of an endpoint may take (T05b review P3, like the agent's).
pub const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Closes `ep` cleanly within [`CLOSE_TIMEOUT`]; past it, logs and drops it.
async fn close_bounded(ep: Endpoint) {
    if tokio::time::timeout(CLOSE_TIMEOUT, ep.close()).await.is_err() {
        tracing::warn!(
            timeout_s = CLOSE_TIMEOUT.as_secs(),
            "the iroh endpoint did not close in time; dropping it"
        );
    }
}

/// Re-selects the addresses when the network changes and re-binds the endpoint (T05 review, carry-over 6).
async fn network_loop(inner: Arc<Inner>, policy: p2pc_proto::net::DirectAddresses) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    // The watcher runs inside this task, not on its own: aborting this task at shutdown stops both (T05b review P3).
    // p2pc-net logs each change, with interface names only (§10).
    let watcher = p2pc_net::watch_network(policy, inner.options.bind.clone(), tx);
    let rebinds = async {
        while let Some(change) = rx.recv().await {
            rebind(&inner, change.addrs).await;
        }
    };
    tokio::join!(watcher, rebinds);
}

async fn rebind(inner: &Inner, bind: Vec<p2pc_proto::net::SelectedAddr>) {
    if inner.closing.load(Ordering::SeqCst) {
        return;
    }
    let mut options = inner.options.clone();
    options.bind = bind;
    match endpoint::bind(inner.state.server.secret_key().clone(), &options).await {
        Ok(new) => {
            // Checked again under the endpoint lock: `shutdown` sets `closing` before it takes the endpoint, so
            // either it sees this swap, or this sees `closing` and closes the new endpoint instead (T05b review P3).
            let swapped = {
                let mut slot = inner.endpoint.lock().unwrap_or_else(PoisonError::into_inner);
                if inner.closing.load(Ordering::SeqCst) {
                    Err(new)
                } else {
                    inner.generation.fetch_add(1, Ordering::SeqCst);
                    Ok(std::mem::replace(&mut *slot, new))
                }
            };
            match swapped {
                Ok(old) => {
                    tracing::info!(
                        sockets = inner.endpoint().bound_sockets().len(),
                        "iroh endpoint re-bound"
                    );
                    close_bounded(old).await;
                }
                Err(unused) => close_bounded(unused).await,
            }
        }
        Err(e) => tracing::warn!(error = %e, "cannot re-bind the iroh endpoint; keeping the old one"),
    }
}

/// Accepts on the current endpoint; when it is replaced ([`rebind`]), goes on with the new one.
async fn accept_loop(inner: Arc<Inner>) {
    loop {
        let generation = inner.generation.load(Ordering::SeqCst);
        let ep = inner.endpoint();
        accept_on(&inner, &ep).await;
        if inner.closing.load(Ordering::SeqCst) || inner.generation.load(Ordering::SeqCst) == generation {
            return;
        }
    }
}

async fn accept_on(inner: &Arc<Inner>, ep: &Endpoint) {
    while let Some(incoming) = ep.accept().await {
        let Ok(permit) = inner.handshakes.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let inner = inner.clone();
        tokio::spawn(async move {
            let conn = match tokio::time::timeout(inner.limits.handshake_timeout, incoming).await {
                Ok(Ok(conn)) => conn,
                _ => return,
            };
            drop(permit);
            match conn.alpn() {
                a if a == PROTOCOL_ALPN_AGENT => agent::handle(inner, conn).await,
                a if a == PROTOCOL_ALPN_HTTP => tunnel::handle(inner, conn).await,
                _ => conn.close(VarInt::from_u32(hub::CLOSE_BY_SERVER), b""),
            }
        });
    }
}

async fn sweep_loop(inner: Arc<Inner>) {
    let mut tick = tokio::time::interval(inner.limits.sweep_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        sweep(&inner).await;
    }
}

async fn sweep(inner: &Inner) {
    let expired = inner.hub().take_expired(inner.state.clock.now(), inner.ttl());
    finish_sweep(inner, expired).await;
}

async fn finish_sweep(inner: &Inner, expired: Vec<Expired>) {
    let now = inner.state.clock.now();
    for expired in expired {
        let node_id = expired.node_id;
        match mark_offline(inner, node_id, expired.last_seen, now).await {
            Ok(Offline::Recorded) => {
                tracing::info!(%node_id, "node offline (no contact for lease_ttl_s)");
                inner.events.on_node_offline(node_id, OfflineReason::Lost).await;
            }
            // It reconnected between the expiry and this write: its new session owns the node.
            Ok(Offline::Reconnected) => {}
            // Deleted meanwhile: `DELETE` already fired `Deleted`; never `Lost` after it.
            Ok(Offline::Deleted) => {}
            // Nothing was recorded and the hook did not fire: put the node back, so the next sweep retries.
            Err(e) => {
                tracing::warn!(error = %e, %node_id, "cannot record a node going offline; retrying next sweep");
                inner.hub().restore_expired(expired);
            }
        }
    }
}

/// What [`mark_offline`] did.
enum Offline {
    /// The node is offline now, with its disconnection row.
    Recorded,
    /// It has a session again: nothing but `last_seen` was written.
    Reconnected,
    /// It was deleted: nothing was written.
    Deleted,
}

/// Records a node going offline. One check, inside the `BEGIN IMMEDIATE` transaction, decides the state, the
/// disconnection row and (in the caller) the hook. See `agent::session` for why this check and the session's
/// `online` write, made after `register`, are serialised.
///
/// A node that was only covered by the boot grace (`last_seen` is `None`) keeps the last contact already stored: the
/// grace is an expiry deadline, never a contact (T05 review).
async fn mark_offline(
    inner: &Inner,
    node_id: NodeId,
    last_seen: Option<time::OffsetDateTime>,
    now: time::OffsetDateTime,
) -> Result<Offline, StoreError> {
    let mut tx = store::begin_immediate(&inner.state.db).await?;
    if let Some(seen) = last_seen {
        store::nodes::touch_last_seen(&mut tx, node_id, seen).await?;
    }
    if inner.hub().has_session(node_id) {
        tx.commit().await?;
        return Ok(Offline::Reconnected);
    }
    if !store::nodes::mark_offline(&mut tx, node_id).await? {
        return Ok(Offline::Deleted);
    }
    let last_contact = match last_seen {
        Some(seen) => seen,
        None => store::nodes::last_contact(&mut tx, node_id)
            .await?
            .ok_or(StoreError::Corrupt("nodes"))?,
    };
    store::nodes::open_disconnection(&mut tx, node_id, last_contact).await?;
    store::nodes::resolve_disconnection(&mut tx, node_id, store::nodes::DisconnectOutcome::Offline, now).await?;
    tx.commit().await?;
    Ok(Offline::Recorded)
}
