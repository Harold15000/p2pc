// SPDX-License-Identifier: AGPL-3.0-only

//! [`NodeHub`]: the live agent connections and their liveness, shared by the gateway and the REST handlers.
//!
//! - **One live connection per node.** Registering a new connection replaces the old one, which is closed.
//! - **Two steps: register, then activate.** [`NodeHub::register`] installs the connection as *pending*: it already
//!   replaces the old one and [`NodeHub::disconnect`] already finds it, but [`NodeHub::send`] only buffers messages
//!   for it, and [`NodeHub::is_connected`] is still `false`. The session then re-reads its node row (deleted?
//!   draining?) and calls [`NodeHub::activate`], which queues the `Welcome` first and the buffered messages after
//!   it. So no message overtakes the `Welcome`, and a `Drain` sent meanwhile is not lost.
//! - **Deletion** (`DELETE /v1/nodes/{id}`) commits `deleted_at` **before** calling [`NodeHub::disconnect`], and a
//!   session re-reads the row **after** [`NodeHub::register`]. Both hub calls take the hub's lock, so either the
//!   re-read sees the deletion, or the disconnect finds the registered session and closes it.
//! - **Sending.** [`NodeHub::send`] queues a message on the node's control stream without waiting (a bounded queue;
//!   a full queue is an error, never unbounded growth).
//! - **Events.** [`NodeHub::subscribe`] streams connect and disconnect events (a broadcast channel: a slow subscriber
//!   misses events and is told how many it missed, it never blocks the gateway).
//! - **Liveness.** The hub remembers each node's last contact, in memory, for nodes connected now **and** for nodes
//!   that disconnected less than `lease_ttl_s` ago (they may come back) or that were online when the server booted
//!   (§6 "Server restart"). The gateway's sweep ([`NodeHub::take_expired`]) turns the ones past their TTL offline.
//! - **The boot grace is not a contact** (T05 review). A node online at boot gets a separate expiry base, the boot
//!   time: it expires `lease_ttl_s` after the later of its last real contact and the boot. Its last contact stays
//!   what it was ([`NodeHub::last_seen`] is `None` until the node really talks), so neither `nodes.last_seen_at`, the
//!   disconnection log nor `GET /v1/nodes` ever shows the boot time as a contact.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use iroh::endpoint::{Connection, VarInt};
use p2pc_proto::ids::NodeId;
use p2pc_proto::protocol::{MAX_PORT_STREAMS_PER_CONNECTION, ServerMsg};
use time::{Duration, OffsetDateTime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc};

/// Messages a node's outgoing queue holds before [`NodeHub::send`] fails with [`SendError::Full`].
///
/// A session queues the `Welcome` and a `Drain` (`activate`), then one `Cancel` per lease of `Hello.running` (at most
/// [`MAX_RUNNING_LEASES`](p2pc_proto::protocol::MAX_RUNNING_LEASES)) right after, so the queue must hold at least that
/// many, plus room for what was buffered meanwhile.
pub const OUTGOING_QUEUE: usize = p2pc_proto::protocol::MAX_RUNNING_LEASES + 64;
const _: () = assert!(OUTGOING_QUEUE >= p2pc_proto::protocol::MAX_RUNNING_LEASES + 2);
/// Capacity of the event channel.
const EVENT_CAPACITY: usize = 256;
/// Why a node went offline, for [`super::NodeEvents::on_node_offline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineReason {
    /// No contact for `lease_ttl_s` (§6 "Liveness").
    Lost,
    /// The owner deleted it (`DELETE /v1/nodes/{id}`).
    Deleted,
}

/// QUIC application close code when the server ends a connection on purpose (replaced, deleted, expired, refused).
pub const CLOSE_BY_SERVER: u32 = 1;

/// A connect or disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEvent {
    /// The node's control stream is up (after its `Welcome`).
    Connected(NodeId),
    /// The node's connection ended (it may still be within its TTL).
    Disconnected(NodeId),
}

/// Why [`NodeHub::port_stream`] gave no connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PortStreamError {
    /// The node has no live, activated connection.
    #[error("the node is not connected")]
    NotConnected,
    /// The node's connection already carries [`MAX_PORT_STREAMS_PER_CONNECTION`] port streams (H2 §6.1).
    #[error("the node's connection carries its most port streams")]
    TooMany,
}

/// Why [`NodeHub::send`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The node has no live connection.
    #[error("the node is not connected")]
    NotConnected,
    /// The node's outgoing queue is full.
    #[error("the node's outgoing queue is full")]
    Full,
}

#[derive(Debug)]
struct Session {
    id: u64,
    tx: mpsc::Sender<ServerMsg>,
    conn: Connection,
    /// `Some` until [`NodeHub::activate`]: messages sent meanwhile, queued after the `Welcome`.
    pending: Option<Vec<ServerMsg>>,
    /// The port streams the hub may still open on this connection (H2 §6.1: 256 at once).
    port_streams: Arc<Semaphore>,
}

impl Session {
    fn is_active(&self) -> bool {
        self.pending.is_none()
    }
}

#[derive(Debug)]
struct Liveness {
    /// The last real contact (a connection or a message). `None` for a node only seen at boot.
    last_seen: Option<OffsetDateTime>,
    /// The boot grace (§6 "Server restart"): the node does not expire before `lease_ttl_s` after this. Never a contact.
    grace_from: Option<OffsetDateTime>,
    /// When `last_seen` was last written to SQLite.
    flushed: OffsetDateTime,
    session: Option<Session>,
}

impl Liveness {
    fn contact(now: OffsetDateTime) -> Self {
        Self {
            last_seen: Some(now),
            grace_from: None,
            flushed: now,
            session: None,
        }
    }

    /// What the TTL counts from: the later of the last contact and the boot grace.
    fn expiry_base(&self) -> OffsetDateTime {
        match (self.last_seen, self.grace_from) {
            (Some(a), Some(b)) => a.max(b),
            (Some(a), None) | (None, Some(a)) => a,
            // Never built: every entry has a contact or a grace.
            (None, None) => OffsetDateTime::UNIX_EPOCH,
        }
    }
}

#[derive(Debug, Default)]
struct State {
    nodes: HashMap<NodeId, Liveness>,
    next_id: u64,
}

/// A node whose TTL expired, as returned by [`NodeHub::take_expired`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expired {
    /// The node.
    pub node_id: NodeId,
    /// Its last real contact since the boot; `None` when it was only covered by the boot grace (its last contact is
    /// then the one already stored in `nodes.last_seen_at`).
    pub last_seen: Option<OffsetDateTime>,
    /// The boot grace it had, if any (so [`NodeHub::restore_expired`] puts it back exactly).
    pub grace_from: Option<OffsetDateTime>,
}

/// A registered connection. Pass it back to [`NodeHub::unregister`] when the connection ends.
#[derive(Debug)]
pub struct Registration {
    /// The node.
    pub node_id: NodeId,
    id: u64,
}

/// The cloneable handle. Cheap to clone; every clone sees the same connections.
#[derive(Debug, Clone)]
pub struct NodeHub {
    state: Arc<Mutex<State>>,
    events: broadcast::Sender<HubEvent>,
    node_events: Arc<std::sync::RwLock<Arc<dyn super::NodeEvents>>>,
}

impl Default for NodeHub {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeHub {
    /// An empty hub.
    #[must_use]
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            state: Arc::new(Mutex::new(State::default())),
            events,
            node_events: Arc::new(std::sync::RwLock::new(Arc::new(super::DropNodeEvents))),
        }
    }

    /// Installs the [`super::NodeEvents`] handler (the gateway does, at start), shared by every clone of the hub, so
    /// the REST handlers reach it too.
    pub fn set_node_events(&self, events: Arc<dyn super::NodeEvents>) {
        *self.node_events.write().unwrap_or_else(PoisonError::into_inner) = events;
    }

    /// The installed [`super::NodeEvents`] handler.
    #[must_use]
    pub fn node_events(&self) -> Arc<dyn super::NodeEvents> {
        self.node_events.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `msg` for `node_id` without waiting. For a session not yet activated, the message is buffered and goes
    /// out right after its `Welcome`.
    pub fn send(&self, node_id: NodeId, msg: ServerMsg) -> Result<(), SendError> {
        let mut state = self.lock();
        let session = state
            .nodes
            .get_mut(&node_id)
            .and_then(|l| l.session.as_mut())
            .ok_or(SendError::NotConnected)?;
        if let Some(buffer) = session.pending.as_mut() {
            if buffer.len() >= OUTGOING_QUEUE {
                return Err(SendError::Full);
            }
            buffer.push(msg);
            return Ok(());
        }
        session.tx.try_send(msg).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SendError::Full,
            mpsc::error::TrySendError::Closed(_) => SendError::NotConnected,
        })
    }

    /// The live, activated connection of `node_id`, to open one hub-opened port stream on (H2 §6.1), with one of
    /// the connection's [`MAX_PORT_STREAMS_PER_CONNECTION`] places: the stream holds the permit for its life. A
    /// pending connection gives none: its agent has not been welcomed yet.
    pub fn port_stream(&self, node_id: NodeId) -> Result<(Connection, OwnedSemaphorePermit), PortStreamError> {
        let state = self.lock();
        let session = state
            .nodes
            .get(&node_id)
            .and_then(|l| l.session.as_ref())
            .filter(|s| s.is_active())
            .ok_or(PortStreamError::NotConnected)?;
        let permit = session
            .port_streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| PortStreamError::TooMany)?;
        Ok((session.conn.clone(), permit))
    }

    /// Whether `node_id` has a live, activated connection.
    #[must_use]
    pub fn is_connected(&self, node_id: NodeId) -> bool {
        self.lock()
            .nodes
            .get(&node_id)
            .and_then(|l| l.session.as_ref())
            .is_some_and(Session::is_active)
    }

    /// Whether `node_id` has a connection, pending or active.
    #[must_use]
    pub fn has_session(&self, node_id: NodeId) -> bool {
        self.lock().nodes.get(&node_id).is_some_and(|l| l.session.is_some())
    }

    /// Connect and disconnect events from now on.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<HubEvent> {
        self.events.subscribe()
    }

    /// Registers the connection of `node_id`, seen at `now`, as pending (see the module docs). An older connection of
    /// the same node is closed.
    pub fn register(
        &self,
        node_id: NodeId,
        conn: Connection,
        tx: mpsc::Sender<ServerMsg>,
        now: OffsetDateTime,
    ) -> Registration {
        let old = {
            let mut state = self.lock();
            state.next_id += 1;
            let id = state.next_id;
            let entry = state.nodes.entry(node_id).or_insert_with(|| Liveness::contact(now));
            entry.last_seen = Some(entry.last_seen.map_or(now, |s| s.max(now)));
            let old = entry.session.replace(Session {
                id,
                tx,
                conn,
                pending: Some(Vec::new()),
                port_streams: Arc::new(Semaphore::new(MAX_PORT_STREAMS_PER_CONNECTION)),
            });
            (old, id)
        };
        let (old, id) = old;
        if let Some(old) = old {
            old.conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"replaced");
            if old.is_active() {
                let _ = self.events.send(HubEvent::Disconnected(node_id));
            }
        }
        Registration { node_id, id }
    }

    /// Activates the pending connection of `reg`: queues `first` (the `Welcome` and what follows it), then the
    /// messages buffered since [`NodeHub::register`]. `false` when `reg` is no longer the node's connection (replaced,
    /// deleted or expired), or its queue is full or closed; the caller then closes the connection.
    pub fn activate(&self, reg: &Registration, first: Vec<ServerMsg>) -> bool {
        {
            let mut state = self.lock();
            let Some(session) = state
                .nodes
                .get_mut(&reg.node_id)
                .and_then(|l| l.session.as_mut())
                .filter(|s| s.id == reg.id)
            else {
                return false;
            };
            let buffered = session.pending.take().unwrap_or_default();
            if !first
                .into_iter()
                .chain(buffered)
                .all(|m| session.tx.try_send(m).is_ok())
            {
                return false;
            }
        }
        let _ = self.events.send(HubEvent::Connected(reg.node_id));
        true
    }

    /// The connection of `reg` ended. Returns the node's last contact when `reg` was still its current connection
    /// (a replaced connection returns `None`). The node stays in the liveness table until its TTL passes. A
    /// registered connection is a contact, so the last contact is always known here.
    ///
    /// It emits no event: the caller records the disconnection first, then calls [`NodeHub::notify_disconnected`], so
    /// a subscriber that sees `Disconnected` also sees the disconnection recorded.
    pub fn unregister(&self, reg: &Registration) -> Option<OffsetDateTime> {
        let mut state = self.lock();
        let entry = state.nodes.get_mut(&reg.node_id)?;
        if entry.session.as_ref().map(|s| s.id) != Some(reg.id) {
            return None;
        }
        entry.session = None;
        entry.last_seen
    }

    /// Emits [`HubEvent::Disconnected`] for a session that ended (after [`NodeHub::unregister`] and its bookkeeping).
    pub fn notify_disconnected(&self, node_id: NodeId) {
        let _ = self.events.send(HubEvent::Disconnected(node_id));
    }

    /// Removes `reg`'s node from the hub altogether (its liveness entry too), without closing the connection, when
    /// `reg` is still its connection. For a session that found its node deleted: it answers `not_enrolled` itself, and
    /// the sweep must never see the node again (no `Lost` after `Deleted`). A newer connection, if any, is left to
    /// make the same discovery.
    pub fn forget(&self, reg: &Registration) {
        let mut state = self.lock();
        if state
            .nodes
            .get(&reg.node_id)
            .and_then(|l| l.session.as_ref())
            .is_some_and(|s| s.id == reg.id)
        {
            state.nodes.remove(&reg.node_id);
        }
    }

    /// Puts an expired node back in the liveness table, unless the node is tracked again already. The sweep does
    /// this when it could not record the node going offline, so the next sweep retries.
    pub fn restore_expired(&self, expired: Expired) {
        self.lock().nodes.entry(expired.node_id).or_insert(Liveness {
            last_seen: expired.last_seen,
            grace_from: expired.grace_from,
            flushed: expired
                .last_seen
                .or(expired.grace_from)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            session: None,
        });
    }

    /// Records contact from `node_id` at `now`. Returns `true` when `last_seen` should be written to SQLite (at most
    /// every `flush_every`), and then counts it as written.
    pub fn touch(&self, node_id: NodeId, now: OffsetDateTime, flush_every: Duration) -> bool {
        let mut state = self.lock();
        let Some(entry) = state.nodes.get_mut(&node_id) else {
            return false;
        };
        entry.last_seen = Some(entry.last_seen.map_or(now, |s| s.max(now)));
        if now - entry.flushed >= flush_every {
            entry.flushed = now;
            true
        } else {
            false
        }
    }

    /// The last real contact of `node_id` since the boot, if the hub tracks it and the node talked. The boot grace is
    /// not a contact: a node only covered by it gives `None`.
    #[must_use]
    pub fn last_seen(&self, node_id: NodeId) -> Option<OffsetDateTime> {
        self.lock().nodes.get(&node_id).and_then(|l| l.last_seen)
    }

    /// Gives `nodes` the boot grace (§6 "Server restart"): none of them expires before `lease_ttl_s` after `now`. It
    /// is an expiry deadline only, never recorded as a contact.
    pub fn seen_at_boot(&self, nodes: &[NodeId], now: OffsetDateTime) {
        let mut state = self.lock();
        for id in nodes {
            state.nodes.entry(*id).or_insert(Liveness {
                last_seen: None,
                grace_from: Some(now),
                flushed: now,
                session: None,
            });
        }
    }

    /// Removes and returns every node whose last contact is `ttl` or more before `now`, closing its connection.
    pub fn take_expired(&self, now: OffsetDateTime, ttl: Duration) -> Vec<Expired> {
        let removed: Vec<(NodeId, Liveness)> = {
            let mut state = self.lock();
            let ids: Vec<NodeId> = state
                .nodes
                .iter()
                .filter(|(_, l)| now - l.expiry_base() >= ttl)
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| state.nodes.remove(&id).map(|l| (id, l)))
                .collect()
        };
        removed
            .into_iter()
            .map(|(node_id, l)| {
                if let Some(s) = l.session {
                    s.conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"expired");
                    if s.is_active() {
                        let _ = self.events.send(HubEvent::Disconnected(node_id));
                    }
                }
                Expired {
                    node_id,
                    last_seen: l.last_seen,
                    grace_from: l.grace_from,
                }
            })
            .collect()
    }

    /// Forgets `node_id` and closes its connection, pending or active (`DELETE /v1/nodes/{id}`).
    ///
    /// Ordering (see the module docs): the caller has **already committed** `deleted_at`. A session that registers
    /// after this call re-reads the row and sees the deletion; one registered before is closed here.
    pub fn disconnect(&self, node_id: NodeId) {
        let removed = self.lock().nodes.remove(&node_id);
        if let Some(s) = removed.and_then(|l| l.session) {
            s.conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"deleted");
            if s.is_active() {
                let _ = self.events.send(HubEvent::Disconnected(node_id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const T: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);

    #[test]
    fn boot_grace_expires_only_after_the_ttl() {
        let hub = NodeHub::new();
        let a = NodeId::generate();
        hub.seen_at_boot(&[a], T);
        assert!(!hub.is_connected(a));
        assert_eq!(hub.send(a, ServerMsg::Drain {}), Err(SendError::NotConnected));
        assert!(
            hub.take_expired(T + Duration::seconds(59), Duration::seconds(60))
                .is_empty()
        );
        let gone = hub.take_expired(T + Duration::seconds(60), Duration::seconds(60));
        assert_eq!(
            gone,
            vec![Expired {
                node_id: a,
                last_seen: None,
                grace_from: Some(T),
            }]
        );
        assert_eq!(hub.last_seen(a), None);
    }

    #[test]
    fn touch_flushes_at_most_every_interval() {
        let hub = NodeHub::new();
        let a = NodeId::generate();
        assert!(!hub.touch(a, T, Duration::seconds(15)), "unknown nodes are ignored");
        hub.seen_at_boot(&[a], T);
        assert_eq!(hub.last_seen(a), None, "the boot grace is not a contact");
        assert!(!hub.touch(a, T + Duration::seconds(5), Duration::seconds(15)));
        assert!(hub.touch(a, T + Duration::seconds(15), Duration::seconds(15)));
        assert!(!hub.touch(a, T + Duration::seconds(20), Duration::seconds(15)));
        assert_eq!(hub.last_seen(a), Some(T + Duration::seconds(20)));
        // The clock never moves last_seen backwards.
        hub.touch(a, T, Duration::seconds(15));
        assert_eq!(hub.last_seen(a), Some(T + Duration::seconds(20)));
    }
}
