// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc/agent/1`: one control stream per connection (spec §6).
//!
//! A connection's first bidirectional stream is its control stream, read with the `p2pc-proto` codec. Every frame
//! is size-limited, decoded under a global cap on concurrent decodes, and validated; a malformed frame closes the
//! connection (SI-10). All writes go through one writer task, so replies and [`NodeHub::send`] never interleave.
//!
//! - **Unknown NodeIds** (not enrolled, or deleted) may send exactly one `Join`, within the first-message timeout,
//!   in a frame of at most 64 KiB. They are capped at 64 connections and 16 pending `Join`s, and failed `Join`s are
//!   rate-limited per NodeId and in total. Beyond any limit the connection is closed with no detail. A `Hello` gets
//!   `Error{not_enrolled}`, the same bytes whether or not the NodeId was ever enrolled.
//! - **Enrolled NodeIds** start with `Hello` (or retry their `Join`, which is idempotent), then heartbeat.
//!
//! [`NodeHub::send`]: super::NodeHub::send

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use p2pc_proto::api::{AuditKind, Inventory};
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{AccountId, NodeId};
use p2pc_proto::protocol::{
    AgentMsg, FrameError, MAX_FRAME_LEN, PRE_JOIN_MAX_FRAME_LEN, RunningLease, ServerMsg, error_code, read_frame_bytes,
    write_frame,
};
use serde_json::json;
use time::OffsetDateTime;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio::task::JoinHandle;

use super::Inner;
use super::hub::{CLOSE_BY_SERVER, OUTGOING_QUEUE, Registration};
use crate::store::audit::NewEvent;
use crate::store::nodes::{DisconnectOutcome, NewNode, NodeRow};
use crate::store::{self, StoreError};

/// Subject of the aggregated `auth_failed` audit rows of failed `Join`s.
pub const JOIN_FAILURE_SUBJECT: &str = "join";

/// Fixed messages of the `Error`s the gateway sends. `not_enrolled` is identical for every NodeId (§5 "Deletion").
const NOT_ENROLLED_MESSAGE: &str = "this node is not enrolled; join it with a join token";
const INVALID_TOKEN_MESSAGE: &str = "the join token is not valid";
const AGENT_TOO_OLD_MESSAGE: &str = "the agent is older than the server's min_agent_version; upgrade it";
const UNSUPPORTED_MESSAGE: &str = "unsupported message type";

fn error(code: &str, message: &str) -> ServerMsg {
    ServerMsg::Error {
        code: code.to_string(),
        message: message.to_string(),
    }
}

/// The `Error{not_enrolled}` every non-enrolled NodeId gets, byte for byte.
pub fn not_enrolled() -> ServerMsg {
    error(error_code::NOT_ENROLLED, NOT_ENROLLED_MESSAGE)
}

/// One connection's control stream: a reader, and the queue of the writer task.
struct Control {
    conn: Connection,
    recv: RecvStream,
    tx: mpsc::Sender<ServerMsg>,
    writer: JoinHandle<()>,
}

impl Control {
    /// Queues a message. A full queue means the agent does not read: close.
    fn send(&self, msg: ServerMsg) -> bool {
        self.tx.try_send(msg).is_ok()
    }

    /// Sends `msg`, waits (bounded) for the writer to flush it and the peer to read it, then closes.
    async fn send_and_close(self, inner: &Inner, msg: ServerMsg) {
        let Control { conn, tx, writer, .. } = self;
        let _ = tx.try_send(msg);
        drop(tx);
        let _ = tokio::time::timeout(inner.limits.final_message_grace, writer).await;
        conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
    }

    /// Lets the writer flush what is already queued (bounded by the final-message grace), then closes. Call it after
    /// the hub's copy of the queue is gone (`end`), so dropping this one ends the writer.
    async fn flush_and_close(self, inner: &Inner) {
        let Control { conn, tx, writer, .. } = self;
        drop(tx);
        let _ = tokio::time::timeout(inner.limits.final_message_grace, writer).await;
        conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
    }

    /// Closes at once, with no detail.
    fn close(self) {
        self.writer.abort();
        self.conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
    }
}

async fn writer(mut send: SendStream, mut rx: mpsc::Receiver<ServerMsg>, grace: std::time::Duration) {
    while let Some(msg) = rx.recv().await {
        if write_frame(&mut send, &msg).await.is_err() {
            return;
        }
    }
    // The queue is closed: finish the stream and give the peer a moment to read the last frame.
    if send.finish().is_ok() {
        let _ = tokio::time::timeout(grace, send.stopped()).await;
    }
}

/// Why a frame could not be taken from the stream.
enum Read {
    Msg(Box<AgentMsg>),
    /// Clean end of the stream.
    End,
    /// Oversize, truncated, malformed or invalid: close (SI-10).
    Bad,
}

async fn read_msg(inner: &Inner, recv: &mut RecvStream, limit: u32) -> Read {
    let body = match read_frame_bytes(recv, limit).await {
        Ok(Some(body)) => body,
        Ok(None) => return Read::End,
        Err(FrameError::TooLarge { len, max }) => {
            tracing::debug!(len, max, "agent frame over the limit");
            return Read::Bad;
        }
        Err(_) => return Read::Bad,
    };
    // The costly part, under the global cap.
    let Some(decoded) = inner.decodes.decode::<AgentMsg>(&body).await else {
        return Read::Bad;
    };
    match decoded {
        Ok(msg) if msg.validate().is_ok() => Read::Msg(Box::new(msg)),
        Ok(msg) => {
            tracing::debug!(kind = msg.kind(), "agent message fails validation");
            Read::Bad
        }
        Err(e) => {
            tracing::debug!(error = %e, "malformed agent frame");
            Read::Bad
        }
    }
}

/// Handles one `p2pc/agent/1` connection until it ends.
pub(super) async fn handle(inner: Arc<Inner>, conn: Connection) {
    let iroh_id = conn.remote_id().to_string();
    let enrolled = match lookup(&inner, &iroh_id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "cannot look up an agent");
            conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
            return;
        }
    };
    // At most this many connections at once per enrolled node: a NodeId cannot hold an unbounded number open.
    let _per_node = match &enrolled {
        Some(node) => match PerNodeSlot::take(&inner, node.id) {
            Some(slot) => Some(slot),
            None => {
                tracing::debug!(node_id = %node.id, "agent connection refused: too many for this node");
                conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
                return;
            }
        },
        None => None,
    };
    // §6 "Before Join": at most this many connections from NodeIds that are not enrolled.
    let unknown_permit = if enrolled.is_none() {
        match inner.unknown_connections.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
                return;
            }
        }
    } else {
        None
    };
    // §6: one deadline for the control stream **and** its first message, counted from the handshake.
    let deadline = tokio::time::Instant::now() + inner.limits.first_message_timeout;
    let (send, recv) = match tokio::time::timeout_at(deadline, conn.accept_bi()).await {
        Ok(Ok(streams)) => streams,
        _ => {
            conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
            return;
        }
    };
    let (tx, rx) = mpsc::channel(OUTGOING_QUEUE);
    let writer = tokio::spawn(writer(send, rx, inner.limits.final_message_grace));
    let mut control = Control { conn, recv, tx, writer };
    let limit = if enrolled.is_some() {
        MAX_FRAME_LEN
    } else {
        PRE_JOIN_MAX_FRAME_LEN
    };
    // One message, within the deadline: `Join` (anyone) or `Hello` (enrolled only).
    let msg = match tokio::time::timeout_at(deadline, read_msg(&inner, &mut control.recv, limit)).await {
        Ok(Read::Msg(msg)) => *msg,
        _ => return control.close(),
    };
    let (node, reenrolled) = match msg {
        AgentMsg::Join { token, inventory } => {
            match join(&inner, &iroh_id, &token, &inventory, unknown_permit.is_some()).await {
                Joined::Node(node, reenrolled) => (*node, reenrolled),
                Joined::InvalidToken => {
                    return control
                        .send_and_close(&inner, error(error_code::INVALID_TOKEN, INVALID_TOKEN_MESSAGE))
                        .await;
                }
                Joined::Refused => return control.close(),
            }
        }
        AgentMsg::Hello {
            agent_version,
            inventory,
            running,
            features,
        } => {
            let Some(node) = enrolled else {
                return control.send_and_close(&inner, not_enrolled()).await;
            };
            if !version_ok(&agent_version, &inner.min_agent_version) {
                return control
                    .send_and_close(&inner, error(error_code::AGENT_TOO_OLD, AGENT_TOO_OLD_MESSAGE))
                    .await;
            }
            let online = Online::Hello {
                inventory: Box::new(inventory),
                agent_version,
                features,
            };
            // Reconciled inside `session`, once the node is registered, online and activated (see there).
            return session(inner, control, node, online, Some(running)).await;
        }
        _ => return control.close(),
    };
    // A successful `Join`: the NodeId is enrolled now and no longer counts as unknown.
    drop(unknown_permit);
    // A first enrolment holds no lease. A re-enrolled node (`join --force`) runs nothing either: it is reconciled like
    // a fresh `Hello` with no running lease, so a lease the server still holds for it is lost at once instead of
    // keeping its reservation until the agent's next `Hello`.
    let running = reenrolled.then(Vec::new);
    session(inner, control, node, Online::Joined, running).await;
}

/// The `online` write a session makes after `register`.
enum Online {
    /// After `Hello`: also the inventory, version and features.
    Hello {
        inventory: Box<Inventory>,
        agent_version: String,
        features: Vec<String>,
    },
    /// After a `Join`, whose inventory the enrollment already stored.
    Joined,
}

impl Online {
    /// Marks the node online. `Some(draining)` while it is live, `None` when it was deleted.
    async fn write(&self, inner: &Inner, node_id: NodeId, now: OffsetDateTime) -> Result<Option<bool>, StoreError> {
        let mut conn = inner.state.db.acquire().await?;
        match self {
            Online::Hello {
                inventory,
                agent_version,
                features,
            } => store::nodes::mark_online(&mut conn, node_id, inventory, agent_version, features, now).await,
            Online::Joined => store::nodes::mark_connected(&mut conn, node_id, now).await,
        }
    }
}

async fn lookup(inner: &Inner, iroh_id: &str) -> Result<Option<NodeRow>, StoreError> {
    let mut conn = inner.state.db.acquire().await?;
    store::nodes::find_live_by_iroh_id(&mut conn, iroh_id).await
}

/// Whether `agent_version` (semver) is at least `min`. An unparsable version is too old.
fn version_ok(agent_version: &str, min: &semver::Version) -> bool {
    semver::Version::parse(agent_version).is_ok_and(|v| v >= *min)
}

/// The result of a `Join`.
enum Joined {
    /// Enrolled now, or earlier by this same NodeId with this token (the idempotent retry).
    /// The node, and whether this `Join` re-enrolled a live node (§5 "Re-enrolling the same machine").
    Node(Box<NodeRow>, bool),
    /// The token does not enroll this NodeId: `Error{invalid_token}`.
    InvalidToken,
    /// Over a limit (failure rate, pending `Join`s) or a storage error: close with no detail.
    Refused,
}

/// Runs a `Join` (§5, SI-11). A NodeId over its failure budget, or a `Join` beyond the pending cap, is refused
/// without the token being looked at.
async fn join(inner: &Inner, iroh_id: &str, token: &JoinToken, inventory: &Inventory, unknown: bool) -> Joined {
    let now = inner.state.clock.now();
    if !inner.join_failures().allows(iroh_id, now) {
        tracing::debug!("join refused: failure rate limit");
        return Joined::Refused;
    }
    // §6: at most this many `Join`s in progress from unknown NodeIds.
    let permit: Option<OwnedSemaphorePermit> = if unknown {
        match inner.pending_joins.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => return Joined::Refused,
        }
    } else {
        None
    };
    let result = enroll(inner, iroh_id, token, inventory, now).await;
    drop(permit);
    match result {
        Ok(Some((node, reenrolled))) => Joined::Node(Box::new(node), reenrolled),
        Ok(None) => {
            inner.join_failures().record(iroh_id, now);
            if let Some(owner) = inner.state.owner_account {
                inner
                    .state
                    .auth_failures
                    .record(owner, JOIN_FAILURE_SUBJECT.to_string(), now);
            }
            Joined::InvalidToken
        }
        Err(e) => {
            tracing::warn!(error = %e, "join failed on a storage error");
            Joined::Refused
        }
    }
}

/// The transaction of a `Join`: the node, and whether it was a live node re-enrolled. `Ok(None)` means "invalid
/// token" (nothing changed).
async fn enroll(
    inner: &Inner,
    iroh_id: &str,
    token: &JoinToken,
    inventory: &Inventory,
    now: OffsetDateTime,
) -> Result<Option<(NodeRow, bool)>, StoreError> {
    let digest = token.code_hash();
    let mut tx = store::begin_immediate(&inner.state.db).await?;
    // 1. Look the row up by the digest, then compare in constant time.
    let row = match store::join_tokens::find_by_digest(&mut tx, &digest).await? {
        Some(row) if row.code_digest.ct_eq(&digest) => row,
        _ => {
            std::hint::black_box(digest.ct_eq(&inner.state.dummy_digest));
            return Ok(None);
        }
    };
    // 2. An already-consumed token: the same NodeId gets the same Welcome again, anyone else is refused.
    if let Some(consumed_by) = row.consumed_by_node_id {
        let node = store::nodes::by_id(&mut tx, consumed_by).await?;
        return Ok(node
            .filter(|n| n.deleted_at.is_none() && n.iroh_node_id == iroh_id)
            .map(|n| (n, false)));
    }
    // 3. The row's own expiry and revocation, never the payload's.
    if !row.is_redeemable(now) {
        return Ok(None);
    }
    // 4. A NodeId that is already a live node (`join --force` with a new token, §5 "Re-enrolling the same machine"):
    //    re-enrolled when the token's account owns it, refused like an invalid token otherwise.
    if let Some(live) = store::nodes::find_live_by_iroh_id(&mut tx, iroh_id).await? {
        if live.account_id != row.account_id {
            return Ok(None);
        }
        let Some(node) =
            store::nodes::reenroll(&mut tx, row.account_id, live.id, row.project_id, inventory, row.id).await?
        else {
            return Ok(None);
        };
        // Atomic like a first enrolment: of two concurrent joins with one token, only one consumes it.
        if !store::join_tokens::consume(&mut tx, &digest, node.id, now).await? {
            return Ok(None);
        }
        audit(
            &mut tx,
            row.account_id,
            AuditKind::JoinTokenConsumed,
            row.id.to_string(),
            json!({"node_id": node.id}),
            now,
        )
        .await?;
        audit(
            &mut tx,
            row.account_id,
            AuditKind::NodeReenrolled,
            node.id.to_string(),
            json!({"name": node.name, "join_token_id": row.id, "iroh_node_id": iroh_id}),
            now,
        )
        .await?;
        tx.commit().await?;
        tracing::info!(node_id = %node.id, name = %node.name, "node re-enrolled");
        return Ok(Some((node, true)));
    }
    // 5. Insert the node (account and project from the token row only), then consume the token atomically.
    let new = NewNode {
        id: NodeId::generate(),
        account_id: row.account_id,
        project_id: row.project_id,
        iroh_node_id: iroh_id.to_string(),
        inventory: inventory.clone(),
        token_id: row.id,
    };
    let node = store::nodes::insert(&mut tx, &new, now).await?;
    if !store::join_tokens::consume(&mut tx, &digest, node.id, now).await? {
        // Lost a race: the transaction is dropped, so the node row goes too.
        return Ok(None);
    }
    audit(
        &mut tx,
        row.account_id,
        AuditKind::JoinTokenConsumed,
        row.id.to_string(),
        json!({"node_id": node.id}),
        now,
    )
    .await?;
    audit(
        &mut tx,
        row.account_id,
        AuditKind::NodeEnrolled,
        node.id.to_string(),
        json!({"name": node.name, "join_token_id": row.id, "iroh_node_id": iroh_id}),
        now,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(node_id = %node.id, name = %node.name, "node enrolled");
    Ok(Some((node, false)))
}

async fn audit(
    conn: &mut store::Conn,
    account: AccountId,
    kind: AuditKind,
    subject: String,
    detail: serde_json::Value,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let event = NewEvent {
        kind,
        actor_key_id: None,
        subject_id: Some(subject),
        detail: match detail {
            serde_json::Value::Object(map) => map,
            _ => serde_json::Map::new(),
        },
    };
    store::audit::append(conn, account, &event, now).await.map(|_| ())
}

/// One of the at most `max_connections_per_node` agent connections of an enrolled node; released on drop.
struct PerNodeSlot {
    inner: Arc<Inner>,
    node_id: NodeId,
}

impl PerNodeSlot {
    fn take(inner: &Arc<Inner>, node_id: NodeId) -> Option<Self> {
        let mut map = inner.agent_connections();
        let count = map.entry(node_id).or_insert(0);
        if *count >= inner.limits.max_connections_per_node {
            return None;
        }
        *count += 1;
        drop(map);
        Some(Self {
            inner: inner.clone(),
            node_id,
        })
    }
}

impl Drop for PerNodeSlot {
    fn drop(&mut self) {
        let mut map = self.inner.agent_connections();
        if let Some(count) = map.get_mut(&self.node_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.node_id);
            }
        }
    }
}

/// An enrolled node's connection: registered in the hub, marked online, then welcomed.
///
/// **Register first, write `online` after.** That one write orders the session against both other writers:
/// - `DELETE /v1/nodes/{id}` commits `deleted_at` and only then calls `NodeHub::disconnect`. If the write finds no live
///   row, the node was deleted: the session drops its hub entry and answers `not_enrolled`. Otherwise the deletion
///   commits later, and its disconnect finds this registration (both hub calls take the hub's lock) and closes it. No
///   tombstone is needed.
/// - The liveness sweep decides inside its `BEGIN IMMEDIATE` transaction, with `NodeHub::has_session`. Either that
///   check runs after `register`, sees the session and writes nothing; or it ran before, and then its `offline`
///   commit precedes this write (SQLite has one writer, and this write starts after `register`), so `online`
///   overrides it. Either way the row ends `online` while the session lives. In the second case the sweep did fire
///   `OfflineReason::Lost`: the node really had no contact for `lease_ttl_s`, and this `Hello` reconciles its leases.
///
/// The write also returns `draining`, read after `register`: a drain committed before it is in the result, one
/// committed after it reaches the registration (buffered until `activate`).
///
/// **Lease reconciliation runs last** (T05 review), after `register`, the `online` write and `activate`, with the
/// `running` list of the `Hello` (`None` after a `Join`, which has no leases). What a `Lost` the sweep decided before
/// this session's `online` write does, depending on when the scheduler applies it (`Scheduler::node_offline`):
/// - **before** the `online` write commits: the node row is still `offline` and the session not yet activated, so
///   the scheduler loses the node's leases and sends a `Cancel` for each through
///   [`NodeHub::send`](super::NodeHub::send), which buffers them for this registered session; they go out right after
///   the `Welcome`. The reconciliation then finds those leases lost and answers `Cancel` for any the `Hello` lists.
/// - **after** it: the scheduler's own guard sees the node `online` and connected, and does nothing. The
///   reconciliation decides alone: listed current leases continue, absent ones are lost at once.
///
/// Either way a lease the server considers lost is cancelled on the agent, and a lease the agent still runs and the
/// server still holds is not lost after the agent came back. The `Cancel`s go after the `Welcome` (queued by
/// `activate`), on the same ordered queue.
///
/// A reconciliation that fails (a database error) closes the session with nothing sent: the agent reconnects and
/// reconciles again, and no healthy lease is cancelled for a server-side failure (§6 "Server restart").
///
/// Every session of a node that is not draining, after a `Join` or a `Hello`, is an eligible node changing (it joined,
/// connected or reconnected), so it re-arms the offer cap of the account's queued jobs (§8, `scheduler::node_changed`).
async fn session(
    inner: Arc<Inner>,
    mut control: Control,
    node: NodeRow,
    online: Online,
    running: Option<Vec<RunningLease>>,
) {
    let now = inner.state.clock.now();
    let reg = inner
        .hub()
        .register(node.id, control.conn.clone(), control.tx.clone(), now);
    let draining = match online.write(&inner, node.id, now).await {
        Ok(Some(draining)) => draining,
        // Deleted: same answer as for any NodeId that is not enrolled, and no hub entry is left behind for the sweep
        // (so a deleted node never gets `Lost` after `Deleted`).
        Ok(None) => {
            inner.hub().forget(&reg);
            return control.send_and_close(&inner, not_enrolled()).await;
        }
        Err(e) => {
            tracing::warn!(error = %e, node_id = %node.id, "cannot mark a node online");
            inner.hub().unregister(&reg);
            return control.close();
        }
    };
    let mut first = vec![ServerMsg::Welcome {
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        node_id: node.id,
        account_id: node.account_id,
        heartbeat_interval_s: inner.state.config.nodes.heartbeat_interval_s,
        lease_ttl_s: inner.state.config.nodes.lease_ttl_s,
    }];
    // The drain request survives reconnects.
    if draining {
        first.push(ServerMsg::Drain {});
    }
    if !inner.hub().activate(&reg, first) {
        inner.hub().unregister(&reg);
        return control.close();
    }
    if let Some(running) = running {
        let Ok(replies) = inner.reconciler.reconcile(node.id, &running).await else {
            tracing::warn!(node_id = %node.id, "closing the session: its leases could not be reconciled");
            end(&inner, &reg).await;
            // The `Welcome` is already queued: flush it, so the agent learns the server is alive before it reconnects,
            // and never sees a bare close race ahead of it.
            return control.flush_and_close(&inner).await;
        };
        if !replies.into_iter().all(|m| control.send(m)) {
            // The agent does not read its queue: end the session like any other that stops reading.
            end(&inner, &reg).await;
            return control.close();
        }
    }
    // A node that joined, connected or reconnected is an eligible node changing, which re-arms the offer cap (§8);
    // a draining one is not eligible, so it re-arms nothing until it is resumed (review P3).
    if draining {
        inner.state.kick.kick();
    } else {
        crate::scheduler::node_changed(&inner.state.db, &inner.state.kick, node.account_id).await;
    }
    // A reconciliation that requeued leases resolved the disconnection as `requeued` already; this is a no-op then.
    if let Ok(mut c) = inner.state.db.acquire().await {
        let _ = store::nodes::resolve_disconnection(&mut c, node.id, DisconnectOutcome::Recovered, now).await;
    }
    tracing::info!(node_id = %node.id, "node connected");
    // Every further bidirectional stream is an output upload (§6 "Uploads"), fenced by its own header.
    let uploads = tokio::spawn(super::upload::accept(inner.clone(), control.conn.clone(), node.id));
    run(&inner, &mut control, &node).await;
    uploads.abort();
    end(&inner, &reg).await;
    control.close();
}

async fn run(inner: &Inner, control: &mut Control, node: &NodeRow) {
    let node_id = node.id;
    loop {
        let msg = match read_msg(inner, &mut control.recv, MAX_FRAME_LEN).await {
            Read::Msg(m) => *m,
            Read::End | Read::Bad => return,
        };
        let reply = match msg {
            AgentMsg::Heartbeat { seq, running, .. } => {
                let now = inner.state.clock.now();
                if inner.hub().touch(node_id, now, inner.limits.last_seen_flush)
                    && let Ok(mut c) = inner.state.db.acquire().await
                    && let Err(e) = store::nodes::touch_last_seen(&mut c, node_id, now).await
                {
                    tracing::debug!(error = %e, %node_id, "cannot flush last_seen");
                }
                // What the node no longer holds is freed before the ack (§8 "Reservations are held until confirmed").
                inner.events.on_heartbeat(node_id, &running).await;
                Some(ServerMsg::HeartbeatAck { seq })
            }
            AgentMsg::InventoryUpdate { inventory } => {
                inner
                    .hub()
                    .touch(node_id, inner.state.clock.now(), inner.limits.last_seen_flush);
                let update = match inner.state.db.acquire().await {
                    Ok(mut c) => store::nodes::update_inventory(&mut c, node_id, &inventory)
                        .await
                        .map_err(|e| tracing::warn!(error = %e, %node_id, "cannot store an inventory update"))
                        .ok()
                        .flatten(),
                    Err(e) => {
                        tracing::warn!(error = %e, "cannot store an inventory update");
                        None
                    }
                };
                // The offered capacity may have changed (§6 `InventoryUpdate`). Only a real change on a node that is
                // not draining is an eligible node changing, which re-arms the offer cap (§8, review P3).
                match update {
                    Some(u) if u.changed && !u.draining => {
                        crate::scheduler::node_changed(&inner.state.db, &inner.state.kick, node.account_id).await;
                    }
                    Some(u) if u.changed => inner.state.kick.kick(),
                    _ => {}
                }
                None
            }
            msg @ (AgentMsg::LeaseAccepted { .. }
            | AgentMsg::LeaseRejected { .. }
            | AgentMsg::JobStarted { .. }
            | AgentMsg::LogChunk { .. }
            | AgentMsg::JobFinished { .. }) => {
                inner
                    .hub()
                    .touch(node_id, inner.state.clock.now(), inner.limits.last_seen_flush);
                inner.events.on_message(node_id, msg).await;
                None
            }
            AgentMsg::Unknown => Some(error(error_code::UNSUPPORTED_MESSAGE, UNSUPPORTED_MESSAGE)),
            // One `Join` or `Hello` per connection.
            AgentMsg::Join { .. } | AgentMsg::Hello { .. } => return,
        };
        if let Some(reply) = reply
            && !control.send(reply)
        {
            return;
        }
    }
}

/// The connection ended: flush `last_seen` and open a disconnection (resolved when the node comes back, or when its
/// TTL expires). A replaced connection does nothing: its successor owns the node.
async fn end(inner: &Inner, reg: &Registration) {
    let Some(last_seen) = inner.hub().unregister(reg) else {
        return;
    };
    let node_id = reg.node_id;
    tracing::info!(%node_id, "node disconnected");
    let result = async {
        let mut tx = store::begin_immediate(&inner.state.db).await?;
        store::nodes::touch_last_seen(&mut tx, node_id, last_seen).await?;
        // A newer connection already registered: the node is online, so no disconnection is open for it.
        if !inner.hub().has_session(node_id) {
            store::nodes::open_disconnection(&mut tx, node_id, last_seen).await?;
        }
        tx.commit().await?;
        Ok::<(), StoreError>(())
    }
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, %node_id, "cannot record a disconnection");
    }
    inner.hub().notify_disconnected(node_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_compared_as_semver() {
        let min = semver::Version::new(0, 1, 0);
        assert!(version_ok("0.1.0", &min));
        assert!(version_ok("0.10.0", &min));
        assert!(version_ok("1.0.0", &min));
        assert!(!version_ok("0.0.9", &min));
        assert!(
            !version_ok("0.1.0-rc.1", &min),
            "a pre-release sorts before its release"
        );
        assert!(!version_ok("one", &min));
        assert!(!version_ok("", &min));
    }
}
