// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests of the scheduler (T06, the core of the task): random sequences of node connects, disconnects and
//! heartbeats, job creation and cancel, agent messages (accept, reject, start, finish, stale ones), `Hello`s with
//! arbitrary `running` sets, liveness sweeps, server restarts, node deletions and clock advances. After **every**
//! step the invariants are checked against the database:
//!
//! 1. no node holds more than it offers, counting every held reservation (lost-but-unconfirmed ones included), and
//!    no GPU is held twice; and a reservation is never released early: an accepted lease the server ends itself
//!    (cancel on an unreachable node, watchdog) still holds it in the step it ends;
//! 2. at most one active lease per job;
//! 3. epochs increase strictly per job, in creation order;
//! 4. a terminal job state never changes;
//! 5. every lost lease (hence every requeue) happened at least `lease_ttl_s` after its node's last contact (and
//!    after the server's boot), or was explicit: absent from a `Hello`, or the node was deleted; and every requeue
//!    in `job_events` has one of those reasons;
//! 6. `usage_records` has exactly one row per finished **slice** (H2 §12): the rows of each attempt tile
//!    `[started_at, ended_at]` with no gap and no overlap, cut only at 00:00 UTC and only for services; a finished
//!    attempt has exactly one `last_slice = 1` row (reported by its node, or estimated by the server when the attempt
//!    ended with no report: the server ended it, or it was lost) and a running one has none; after a pass, a running
//!    service attempt has one row for each midnight it crossed and none for its current slice. The clock is driven
//!    across midnights, and `spent(P, D)` equals the reference sum of H2 §12 for every day it touched;
//! 7. no lease ever reaches a `pending_approval` node (H2 §5.5, SI-H2-19). One node starts pending, and nodes are
//!    approved and (as no API does) turned pending again at random: no `Lease` is ever sent to a node that is pending,
//!    no offer is accepted from one, no lease on one was offered or accepted after it turned pending, and after a
//!    scheduling pass no active lease is left on one.
//!
//! A second property test (SI-H2-20, [`the_ledger_and_the_caps_stay_exact`]) drives well-behaved agents over batch
//! and service jobs of key and device principals with daily caps, across midnights.
//!
//! 256 cases run by default. More locally: `PROPTEST_CASES=5000 cargo test -p p2pc-server --lib scheduler::tests::props`.

use std::collections::{BTreeMap, HashMap, HashSet};

use p2pc_proto::api::Principal;
use proptest::prelude::*;

use super::*;

#[derive(Debug, Clone)]
enum Op {
    Create {
        size: u8,
        gpu: bool,
        attempts: u8,
    },
    /// A service (H2 §7.1) of 1 vCPU, with a long or a short `timeout_s`.
    CreateService {
        long: bool,
        attempts: u8,
    },
    /// The clock jumps to the next 00:00 UTC, one second before it, or one second after it.
    Midnight(u8),
    Cancel(u8),
    Accept(u8),
    Reject(u8),
    Start(u8),
    Finish(u8, u8),
    Stale(u8, u8),
    LogChunk(u8, u8),
    /// A heartbeat. An even `u8` lists nothing (the node holds no resources, or it is an older agent that lists only
    /// what runs); an odd one lists every lease the server holds for the node (all being cleaned up or run).
    Heartbeat(u8),
    Disconnect(u8),
    Hello(u8, u16, bool),
    Advance(u8),
    Tick,
    Sweep,
    /// The node's row turns offline and the `Lost` hook fires **before** its TTL: what a crash between the sweep's
    /// commit and its hook, or any premature signal, looks like to the scheduler. Its own guard must hold.
    EarlyOffline(u8),
    Restart,
    Delete(u8),
    /// An `admin` approves a node (`POST /v1/nodes/{id}/approve`).
    Approve(u8),
    /// A node's row turns `pending_approval`, whatever it holds. No operation of the spec does this: it is what the
    /// scheduler's backstop is for.
    Unapprove(u8),
}

fn op() -> impl Strategy<Value = Op> {
    op_with(1)
}

/// The steps: H1's, then services and midnight jumps, `services` each against H1's 44.
fn op_with(services: u32) -> impl Strategy<Value = Op> {
    prop_oneof![
        44 => h1_op(),
        services => (prop::bool::weighted(0.7), 1u8..=3).prop_map(|(long, attempts)| Op::CreateService { long, attempts }),
        services => any::<u8>().prop_map(Op::Midnight),
    ]
}

/// The steps of H1's property test, with H1's weights.
fn h1_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (any::<u8>(), prop::bool::weighted(0.2), 1u8..=3).prop_map(|(size, gpu, attempts)| Op::Create { size, gpu, attempts }),
        1 => any::<u8>().prop_map(Op::Cancel),
        4 => any::<u8>().prop_map(Op::Accept),
        1 => any::<u8>().prop_map(Op::Reject),
        3 => any::<u8>().prop_map(Op::Start),
        3 => (any::<u8>(), any::<u8>()).prop_map(|(l, o)| Op::Finish(l, o)),
        2 => (any::<u8>(), any::<u8>()).prop_map(|(l, k)| Op::Stale(l, k)),
        1 => (any::<u8>(), any::<u8>()).prop_map(|(l, s)| Op::LogChunk(l, s)),
        3 => any::<u8>().prop_map(Op::Heartbeat),
        2 => any::<u8>().prop_map(Op::Disconnect),
        2 => (any::<u8>(), any::<u16>(), any::<bool>()).prop_map(|(n, m, g)| Op::Hello(n, m, g)),
        4 => (1u8..=90).prop_map(Op::Advance),
        5 => Just(Op::Tick),
        2 => Just(Op::Sweep),
        2 => any::<u8>().prop_map(Op::EarlyOffline),
        1 => Just(Op::Restart),
        1 => any::<u8>().prop_map(Op::Delete),
        2 => any::<u8>().prop_map(Op::Approve),
        1 => any::<u8>().prop_map(Op::Unapprove),
    ]
}

/// What the test knows besides the database.
struct Model {
    sched: Scheduler,
    nodes: Vec<NodeId>,
    /// What each node offers: milli-vCPUs, MiB, GPU UUIDs.
    offered: HashMap<NodeId, (u64, u64, Vec<String>)>,
    deleted: HashSet<NodeId>,
    last_contact: HashMap<NodeId, OffsetDateTime>,
    boot: OffsetDateTime,
    jobs: Vec<JobId>,
    /// Every lease ever offered, in order.
    leases: Vec<(NodeId, LeaseId, u64)>,
    /// The terminal state each job was first seen in.
    terminal: HashMap<JobId, JobStatus>,
    /// Lost leases already checked.
    lost_seen: HashSet<LeaseId>,
    /// Revoked leases already checked.
    revoked_seen: HashSet<LeaseId>,
    /// The nodes that are `pending_approval` now, and since when.
    pending: HashMap<NodeId, OffsetDateTime>,
}

impl Model {
    fn pick_lease(&self, i: u8) -> Option<(NodeId, LeaseId, u64)> {
        (!self.leases.is_empty()).then(|| self.leases[usize::from(i) % self.leases.len()])
    }

    fn pick_node(&self, i: u8) -> NodeId {
        self.nodes[usize::from(i) % self.nodes.len()]
    }

    fn contact(&mut self, node: NodeId, now: OffsetDateTime) {
        self.last_contact.insert(node, now);
    }
}

async fn step(fx: &Fx, m: &mut Model, op: &Op) {
    let now = fx.now();
    match *op {
        Op::Create { size, gpu, attempts } => {
            let (cpu, mem) = [(0.5, 256), (1.0, 512), (1.5, 1024), (2.0, 2048)][usize::from(size % 4)];
            // Short timeouts reach the watchdog; long ones leave room for node loss.
            let timeout_s = if size & 4 == 0 { 5 } else { 3600 };
            let job = fx
                .job_with(serde_json::json!({
                    "image": "docker.io/library/alpine:3", "command": ["true"],
                    "resources": {"cpu": cpu, "memory_mb": mem, "gpu": u32::from(gpu)},
                    "timeout_s": timeout_s, "retry": {"max_attempts": attempts},
                }))
                .await;
            m.jobs.push(job);
        }
        Op::CreateService { long, attempts } => {
            let job = fx
                .job_with(serde_json::json!({
                    "kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
                    "resources": {"cpu": 1, "memory_mb": 256},
                    "timeout_s": if long { 30 * 86_400 } else { 5 }, "retry": {"max_attempts": attempts},
                    "service": {"ports": [{"port": 8080, "name": "http"}]},
                }))
                .await;
            m.jobs.push(job);
        }
        Op::Midnight(k) => {
            let next = crate::units::day_of(now.unix_timestamp()) + crate::units::DAY_S;
            let target = next + i64::from(k % 3) - 1;
            fx.advance((target - now.unix_timestamp()).max(0));
        }
        Op::Cancel(i) => {
            if m.jobs.is_empty() {
                return;
            }
            // What `POST /v1/jobs/{id}/cancel` does.
            let job = m.jobs[usize::from(i) % m.jobs.len()];
            let mut tx = store::begin_immediate(&fx.db).await.unwrap();
            let row = jobs::get(&mut tx, fx.account, fx.project, job).await.unwrap().unwrap();
            match row.status {
                JobStatus::Queued => {
                    transition(&mut tx, &row, JobStatus::Cancelled, "cancelled_by_user", now)
                        .await
                        .unwrap();
                }
                JobStatus::Assigned | JobStatus::Running => {
                    jobs::request_cancel(&mut tx, fx.account, fx.project, job, now)
                        .await
                        .unwrap();
                }
                _ => {}
            }
            tx.commit().await.unwrap();
        }
        Op::Accept(i) | Op::Reject(i) | Op::Start(i) | Op::Finish(i, _) | Op::LogChunk(i, _) => {
            let Some((node, lease_id, epoch)) = m.pick_lease(i) else {
                return;
            };
            // Messages only travel on a live connection.
            if !fx.link.is_connected(node) {
                return;
            }
            m.contact(node, now);
            let was_offer = fx.lease(lease_id).await.state == LeaseState::Offered;
            let msg = match *op {
                Op::Accept(_) => AgentMsg::LeaseAccepted { lease_id, epoch },
                Op::Reject(_) => AgentMsg::LeaseRejected {
                    lease_id,
                    epoch,
                    reason: LeaseRejectReason::InsufficientCapacity,
                },
                Op::Start(_) => AgentMsg::JobStarted {
                    lease_id,
                    epoch,
                    started_at: now,
                },
                Op::Finish(_, o) => {
                    let (outcome, code) = [
                        (Outcome::Exited, Some(0)),
                        (Outcome::Exited, Some(1)),
                        (Outcome::TimedOut, None),
                        (Outcome::Cancelled, None),
                        (Outcome::Error, None),
                    ][usize::from(o % 5)];
                    finished(lease_id, epoch, outcome, code)
                }
                _ => AgentMsg::LogChunk {
                    lease_id,
                    epoch,
                    stream: p2pc_proto::api::LogStream::Stderr,
                    seq: u64::from(match *op {
                        Op::LogChunk(_, s) => s % 4,
                        _ => 0,
                    }),
                    data_b64: LogData::from("aGk="),
                },
            };
            m.sched.on_agent_message(node, msg).await.unwrap();
            // 7. No offer is accepted from a pending node, by any message that implies the acceptance.
            if was_offer && m.pending.contains_key(&node) {
                let l = fx.lease(lease_id).await;
                assert!(
                    l.accepted_at.is_none() && !matches!(l.state, LeaseState::Accepted | LeaseState::Running),
                    "a pending node got lease {lease_id}: {l:?}"
                );
            }
        }
        Op::Stale(i, kind) => {
            let Some((node, lease_id, epoch)) = m.pick_lease(i) else {
                return;
            };
            let (from, lease_id, epoch) = match kind % 3 {
                // An old or future epoch of a real lease.
                0 => (node, lease_id, epoch + 1 + u64::from(kind)),
                // Another node reporting it.
                1 => (
                    m.nodes[(m.nodes.iter().position(|n| *n == node).unwrap_or(0) + 1) % m.nodes.len()],
                    lease_id,
                    epoch,
                ),
                // A lease nobody issued.
                _ => (node, LeaseId::generate(), 1),
            };
            if !fx.link.is_connected(from) {
                return;
            }
            m.sched
                .on_agent_message(from, finished(lease_id, epoch, Outcome::Exited, Some(0)))
                .await
                .unwrap();
        }
        Op::Heartbeat(n) => {
            let node = m.pick_node(n);
            if fx.link.is_connected(node) {
                m.contact(node, now);
                // §8: it frees the finished leases the node no longer lists; it ends no other lease.
                let mut listed = Vec::new();
                if n % 2 == 1 {
                    let mut conn = fx.db.acquire().await.unwrap();
                    for l in leases::held_on_node(&mut conn, node).await.unwrap() {
                        listed.push((l.id, l.epoch));
                    }
                }
                fx.heartbeat(node, &listed).await;
            }
        }
        Op::Disconnect(n) => {
            let node = m.pick_node(n);
            if fx.link.is_connected(node) {
                // `agent::end`: flush the last contact and open a disconnection.
                fx.link.disconnect(node);
                let last = m.last_contact[&node];
                let mut conn = fx.db.acquire().await.unwrap();
                nodes::touch_last_seen(&mut conn, node, last).await.unwrap();
                nodes::open_disconnection(&mut conn, node, last).await.unwrap();
            }
        }
        Op::Hello(n, mask, ghost) => {
            let node = m.pick_node(n);
            if m.deleted.contains(&node) || fx.link.is_connected(node) {
                return;
            }
            // Arbitrary `running`: any of the 16 latest leases (of any node), and maybe one nobody issued.
            let recent: Vec<_> = m.leases.iter().rev().take(16).collect();
            let mut running: Vec<RunningLease> = recent
                .iter()
                .enumerate()
                .filter(|(k, _)| mask & (1 << k) != 0)
                .map(|(_, (_, lease_id, epoch))| RunningLease::new(*lease_id, *epoch))
                .collect();
            if ghost {
                running.push(RunningLease::new(LeaseId::generate(), 1));
            }
            // `agent::session`: register, online, activate, then reconcile.
            let mut conn = fx.db.acquire().await.unwrap();
            nodes::mark_connected(&mut conn, node, now).await.unwrap();
            drop(conn);
            fx.link.connect(node);
            m.contact(node, now);
            m.sched.reconcile_hello(node, &running).await.unwrap();
            // An eligible node connected: the offer cap re-arms (§8), as `agent::session` does.
            node_changed(&fx.db, &Kick::default(), fx.account).await;
            let mut conn = fx.db.acquire().await.unwrap();
            nodes::resolve_disconnection(&mut conn, node, nodes::DisconnectOutcome::Recovered, now)
                .await
                .unwrap();
        }
        Op::Advance(s) => fx.advance(i64::from(s)),
        Op::Tick => {
            m.sched.tick().await.clean();
        }
        Op::Sweep => {
            // The gateway's liveness sweep: no contact for lease_ttl_s (from the boot at the earliest).
            for &node in &m.nodes.clone() {
                if m.deleted.contains(&node) {
                    continue;
                }
                let base = m.last_contact[&node].max(m.boot);
                let mut conn = fx.db.acquire().await.unwrap();
                let row = nodes::by_id(&mut conn, node).await.unwrap().unwrap();
                if now - base < TTL || row.state == nodes::DbState::Offline {
                    continue;
                }
                fx.link.disconnect(node);
                nodes::touch_last_seen(&mut conn, node, m.last_contact[&node])
                    .await
                    .unwrap();
                nodes::mark_offline(&mut conn, node).await.unwrap();
                nodes::open_disconnection(&mut conn, node, m.last_contact[&node])
                    .await
                    .unwrap();
                nodes::resolve_disconnection(&mut conn, node, nodes::DisconnectOutcome::Offline, now)
                    .await
                    .unwrap();
                drop(conn);
                m.sched.node_offline(node, OfflineReason::Lost).await.unwrap();
            }
        }
        Op::EarlyOffline(n) => {
            let node = m.pick_node(n);
            if m.deleted.contains(&node) {
                return;
            }
            fx.link.disconnect(node);
            let mut conn = fx.db.acquire().await.unwrap();
            nodes::touch_last_seen(&mut conn, node, m.last_contact[&node])
                .await
                .unwrap();
            nodes::mark_offline(&mut conn, node).await.unwrap();
            drop(conn);
            m.sched.node_offline(node, OfflineReason::Lost).await.unwrap();
        }
        Op::Restart => {
            // Every connection drops; the new process boots now.
            for &node in &m.nodes {
                fx.link.disconnect(node);
            }
            m.sched = fx.another_scheduler();
            m.boot = now;
        }
        Op::Delete(i) => {
            let live: Vec<NodeId> = m.nodes.iter().copied().filter(|n| !m.deleted.contains(n)).collect();
            // Keep one node, so the sequence goes on.
            if live.len() < 2 {
                return;
            }
            let node = live[usize::from(i) % live.len()];
            let mut conn = fx.db.acquire().await.unwrap();
            nodes::soft_delete(&mut conn, fx.account, node, now).await.unwrap();
            drop(conn);
            fx.link.disconnect(node);
            m.deleted.insert(node);
            let before = fx.link.take();
            m.sched.node_offline(node, OfflineReason::Deleted).await.unwrap();
            let after = fx.link.take();
            assert!(
                after.iter().all(|(n, _)| *n != node),
                "a deleted node was sent {after:?}"
            );
            fx.link.sent.lock().unwrap().extend(before.into_iter().chain(after));
        }
        Op::Approve(n) => {
            let node = m.pick_node(n);
            let mut conn = fx.db.acquire().await.unwrap();
            nodes::approve(&mut conn, fx.account, node).await.unwrap();
            m.pending.remove(&node);
        }
        Op::Unapprove(n) => {
            let node = m.pick_node(n);
            fx.set_approval(node, false).await;
            m.pending.entry(node).or_insert(now);
        }
    }
    for (node, msg) in fx.link.take() {
        if let ServerMsg::Lease { lease_id, epoch, .. } = msg {
            // 7. Approval does not change inside a step, so this is the node's approval when the lease was sent.
            assert!(
                !m.pending.contains_key(&node),
                "lease {lease_id} was sent to the pending node {node}"
            );
            m.leases.push((node, lease_id, epoch));
        }
    }
}

/// Invariant 7 (SI-H2-19) against the database: every lease on a node that is pending now was offered, and accepted
/// if it was, no later than the second the node turned pending; and after a scheduling pass (`ticked`) none of them
/// is still active.
async fn check_no_lease_on_pending_nodes(fx: &Fx, m: &Model, ticked: bool) {
    for (node, since) in &m.pending {
        let rows: Vec<(String, String, i64, Option<i64>)> =
            sqlx::query_as("SELECT id, state, offered_at_ms / 1000, accepted_at FROM leases WHERE node_id = ?")
                .bind(node.to_string())
                .fetch_all(&fx.db)
                .await
                .unwrap();
        for (id, state, offered, accepted) in rows {
            let since = since.unix_timestamp();
            assert!(
                offered <= since,
                "lease {id} was offered to {node} after it turned pending"
            );
            assert!(
                accepted.is_none_or(|at| at <= since),
                "lease {id} was accepted from {node} after it turned pending"
            );
            assert!(
                !ticked || !["offered", "accepted", "running"].contains(&state.as_str()),
                "lease {id} is still {state} on the pending node {node} after a pass"
            );
        }
    }
}

async fn check_invariants(fx: &Fx, m: &mut Model, op: &Op) {
    let now = fx.now();
    let mut conn = fx.db.acquire().await.unwrap();
    // 1. Capacity, counting every held reservation.
    let held: BTreeMap<NodeId, Vec<Reserved>> = leases::held_everywhere(&mut conn).await.unwrap();
    for (node, rs) in &held {
        let (cpu, mem, gpus) = &m.offered[node];
        let mut h = Held::default();
        for r in rs {
            h.add(r);
        }
        assert!(h.cpu_milli <= *cpu, "node {node} over its CPU: {} > {cpu}", h.cpu_milli);
        assert!(
            h.memory_mb <= *mem,
            "node {node} over its memory: {} > {mem}",
            h.memory_mb
        );
        let held_gpus: Vec<&String> = rs.iter().filter_map(|r| r.gpu_uuid.as_ref()).collect();
        assert_eq!(held_gpus.len(), h.gpus.len(), "a GPU of {node} is held twice");
        assert!(
            h.gpus.iter().all(|g| gpus.contains(g)),
            "a GPU {node} does not offer is held"
        );
    }
    // 1b. Released only when confirmed dead: an accepted lease the server revoked holds its reservation at first.
    let revoked: Vec<(String, Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT id, accepted_at, confirmed_dead_at FROM leases WHERE state = 'revoked'")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
    for (id, accepted, confirmed) in revoked {
        let id: LeaseId = id.parse().unwrap();
        if m.revoked_seen.insert(id) && accepted.is_some() {
            assert_eq!(
                confirmed, None,
                "lease {id} was accepted, then revoked and released in the same step"
            );
        }
    }
    // 2. One active lease per job.
    let doubles: Vec<(String, i64)> = sqlx::query_as(
        "SELECT job_id, COUNT(*) FROM leases WHERE state IN ('offered', 'accepted', 'running') \
         GROUP BY job_id HAVING COUNT(*) > 1",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    assert!(doubles.is_empty(), "{doubles:?}");
    // 3. Strictly increasing epochs per job, in creation order.
    let rows: Vec<(String, i64)> = sqlx::query_as("SELECT job_id, epoch FROM leases ORDER BY rowid")
        .fetch_all(&mut *conn)
        .await
        .unwrap();
    let mut last: HashMap<String, i64> = HashMap::new();
    for (job, epoch) in rows {
        if let Some(prev) = last.insert(job.clone(), epoch) {
            assert!(epoch > prev, "job {job}: epoch {epoch} after {prev}");
        }
    }
    // 4. Terminal states never change.
    for &job in &m.jobs {
        let status = jobs::get(&mut conn, fx.account, fx.project, job)
            .await
            .unwrap()
            .unwrap()
            .status;
        match m.terminal.get(&job) {
            Some(t) => assert_eq!(status, *t, "terminal job {job} changed"),
            None if status.is_terminal() => {
                m.terminal.insert(job, status);
            }
            None => {}
        }
    }
    // 5. Losses only when confirmed dead.
    let lost: Vec<(String, String, Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT id, node_id, end_reason, confirmed_dead_at FROM leases WHERE state = 'lost'")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
    for (id, node, reason, confirmed) in lost {
        let id: LeaseId = id.parse().unwrap();
        if !m.lost_seen.insert(id) {
            continue;
        }
        let node: NodeId = node.parse().unwrap();
        assert_eq!(
            confirmed,
            Some(now.unix_timestamp()),
            "lost and confirmed in the same step"
        );
        match reason.as_deref() {
            Some(code::NODE_LOST) => {
                let base = m.last_contact[&node].max(m.boot);
                assert!(
                    now - base >= TTL,
                    "lease {id} lost {} s after the last contact",
                    (now - base).whole_seconds()
                );
            }
            Some(code::ABSENT_FROM_HELLO | code::NODE_DELETED) => {}
            other => panic!("lease {id} lost for {other:?}"),
        }
    }
    let requeues: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM job_events WHERE to_status = 'queued' AND from_status IN ('assigned', 'running')",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    for r in requeues {
        // The fourth reason is the backstop of invariant 7: a lease taken from a node found pending.
        assert!(
            [
                code::NODE_LOST,
                code::ABSENT_FROM_HELLO,
                code::NODE_DELETED,
                code::PENDING_APPROVAL
            ]
            .contains(&r.as_str()),
            "requeued for {r}"
        );
    }
    drop(conn);
    // 6. One row per finished slice (H2 §12).
    check_slices(fx, matches!(op, Op::Tick)).await;
    // `spent(P, D)` is the reference sum of H2 §12, for every day the sequence touched.
    for day in days_until(now) {
        check_spent(fx, fx.account, Principal::Key(fx.key), day).await;
    }
}

/// The UTC days from the fixture's first one to the one after `now`.
fn days_until(now: OffsetDateTime) -> impl Iterator<Item = i64> {
    let first = crate::units::day_of(T0.unix_timestamp());
    let last = crate::units::day_of(now.unix_timestamp()) + crate::units::DAY_S;
    (first..=last).step_by(86_400)
}

/// Invariant 6 (H2 §12): one row per finished slice. `ticked`: a scheduling pass just ran, so every midnight a running
/// service attempt crossed has its row.
async fn check_slices(fx: &Fx, ticked: bool) {
    let now = fx.now().unix_timestamp();
    type Slice = (String, i64, String, String, i64, i64, i64, bool, bool);
    let rows: Vec<Slice> = sqlx::query_as(
        "SELECT u.job_id, u.attempt, u.lease_id, u.kind, u.started_at, u.slice_start, u.slice_end, u.last_slice, \
                u.estimated FROM usage_records u ORDER BY u.job_id, u.attempt, u.slice_start",
    )
    .fetch_all(&fx.db)
    .await
    .unwrap();
    let mut attempts: BTreeMap<(String, i64), Vec<Slice>> = BTreeMap::new();
    for r in rows {
        attempts.entry((r.0.clone(), r.1)).or_default().push(r);
    }
    // The tiling of each attempt's rows.
    for ((job, attempt), slices) in &attempts {
        let first = &slices[0];
        assert_eq!(
            first.5, first.4,
            "{job}/{attempt}: the first slice starts at the attempt's start"
        );
        for w in slices.windows(2) {
            assert_eq!(w[1].5, w[0].6, "{job}/{attempt}: a gap or an overlap between slices");
        }
        for (k, sl) in slices.iter().enumerate() {
            assert_eq!(sl.4, first.4, "{job}/{attempt}: one start for the attempt");
            assert!(sl.5 <= sl.6, "{job}/{attempt}: a slice ends before it starts");
            assert_eq!(sl.2, first.2, "{job}/{attempt}: every slice names the attempt's lease");
            let is_final = k + 1 == slices.len();
            if !is_final || !sl.7 {
                assert!(!sl.7, "{job}/{attempt}: a last slice before the end");
                assert_eq!(sl.6 % 86_400, 0, "{job}/{attempt}: a cut that is not at 00:00 UTC");
                assert_eq!(sl.3, "service", "{job}/{attempt}: a batch attempt was cut");
            }
        }
    }
    // Finished attempts have their last slice, with the right estimate flag; running ones have none.
    /// `id, job_id, attempt, state, accepted_at, started_at, kind`.
    type LeaseCols = (String, String, i64, String, Option<i64>, Option<i64>, String);
    let leases: Vec<LeaseCols> = sqlx::query_as(
        "SELECT l.id, l.job_id, l.attempt, l.state, l.accepted_at, l.started_at, j.kind FROM leases l \
         JOIN jobs j ON j.job_id = l.job_id",
    )
    .fetch_all(&fx.db)
    .await
    .unwrap();
    let mut finished = 0;
    for (id, job, attempt, state, accepted, started, kind) in &leases {
        let slices = attempts.get(&(job.clone(), *attempt));
        let last = slices.and_then(|s| s.iter().find(|r| r.7));
        match state.as_str() {
            "finished" | "lost" => {}
            "revoked" if accepted.is_some() => {}
            "accepted" | "running" => {
                assert!(last.is_none(), "running attempt {job}/{attempt} has a last slice");
                if let Some(sl) = slices {
                    assert!(
                        sl.iter().all(|r| r.2 == *id),
                        "rows of {job}/{attempt} name another lease"
                    );
                }
                let start = slices
                    .map(|s| s[0].4)
                    .or(*started)
                    .or(*accepted)
                    .expect("an accepted lease has a start");
                // A batch attempt is never cut.
                let crossed = if kind == "service" {
                    crate::units::midnights(start, now).count()
                } else {
                    0
                };
                let cut = slices.map_or(0, Vec::len);
                assert!(
                    cut <= crossed,
                    "{job}/{attempt}: a row for a midnight it has not crossed"
                );
                if ticked {
                    assert_eq!(cut, crossed, "{job}/{attempt}: a pass left a midnight uncut");
                }
                continue;
            }
            _ => {
                assert!(
                    slices.is_none_or(|s| s.iter().all(|r| r.2 != *id)),
                    "lease {id} never ran an attempt but has rows"
                );
                continue;
            }
        }
        finished += 1;
        let last = last.unwrap_or_else(|| panic!("finished attempt {job}/{attempt} ({state}) has no last slice"));
        assert_eq!(last.2, *id, "the last slice of {job}/{attempt} names another lease");
        assert_eq!(
            last.8,
            state != "finished",
            "{job}/{attempt} ({state}): estimated is {}",
            last.8
        );
    }
    let last_slices = attempts.values().flatten().filter(|r| r.7).count();
    assert_eq!(last_slices, finished, "last slices vs finished attempts");
}

/// `spent(P, D)` against the reference sum of H2 §12, computed here from the raw tables.
pub(crate) async fn check_spent(fx: &Fx, account: AccountId, principal: Principal, day: i64) -> u64 {
    let (col_key, col_dev) = match principal {
        Principal::Key(k) => (Some(k.to_string()), None),
        Principal::Device(d) => (None, Some(d.to_string())),
    };
    let mine = |key: &Option<String>, dev: &Option<String>| -> bool {
        (col_key.is_some() && *key == col_key) || (col_dev.is_some() && *dev == col_dev)
    };
    /// `job_id, key_id, device_id, charge_day, units`.
    type RowCols = (String, Option<String>, Option<String>, i64, i64);
    let rows: Vec<RowCols> = sqlx::query_as("SELECT job_id, key_id, device_id, charge_day, units FROM usage_records")
        .fetch_all(&fx.db)
        .await
        .unwrap();
    type JobCols = (
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        i64,
        i64,
        bool,
        Option<i64>,
        Option<i64>,
    );
    let jobs: Vec<JobCols> = sqlx::query_as(
        "SELECT j.job_id, j.key_id, j.device_id, j.kind, j.status, j.units_reserved, j.created_at, \
                EXISTS (SELECT 1 FROM job_events e WHERE e.job_id = j.job_id AND e.to_status = 'running'), \
                s.cap_day, s.cap_reserved_units \
         FROM jobs j LEFT JOIN service_state s ON s.job_id = j.job_id",
    )
    .fetch_all(&fx.db)
    .await
    .unwrap();
    let terminal = |s: &str| ["succeeded", "failed", "timed_out", "cancelled", "lost"].contains(&s);
    let mut reference: i64 = rows
        .iter()
        .filter(|r| mine(&r.1, &r.2) && r.3 == day)
        .map(|r| r.4)
        .sum();
    for (job, key, dev, kind, status, reserved, created, ran, cap_day, cap_reserved) in &jobs {
        if !mine(key, dev) {
            continue;
        }
        let has_rows = rows.iter().any(|r| r.0 == *job);
        if kind == "batch" && crate::units::day_of(*created) == day {
            reference += if !terminal(status) {
                *reserved
            } else if has_rows || (status == "cancelled" && !ran) {
                0
            } else {
                *reserved
            };
        }
        if kind == "service" && !terminal(status) && *cap_day == Some(day) {
            let on_day: i64 = rows.iter().filter(|r| r.0 == *job && r.3 == day).map(|r| r.4).sum();
            reference += (cap_reserved.unwrap_or(0) - on_day).max(0);
        }
    }
    let mut conn = fx.db.acquire().await.unwrap();
    let got = leases::spent(&mut conn, account, principal, day).await.unwrap();
    assert_eq!(i64::try_from(got).unwrap(), reference, "spent({principal:?}, {day})");
    got
}

/// How many leases ended each way (`state:end_reason`), and how many requeues: what one sequence reached.
type Coverage = BTreeMap<String, i64>;

async fn coverage(fx: &Fx) -> Coverage {
    let mut out: Coverage = sqlx::query_as(
        "SELECT state || ':' || COALESCE(substr(end_reason, 1, instr(end_reason || ':', ':') - 1), '-'), COUNT(*) \
         FROM leases GROUP BY 1",
    )
    .fetch_all(&fx.db)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let requeues: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM job_events WHERE to_status = 'queued' AND from_status IN ('assigned', 'running')",
    )
    .fetch_one(&fx.db)
    .await
    .unwrap();
    out.insert("requeue".into(), requeues);
    // H2 §12: service attempts cut at a midnight.
    let midnight_slices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_records WHERE last_slice = 0")
        .fetch_one(&fx.db)
        .await
        .unwrap();
    out.insert("midnight_slice".into(), midnight_slices);
    out
}

async fn run(ops: Vec<Op>) -> Coverage {
    let fx = Fx::new().await;
    let mut offered = HashMap::new();
    let mut ids = Vec::new();
    for (cpu, mem, gpus) in [(2.0, 2048, 1), (1.5, 1024, 0), (4.0, 4096, 1), (4.0, 8192, 1)] {
        let id = fx.node(cpu, mem, gpus).await;
        let uuids = (0..gpus).map(|i| format!("GPU-{id}-{i}")).collect();
        offered.insert(id, (fit::cpu_milli(cpu), mem, uuids));
        ids.push(id);
    }
    // Two nodes run services too (H2 §6.1 `service_jobs`).
    for &id in &[ids[0], ids[2]] {
        sqlx::query("UPDATE nodes SET features = ? WHERE id = ?")
            .bind(serde_json::json!([p2pc_proto::protocol::capability::SERVICE_JOBS]).to_string())
            .bind(id.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
    }
    // The last node, the largest, enrolled with a token of a non-`admin` principal: it waits for approval.
    let waiting = ids[3];
    fx.set_approval(waiting, false).await;
    let mut m = Model {
        sched: fx.sched.clone(),
        last_contact: ids.iter().map(|n| (*n, T0)).collect(),
        nodes: ids,
        offered,
        deleted: HashSet::new(),
        boot: T0,
        jobs: Vec::new(),
        leases: Vec::new(),
        terminal: HashMap::new(),
        lost_seen: HashSet::new(),
        revoked_seen: HashSet::new(),
        pending: HashMap::from([(waiting, T0)]),
    };
    for op in &ops {
        step(&fx, &mut m, op).await;
        check_invariants(&fx, &mut m, op).await;
        check_no_lease_on_pending_nodes(&fx, &m, matches!(op, Op::Tick)).await;
    }
    coverage(&fx).await
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        // Regressions are not written into the source tree; a failure prints the minimal sequence instead.
        failure_persistence: None,
        max_shrink_iters: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn the_scheduler_keeps_its_invariants(ops in prop::collection::vec(op(), 16..64)) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(run(ops));
    }
}

/// The generator is not vacuous: sequences drawn from it reach every way a lease can end, and requeues.
#[test]
fn the_generated_sequences_reach_every_lease_outcome() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut total = Coverage::new();
    // H1's sequences, then sequences rich in services and midnights (H2 §12).
    for k in 0..192 {
        let ops = if k < 128 {
            prop::collection::vec(h1_op(), 40..48)
                .new_tree(&mut runner)
                .unwrap()
                .current()
        } else {
            prop::collection::vec(op_with(6), 40..48)
                .new_tree(&mut runner)
                .unwrap()
                .current()
        };
        for (k, v) in rt.block_on(run(ops)) {
            *total.entry(k).or_default() += v;
        }
    }
    for want in [
        "finished:exited_0",
        "lost:node_lost",
        "lost:absent_from_hello",
        "revoked:accept_timeout",
        "revoked:rejected",
        "revoked:watchdog",
        "revoked:cancelled_unreachable",
        "revoked:pending_approval",
        "requeue",
        "midnight_slice",
    ] {
        assert!(
            total.get(want).is_some_and(|n| *n > 0),
            "never reached {want}: {total:?}"
        );
    }
}

// --- SI-H2-20: the ledger and the caps stay exact ----------------------------------------------------------------

/// What one step of the cap property test does.
#[derive(Debug, Clone)]
enum CapOp {
    /// A batch job of principal `who % 3`, refused when it does not fit the day's cap.
    Batch { who: u8, size: u8, long: bool },
    /// A service of principal `who % 3`, refused when its day reservation buys under 15 minutes.
    Service { who: u8, size: u8, long: bool },
    /// A principal cancels a job (`POST /v1/jobs/{id}/cancel`).
    Cancel(u8),
    /// A running job exits by itself.
    Exit(u8),
    /// Time passes, by this many minutes, with the hub's passes on time.
    Advance(u16),
    /// Time passes to the next 00:00 UTC and a little past it.
    Midnight(u8),
    /// A node's agent restarts: its `Hello` lists nothing, so its attempts are lost at once and requeued.
    Lose(u8),
    /// A node's connection drops; its agent keeps running what it has.
    Partition(u8),
    /// A partitioned node comes back with `Hello` listing what it still runs.
    Reconnect(u8),
    /// The hub restarts at once and catches up.
    Restart,
}

fn cap_op() -> impl Strategy<Value = CapOp> {
    prop_oneof![
        3 => (any::<u8>(), any::<u8>(), any::<bool>()).prop_map(|(who, size, long)| CapOp::Batch { who, size, long }),
        3 => (any::<u8>(), any::<u8>(), prop::bool::weighted(0.7)).prop_map(|(who, size, long)| CapOp::Service { who, size, long }),
        1 => any::<u8>().prop_map(CapOp::Cancel),
        1 => any::<u8>().prop_map(CapOp::Exit),
        4 => (1u16..=600).prop_map(CapOp::Advance),
        2 => any::<u8>().prop_map(CapOp::Midnight),
        1 => any::<u8>().prop_map(CapOp::Lose),
        1 => any::<u8>().prop_map(CapOp::Partition),
        1 => any::<u8>().prop_map(CapOp::Reconnect),
        1 => Just(CapOp::Restart),
    ]
}

/// The cap test's world: the hub's scheduler, two service nodes, three principals and what was observed.
struct CapWorld {
    sched: Scheduler,
    nodes: Vec<NodeId>,
    /// `(principal, its cap)`: the key and one device capped, one device not.
    principals: Vec<(Principal, Option<u64>)>,
    jobs: Vec<(JobId, Principal)>,
    /// Every day reservation seen: `(job, day) → milli-units`.
    reservations: BTreeMap<(String, i64), i64>,
}

const CAP_GPU_HOUR: Units = Units::from_units(10);

impl CapWorld {
    fn principal(&self, who: u8) -> (Principal, Option<u64>) {
        self.principals[usize::from(who) % self.principals.len()]
    }
}

/// Creates a job as `POST /v1/jobs` does: the cap check of a batch job, or a service's day reservation.
async fn cap_create(fx: &Fx, w: &mut CapWorld, who: u8, spec: serde_json::Value) {
    let (principal, cap) = w.principal(who);
    let spec: JobSpec = serde_json::from_value(spec).unwrap();
    let service = spec.kind == p2pc_proto::api::JobKind::Service;
    let mut tx = store::begin_immediate(&fx.db).await.unwrap();
    let now = fx.now();
    let units = if service {
        Units::ZERO
    } else {
        estimate_units(&spec.resources, spec.timeout_s, CAP_GPU_HOUR)
    };
    let mut held = None;
    if let Some(cap) = cap.map(Units::from_milli) {
        if service {
            match crate::units::reserve_new_service(&mut tx, fx.account, principal, cap, &spec, CAP_GPU_HOUR, now)
                .await
                .unwrap()
            {
                Ok(h) => held = Some(h),
                Err(_) => return,
            }
        } else {
            let spent = crate::units::spent_today(&mut tx, fx.account, principal, now)
                .await
                .unwrap();
            if crate::units::check_cap(cap, spent, units).is_err() {
                return;
            }
        }
    }
    let job = NewJob {
        job_id: JobId::generate(),
        account_id: fx.account,
        project_id: fx.project,
        principal,
        units_reserved: units,
        files_meta: p2pc_proto::api::FileMeta::compute_all(&spec).unwrap(),
        spec,
        spec_hash: format!("sha256:{}", "0".repeat(64)),
    };
    let id = jobs::insert(&mut tx, &job, now).await.unwrap().job_id;
    if let Some(h) = held {
        crate::units::hold(&mut tx, id, h, now).await.unwrap();
    }
    tx.commit().await.unwrap();
    w.jobs.push((id, principal));
}

/// Active leases (accepted or running): `(lease, node, epoch, job, start, timeout_s, kind)`.
async fn active_leases(fx: &Fx) -> Vec<(LeaseId, NodeId, u64, JobId, i64, i64, String)> {
    let rows: Vec<(String, String, i64, String, i64, i64, String)> = sqlx::query_as(
        "SELECT l.id, l.node_id, l.epoch, l.job_id, COALESCE(l.started_at, l.accepted_at), \
                json_extract(j.spec_view, '$.timeout_s'), j.kind \
         FROM leases l JOIN jobs j ON j.job_id = l.job_id WHERE l.state IN ('accepted', 'running')",
    )
    .fetch_all(&fx.db)
    .await
    .unwrap();
    rows.into_iter()
        .map(|(l, n, e, j, s, t, k)| {
            (
                l.parse().unwrap(),
                n.parse().unwrap(),
                u64::try_from(e).unwrap(),
                j.parse().unwrap(),
                s,
                t,
                k,
            )
        })
        .collect()
}

/// The agents, well behaved: a connected agent accepts and starts every lease at once, stops a job at once when
/// told `Cancel` and when its `timeout_s` is reached, and reports its services' usage in each heartbeat. A
/// partitioned agent does nothing the hub can see.
async fn agents(fx: &Fx, w: &CapWorld) {
    for _ in 0..8 {
        w.sched.tick().await.clean();
        let now = fx.now().unix_timestamp();
        let msgs = fx.link.take();
        let mut acted = false;
        for (node, msg) in msgs {
            if !fx.link.is_connected(node) {
                continue;
            }
            match msg {
                ServerMsg::Lease { lease_id, epoch, .. } => {
                    w.sched
                        .on_agent_message(node, AgentMsg::LeaseAccepted { lease_id, epoch })
                        .await
                        .unwrap();
                    w.sched
                        .on_agent_message(
                            node,
                            AgentMsg::JobStarted {
                                lease_id,
                                epoch,
                                started_at: fx.now(),
                            },
                        )
                        .await
                        .unwrap();
                    acted = true;
                }
                ServerMsg::Cancel { lease_id, epoch, .. } => {
                    let l = fx.lease(lease_id).await;
                    if l.state.is_active() && l.epoch == epoch && l.state != LeaseState::Offered {
                        w.sched
                            .on_agent_message(node, finished(lease_id, epoch, Outcome::Cancelled, None))
                            .await
                            .unwrap();
                        acted = true;
                    }
                }
                _ => {}
            }
        }
        // Timeouts, on the agents' side.
        for (lease, node, epoch, _, start, timeout, _) in active_leases(fx).await {
            if fx.link.is_connected(node) && start + timeout <= now {
                w.sched
                    .on_agent_message(node, finished(lease, epoch, Outcome::TimedOut, None))
                    .await
                    .unwrap();
                acted = true;
            }
        }
        // Heartbeats: what runs, with the services' cumulative usage; finished leases are freed.
        for &node in &w.nodes {
            if !fx.link.is_connected(node) {
                continue;
            }
            let running: Vec<RunningLease> = active_leases(fx)
                .await
                .into_iter()
                .filter(|l| l.1 == node)
                .map(|(lease, _, epoch, _, start, _, kind)| {
                    let mut r = RunningLease::new(lease, epoch);
                    if kind == "service" {
                        r.used_cpu_ms = Some(u64::try_from((now - start).max(0)).unwrap() * 500);
                        r.max_rss_mb = Some(64);
                    }
                    r
                })
                .collect();
            w.sched.on_heartbeat(node, &running).await.unwrap();
        }
        if !acted {
            break;
        }
    }
}

/// The next instant after `now` at which the hub or an agent must act: a midnight, a cap deadline, a timeout (the
/// agent's, or the watchdog's for a partitioned node).
async fn next_event(fx: &Fx, w: &CapWorld, now: i64) -> i64 {
    let mut next = crate::units::day_of(now) + crate::units::DAY_S;
    let mut conn = fx.db.acquire().await.unwrap();
    for (job, _) in &w.jobs {
        if let Some(d) = crate::units::cap_deadline(&mut conn, *job, CAP_GPU_HOUR).await.unwrap() {
            let d = d.unix_timestamp();
            if d > now {
                next = next.min(d);
            }
        }
    }
    drop(conn);
    for (_, node, _, _, start, timeout, _) in active_leases(fx).await {
        let end = if fx.link.is_connected(node) {
            start + timeout
        } else {
            start + timeout + WATCHDOG_MARGIN.whole_seconds()
        };
        if end > now {
            next = next.min(end);
        }
    }
    next
}

/// Moves the clock to `target` with the hub's passes on time: it stops at every event on the way.
async fn run_until(fx: &Fx, w: &mut CapWorld, target: i64) {
    loop {
        let now = fx.now().unix_timestamp();
        let next = next_event(fx, w, now).await.min(target);
        fx.advance(next - now);
        agents(fx, w).await;
        observe(fx, w).await;
        if next >= target {
            break;
        }
    }
}

/// Records the day reservations, which a later step replaces.
async fn observe(fx: &Fx, w: &mut CapWorld) {
    let rows: Vec<(String, i64, i64)> =
        sqlx::query_as("SELECT job_id, cap_day, cap_reserved_units FROM service_state WHERE cap_day IS NOT NULL")
            .fetch_all(&fx.db)
            .await
            .unwrap();
    for (job, day, units) in rows {
        let seen = w.reservations.entry((job.clone(), day)).or_insert(units);
        assert_eq!(
            *seen, units,
            "the reservation of {job} for {day} changed within its day"
        );
    }
}

async fn cap_step(fx: &Fx, w: &mut CapWorld, op: &CapOp) {
    let now = fx.now().unix_timestamp();
    match *op {
        CapOp::Batch { who, size, long } => {
            let cpu = [0.5, 1.0, 2.0][usize::from(size % 3)];
            let timeout = if long { 6 * 3_600 } else { 1_800 };
            cap_create(
                fx,
                w,
                who,
                serde_json::json!({
                    "image": "docker.io/library/alpine:3", "command": ["true"],
                    "resources": {"cpu": cpu, "memory_mb": 256}, "timeout_s": timeout,
                }),
            )
            .await;
        }
        CapOp::Service { who, size, long } => {
            let cpu = [0.5, 1.0][usize::from(size % 2)];
            let timeout = if long { 30 * 86_400 } else { 2 * 3_600 };
            cap_create(
                fx,
                w,
                who,
                serde_json::json!({
                    "kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
                    "resources": {"cpu": cpu, "memory_mb": 256}, "timeout_s": timeout,
                    "service": {"ports": [{"port": 8080, "name": "http"}]},
                }),
            )
            .await;
        }
        CapOp::Cancel(i) => {
            if w.jobs.is_empty() {
                return;
            }
            let job = w.jobs[usize::from(i) % w.jobs.len()].0;
            let mut tx = store::begin_immediate(&fx.db).await.unwrap();
            let row = jobs::get(&mut tx, fx.account, fx.project, job).await.unwrap().unwrap();
            let service = row.spec_view.kind == p2pc_proto::api::JobKind::Service;
            match row.status {
                JobStatus::Queued => {
                    transition(&mut tx, &row, JobStatus::Cancelled, "cancelled_by_user", fx.now())
                        .await
                        .unwrap();
                }
                JobStatus::Assigned | JobStatus::Running if service => {
                    leases::request_stop(&mut tx, job, p2pc_proto::api::REASON_STOPPED, fx.now())
                        .await
                        .unwrap();
                }
                JobStatus::Assigned | JobStatus::Running => {
                    jobs::request_cancel(&mut tx, fx.account, fx.project, job, fx.now())
                        .await
                        .unwrap();
                }
                _ => {}
            }
            tx.commit().await.unwrap();
        }
        CapOp::Exit(i) => {
            let active = active_leases(fx).await;
            if active.is_empty() {
                return;
            }
            let (lease, node, epoch, ..) = active[usize::from(i) % active.len()];
            if fx.link.is_connected(node) {
                w.sched
                    .on_agent_message(node, finished(lease, epoch, Outcome::Exited, Some(0)))
                    .await
                    .unwrap();
            }
        }
        CapOp::Advance(minutes) => {
            run_until(fx, w, now + i64::from(minutes) * 60).await;
            return;
        }
        CapOp::Midnight(k) => {
            let target = crate::units::day_of(now) + crate::units::DAY_S + i64::from(k % 4);
            run_until(fx, w, target).await;
            return;
        }
        CapOp::Lose(n) => {
            let node = w.nodes[usize::from(n) % w.nodes.len()];
            fx.hello(node, &[]).await;
        }
        CapOp::Partition(n) => {
            let node = w.nodes[usize::from(n) % w.nodes.len()];
            fx.link.disconnect(node);
        }
        CapOp::Reconnect(n) => {
            let node = w.nodes[usize::from(n) % w.nodes.len()];
            if !fx.link.is_connected(node) {
                let held: Vec<(LeaseId, u64)> = active_leases(fx)
                    .await
                    .into_iter()
                    .filter(|l| l.1 == node)
                    .map(|l| (l.0, l.2))
                    .collect();
                fx.hello(node, &held).await;
            }
        }
        CapOp::Restart => {
            w.sched = fx.another_scheduler();
            w.sched.catch_up().await;
        }
    }
    agents(fx, w).await;
    observe(fx, w).await;
}

/// SI-H2-20, after every step: `spent(P, D)` is the reference sum of H2 §12 and stays within each capped principal's
/// cap; a service's rows for a day exceed that day's reservation only by estimated slices; and invariant 6 holds.
async fn check_caps(fx: &Fx, w: &CapWorld) {
    let now = fx.now();
    for &(principal, cap) in &w.principals {
        let (key, device) = crate::store::jobs::principal_binds(principal);
        for day in days_until(now) {
            let spent = check_spent(fx, fx.account, principal, day).await;
            // Only what the hub could not stop on time goes over a cap: an attempt it ended with no report (a
            // partitioned node's watchdog, H1's margin) is an estimate.
            let estimated: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(units), 0) FROM usage_records WHERE charge_day = ?1 AND estimated = 1 \
                 AND (key_id = ?2 OR device_id = ?3)",
            )
            .bind(day)
            .bind(&key)
            .bind(&device)
            .fetch_one(&fx.db)
            .await
            .unwrap();
            if let Some(cap) = cap {
                let limit = cap + u64::try_from(estimated).unwrap();
                assert!(
                    spent <= limit,
                    "{principal:?} spent {spent} > its cap {cap} on {day} (+{estimated} estimated)"
                );
            }
        }
    }
    let rows: Vec<(String, i64, i64, bool)> =
        sqlx::query_as("SELECT job_id, charge_day, units, estimated FROM usage_records WHERE kind = 'service'")
            .fetch_all(&fx.db)
            .await
            .unwrap();
    let mut per_day: BTreeMap<(String, i64), (i64, i64)> = BTreeMap::new();
    for (job, day, units, estimated) in rows {
        let e = per_day.entry((job, day)).or_default();
        e.0 += units;
        if estimated {
            e.1 += units;
        }
    }
    for ((job, day), (units, estimated)) in per_day {
        if let Some(reserved) = w.reservations.get(&(job.clone(), day)) {
            assert!(
                units <= reserved + estimated,
                "{job} on {day}: rows {units} over the reservation {reserved}, estimated rows {estimated}"
            );
        }
    }
    check_slices(fx, true).await;
}

async fn run_caps(key_cap: u64, device_cap: u64, ops: Vec<CapOp>) {
    let fx = Fx::new().await;
    let mut nodes = Vec::new();
    for _ in 0..2 {
        let id = fx.node(4.0, 8192, 0).await;
        sqlx::query("UPDATE nodes SET features = ? WHERE id = ?")
            .bind(serde_json::json!([p2pc_proto::protocol::capability::SERVICE_JOBS]).to_string())
            .bind(id.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
        nodes.push(id);
    }
    sqlx::query("UPDATE api_keys SET daily_unit_cap = ? WHERE key_id = ?")
        .bind(i64::try_from(key_cap).unwrap())
        .bind(fx.key.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
    let mut principals = vec![(Principal::Key(fx.key), Some(key_cap))];
    for cap in [Some(device_cap), None] {
        let id = p2pc_proto::ids::DeviceId::generate();
        sqlx::query(
            "INSERT INTO devices (device_id, account_id, project_id, iroh_node_id, scopes, daily_unit_cap, \
             created_at) VALUES (?, ?, ?, ?, '[\"admin\"]', ?, 0)",
        )
        .bind(id.to_string())
        .bind(fx.account.to_string())
        .bind(fx.project.to_string())
        .bind(format!(
            "{:0<64}",
            data_encoding::HEXLOWER.encode(id.to_string().as_bytes())
        ))
        .bind(cap.map(|c| i64::try_from(c).unwrap()))
        .execute(&fx.db)
        .await
        .unwrap();
        principals.push((Principal::Device(id), cap));
    }
    let mut w = CapWorld {
        sched: fx.sched.clone(),
        nodes,
        principals,
        jobs: Vec::new(),
        reservations: BTreeMap::new(),
    };
    for op in &ops {
        cap_step(&fx, &mut w, op).await;
        check_caps(&fx, &w).await;
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() / 4,
        failure_persistence: None,
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    })]

    /// SI-H2-20: the ledger and the caps stay exact with key and device principals and daily slices.
    #[test]
    fn the_ledger_and_the_caps_stay_exact(
        key_cap in 2_000u64..=40_000,
        device_cap in 2_000u64..=40_000,
        ops in prop::collection::vec(cap_op(), 8..40),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(run_caps(key_cap, device_cap, ops));
    }
}
