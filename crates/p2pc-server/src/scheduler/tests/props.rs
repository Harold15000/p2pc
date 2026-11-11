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
//! 6. `usage_records` has exactly one row per finished attempt: reported by its node, or estimated by the server when
//!    the attempt ended with no report (the server ended it, or it was lost);
//! 7. no lease ever reaches a `pending_approval` node (H2 §5.5, SI-H2-19). One node starts pending, and nodes are
//!    approved and (as no API does) turned pending again at random: no `Lease` is ever sent to a node that is pending,
//!    no offer is accepted from one, no lease on one was offered or accepted after it turned pending, and after a
//!    scheduling pass no active lease is left on one.
//!
//! 256 cases run by default. More locally: `PROPTEST_CASES=5000 cargo test -p p2pc-server --lib scheduler::tests::props`.

use std::collections::{BTreeMap, HashMap, HashSet};

use proptest::prelude::*;

use super::*;

#[derive(Debug, Clone)]
enum Op {
    Create {
        size: u8,
        gpu: bool,
        attempts: u8,
    },
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

async fn check_invariants(fx: &Fx, m: &mut Model) {
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
    // 6. One usage record per finished attempt, and only for those: an attempt whose node reported its end, or one
    //    that ended with no report (accepted, then revoked by the server or lost: an estimate).
    let (finished, records, matched): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM leases WHERE state IN ('finished', 'lost') \
                 OR (state = 'revoked' AND accepted_at IS NOT NULL)), \
                (SELECT COUNT(*) FROM usage_records), \
                (SELECT COUNT(*) FROM usage_records u JOIN leases l ON l.id = u.lease_id \
                 WHERE (l.state = 'finished' AND u.estimated = 0) \
                    OR (l.state IN ('revoked', 'lost') AND l.accepted_at IS NOT NULL AND u.estimated = 1))",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        (records, matched),
        (finished, finished),
        "usage records vs finished attempts"
    );
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
        check_invariants(&fx, &mut m).await;
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
    for _ in 0..128 {
        let ops = prop::collection::vec(op(), 40..48)
            .new_tree(&mut runner)
            .unwrap()
            .current();
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
    ] {
        assert!(
            total.get(want).is_some_and(|n| *n > 0),
            "never reached {want}: {total:?}"
        );
    }
}
