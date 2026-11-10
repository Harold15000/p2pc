// SPDX-License-Identifier: AGPL-3.0-only

//! The scheduler (spec §8): places queued jobs on nodes with leases fenced by epochs (§6), runs the two-phase
//! assignment, reconciles agents, expires leases and watches timeouts. Every decision takes its time from the
//! injectable clock.
//!
//! # Leases
//!
//! A lease is offered to one node (`offered`), accepted within 10 s (`accepted`, the job `assigned`), started
//! (`running`) and finished (`finished`, the job terminal). The server ends it otherwise: `revoked` (a refused or
//! unanswered offer, a cancel on an unreachable node, the watchdog) or `lost` (node loss).
//!
//! - **Epochs** (SI-8). Every lease takes the job's next epoch, issued in the transaction that creates it, so epochs
//!   increase strictly per job, offers included. The job's *current* lease is the active one with the latest epoch;
//!   any message for another `(lease_id, epoch)` changes nothing and gets `Cancel`.
//! - **Attempts.** An offer is not an attempt (§8 "Offer cap"); an accepted lease is, with one `job_attempts` row.
//!   Only node loss consumes one (`attempt + 1` on requeue).
//! - **Reservations** (§8 "Reservations are held until confirmed"). A lease holds its `reserved` capacity until
//!   `confirmed_dead_at` is set: when an offer is revoked (never started); for a finished lease, at the node's first
//!   `Heartbeat` that no longer lists it ([`Scheduler::on_heartbeat`]: the node frees the resources after its
//!   cleanup); and for an execution that may still run (cancelled on an unreachable node, watchdog) only once the node
//!   reports `JobFinished`, leaves it out of a `Hello`, is deleted, or stays silent for `lease_ttl_s`. Free capacity
//!   counts every held reservation.
//! - **Node loss** (SI-13, server half). A lease is lost only when its node is confirmed dead for it: no contact for
//!   `lease_ttl_s` (counted from the later of the node's last contact and this server's boot, §6 "Server restart"),
//!   absent from a fresh `Hello`, or the node was deleted. Then its reservation is released and the job requeued
//!   with `attempt + 1`, or `lost` when no attempt is left.
//!
//! # Atomicity
//!
//! Every change is one `BEGIN IMMEDIATE` transaction that re-reads what it decides on: placement re-reads the job,
//! the nodes and their held reservations, inserts the lease and issues the epoch; a message re-reads its lease. Two
//! schedulers running at once therefore serialise on SQLite's single writer and can never double-book a node; the
//! unique indexes (one active lease per job, one holder per GPU) are the backstop. Messages to nodes go out only
//! after the commit.
//!
//! # When it runs
//!
//! [`Scheduler::spawn`] runs [`Scheduler::tick`] on every [`Kick`] (job created or cancelled, node connected,
//! inventory changed, lease ended) and every second.

pub mod fit;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use p2pc_proto::api::{JobSpec, JobStatus, LogStream, OutputFile, UsageRecord, transition_allowed};
use p2pc_proto::ids::{AccountId, JobId, LeaseId, NodeId};
use p2pc_proto::protocol::{
    AgentMsg, LEASE_ACCEPT_TIMEOUT_S, LeaseJob, LeaseRejectReason, LogData, Outcome, RunningLease, ServerMsg, Usage,
};
use p2pc_proto::units::Units;
use time::{Duration, OffsetDateTime};
use tokio::sync::{Notify, broadcast};
use tokio::task::JoinHandle;

use self::fit::{Candidate, Held, Request, Reserved};
use crate::app::AppState;
use crate::clock::Clock;
use crate::gateway::{
    BoxFuture, HubEvent, LeaseReconciler, NodeEvents, NodeHub, OfflineReason, ReconcileFailed, SendError,
};
use crate::node_directory::{NodeDirectory, NodeMatch};
use crate::store::job_state::{TransitionError, transition};
use crate::store::jobs::{self, JobRow};
use crate::store::leases::{self, LeaseRow, LeaseState, NewLease};
use crate::store::nodes::{self, DbState, NodeRow};
use crate::store::{self, Conn, Db, StoreError, from_ts};

/// Failed offers after which a job is no longer offered, until an eligible node changes ([`node_changed`]) or the job
/// is requeued (§8 "Offer cap").
pub const OFFER_CAP: u32 = 10;
/// How long a (job, node) pair is not offered again after a failed offer (§8).
pub const OFFER_COOLDOWN: Duration = Duration::seconds(60);
/// The watchdog's margin over `timeout_s` (§8 "Timeouts").
pub const WATCHDOG_MARGIN: Duration = Duration::seconds(60);
/// How often a `Cancel` for a cancel request is sent again while the lease runs and its node has not reported the
/// end: a `Cancel` that could not be queued (a full session queue) or that was lost on a dropped connection is never
/// lost for good (review P3).
pub const CANCEL_RESEND: Duration = Duration::seconds(5);
/// Most queued jobs one tick looks at (review P3): a longer queue is served in rounds, see `Scheduler::queue_window`.
pub const MAX_JOBS_PER_TICK: usize = 256;
/// The fallback period of the loop (§8 "When it runs").
pub const TICK: std::time::Duration = std::time::Duration::from_secs(1);
/// Time the agent has to accept a lease (§6 "Two-phase assignment").
pub const ACCEPT_TIMEOUT: Duration = Duration::seconds(LEASE_ACCEPT_TIMEOUT_S as i64);

/// `reason` codes of the `Cancel`s the scheduler sends, and of lease ends. Stable, never secrets.
pub mod code {
    /// A message for a lease that is not the job's current one (SI-8).
    pub const STALE_EPOCH: &str = "stale_epoch";
    /// A message for a lease this node does not hold.
    pub const UNKNOWN_LEASE: &str = "unknown_lease";
    /// The user cancelled the job.
    pub const USER: &str = "user";
    /// The lease was not accepted within 10 s.
    pub const ACCEPT_TIMEOUT: &str = "accept_timeout";
    /// The lease could not be sent to the node.
    pub const SEND_FAILED: &str = "send_failed";
    /// The job was cancelled while its lease was an offer.
    pub const JOB_CANCELLED: &str = "job_cancelled";
    /// The node sent no heartbeat for `lease_ttl_s`.
    pub const NODE_LOST: &str = "node_lost";
    /// The node's fresh `Hello` did not list the lease.
    pub const ABSENT_FROM_HELLO: &str = "absent_from_hello";
    /// The owner deleted the node.
    pub const NODE_DELETED: &str = "node_deleted";
    /// The job was cancelled while its node was unreachable.
    pub const CANCELLED_UNREACHABLE: &str = "cancelled_unreachable";
    /// The server watchdog fired (§8 "Timeouts").
    pub const WATCHDOG: &str = "watchdog";
}

/// How the scheduler reaches nodes. [`NodeHub`] in the server; a recorder in tests.
pub trait NodeLink: Send + Sync + fmt::Debug + 'static {
    /// Queues `msg` for `node_id` without waiting.
    fn send(&self, node_id: NodeId, msg: ServerMsg) -> Result<(), SendError>;
    /// Whether the node has a live, activated connection.
    fn is_connected(&self, node_id: NodeId) -> bool;
}

impl NodeLink for NodeHub {
    fn send(&self, node_id: NodeId, msg: ServerMsg) -> Result<(), SendError> {
        NodeHub::send(self, node_id, msg)
    }

    fn is_connected(&self, node_id: NodeId) -> bool {
        NodeHub::is_connected(self, node_id)
    }
}

/// Wakes the scheduler loop. Cheap to clone; a kick while the loop is busy makes it run once more.
#[derive(Debug, Clone, Default)]
pub struct Kick(Arc<Notify>);

impl Kick {
    /// Asks for a scheduling pass soon.
    pub fn kick(&self) {
        self.0.notify_one();
    }

    /// Waits for the next kick.
    pub async fn wait(&self) {
        self.0.notified().await;
    }
}

/// §8 "Offer cap" (amended): an eligible node of `account_id` changed — it connected or reconnected, sent an
/// `InventoryUpdate`, was resumed, or joined. Re-arms the offer cap of the account's queued jobs (in one transaction)
/// and wakes the scheduler. A failure is logged: the jobs keep their count until the next change.
pub async fn node_changed(db: &Db, kick: &Kick, account_id: AccountId) {
    let result = async {
        let mut tx = store::begin_immediate(db).await?;
        let n = leases::rearm_offers(&mut tx, account_id).await?;
        tx.commit().await?;
        Ok::<u64, StoreError>(n)
    }
    .await;
    match result {
        Ok(0) => {}
        Ok(n) => tracing::info!(jobs = n, "offer cap re-armed: an eligible node changed"),
        Err(e) => tracing::warn!(error = %e, "cannot re-arm the offer cap"),
    }
    kick.kick();
}

/// The `reason` text of a job held at the offer cap (§8), from the last rejection reason. A capacity refusal says so in
/// words, because that is the case the owner can act on (a job ends, or the share grows); the others keep their code.
fn cap_reason(why: &str) -> String {
    if why == LeaseRejectReason::InsufficientCapacity.to_string() {
        format!("the nodes refused it for capacity ({why})")
    } else {
        why.to_string()
    }
}

/// §8 "Offer cap" (amended 2026-11-07, ACC-1 round 2): a lease that had been accepted has ended (any terminal state,
/// or its execution is confirmed dead), so its capacity comes back. Re-arms the offer cap of the account's queued
/// jobs with the same statement as [`node_changed`], inside the caller's transaction, and asks for another pass.
///
/// An offer that was never accepted (refused, unanswered, revoked) does not call this: it held nothing on the node,
/// and counting it would reset the cap with every refusal, so the cap would never be reached. The 60 s cooldown of a
/// (job, node) pair is not touched, so a re-arm cannot turn into an offer storm: a pair is offered at most once per
/// 60 s however many leases end.
///
/// Only a lease of an eligible node frees capacity an offer can use (§8): one whose node is draining, offline or
/// deleted does not re-arm. The node's return or resume does, through [`node_changed`].
async fn rearm_on_lease_end(tx: &mut Conn, lease: &LeaseRow, fx: &mut Effects) -> Result<()> {
    fx.kick = true;
    let offerable = nodes::get(tx, lease.account_id, lease.node_id)
        .await?
        .is_some_and(|n| n.state == nodes::DbState::Online && !n.draining);
    if !offerable {
        return Ok(());
    }
    let n = leases::rearm_offers(tx, lease.account_id).await?;
    if n > 0 {
        tracing::info!(jobs = n, lease_id = %lease.id, "offer cap re-armed: a lease ended");
    }
    Ok(())
}

/// One fenced chunk of job output (`LogChunk`), for the [`LogSink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogChunk {
    /// Source stream.
    pub stream: LogStream,
    /// Sequence number within the attempt.
    pub seq: u64,
    /// The bytes, base64 (`Debug` shows only the length).
    pub data_b64: LogData,
    /// When the server received it.
    pub received_at: OffsetDateTime,
}

/// Where fenced, deduplicated log chunks go. T10b stores them; the default drops them.
pub trait LogSink: Send + Sync + fmt::Debug + 'static {
    /// A chunk of attempt `attempt` of `job_id`.
    fn on_chunk(&self, job_id: JobId, attempt: u32, chunk: LogChunk) -> BoxFuture<'_, ()>;
}

/// Drops every chunk (tests that do not look at logs).
#[derive(Debug, Default, Clone, Copy)]
pub struct DropLogs;

impl LogSink for DropLogs {
    fn on_chunk(&self, _job_id: JobId, _attempt: u32, _chunk: LogChunk) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

/// Publishes an attempt's outputs before its job's terminal transition (§6 "Uploads"). T10b implements it.
pub trait OutputsFinalizer: Send + Sync + fmt::Debug + 'static {
    /// Publishes the staged files `outputs` lists. Returns a note for the job's `error` (for example
    /// `outputs_incomplete: 2`), or `None`. Idempotent: it may run again for the same attempt.
    fn finalize<'a>(&'a self, job_id: JobId, attempt: u32, outputs: &'a [OutputFile]) -> BoxFuture<'a, Option<String>>;
}

/// Publishes nothing (tests that do not look at outputs).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOutputs;

impl OutputsFinalizer for NoOutputs {
    fn finalize<'a>(&'a self, _: JobId, _: u32, _: &'a [OutputFile]) -> BoxFuture<'a, Option<String>> {
        Box::pin(async { None })
    }
}

/// The durations the scheduler works with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// `nodes.lease_ttl_s`.
    pub lease_ttl: Duration,
    /// `scheduler.pull_timeout_s`.
    pub pull_timeout: Duration,
    /// `gpu_hour_units`.
    pub gpu_hour_units: Units,
}

impl Timing {
    /// From the server configuration.
    #[must_use]
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            lease_ttl: Duration::seconds(i64::from(config.nodes.lease_ttl_s)),
            pull_timeout: Duration::seconds(i64::from(config.scheduler.pull_timeout_s)),
            gpu_hour_units: crate::units::gpu_hour_units(config),
        }
    }
}

/// Why a scheduling step failed. The step's transaction was rolled back; the next tick retries.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A job transition was refused (a bug, or a race the re-read should have prevented).
    #[error("job transition refused: {0}")]
    Transition(String),
}

impl From<sqlx::Error> for SchedulerError {
    fn from(e: sqlx::Error) -> Self {
        Self::Store(e.into())
    }
}

impl From<TransitionError> for SchedulerError {
    fn from(e: TransitionError) -> Self {
        match e {
            TransitionError::Store(s) => Self::Store(s),
            other => Self::Transition(other.to_string()),
        }
    }
}

type Result<T, E = SchedulerError> = std::result::Result<T, E>;

/// What a committed transaction asks for: messages to nodes, ended leases, another pass.
#[derive(Debug, Default)]
struct Effects {
    send: Vec<(NodeId, ServerMsg)>,
    ended: Vec<LeaseId>,
    kick: bool,
}

/// Logs and counts a failed step of a tick.
fn failed(r: &mut TickReport, step: &str, e: &SchedulerError) {
    r.errors += 1;
    tracing::warn!(error = %e, step, "scheduling step failed; skipped until the next tick");
}

fn cancel(lease_id: LeaseId, epoch: u64, reason: &str) -> ServerMsg {
    ServerMsg::Cancel {
        lease_id,
        epoch,
        reason: reason.to_string(),
    }
}

/// What one [`Scheduler::tick`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Leases offered.
    pub offered: usize,
    /// Queued jobs looked at (at most [`MAX_JOBS_PER_TICK`]).
    pub considered: usize,
    /// Placement transactions (`BEGIN IMMEDIATE`) opened: only for jobs the read-only snapshot says can fit.
    pub placements_tried: usize,
    /// Cancel transactions (`BEGIN IMMEDIATE`) opened: only for cancels the read-only pre-pass says are due.
    pub cancels_tried: usize,
    /// Steps that failed (a phase, or one lease, node or job inside it). Each was logged, rolled back and skipped;
    /// the others went on, and the next tick retries.
    pub errors: usize,
}

/// The scheduler. Cheap to clone; every clone shares the same state.
#[derive(Debug, Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    db: Db,
    clock: Arc<dyn Clock>,
    link: Arc<dyn NodeLink>,
    timing: Timing,
    /// No lease expires before `lease_ttl_s` after this (§6 "Server restart").
    booted_at: OffsetDateTime,
    kick: Kick,
    logs: Arc<dyn LogSink>,
    outputs: Arc<dyn OutputsFinalizer>,
    /// The highest `LogChunk.seq` forwarded per active lease (deduplication).
    log_seq: Mutex<HashMap<LeaseId, u64>>,
    /// Where the next round of a queue longer than [`MAX_JOBS_PER_TICK`] starts: after this job.
    queue_resume: Mutex<Option<leases::QueuePosition>>,
}

/// A lease just created by placement, to be sent.
#[derive(Debug)]
struct Placed {
    lease: NewLease,
    account_id: AccountId,
    project_id: p2pc_proto::ids::ProjectId,
    timeout_s: u32,
    offered_at: OffsetDateTime,
}

/// The kinds of lease messages, after decoding.
#[derive(Debug)]
enum LeaseMsg {
    Accepted,
    Rejected(LeaseRejectReason),
    Started,
    Finished(Box<Finished>),
}

#[derive(Debug)]
struct Finished {
    outcome: Outcome,
    exit_code: Option<i32>,
    error: Option<String>,
    usage: Usage,
    outputs: Vec<OutputFile>,
}

impl Scheduler {
    /// The scheduler of a server, sending through `link` (the gateway's hub), with the server's log store as its
    /// [`LogSink`] and its output store as its [`OutputsFinalizer`] (T10b).
    #[must_use]
    pub fn new(state: &AppState, link: Arc<dyn NodeLink>) -> Self {
        Self::with_hooks(
            state,
            link,
            Arc::new(state.logs.clone()),
            Arc::new(state.outputs.clone()),
        )
    }

    /// [`Scheduler::new`] with a [`LogSink`] and an [`OutputsFinalizer`] (T10b).
    #[must_use]
    pub fn with_hooks(
        state: &AppState,
        link: Arc<dyn NodeLink>,
        logs: Arc<dyn LogSink>,
        outputs: Arc<dyn OutputsFinalizer>,
    ) -> Self {
        Self::from_parts(
            state.db.clone(),
            state.clock.clone(),
            Timing::from_config(&state.config),
            state.kick.clone(),
            link,
            logs,
            outputs,
        )
    }

    /// The scheduler over explicit parts. Its boot time, for the restart grace, is the clock's time now.
    #[must_use]
    pub fn from_parts(
        db: Db,
        clock: Arc<dyn Clock>,
        timing: Timing,
        kick: Kick,
        link: Arc<dyn NodeLink>,
        logs: Arc<dyn LogSink>,
        outputs: Arc<dyn OutputsFinalizer>,
    ) -> Self {
        let booted_at = clock.now();
        Self {
            inner: Arc::new(Inner {
                db,
                clock,
                link,
                timing,
                booted_at,
                kick,
                logs,
                outputs,
                log_seq: Mutex::new(HashMap::new()),
                queue_resume: Mutex::new(None),
            }),
        }
    }

    fn now(&self) -> OffsetDateTime {
        self.inner.clock.now()
    }

    /// Runs the loop in a task: a tick on every kick, on every node connect, and every second. Abort the handle to
    /// stop it.
    #[must_use]
    pub fn spawn(&self, hub_events: Option<broadcast::Receiver<HubEvent>>) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move { this.run(hub_events).await })
    }

    async fn run(self, mut hub_events: Option<broadcast::Receiver<HubEvent>>) {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let event = async {
                match hub_events.as_mut() {
                    Some(rx) => match rx.recv().await {
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => true,
                        Err(broadcast::error::RecvError::Closed) => false,
                    },
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = tick.tick() => {}
                () = self.inner.kick.wait() => {}
                open = event => if !open { hub_events = None },
            }
            self.tick().await;
        }
    }

    /// One scheduling pass: expire unanswered offers, expire leases of nodes silent for `lease_ttl_s`, deliver
    /// cancels, run the watchdog, send again the `Cancel`s of executions the server ended, forget the log `seq`s of
    /// ended leases, then place queued jobs FIFO.
    ///
    /// Each phase runs on its own, and inside a phase each lease, node or job is its own step (its own
    /// transaction): a failure is logged and counted in [`TickReport::errors`], and the rest goes on. One bad row never
    /// stops the scheduler.
    pub async fn tick(&self) -> TickReport {
        let mut r = TickReport::default();
        if let Err(e) = self.expire_offers(&mut r).await {
            failed(&mut r, "expire offers", &e);
        }
        if let Err(e) = self.expire_silent_nodes(&mut r).await {
            failed(&mut r, "expire silent nodes", &e);
        }
        if let Err(e) = self.deliver_cancels(&mut r).await {
            failed(&mut r, "deliver cancels", &e);
        }
        if let Err(e) = self.watchdog(&mut r).await {
            failed(&mut r, "watchdog", &e);
        }
        if let Err(e) = self.resend_server_cancels(&mut r).await {
            failed(&mut r, "resend server cancels", &e);
        }
        if let Err(e) = self.prune_log_seq().await {
            failed(&mut r, "prune log seqs", &e);
        }
        if let Err(e) = self.place(&mut r).await {
            failed(&mut r, "place", &e);
        }
        r
    }

    /// Sends the effects of a committed transaction.
    fn deliver(&self, fx: Effects) {
        for (node_id, msg) in fx.send {
            match self.inner.link.send(node_id, msg) {
                // Not connected: the node gets a `Cancel` when it reconciles, or its lease expires.
                Ok(()) | Err(SendError::NotConnected) => {}
                Err(SendError::Full) => tracing::warn!(%node_id, "message not sent: the node's queue is full"),
            }
        }
        if !fx.ended.is_empty() {
            let mut seqs = self.inner.log_seq.lock().unwrap_or_else(PoisonError::into_inner);
            for id in fx.ended {
                seqs.remove(&id);
            }
        }
        if fx.kick {
            self.inner.kick.kick();
        }
    }

    // --- Job transitions ------------------------------------------------------------------------------------------

    /// Moves the job of `lease` to `to` (nothing if it is there already), through `job_state::transition`.
    async fn move_job(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        to: JobStatus,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<JobRow> {
        let job = jobs::get(tx, lease.account_id, lease.project_id, lease.job_id)
            .await?
            .ok_or(StoreError::Corrupt("leases.job_id"))?;
        if job.status == to {
            return Ok(job);
        }
        Ok(transition(tx, &job, to, reason, now).await?)
    }

    // --- Lease operations (inside the caller's transaction) -----------------------------------------------------

    /// A refused or unanswered offer, or one revoked for another reason: the lease is revoked and confirmed dead
    /// (it never started). `why` counts it against the job's offer cap, with a cooldown for the pair, unless the job
    /// is already terminal.
    async fn fail_offer(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        end_reason: &str,
        why: Option<&str>,
        now: OffsetDateTime,
        fx: &mut Effects,
    ) -> Result<()> {
        if !leases::end(tx, lease.id, LeaseState::Revoked, end_reason, true, now).await? {
            return Ok(());
        }
        fx.ended.push(lease.id);
        fx.kick = true;
        // A job that ended meanwhile (cancelled while its lease was an offer) is not offered again anyway: no
        // count, no cooldown, and never the offer cap's reason on it (T06 review). `job_status` was read in `tx`.
        if let Some(why) = why
            && !lease.job_status.is_terminal()
        {
            let count = leases::count_failed_offer(tx, lease.job_id).await?;
            leases::set_cooldown(tx, lease.job_id, lease.node_id, now + OFFER_COOLDOWN).await?;
            if count >= OFFER_CAP {
                let reason = format!("no node accepted the job: {}", cap_reason(why));
                leases::set_reason(tx, lease.job_id, Some(&reason)).await?;
                tracing::info!(job_id = %lease.job_id, "offer cap reached; the job stays queued");
            }
        }
        Ok(())
    }

    /// `LeaseAccepted` (or a lease an agent lists in `Hello`): `offered → accepted`, the job `assigned`, its attempt
    /// opened. Too late (10 s) is an unanswered offer instead. Returns whether it was accepted.
    async fn accept(&self, tx: &mut Conn, lease: &LeaseRow, now: OffsetDateTime, fx: &mut Effects) -> Result<bool> {
        if now >= lease.offered_at + ACCEPT_TIMEOUT {
            self.fail_offer(
                tx,
                lease,
                code::ACCEPT_TIMEOUT,
                Some("the lease was not accepted within 10 s"),
                now,
                fx,
            )
            .await?;
            fx.send
                .push((lease.node_id, cancel(lease.id, lease.epoch, code::ACCEPT_TIMEOUT)));
            return Ok(false);
        }
        if !leases::mark_accepted(tx, lease.id, now).await? {
            return Ok(false);
        }
        self.move_job(tx, lease, JobStatus::Assigned, "lease_accepted", now)
            .await?;
        leases::set_node(tx, lease.job_id, lease.node_id).await?;
        leases::open_attempt(tx, lease, now).await?;
        Ok(true)
    }

    /// `JobStarted`: `accepted → running`, the job `running`. An offer is accepted first.
    async fn start(&self, tx: &mut Conn, lease: &LeaseRow, now: OffsetDateTime, fx: &mut Effects) -> Result<()> {
        if lease.state == LeaseState::Offered && !self.accept(tx, lease, now, fx).await? {
            return Ok(());
        }
        if leases::mark_running(tx, lease.id, now).await? {
            self.move_job(tx, lease, JobStatus::Running, "job_started", now).await?;
            leases::attempt_started(tx, lease.id, now).await?;
        }
        Ok(())
    }

    /// The node is confirmed dead for `lease` (`reason`: TTL, absent from `Hello`, deleted). An offer is revoked
    /// (not counted); an accepted or running lease is lost and its job requeued with `attempt + 1`, or `lost`, or
    /// `cancelled` if a cancel was pending; an ended lease is confirmed dead. `notify` sends the node `Cancel`.
    /// Returns whether the job was requeued.
    async fn lose(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        reason: &str,
        notify: bool,
        now: OffsetDateTime,
        fx: &mut Effects,
    ) -> Result<bool> {
        let mut requeued = false;
        match lease.state {
            LeaseState::Offered => self.fail_offer(tx, lease, reason, None, now, fx).await?,
            LeaseState::Accepted | LeaseState::Running => {
                if !leases::end(tx, lease.id, LeaseState::Lost, reason, true, now).await? {
                    return Ok(false);
                }
                leases::attempt_ended(tx, lease.id, JobStatus::Lost, reason, now).await?;
                // §11 (amended 54959f6): a lost attempt held a reservation, so it is billed: the server's estimate,
                // from its start (or acceptance) to now, when the loss was decided.
                let record = self.estimated_record(tx, lease, now).await?;
                leases::insert_usage(tx, lease.id, &record).await?;
                let job = jobs::get(tx, lease.account_id, lease.project_id, lease.job_id)
                    .await?
                    .ok_or(StoreError::Corrupt("leases.job_id"))?;
                if !job.status.is_terminal() {
                    if job.cancel_requested_at.is_some() {
                        transition(tx, &job, JobStatus::Cancelled, "cancelled_by_user", now).await?;
                    } else if job.attempt < job.max_attempts {
                        transition(tx, &job, JobStatus::Queued, reason, now).await?;
                        leases::next_attempt(tx, lease.job_id, lease.node_id).await?;
                        requeued = true;
                    } else {
                        transition(tx, &job, JobStatus::Lost, reason, now).await?;
                    }
                }
                fx.ended.push(lease.id);
                fx.kick = true;
                rearm_on_lease_end(tx, lease, fx).await?;
                tracing::info!(job_id = %lease.job_id, lease_id = %lease.id, node_id = %lease.node_id, reason,
                    requeued, "lease lost");
            }
            LeaseState::Finished | LeaseState::Revoked | LeaseState::Lost => {
                if leases::confirm_dead(tx, lease.id, now).await? {
                    fx.kick = true;
                    // The execution a lease held is gone: its capacity is free (a never-accepted offer held none).
                    if lease.accepted_at.is_some() {
                        rearm_on_lease_end(tx, lease, fx).await?;
                    }
                }
            }
        }
        // A finished lease has nothing left to cancel: its node only holds the cleanup's resources.
        if notify && lease.state != LeaseState::Finished {
            fx.send.push((lease.node_id, cancel(lease.id, lease.epoch, reason)));
        }
        Ok(requeued)
    }

    /// The server ends an accepted or running lease's job (`cancelled` on an unreachable node, `timed_out` by the
    /// watchdog). The execution may still run, so the reservation stays held until it is confirmed dead. The ledger
    /// gets an estimated row now, since no report will be counted for this attempt.
    async fn end_by_server(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        to: JobStatus,
        reason: &str,
        now: OffsetDateTime,
        fx: &mut Effects,
    ) -> Result<()> {
        if !leases::end(tx, lease.id, LeaseState::Revoked, reason, false, now).await? {
            return Ok(());
        }
        leases::attempt_ended(tx, lease.id, to, reason, now).await?;
        self.move_job(tx, lease, to, reason, now).await?;
        // No report will come for this attempt: the ledger gets the server's estimate.
        let record = self.estimated_record(tx, lease, now).await?;
        leases::insert_usage(tx, lease.id, &record).await?;
        fx.send.push((lease.node_id, cancel(lease.id, lease.epoch, reason)));
        // Sent again every `CANCEL_RESEND` until the node confirms the end (`resend_server_cancels`).
        leases::mark_cancel_sent(tx, lease.id, now).await?;
        fx.ended.push(lease.id);
        rearm_on_lease_end(tx, lease, fx).await?;
        tracing::info!(job_id = %lease.job_id, lease_id = %lease.id, reason, "job ended by the server");
        Ok(())
    }

    /// `JobFinished` on the current lease: the job's terminal state, the ledger row and the lease closed. Its
    /// reservation is **not** released: it is held until the node's `Heartbeat` stops listing the lease (§8).
    async fn finish(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        msg: &Finished,
        note: Option<&str>,
        now: OffsetDateTime,
        fx: &mut Effects,
    ) -> Result<()> {
        if lease.state == LeaseState::Offered && !self.accept(tx, lease, now, fx).await? {
            return Ok(());
        }
        let (to, reason) = match (msg.outcome, msg.exit_code) {
            (Outcome::Exited, Some(0)) => (JobStatus::Succeeded, "exited_0"),
            (Outcome::Exited, _) => (JobStatus::Failed, "exit_code"),
            (Outcome::TimedOut, _) => (JobStatus::TimedOut, "timed_out"),
            (Outcome::Cancelled, _) => (JobStatus::Cancelled, "cancelled"),
            (Outcome::Error, _) => (JobStatus::Failed, "sandbox_error"),
        };
        let job = jobs::get(tx, lease.account_id, lease.project_id, lease.job_id)
            .await?
            .ok_or(StoreError::Corrupt("leases.job_id"))?;
        // An agent may report the end of a job it never reported started (for example an exit before `JobStarted`
        // reached us): the start is implied, so the job goes through `running`.
        if job.status == JobStatus::Assigned && !transition_allowed(JobStatus::Assigned, to) {
            leases::mark_running(tx, lease.id, now).await?;
            self.move_job(tx, lease, JobStatus::Running, "job_started", now).await?;
            leases::attempt_started(tx, lease.id, now).await?;
        }
        let error = match (msg.error.as_deref(), note) {
            (Some(e), Some(n)) => Some(format!("{e}; {n}")),
            (Some(e), None) => Some(e.to_string()),
            (None, Some(n)) => Some(n.to_string()),
            (None, None) => None,
        };
        let outcome = match msg.outcome {
            Outcome::Exited => "exited",
            Outcome::TimedOut => "timed_out",
            Outcome::Cancelled => "cancelled",
            Outcome::Error => "error",
        };
        leases::set_result(tx, lease.job_id, outcome, msg.exit_code, error.as_deref()).await?;
        self.move_job(tx, lease, to, reason, now).await?;
        // §8 "Reservations are held until confirmed": the node frees the lease's resources only after its cleanup, so
        // the reservation stays held until its first `Heartbeat` that no longer lists the lease ([`Scheduler::on_heartbeat`]).
        if !leases::end(tx, lease.id, LeaseState::Finished, reason, false, now).await? {
            return Err(StoreError::Corrupt("leases.state").into());
        }
        leases::attempt_ended(tx, lease.id, to, reason, now).await?;
        // The ledger (§11), with what the row says now (the start may have been implied above).
        let lease_now = leases::get(tx, lease.id).await?.ok_or(StoreError::Corrupt("leases"))?;
        let record = self.usage_record(tx, &lease_now, &msg.usage, now).await?;
        leases::insert_usage(tx, lease.id, &record).await?;
        fx.ended.push(lease.id);
        tracing::info!(job_id = %lease.job_id, lease_id = %lease.id, status = %to, "job finished");
        Ok(())
    }

    /// The ledger row of a finished attempt (§11). Reserved time is the reported wall time, capped at the job's
    /// `timeout_s` plus the watchdog margin; units are computed from it like the estimate (rounded up to the
    /// milli-unit).
    async fn usage_record(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        usage: &Usage,
        now: OffsetDateTime,
    ) -> Result<UsageRecord> {
        let cap_ms = (u64::from(lease.timeout_s) + WATCHDOG_MARGIN.whole_seconds() as u64) * 1000;
        let mut record = self.reserved_record(tx, lease, usage.wall_ms.min(cap_ms), now).await?;
        record.used_cpu_ms = usage.cpu_used_ms;
        record.max_rss_mb = usage.max_rss_mb;
        Ok(record)
    }

    /// The **estimated** ledger row of an attempt that ended with no report: one the server ended itself (watchdog,
    /// cancel on an unreachable node) or one that was lost (§11, amended 54959f6). What it reserved from its start (or
    /// acceptance) to now, with nothing measured. The daily cap and
    /// `GET /v1/usage` then count the same units.
    async fn estimated_record(&self, tx: &mut Conn, lease: &LeaseRow, now: OffsetDateTime) -> Result<UsageRecord> {
        let started = lease.started_at.or(lease.accepted_at).unwrap_or(lease.offered_at);
        let wall_ms = u64::try_from((now - started).whole_milliseconds()).unwrap_or(0);
        let mut record = self.reserved_record(tx, lease, wall_ms, now).await?;
        record.estimated = true;
        Ok(record)
    }

    /// A ledger row for `wall_ms` of what `lease` reserved, from its start (or acceptance) to `now`.
    async fn reserved_record(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        wall_ms: u64,
        now: OffsetDateTime,
    ) -> Result<UsageRecord> {
        // `UsageRecord` (p2pc-proto) still names the principal by a key ID. `insert_usage` takes the principal (key or
        // device) from the job's own row and never stores this field (H2 §5.6), so a device's job carries a random
        // stand-in here that goes nowhere. T2-16 replaces the ledger row type.
        let key_id = leases::job_principal(tx, lease.job_id)
            .await?
            .key_id()
            .unwrap_or_else(p2pc_proto::ids::KeyId::generate);
        let started = lease.started_at.or(lease.accepted_at).unwrap_or(lease.offered_at);
        let wall_ms = u128::from(wall_ms);
        let cpu_milli = u128::from(fit::cpu_milli(lease.reserved.cpu));
        let gpus = u128::from(u8::from(lease.reserved.gpu_uuid.is_some()));
        let gpu_hour = u128::from(self.inner.timing.gpu_hour_units.milli());
        let milli_units = (cpu_milli * wall_ms + gpus * gpu_hour * wall_ms).div_ceil(3_600_000);
        let to_u64 = |v: u128| u64::try_from(v).unwrap_or(u64::MAX);
        // A constructor, then the fields: the shared type may grow (CONTRIBUTING rule 7).
        let mut record = UsageRecord::new(
            lease.job_id,
            lease.attempt,
            lease.node_id,
            key_id,
            lease.account_id,
            lease.project_id,
        );
        record.started_at = started;
        record.ended_at = now.max(started);
        record.reserved_cpu_ms = to_u64(cpu_milli * wall_ms / 1000);
        record.reserved_gpu_ms = to_u64(gpus * wall_ms);
        record.units = Units::from_milli(to_u64(milli_units));
        Ok(record)
    }

    // --- Messages from agents ---------------------------------------------------------------------------------

    /// Handles one lease or job message from `node_id`.
    pub async fn on_agent_message(&self, node_id: NodeId, msg: AgentMsg) -> Result<()> {
        let (lease_id, epoch, kind) = match msg {
            AgentMsg::LeaseAccepted { lease_id, epoch } => (lease_id, epoch, LeaseMsg::Accepted),
            AgentMsg::LeaseRejected {
                lease_id,
                epoch,
                reason,
            } => (lease_id, epoch, LeaseMsg::Rejected(reason)),
            AgentMsg::JobStarted { lease_id, epoch, .. } => (lease_id, epoch, LeaseMsg::Started),
            AgentMsg::JobFinished {
                lease_id,
                epoch,
                outcome,
                exit_code,
                error,
                usage,
                outputs,
            } => (
                lease_id,
                epoch,
                LeaseMsg::Finished(Box::new(Finished {
                    outcome,
                    exit_code,
                    error,
                    usage,
                    outputs,
                })),
            ),
            AgentMsg::LogChunk {
                lease_id,
                epoch,
                stream,
                seq,
                data_b64,
            } => {
                return self.on_log_chunk(node_id, lease_id, epoch, stream, seq, data_b64).await;
            }
            // The gateway handles the rest itself.
            _ => return Ok(()),
        };
        // Outputs are published before the terminal transition, outside the write lock, and only for the current
        // lease (finalising is idempotent, so a lost race below only repeats it).
        let note = match &kind {
            LeaseMsg::Finished(f) => {
                let mut conn = self.inner.db.acquire().await?;
                match leases::get(&mut conn, lease_id).await? {
                    Some(l) if l.node_id == node_id && l.epoch == epoch && l.is_current() => {
                        drop(conn);
                        self.inner.outputs.finalize(l.job_id, l.attempt, &f.outputs).await
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let lease = match leases::get(&mut tx, lease_id).await? {
            Some(l) if l.node_id == node_id && l.epoch == epoch => l,
            Some(l) if l.node_id == node_id => {
                fx.send.push((node_id, cancel(lease_id, epoch, code::STALE_EPOCH)));
                drop(tx);
                self.deliver(fx);
                return Ok(());
            }
            // Unknown, or another node's lease: the same answer, which says nothing about other nodes.
            _ => {
                fx.send.push((node_id, cancel(lease_id, epoch, code::UNKNOWN_LEASE)));
                drop(tx);
                self.deliver(fx);
                return Ok(());
            }
        };
        if lease.is_current() {
            match (kind, lease.state) {
                (LeaseMsg::Accepted, LeaseState::Offered) => {
                    self.accept(&mut tx, &lease, now, &mut fx).await?;
                }
                (LeaseMsg::Rejected(reason), LeaseState::Offered) => {
                    let why = reason.to_string();
                    let end = format!("rejected:{why}");
                    self.fail_offer(&mut tx, &lease, &end, Some(&why), now, &mut fx).await?;
                }
                (LeaseMsg::Started, LeaseState::Offered | LeaseState::Accepted) => {
                    self.start(&mut tx, &lease, now, &mut fx).await?;
                }
                (LeaseMsg::Finished(f), _) => {
                    self.finish(&mut tx, &lease, &f, note.as_deref(), now, &mut fx).await?;
                }
                // Duplicates (a resent `LeaseAccepted` or `JobStarted`), and a refusal after an acceptance: no effect.
                (_, state) => {
                    tracing::debug!(lease_id = %lease.id, ?state, "duplicate lease message ignored");
                }
            }
        } else {
            match (&kind, lease.state) {
                // A second `JobFinished` is harmless (§6 "Idempotency").
                (LeaseMsg::Finished(_), LeaseState::Finished) => {}
                // The execution of a lease the server ended has ended: release what it held.
                (LeaseMsg::Finished(_), LeaseState::Revoked | LeaseState::Lost) if lease.holds() => {
                    if leases::confirm_dead(&mut tx, lease.id, now).await? {
                        fx.kick = true;
                        // The server had ended the job; now its execution is gone and the node's capacity is back.
                        rearm_on_lease_end(&mut tx, &lease, &mut fx).await?;
                    }
                }
                // SI-8: anything else for a lease that is not current is fenced.
                _ => fx.send.push((node_id, cancel(lease_id, epoch, code::STALE_EPOCH))),
            }
        }
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    /// `Heartbeat.running` from `node_id` (§6, §8 "Reservations are held until confirmed"): a finished lease keeps its
    /// reservation until the node's first heartbeat that no longer lists it, because `running` lists every lease that
    /// still holds resources on the node (running, uploading or being cleaned up). Then the capacity comes back, the
    /// offer cap is re-armed and the scheduler is kicked.
    ///
    /// A finished lease that is still listed is normal (its cleanup is running): nothing changes and nothing is
    /// logged above `debug`. Only leases of `node_id` are looked at, and only finished ones: the ways to end any
    /// other lease (node loss, `Hello`, `lease_ttl_s`, a cancel on an unreachable node) are not this one's. An older
    /// agent lists only the jobs that run, so its finished leases come back at its next heartbeat.
    pub async fn on_heartbeat(&self, node_id: NodeId, running: &[RunningLease]) -> Result<()> {
        let listed: HashSet<(LeaseId, u64)> = running.iter().map(|r| (r.lease_id, r.epoch)).collect();
        let freed = |held: Vec<LeaseRow>| -> Vec<LeaseRow> {
            held.into_iter()
                .filter(|l| !listed.contains(&(l.id, l.epoch)))
                .collect()
        };
        // Read-only first: most heartbeats have nothing to free, and must not take the write lock.
        let due = {
            let mut conn = self.inner.db.acquire().await?;
            freed(leases::finished_held_on_node(&mut conn, node_id).await?)
        };
        if due.is_empty() {
            return Ok(());
        }
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        // Re-read inside the transaction: another message or a node-loss decision may have freed it meanwhile.
        for lease in freed(leases::finished_held_on_node(&mut tx, node_id).await?) {
            if leases::confirm_dead(&mut tx, lease.id, now).await? {
                rearm_on_lease_end(&mut tx, &lease, &mut fx).await?;
                tracing::debug!(lease_id = %lease.id, %node_id, "the node freed a finished lease");
            }
        }
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    async fn on_log_chunk(
        &self,
        node_id: NodeId,
        lease_id: LeaseId,
        epoch: u64,
        stream: LogStream,
        seq: u64,
        data_b64: LogData,
    ) -> Result<()> {
        let lease = {
            let mut conn = self.inner.db.acquire().await?;
            leases::get(&mut conn, lease_id).await?
        };
        let lease = match lease {
            Some(l) if l.node_id == node_id && l.epoch == epoch && l.is_current() => l,
            other => {
                let reason = if other.is_some_and(|l| l.node_id == node_id) {
                    code::STALE_EPOCH
                } else {
                    code::UNKNOWN_LEASE
                };
                self.deliver(Effects {
                    send: vec![(node_id, cancel(lease_id, epoch, reason))],
                    ..Effects::default()
                });
                return Ok(());
            }
        };
        // Deduplication by (lease_id, epoch, seq): the epoch is fenced above, so the lease's last seq decides.
        {
            let mut seqs = self.inner.log_seq.lock().unwrap_or_else(PoisonError::into_inner);
            match seqs.get(&lease_id) {
                Some(last) if seq <= *last => return Ok(()),
                _ => {
                    seqs.insert(lease_id, seq);
                }
            }
        }
        let chunk = LogChunk {
            stream,
            seq,
            data_b64,
            received_at: self.now(),
        };
        self.inner.logs.on_chunk(lease.job_id, lease.attempt, chunk).await;
        Ok(())
    }

    // --- Liveness and reconciliation ----------------------------------------------------------------------------

    /// `Hello.running` from `node_id` (§6 "Reconnects"): valid current leases continue (an offer listed there is
    /// accepted, and a pending cancel is delivered again); anything else gets `Cancel`; a lease the server holds for
    /// this node that the `Hello` does not list is confirmed dead at once (lost and requeued, or its reservation
    /// released). Returns the messages for the node, sent after its `Welcome`.
    pub async fn reconcile_hello(&self, node_id: NodeId, running: &[RunningLease]) -> Result<Vec<ServerMsg>> {
        let mut fx = Effects::default();
        let mut replies = Vec::new();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let mut listed = HashSet::new();
        for r in running {
            listed.insert(r.lease_id);
            let lease = match leases::get(&mut tx, r.lease_id).await {
                Ok(l) => l,
                // A row that does not decode will not decode on a retry either, so closing the session would only
                // loop: the server cannot track that lease, and the agent stops it.
                Err(StoreError::Corrupt(column)) => {
                    tracing::warn!(lease_id = %r.lease_id, column, "a listed lease does not decode; cancelling it");
                    replies.push(cancel(r.lease_id, r.epoch, code::UNKNOWN_LEASE));
                    continue;
                }
                // Anything else may be transient: the session is closed and the agent reconciles again.
                Err(e) => return Err(e.into()),
            };
            match lease {
                Some(l) if l.node_id == node_id && l.epoch == r.epoch && l.is_current() => {
                    if l.state == LeaseState::Offered {
                        self.accept(&mut tx, &l, now, &mut fx).await?;
                    }
                    if l.cancel_requested_at.is_some() {
                        replies.push(cancel(l.id, l.epoch, code::USER));
                        leases::mark_cancel_sent(&mut tx, l.id, now).await?;
                    }
                }
                Some(l) if l.node_id == node_id => replies.push(cancel(r.lease_id, r.epoch, code::STALE_EPOCH)),
                _ => replies.push(cancel(r.lease_id, r.epoch, code::UNKNOWN_LEASE)),
            }
        }
        let mut requeued = false;
        for l in leases::held_on_node(&mut tx, node_id).await? {
            // An offer may simply not have reached the agent before its `Hello`: the 10 s timeout handles it.
            if l.state == LeaseState::Offered || listed.contains(&l.id) {
                continue;
            }
            requeued |= self
                .lose(&mut tx, &l, code::ABSENT_FROM_HELLO, false, now, &mut fx)
                .await?;
        }
        if requeued {
            nodes::disconnection_requeued(&mut tx, node_id, now).await?;
        }
        tx.commit().await?;
        // Messages for this node go after its `Welcome`, in order, with the replies.
        let (mine, others): (Vec<_>, Vec<_>) = std::mem::take(&mut fx.send)
            .into_iter()
            .partition(|(n, _)| *n == node_id);
        replies.extend(mine.into_iter().map(|(_, m)| m));
        fx.send = others;
        fx.kick = true;
        self.deliver(fx);
        Ok(replies)
    }

    /// `on_node_offline`: a deleted node's leases are lost at once and it is sent nothing more; a lost node's leases
    /// are lost once it is confirmed silent for `lease_ttl_s` (the gateway's sweep decided so; checked again here).
    ///
    /// Both cases are decided from the node's row, so the tick's backstop ([`Scheduler::tick`]) reaches the same
    /// result if this hook is missed: a deleted row loses everything at once, an offline one is checked against the
    /// TTL.
    pub async fn node_offline(&self, node_id: NodeId, _reason: OfflineReason) -> Result<()> {
        self.expire_node(node_id).await
    }

    /// Loses the leases of `node_id` if it is deleted, or offline, not connected and silent for `lease_ttl_s` since
    /// the later of its last contact and this server's boot. Otherwise nothing.
    async fn expire_node(&self, node_id: NodeId) -> Result<()> {
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let Some(node) = nodes::by_id(&mut tx, node_id).await? else {
            return Ok(());
        };
        let (reason, notify) = if node.deleted_at.is_some() {
            // §5 "Deletion": never send anything more to that node.
            (code::NODE_DELETED, false)
        } else if self.silent_for_ttl(&node, now) {
            (code::NODE_LOST, true)
        } else {
            return Ok(());
        };
        let mut requeued = false;
        for l in leases::held_on_node(&mut tx, node_id).await? {
            requeued |= self.lose(&mut tx, &l, reason, notify, now, &mut fx).await?;
        }
        if requeued && reason == code::NODE_LOST {
            nodes::disconnection_requeued(&mut tx, node_id, now).await?;
        }
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    /// SI-13, server half: the node is offline, not connected, and no contact for `lease_ttl_s`, counted from the
    /// later of its last contact (flushed by the sweep) and this server's boot.
    fn silent_for_ttl(&self, node: &NodeRow, now: OffsetDateTime) -> bool {
        let base = node.last_seen_at.unwrap_or(node.created_at).max(self.inner.booted_at);
        node.state == DbState::Offline
            && !self.inner.link.is_connected(node.id)
            && now - base >= self.inner.timing.lease_ttl
    }

    /// Backstop of the gateway's sweep: every node that holds reservations past an offer is checked. The pre-pass
    /// is read-only: only nodes that are deleted, or offline, not connected and silent for `lease_ttl_s`, get a write
    /// transaction (which checks again).
    async fn expire_silent_nodes(&self, r: &mut TickReport) -> Result<()> {
        let now = self.now();
        let due: Vec<NodeId> = {
            let mut conn = self.inner.db.acquire().await?;
            let mut ids: Vec<NodeId> = leases::held_after_offer(&mut conn)
                .await?
                .into_iter()
                .map(|l| l.node_id)
                .collect();
            ids.sort_by_key(ToString::to_string);
            ids.dedup();
            let mut due = Vec::new();
            for id in ids {
                match nodes::by_id(&mut conn, id).await {
                    Ok(Some(n)) if n.deleted_at.is_some() || self.silent_for_ttl(&n, now) => due.push(id),
                    Ok(_) => {}
                    Err(e) => failed(r, "read a node", &e.into()),
                }
            }
            due
        };
        for node_id in due {
            if let Err(e) = self.expire_node(node_id).await {
                failed(r, "expire a node", &e);
            }
        }
        Ok(())
    }

    // --- Timers ---------------------------------------------------------------------------------------------------

    /// Offers not accepted within 10 s (§6 "Two-phase assignment"): revoked, counted against the offer cap, and the
    /// node told `Cancel` in case it accepts late. Each lease is re-read in its own transaction.
    async fn expire_offers(&self, r: &mut TickReport) -> Result<()> {
        let now = self.now();
        let due = {
            let mut conn = self.inner.db.acquire().await?;
            leases::offers_sent_before(&mut conn, now - ACCEPT_TIMEOUT).await?
        };
        for lease in due {
            if let Err(e) = self.expire_offer(lease.id).await {
                failed(r, "expire an offer", &e);
            }
        }
        Ok(())
    }

    async fn expire_offer(&self, id: LeaseId) -> Result<()> {
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let Some(l) = leases::get(&mut tx, id).await? else {
            return Ok(());
        };
        if l.state != LeaseState::Offered || now < l.offered_at + ACCEPT_TIMEOUT {
            return Ok(());
        }
        self.fail_offer(
            &mut tx,
            &l,
            code::ACCEPT_TIMEOUT,
            Some("the lease was not accepted within 10 s"),
            now,
            &mut fx,
        )
        .await?;
        fx.send.push((l.node_id, cancel(l.id, l.epoch, code::ACCEPT_TIMEOUT)));
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    /// Cancel requests (§8): a connected node gets `Cancel` (again every [`CANCEL_RESEND`] until it reports) and the
    /// job ends when it reports; on an
    /// unreachable node the job is `cancelled` at once and the reservation stays held until the lease is confirmed
    /// dead. An offer whose job was cancelled while queued is revoked.
    async fn deliver_cancels(&self, r: &mut TickReport) -> Result<()> {
        let now = self.now();
        let due: Vec<LeaseRow> = {
            let mut conn = self.inner.db.acquire().await?;
            leases::needing_cancel(&mut conn).await?
        };
        // Read-only pre-pass (T06 review): only what `deliver_cancel` would act on gets a write transaction. A user
        // cancel on a connected node is due when it was never sent or was sent `CANCEL_RESEND` ago; on an
        // unreachable node it is due at once; an offer of a terminal job always is.
        let due = due.into_iter().filter(|l| match l.state {
            LeaseState::Offered => l.job_status.is_terminal(),
            LeaseState::Accepted | LeaseState::Running => {
                l.cancel_requested_at.is_some()
                    && (!self.inner.link.is_connected(l.node_id)
                        || l.cancel_sent_at.is_none_or(|sent| now - sent >= CANCEL_RESEND))
            }
            _ => false,
        });
        for lease in due {
            r.cancels_tried += 1;
            if let Err(e) = self.deliver_cancel(lease.id).await {
                failed(r, "deliver a cancel", &e);
            }
        }
        Ok(())
    }

    async fn deliver_cancel(&self, id: LeaseId) -> Result<()> {
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let Some(l) = leases::get(&mut tx, id).await? else {
            return Ok(());
        };
        match l.state {
            LeaseState::Offered if l.job_status.is_terminal() => {
                self.fail_offer(&mut tx, &l, code::JOB_CANCELLED, None, now, &mut fx)
                    .await?;
                fx.send.push((l.node_id, cancel(l.id, l.epoch, code::JOB_CANCELLED)));
            }
            LeaseState::Accepted | LeaseState::Running if l.cancel_requested_at.is_some() => {
                if !self.inner.link.is_connected(l.node_id) {
                    self.end_by_server(
                        &mut tx,
                        &l,
                        JobStatus::Cancelled,
                        code::CANCELLED_UNREACHABLE,
                        now,
                        &mut fx,
                    )
                    .await?;
                } else if l.cancel_sent_at.is_none_or(|sent| now - sent >= CANCEL_RESEND) {
                    // Again every `CANCEL_RESEND` until `JobFinished` ends the lease: whether this send reaches the
                    // agent is only known from its report.
                    fx.send.push((l.node_id, cancel(l.id, l.epoch, code::USER)));
                    leases::mark_cancel_sent(&mut tx, l.id, now).await?;
                }
            }
            _ => return Ok(()),
        }
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    /// The `Cancel`s of executions the server ended itself (the watchdog, a cancel on an unreachable node), sent again
    /// every [`CANCEL_RESEND`] to a connected node until it confirms the end (T06 review): a `Cancel` dropped by a
    /// full session queue, or never sent to an unreachable node, is not lost for good. The pre-pass is read-only.
    async fn resend_server_cancels(&self, r: &mut TickReport) -> Result<()> {
        let now = self.now();
        let due: Vec<leases::ServerEnded> = {
            let mut conn = self.inner.db.acquire().await?;
            leases::server_ended_unconfirmed(&mut conn).await?
        };
        let due = due.into_iter().filter(|l| {
            self.inner.link.is_connected(l.node_id) && l.cancel_sent_at.is_none_or(|sent| now - sent >= CANCEL_RESEND)
        });
        for lease in due {
            r.cancels_tried += 1;
            if let Err(e) = self.resend_server_cancel(&lease).await {
                failed(r, "resend a server cancel", &e);
            }
        }
        Ok(())
    }

    async fn resend_server_cancel(&self, seen: &leases::ServerEnded) -> Result<()> {
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let Some(l) = leases::get(&mut tx, seen.id).await? else {
            return Ok(());
        };
        if l.state != LeaseState::Revoked
            || !l.holds()
            || l.cancel_sent_at.is_some_and(|sent| now - sent < CANCEL_RESEND)
        {
            return Ok(());
        }
        fx.send.push((l.node_id, cancel(l.id, l.epoch, &seen.end_reason)));
        leases::mark_cancel_sent(&mut tx, l.id, now).await?;
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    /// Forgets the `LogChunk` deduplication entries of leases that are no longer active (T06 review): a chunk whose
    /// fencing read raced `finish` can re-insert its entry after `finish` cleared it. Read-only; nothing to do when
    /// the map is empty. An entry of a lease offered after the read may be dropped too: that only forwards a resent
    /// chunk again, which the log store drops by `seq` itself.
    async fn prune_log_seq(&self) -> Result<()> {
        if self
            .inner
            .log_seq
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
        {
            return Ok(());
        }
        let active: HashSet<LeaseId> = {
            let mut conn = self.inner.db.acquire().await?;
            leases::active_ids(&mut conn).await?.into_iter().collect()
        };
        self.inner
            .log_seq
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| active.contains(id));
        Ok(())
    }

    /// The watchdog (§8 "Timeouts"): `running` for `timeout_s + 60 s` after `JobStarted`, or still `assigned`
    /// `pull_timeout_s + timeout_s + 60 s` after acceptance: the job is `timed_out` and the node gets `Cancel`.
    async fn watchdog(&self, r: &mut TickReport) -> Result<()> {
        let leases = {
            let mut conn = self.inner.db.acquire().await?;
            leases::accepted_or_running(&mut conn).await?
        };
        let now = self.now();
        for lease in leases.into_iter().filter(|l| self.watchdog_due(l, now)) {
            if let Err(e) = self.time_out(lease.id).await {
                failed(r, "watchdog a lease", &e);
            }
        }
        Ok(())
    }

    async fn time_out(&self, id: LeaseId) -> Result<()> {
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let Some(l) = leases::get(&mut tx, id).await? else {
            return Ok(());
        };
        if !l.is_current() || !self.watchdog_due(&l, now) {
            return Ok(());
        }
        self.end_by_server(&mut tx, &l, JobStatus::TimedOut, code::WATCHDOG, now, &mut fx)
            .await?;
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    fn watchdog_due(&self, l: &LeaseRow, now: OffsetDateTime) -> bool {
        let timeout = Duration::seconds(i64::from(l.timeout_s)) + WATCHDOG_MARGIN;
        let deadline = match (l.state, l.started_at, l.accepted_at) {
            (LeaseState::Running, Some(started), _) => started + timeout,
            (LeaseState::Accepted, _, Some(accepted)) => accepted + self.inner.timing.pull_timeout + timeout,
            _ => return false,
        };
        now >= deadline
    }

    // --- Placement ------------------------------------------------------------------------------------------------

    /// The candidates of `account_id`: its live nodes, their held reservations and when they were last busy.
    async fn candidates(&self, conn: &mut Conn, account_id: AccountId) -> Result<Vec<Candidate>> {
        let nodes = nodes::live_of_account(conn, account_id).await?;
        let held = leases::held_for_account(conn, account_id).await?;
        let activity = leases::last_activity(conn, account_id).await?;
        nodes
            .into_iter()
            .map(|n| {
                let mut h = Held::default();
                for r in held.get(&n.id).into_iter().flatten() {
                    h.add(r);
                }
                let idle_since = match activity.get(&n.id) {
                    Some(at) => from_ts(*at, "leases.offered_at")?,
                    None => n.created_at,
                };
                Ok(Candidate {
                    available: n.state == DbState::Online && !n.draining && self.inner.link.is_connected(n.id),
                    node_id: n.id,
                    inventory: n.inventory,
                    labels: BTreeMap::new(),
                    held: h,
                    idle_since,
                })
            })
            .collect()
    }

    /// The queued jobs this tick looks at (review P3): the whole queue, FIFO, when it fits in one round of
    /// [`MAX_JOBS_PER_TICK`]; otherwise one round, resuming after the last job the previous round looked at and
    /// wrapping to the start (round-robin), so a long queue never stalls a tick and every job gets its turn.
    async fn queue_window(&self) -> Result<Vec<leases::QueuedJob>> {
        let mut conn = self.inner.db.acquire().await?;
        let mut head = leases::queued_page(&mut conn, OFFER_CAP, None, MAX_JOBS_PER_TICK as u32 + 1).await?;
        let mut resume = self
            .inner
            .queue_resume
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if head.len() <= MAX_JOBS_PER_TICK {
            // Short: always from the oldest job, so a newer job never jumps ahead (FIFO).
            *self.inner.queue_resume.lock().unwrap_or_else(PoisonError::into_inner) = None;
            return Ok(head);
        }
        let mut window = match resume.take() {
            Some(after) => leases::queued_page(&mut conn, OFFER_CAP, Some(&after), MAX_JOBS_PER_TICK as u32).await?,
            None => {
                head.truncate(MAX_JOBS_PER_TICK);
                std::mem::take(&mut head)
            }
        };
        if window.len() < MAX_JOBS_PER_TICK {
            // The end of the queue: wrap to its start.
            let seen: HashSet<JobId> = window.iter().map(|j| j.job_id).collect();
            let missing = u32::try_from(MAX_JOBS_PER_TICK - window.len()).unwrap_or(0);
            let wrap = leases::queued_page(&mut conn, OFFER_CAP, None, missing).await?;
            window.extend(wrap.into_iter().filter(|j| !seen.contains(&j.job_id)));
        }
        *self.inner.queue_resume.lock().unwrap_or_else(PoisonError::into_inner) =
            window.last().map(|j| j.position.clone());
        Ok(window)
    }

    /// Places queued jobs, FIFO by `created_at` (at most [`MAX_JOBS_PER_TICK`] of them, see [`Self::queue_window`]). A
    /// job that fits nowhere now is skipped, and later jobs still get their turn (no head-of-line blocking). A
    /// read-only snapshot of each account's nodes, and of the (job, node) pairs cooling down, skips jobs that fit
    /// nowhere without a write transaction; every placement is decided again inside its own.
    async fn place(&self, r: &mut TickReport) -> Result<()> {
        let queued = self.queue_window().await?;
        let cooling = {
            let mut conn = self.inner.db.acquire().await?;
            leases::cooling_pairs(&mut conn, self.now()).await?
        };
        let mut snapshots: HashMap<AccountId, Vec<Candidate>> = HashMap::new();
        for job in queued {
            r.considered += 1;
            if let std::collections::hash_map::Entry::Vacant(slot) = snapshots.entry(job.account_id) {
                let mut conn = self.inner.db.acquire().await?;
                match self.candidates(&mut conn, job.account_id).await {
                    Ok(c) => {
                        slot.insert(c);
                    }
                    Err(e) => {
                        failed(r, "read an account's nodes", &e);
                        continue;
                    }
                }
            }
            let snapshot: Vec<Candidate> = snapshots
                .get(&job.account_id)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter(|c| !cooling.contains(&(job.job_id, c.node_id)))
                .cloned()
                .collect();
            if fit::choose(&snapshot, &job.request, None).is_none() {
                continue;
            }
            r.placements_tried += 1;
            let placed = match self.place_one(job.job_id).await {
                Ok(Some(placed)) => placed,
                Ok(None) => continue,
                Err(e) => {
                    failed(r, "place a job", &e);
                    continue;
                }
            };
            if let Some(c) = snapshots
                .get_mut(&job.account_id)
                .and_then(|s| s.iter_mut().find(|c| c.node_id == placed.lease.node_id))
            {
                c.held.add(&placed.lease.reserved);
            }
            if let Err(e) = self.send_lease(&placed).await {
                // The offer is committed: unanswered, it times out in 10 s like any other.
                failed(r, "send a lease", &e);
            }
            r.offered += 1;
        }
        Ok(())
    }

    /// Decides and records one placement, in one transaction: the job is re-read (still queued, no active lease,
    /// under the cap), the nodes and their held reservations too; the best node gets an `offered` lease with the
    /// job's next epoch.
    async fn place_one(&self, job_id: JobId) -> Result<Option<Placed>> {
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let Some(job) = leases::queued_one(&mut tx, job_id, OFFER_CAP).await? else {
            return Ok(None);
        };
        let cooling: HashSet<NodeId> = leases::cooling_nodes(&mut tx, job_id, now).await?.into_iter().collect();
        let candidates: Vec<Candidate> = self
            .candidates(&mut tx, job.account_id)
            .await?
            .into_iter()
            .filter(|c| !cooling.contains(&c.node_id))
            .collect();
        let Some(choice) = fit::choose(&candidates, &job.request, job.last_lost_node_id) else {
            return Ok(None);
        };
        if !leases::bump_epoch(&mut tx, job_id, job.epoch).await? {
            return Ok(None);
        }
        let lease = NewLease {
            id: LeaseId::generate(),
            job_id,
            node_id: choice.node_id,
            epoch: job.epoch + 1,
            attempt: job.attempt,
            reserved: Reserved {
                cpu: job.request.cpu_milli as f64 / 1000.0,
                memory_mb: job.request.memory_mb,
                disk_mb: job.request.disk_mb,
                gpu_uuid: choice.gpu_uuid,
            },
        };
        leases::insert(&mut tx, &lease, now).await?;
        tx.commit().await?;
        tracing::info!(%job_id, lease_id = %lease.id, node_id = %lease.node_id, epoch = lease.epoch, "lease offered");
        Ok(Some(Placed {
            lease,
            account_id: job.account_id,
            project_id: job.project_id,
            timeout_s: job.timeout_s,
            offered_at: now,
        }))
    }

    /// Sends a committed offer: `Lease{lease_id, epoch, job, account_id, deadline}`, the job read with `load_spec`
    /// (the only read of the full spec, one row). `deadline` is the latest the watchdog allows: acceptance, pull,
    /// `timeout_s` and the margin. An offer that cannot be sent is a failed offer.
    async fn send_lease(&self, placed: &Placed) -> Result<()> {
        let spec: Option<JobSpec> = {
            let mut conn = self.inner.db.acquire().await?;
            jobs::load_spec(&mut conn, placed.account_id, placed.project_id, placed.lease.job_id).await?
        };
        let sent = spec.is_some_and(|spec| {
            let deadline = placed.offered_at
                + ACCEPT_TIMEOUT
                + self.inner.timing.pull_timeout
                + Duration::seconds(i64::from(placed.timeout_s))
                + WATCHDOG_MARGIN;
            let msg = ServerMsg::Lease {
                lease_id: placed.lease.id,
                epoch: placed.lease.epoch,
                job: LeaseJob::from_spec(&spec),
                account_id: placed.account_id,
                deadline,
            };
            self.inner.link.send(placed.lease.node_id, msg).is_ok()
        });
        if sent {
            return Ok(());
        }
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        if let Some(l) = leases::get(&mut tx, placed.lease.id).await?
            && l.state == LeaseState::Offered
        {
            self.fail_offer(
                &mut tx,
                &l,
                code::SEND_FAILED,
                Some("the node could not be reached"),
                now,
                &mut fx,
            )
            .await?;
        }
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }

    /// How the nodes of `account_id` match `spec` (`POST /v1/estimate`).
    pub async fn match_spec(&self, account_id: AccountId, spec: &JobSpec) -> Result<NodeMatch> {
        let req = Request {
            cpu_milli: fit::cpu_milli(spec.resources.cpu),
            memory_mb: spec.resources.memory_mb,
            disk_mb: spec.resources.disk_mb,
            gpu: spec.resources.gpu,
            pools: spec.placement.pools.clone(),
            labels: spec.placement.labels.clone(),
            node_id: spec.placement.node_id,
        };
        let mut conn = self.inner.db.acquire().await?;
        let mut m = NodeMatch::default();
        for c in self.candidates(&mut conn, account_id).await? {
            match fit::fits(&c, &req) {
                Ok(_) => {
                    m.matching_nodes += 1;
                    m.free_nodes += 1;
                }
                Err(e) if !e.is_static() => m.matching_nodes += 1,
                Err(_) => {}
            }
        }
        Ok(m)
    }
}

impl NodeEvents for Scheduler {
    fn on_heartbeat<'a>(&'a self, node_id: NodeId, running: &'a [RunningLease]) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Err(e) = self.on_heartbeat(node_id, running).await {
                // The node's next heartbeat tries again.
                tracing::warn!(error = %e, %node_id, "cannot free the finished leases a heartbeat dropped");
            }
        })
    }

    fn on_message(&self, node_id: NodeId, msg: AgentMsg) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let kind = msg.kind();
            if let Err(e) = self.on_agent_message(node_id, msg).await {
                tracing::warn!(error = %e, %node_id, kind, "cannot handle an agent message");
            }
        })
    }

    fn on_node_offline(&self, node_id: NodeId, reason: OfflineReason) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Err(e) = self.node_offline(node_id, reason).await {
                // The tick's expiry backstop retries a lost node; a deleted one is retried there too.
                tracing::warn!(error = %e, %node_id, ?reason, "cannot expire the leases of an offline node");
            }
            self.inner.kick.kick();
        })
    }
}

impl LeaseReconciler for Scheduler {
    fn reconcile<'a>(
        &'a self,
        node_id: NodeId,
        running: &'a [RunningLease],
    ) -> BoxFuture<'a, Result<Vec<ServerMsg>, ReconcileFailed>> {
        Box::pin(async move {
            self.reconcile_hello(node_id, running).await.map_err(|e| {
                // Never cancel healthy jobs for a server-side failure (§6 "Server restart"): the gateway closes the
                // session, the agent reconnects and reconciles again.
                tracing::warn!(error = %e, %node_id, "cannot reconcile a Hello; the session is closed");
                ReconcileFailed
            })
        })
    }
}

impl NodeDirectory for Scheduler {
    fn match_job<'a>(&'a self, account_id: AccountId, spec: &'a JobSpec) -> BoxFuture<'a, NodeMatch> {
        Box::pin(async move {
            self.match_spec(account_id, spec).await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "cannot match nodes for an estimate");
                NodeMatch::default()
            })
        })
    }
}
