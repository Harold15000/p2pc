// SPDX-License-Identifier: Apache-2.0

//! The lease executor (T10a): runs the jobs the server leases to this node, end to end, on top of the sandbox
//! driver (T08), behind T05b's [`LeaseHandler`] and [`LeaseSupervisor`].
//!
//! **Admission** (§6 "Two-phase assignment", well within its 10 s: it never waits). A `Lease` is answered from one
//! critical section, so a lease is either fully registered or not at all:
//! 1. the same `(lease_id, epoch)` again gets the answer it got before (idempotent);
//! 2. after a terminal [`LeaseSupervisor::stop_all`] (anything but `lease_lost`) every lease gets `agent_not_ready`;
//! 3. another account than the enrolled owner gets `not_owner` (SI-1; the connection already checked, this is the
//!    second lock), before anything touches the disk;
//! 4. a draining node gets `draining`; a passed `deadline` gets `deadline_passed`;
//! 5. a node that is not ready (RAM unknown, sandbox not ready, no inventory yet) gets `agent_not_ready`;
//! 6. the lease must fit the **offered** capacity still free: CPU, memory, disk, and a free offerable GPU picked by
//!    UUID ([`capacity`]); otherwise `insufficient_capacity` (or `gpu_selection_unsupported` on WSL2).
//!
//! The capacity is reserved on accept and released when the run's **cleanup** ends (the container is removed and the job
//! directory deleted), on every path. It does not wait for the server to confirm `JobFinished` (T06e): the server holds
//! the lease's reservation until a `Heartbeat` stops listing it, so the slot must be free when that heartbeat is sent.
//!
//! **Run**, on the executor's own task: `prepare` (SI-1 again inside it) → `start` (`JobStarted` on
//! [`SandboxEvent::Started`]) → `wait` → collect the outputs → upload them ([`upload`]) → `JobFinished` → `cleanup`.
//! A failure in a phase is `outcome: "error"` with a short fixed `error` code, never raw stderr or a path. Logs become
//! `LogChunk`s with the pump's `seq`, through a bounded per-run queue ([`outbox`]) that never blocks the pump. A run
//! stays in [`LeaseSupervisor::running`] (what `Hello` lists) until its `JobFinished` is **confirmed**: the server
//! answered a heartbeat written after it (§6, amended 2026-11-06). A reconnect in between lists it in `Hello`, and the
//! report is sent again right after `Welcome`, so a report lost with a connection never turns a finished job into a
//! requeue. What `Heartbeat` lists is another set, [`LeaseSupervisor::holding`]: the runs that still hold resources,
//! which leave it when their cleanup ends, confirmed or not (§6, amended 2026-11-08). Each such release also wakes the
//! session ([`LeaseSupervisor::released`]), which heartbeats at once.
//!
//! **Fencing on the node.** Every message carries the run's own `(lease_id, epoch)`. A newer epoch of the same lease,
//! a `Cancel` with a newer epoch, or a `Cancel` whose reason says the server no longer holds the lease
//! ([`FENCED_CANCELS`]: `stale_epoch`, `unknown_lease`) makes the run stale: it is stopped and silenced (no upload, no
//! `JobFinished`). Any other `Cancel` for the run's own epoch (`user`, …) cancels it: it ends as `cancelled`, and its
//! outputs are still uploaded. The same epoch offered again is a duplicate: accepted, nothing started.
//!
//! **`stop_all`** (SI-13, and the daemon's exits) cancels every run at once, silences them (their `JobFinished` is
//! dropped, not queued: the server has requeued them), forgets them, and waits for their cleanup.
//!
//! **Start.** No checkpointing in v0.1 (§9): before the first `Hello`, [`Executor::startup`] removes the containers,
//! job directories and lease cgroups a previous process left, and the executor reports `running: []`.

pub mod capacity;
pub mod outbox;
pub mod status;
pub mod upload;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use p2pc_proto::api::OutputFile;
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::{AgentMsg, LeaseRejectReason, LogData, MAX_RUNNING_LEASES, Outcome, RunningLease};
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc, watch};

use self::capacity::{LeaseKey, Ledger, Offer};
use self::outbox::{RunOutbox, deliver};
use self::status::{LeaseStatus, LeasesFile, LeasesState, RunPhase};
use crate::connection::lease::{LEASE_LOST, LeaseDecision, LeaseHandler, LeaseOffer, LeaseSupervisor};
use crate::connection::{BoxFuture, Uplink};
use crate::sandbox::{
    CancelHandle, CollectedOutputs, Finished, GpuRef, LeaseContext, Phase, PodmanDriver, Sandbox, SandboxError,
    SandboxEvent, SweepReport,
};

/// Longest [`LeaseSupervisor::stop_all`] waits for the runs it stopped to be cleaned up: SIGTERM, the 10 s grace,
/// SIGKILL, the driver's own wait, then `podman rm` and the directory.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(120);
/// How many past decisions are remembered, to answer a repeated `Lease` the same way.
pub const RECENT_DECISIONS: usize = 1024;
/// `Cancel` reasons for a lease the server no longer holds: the run is stopped and silenced, not reported.
pub const FENCED_CANCELS: [&str; 2] = ["stale_epoch", "unknown_lease"];
/// How often the leases file is refreshed while leases run (their log bytes).
pub const STATUS_INTERVAL: Duration = Duration::from_secs(5);
/// Events queued between the sandbox and the run task.
const EVENTS: usize = 64;

/// The wall clock, for `deadline` checks and `JobStarted.started_at` (fixed in tests).
pub trait Clock: Send + Sync + fmt::Debug + 'static {
    /// Now.
    fn now(&self) -> OffsetDateTime;
}

/// The system's clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A sandbox that can clean up what an earlier agent process left behind.
pub trait Startup: Sandbox {
    /// Removes every container, job directory and lease cgroup of this agent: none is running at start.
    fn sweep_at_start(&self) -> impl Future<Output = SweepReport> + Send;
}

impl<E, C, X> Startup for PodmanDriver<E, C, X>
where
    E: crate::sandbox::engine::Engine,
    C: crate::sandbox::cgroup::Cgroups,
    X: crate::sandbox::Egress,
{
    async fn sweep_at_start(&self) -> SweepReport {
        self.sweep_orphans(&HashSet::new()).await
    }
}

/// One accepted lease, from acceptance to the end of its run.
#[derive(Debug)]
struct Run {
    cancel: CancelHandle,
    outbox: Arc<RunOutbox>,
    /// Listed in `running()`: false once stale or stopped.
    listed: bool,
    /// Holds resources (the capacity, the container, the job directory): listed in `holding()` until the cleanup ends.
    holds: bool,
    phase: RunPhase,
    job_name: Option<String>,
    accepted_at: OffsetDateTime,
    started_at: Option<OffsetDateTime>,
    /// Becomes true when the run task is over (capacity released).
    done: watch::Receiver<bool>,
}

#[derive(Debug, Default)]
struct State {
    draining: bool,
    /// A terminal `stop_all` happened: no lease is ever taken again.
    closed: bool,
    runs: HashMap<LeaseKey, Run>,
    ledger: Ledger,
    recent: VecDeque<(LeaseKey, LeaseDecision)>,
}

impl State {
    fn remember(&mut self, key: LeaseKey, decision: LeaseDecision) {
        if self.recent.len() >= RECENT_DECISIONS {
            self.recent.pop_front();
        }
        self.recent.push_back((key, decision));
    }

    fn recalled(&self, key: &LeaseKey) -> Option<LeaseDecision> {
        self.recent.iter().rev().find(|(k, _)| k == key).map(|(_, d)| *d)
    }

    /// The listed run of `lease_id`, if any.
    fn listed(&mut self, lease_id: &LeaseId) -> Option<(&LeaseKey, &mut Run)> {
        self.runs.iter_mut().find(|(k, r)| k.0 == *lease_id && r.listed)
    }
}

/// Makes a run stale: it is stopped and sends nothing more.
fn retire(run: &mut Run) {
    run.listed = false;
    run.outbox.silence();
    run.cancel.cancel();
}

struct Inner<S> {
    sandbox: S,
    owner: AccountId,
    uplink: Uplink,
    clock: Arc<dyn Clock>,
    offer: watch::Receiver<Option<Offer>>,
    state: Mutex<State>,
    status_changed: Arc<Notify>,
    /// Woken (one permit, kept if nobody waits) each time a run releases its resources.
    released: Notify,
    log_cap: AtomicUsize,
    /// Log chunks every finished run dropped (its [`outbox::Drops`]), in total.
    dropped_log_chunks: AtomicU64,
}

impl<S> Inner<S> {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn update(&self, key: &LeaseKey, f: impl FnOnce(&mut Run)) {
        if let Some(run) = self.lock().runs.get_mut(key) {
            f(run);
        }
        self.status_changed.notify_one();
    }

    fn snapshot(&self) -> LeasesState {
        let state = self.lock();
        let mut leases: Vec<LeaseStatus> = state
            .runs
            .iter()
            .filter(|(_, r)| r.listed)
            .map(|((lease_id, epoch), r)| LeaseStatus {
                lease_id: *lease_id,
                epoch: *epoch,
                job_name: r.job_name.clone(),
                phase: r.phase,
                accepted_at: r.accepted_at,
                started_at: r.started_at,
                log_bytes_sent: r.outbox.log_bytes_sent(),
            })
            .collect();
        leases.sort_by_key(|l| (l.accepted_at, l.lease_id.to_string()));
        LeasesState {
            updated_at: self.clock.now(),
            leases,
        }
    }
}

/// Ends a run on every path, panics included: the capacity is released, the run forgotten, `done` set.
///
/// The two ends are apart (T06e). [`RunGuard::release`] frees the resources when the cleanup ends; dropping the guard,
/// once the server confirmed `JobFinished` (or the run was silenced), forgets the run. A drop that comes first (a panic)
/// does both.
struct RunGuard<S> {
    inner: Arc<Inner<S>>,
    key: LeaseKey,
    done: watch::Sender<bool>,
    released: bool,
}

impl<S> RunGuard<S> {
    /// The run's resources are free: its capacity goes back to the ledger, it leaves `holding()`, `done` is set (the
    /// cleanup is over) and the session is woken to heartbeat. The run stays in `running()` until it is forgotten.
    /// Calling it again does nothing.
    fn release(&mut self) {
        if std::mem::replace(&mut self.released, true) {
            return;
        }
        {
            let mut state = self.inner.lock();
            state.ledger.release(&self.key);
            if let Some(run) = state.runs.get_mut(&self.key) {
                run.holds = false;
            }
        }
        self.inner.status_changed.notify_one();
        self.done.send_replace(true);
        // After the state changed: the woken session reads `holding()`.
        self.inner.released.notify_one();
    }
}

impl<S> Drop for RunGuard<S> {
    fn drop(&mut self) {
        self.release();
        self.inner.lock().runs.remove(&self.key);
        self.inner.status_changed.notify_one();
    }
}

/// The lease executor. Clones share it.
pub struct Executor<S> {
    inner: Arc<Inner<S>>,
}

impl<S> Clone for Executor<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S> fmt::Debug for Executor<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.inner.lock();
        f.debug_struct("Executor")
            .field("owner", &self.inner.owner)
            .field("runs", &state.runs.len())
            .field("draining", &state.draining)
            .field("closed", &state.closed)
            .finish_non_exhaustive()
    }
}

/// Runs `fut` while passing every sandbox event to `on`, then the events still queued when it ends.
async fn pumping<F: Future>(
    fut: F,
    rx: &mut mpsc::Receiver<SandboxEvent>,
    on: &mut impl FnMut(SandboxEvent),
) -> F::Output {
    tokio::pin!(fut);
    loop {
        tokio::select! {
            out = &mut fut => {
                while let Ok(ev) = rx.try_recv() {
                    on(ev);
                }
                return out;
            }
            Some(ev) = rx.recv() => on(ev),
        }
    }
}

/// The `JobFinished` fields for a sandbox error.
fn finished_from(e: &SandboxError) -> Finished {
    match e {
        SandboxError::Cancelled => Finished::without_run(Outcome::Cancelled, None),
        SandboxError::Failed { code, .. } => Finished::without_run(Outcome::Error, Some((*code).to_string())),
        // Accepted, then refused by the driver (for example the disk floor): the reason is the code.
        SandboxError::Rejected(reason) => Finished::without_run(Outcome::Error, Some(reason.to_string())),
    }
}

impl<S> Executor<S>
where
    S: Sandbox + Send + Sync + 'static,
    S::Job: Send + Sync + 'static,
{
    /// An executor running the leases of `owner` in `sandbox`, reporting through `uplink`, within the offers of
    /// `offer` (the latest inventory's; `None` until the first detection).
    #[must_use]
    pub fn new(
        sandbox: S,
        owner: AccountId,
        uplink: Uplink,
        offer: watch::Receiver<Option<Offer>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                sandbox,
                owner,
                uplink,
                clock,
                offer,
                state: Mutex::new(State::default()),
                status_changed: Arc::new(Notify::new()),
                released: Notify::new(),
                log_cap: AtomicUsize::new(outbox::LOG_QUEUE_BYTES),
                dropped_log_chunks: AtomicU64::new(0),
            }),
        }
    }

    /// The same, with another per-run log queue cap (tests).
    #[must_use]
    pub fn with_log_cap(self, cap: usize) -> Self {
        self.inner.log_cap.store(cap, Ordering::Relaxed);
        self
    }

    /// The sandbox.
    #[must_use]
    pub fn sandbox(&self) -> &S {
        &self.inner.sandbox
    }

    /// Cleans up what an earlier agent process left (containers, job directories, lease cgroups), before the first
    /// `Hello`: v0.1 has no checkpointing (§9), so nothing of it is running any more.
    pub async fn startup(&self) -> SweepReport
    where
        S: Startup,
    {
        let report = self.inner.sandbox.sweep_at_start().await;
        let removed = report.containers.len() + report.job_dirs.len() + report.cgroups.len();
        if removed > 0 || !report.errors.is_empty() {
            tracing::info!(
                containers = report.containers.len(),
                job_dirs = report.job_dirs.len(),
                cgroups = report.cgroups.len(),
                errors = report.errors.len(),
                "removed what an earlier agent process left behind (no checkpointing in v0.1)"
            );
        }
        for e in &report.errors {
            tracing::warn!(error = %e, "start-up cleanup");
        }
        self.inner.status_changed.notify_one();
        report
    }

    /// Keeps `file` up to date with the running leases until the executor is dropped.
    #[must_use]
    pub fn spawn_status_writer(&self, file: LeasesFile) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(&self.inner);
        let changed = Arc::clone(&self.inner.status_changed);
        tokio::spawn(async move {
            let mut last: Option<LeasesState> = None;
            loop {
                let Some(inner) = weak.upgrade() else { return };
                let snapshot = inner.snapshot();
                drop(inner);
                let same = last
                    .as_ref()
                    .is_some_and(|l| l.leases == snapshot.leases && snapshot.leases.is_empty());
                if !same {
                    let (file, s) = (file.clone(), snapshot.clone());
                    let _ = tokio::task::spawn_blocking(move || file.write(&s)).await;
                    last = Some(snapshot);
                }
                tokio::select! {
                    () = changed.notified() => {}
                    () = tokio::time::sleep(STATUS_INTERVAL) => {}
                }
            }
        })
    }

    /// The running leases as `p2pc-agent status` shows them.
    #[must_use]
    pub fn status(&self) -> LeasesState {
        self.inner.snapshot()
    }

    /// Log chunks the finished runs dropped, in total: to the per-run cap, or with a session that ended before
    /// writing them. None is ever lost without being counted.
    #[must_use]
    pub fn dropped_log_chunks(&self) -> u64 {
        self.inner.dropped_log_chunks.load(Ordering::Relaxed)
    }

    fn admit(&self, offer: LeaseOffer) -> LeaseDecision {
        let key = (offer.lease_id, offer.epoch);
        let mut state = self.inner.lock();
        if let Some(earlier) = state.recalled(&key) {
            tracing::debug!(lease_id = %key.0, epoch = key.1, "a repeated lease; answering as before");
            return earlier;
        }
        let decision = self.decide(&mut state, offer);
        state.remember(key, decision);
        drop(state);
        self.inner.status_changed.notify_one();
        decision
    }

    fn decide(&self, state: &mut State, offer: LeaseOffer) -> LeaseDecision {
        use LeaseRejectReason as R;
        let reject = |reason: R| {
            tracing::info!(lease_id = %offer.lease_id, epoch = offer.epoch, %reason, "lease refused");
            LeaseDecision::Reject(reason)
        };
        if state.closed {
            return reject(R::AgentNotReady);
        }
        // SI-1, again: nothing below (and no `prepare`) ever sees another account's lease.
        if offer.account_id != self.inner.owner {
            return reject(R::NotOwner);
        }
        if state.draining {
            return reject(R::Draining);
        }
        if offer.deadline <= self.inner.clock.now() {
            return reject(R::DeadlinePassed);
        }
        if let Some(((_, running), _)) = state.listed(&offer.lease_id) {
            let running = *running;
            // The same epoch as the one running is a duplicate offer (its first answer may be forgotten by now):
            // accept it again and start nothing (T10a review, P3-6).
            if running == offer.epoch {
                tracing::debug!(lease_id = %offer.lease_id, epoch = offer.epoch, "a duplicate of the running lease");
                return LeaseDecision::Accept;
            }
            // An older epoch than the one running: never run it. The server fences the answer anyway.
            if running > offer.epoch {
                tracing::debug!(lease_id = %offer.lease_id, epoch = offer.epoch, running, "a lease older than the running one");
                return reject(R::AgentNotReady);
            }
        }
        let current = self.inner.offer.borrow().clone();
        let Some(available) = current.filter(|o| o.ready) else {
            return reject(R::AgentNotReady);
        };
        // `Hello.running` lists the `listed` runs and `Heartbeat.running` the ones that `holds`: neither may pass the
        // protocol's limit.
        if state.runs.values().filter(|r| r.listed || r.holds).count() >= MAX_RUNNING_LEASES {
            return reject(R::InsufficientCapacity);
        }
        let key = (offer.lease_id, offer.epoch);
        let reservation = match state.ledger.reserve(key, &available, &offer.job.resources) {
            Ok(r) => r,
            Err(reason) => return reject(reason),
        };
        // A newer epoch replaces the running one: the old run is stopped and goes silent (its reservation stays
        // held until its container is gone).
        if let Some((old, run)) = state.listed(&offer.lease_id) {
            tracing::info!(lease_id = %old.0, old_epoch = old.1, epoch = offer.epoch, "a newer epoch replaces a running lease");
            retire(run);
        }
        let cancel = CancelHandle::new();
        let run_outbox = Arc::new(RunOutbox::with_cap(self.inner.log_cap.load(Ordering::Relaxed)));
        let (done_tx, done_rx) = watch::channel(false);
        let now = self.inner.clock.now();
        state.runs.insert(
            key,
            Run {
                cancel: cancel.clone(),
                outbox: Arc::clone(&run_outbox),
                listed: true,
                phase: RunPhase::Preparing,
                job_name: offer.job.name.clone(),
                accepted_at: now,
                started_at: None,
                done: done_rx,
                holds: true,
            },
        );
        let ctx = LeaseContext {
            lease_id: offer.lease_id,
            epoch: offer.epoch,
            account_id: offer.account_id,
            job: offer.job,
            gpu: reservation.gpu.clone().map(|uuid| GpuRef { uuid }),
        };
        let guard = RunGuard {
            inner: Arc::clone(&self.inner),
            key,
            done: done_tx,
            released: false,
        };
        tracing::info!(lease_id = %key.0, epoch = key.1, gpu = ?reservation.gpu, "lease accepted");
        tokio::spawn(execute(guard, ctx, cancel, run_outbox));
        LeaseDecision::Accept
    }
}

/// One run, from `prepare` to the delivery of `JobFinished`.
async fn execute<S>(mut guard: RunGuard<S>, ctx: LeaseContext, cancel: CancelHandle, outbox: Arc<RunOutbox>)
where
    S: Sandbox + Send + Sync + 'static,
    S::Job: Send + Sync + 'static,
{
    let inner = Arc::clone(&guard.inner);
    let key = guard.key;
    let (lease_id, epoch) = key;
    let sender = {
        let (outbox, uplink) = (Arc::clone(&outbox), inner.uplink.clone());
        tokio::spawn(async move { deliver(&outbox, &uplink).await })
    };
    let (tx, mut rx) = mpsc::channel(EVENTS);
    let mut on_event = |ev: SandboxEvent| match ev {
        SandboxEvent::Started => {
            let started_at = inner.clock.now();
            outbox.push(AgentMsg::JobStarted {
                lease_id,
                epoch,
                started_at,
            });
            inner.update(&key, |r| {
                r.started_at = Some(started_at);
                r.phase = RunPhase::Running;
            });
        }
        SandboxEvent::Log(chunk) => {
            let raw = chunk.data.len() as u64;
            outbox.push_log(
                AgentMsg::LogChunk {
                    lease_id,
                    epoch,
                    stream: chunk.stream,
                    seq: chunk.seq,
                    data_b64: LogData::encode(&chunk.data),
                },
                raw,
            );
        }
        SandboxEvent::Phase(Phase::Pulling) => inner.update(&key, |r| r.phase = RunPhase::Pulling),
        SandboxEvent::Phase(Phase::Creating) => inner.update(&key, |r| r.phase = RunPhase::Creating),
    };

    let mut outputs = CollectedOutputs::default();
    let finished = match pumping(
        inner.sandbox.prepare(&inner.owner, ctx, tx, cancel.clone()),
        &mut rx,
        &mut on_event,
    )
    .await
    {
        // `prepare` cleans up after itself (the driver's guard).
        Err(e) => {
            e.log_failure(&lease_id, epoch);
            finished_from(&e)
        }
        Ok(mut job) => {
            inner.update(&key, |r| r.phase = RunPhase::Starting);
            let ran = match pumping(inner.sandbox.start(&mut job), &mut rx, &mut on_event).await {
                Err(e) => Err(e),
                Ok(()) => pumping(inner.sandbox.wait(&mut job), &mut rx, &mut on_event).await,
            };
            // Outputs exist only when the job ran: `start` and `wait` both succeeded.
            let (mut finished, ran) = match ran {
                Ok(f) => (f, true),
                Err(e) => {
                    e.log_failure(&lease_id, epoch);
                    (finished_from(&e), false)
                }
            };
            if ran {
                inner.update(&key, |r| r.phase = RunPhase::Collecting);
                match inner.sandbox.collect_outputs(&job).await {
                    Ok(o) => outputs = o,
                    Err(e) => {
                        tracing::warn!(%lease_id, epoch, error = %e, "cannot collect the outputs");
                        if finished.outcome != Outcome::Error {
                            finished.outcome = Outcome::Error;
                            finished.exit_code = None;
                            finished.error = Some(crate::sandbox::error_code::OUTPUTS_FAILED.into());
                        }
                    }
                }
            }
            if outputs.total_skipped() > 0 {
                tracing::info!(%lease_id, epoch, skipped = outputs.total_skipped(), "outputs left out by the collection");
            }
            inner.update(&key, |r| r.phase = RunPhase::Uploading);
            let uploaded: Vec<OutputFile> = if outbox.is_silenced() {
                Vec::new()
            } else {
                upload::upload_all(lease_id, epoch, &outputs.files, &inner.uplink, &outbox).await
            };
            // All uploads ended: now `JobFinished` (the server publishes what it lists), then the cleanup.
            report(&inner, &key, &outbox, &finished, uploaded);
            inner.sandbox.cleanup(job).await;
            // The container is removed and the directory deleted: the resources are free now, whether or not the
            // server has confirmed the report. The report is kept and sent again until it is.
            guard.release();
            finish(key, outbox, sender, guard).await;
            return;
        }
    };
    report(&inner, &key, &outbox, &finished, Vec::new());
    // `prepare` cleaned up after itself (the driver's guard).
    guard.release();
    finish(key, outbox, sender, guard).await;
}

/// Queues `JobFinished` and closes the run's queue.
fn report<S>(inner: &Inner<S>, key: &LeaseKey, outbox: &RunOutbox, finished: &Finished, outputs: Vec<OutputFile>) {
    let (lease_id, epoch) = *key;
    tracing::info!(
        %lease_id, epoch,
        outcome = ?finished.outcome,
        exit_code = ?finished.exit_code,
        error = ?finished.error,
        outputs = outputs.len(),
        silenced = outbox.is_silenced(),
        "job finished"
    );
    outbox.push(AgentMsg::JobFinished {
        lease_id,
        epoch,
        outcome: finished.outcome,
        exit_code: finished.exit_code,
        error: finished.error.clone(),
        usage: finished.usage,
        outputs,
    });
    outbox.close();
    inner.update(key, |r| r.phase = RunPhase::Finishing);
}

/// Waits for the run's messages to be handed to a session (or for the run to be silenced), logs the drops once, and
/// ends the run.
async fn finish<S>(key: LeaseKey, outbox: Arc<RunOutbox>, sender: tokio::task::JoinHandle<()>, guard: RunGuard<S>) {
    let _ = sender.await;
    let drops = outbox.drops();
    guard
        .inner
        .dropped_log_chunks
        .fetch_add(drops.chunks, Ordering::Relaxed);
    if drops.chunks > 0 {
        tracing::warn!(
            lease_id = %key.0,
            epoch = key.1,
            dropped_chunks = drops.chunks,
            dropped_bytes = drops.bytes,
            "log chunks dropped: more than 8 MiB queued while the server could not take them"
        );
    }
    drop(guard);
}

impl<S> LeaseHandler for Executor<S>
where
    S: Sandbox + Send + Sync + 'static,
    S::Job: Send + Sync + 'static,
{
    /// Decides at once, in one critical section (see the module docs): nothing to abort half-way.
    fn lease(&self, offer: LeaseOffer) -> BoxFuture<'_, LeaseDecision> {
        let decision = self.admit(offer);
        Box::pin(async move { decision })
    }

    fn cancel(&self, lease_id: LeaseId, epoch: u64, reason: String) -> BoxFuture<'_, ()> {
        {
            let mut state = self.inner.lock();
            let fenced = FENCED_CANCELS.contains(&reason.as_str());
            match state.listed(&lease_id) {
                // The server no longer holds this lease (T10a review, P3-3): stop it and send nothing more for it, no
                // upload and no JobFinished; it would only be fenced again.
                Some(((_, running), run)) if *running == epoch && fenced => {
                    tracing::info!(%lease_id, epoch, %reason, "cancel: the server no longer holds this lease; stopping it silently");
                    retire(run);
                }
                Some(((_, running), run)) if *running == epoch => {
                    tracing::info!(%lease_id, epoch, %reason, "cancel: stopping the job");
                    run.cancel.cancel();
                }
                Some(((_, running), run)) if *running < epoch => {
                    // The server has a newer epoch for this lease and cancels it: ours is stale too.
                    tracing::info!(%lease_id, epoch, running = *running, %reason, "cancel for a newer epoch: the running one is stale");
                    retire(run);
                }
                _ => tracing::debug!(%lease_id, epoch, %reason, "cancel for an unknown or stale lease ignored"),
            }
        }
        self.inner.status_changed.notify_one();
        Box::pin(async {})
    }
}

impl<S> LeaseSupervisor for Executor<S>
where
    S: Sandbox + Send + Sync + 'static,
    S::Job: Send + Sync + 'static,
{
    fn running(&self) -> Vec<RunningLease> {
        let state = self.inner.lock();
        let mut running: Vec<RunningLease> = state
            .runs
            .iter()
            .filter(|(_, r)| r.listed)
            .map(|((lease_id, epoch), _)| RunningLease {
                lease_id: *lease_id,
                epoch: *epoch,
            })
            .collect();
        running.sort_by_key(|r| (r.lease_id.to_string(), r.epoch));
        running
    }

    /// Every run that still holds resources, stale or silenced ones included: their container and directory are real
    /// until the cleanup ends.
    fn holding(&self) -> Vec<RunningLease> {
        let state = self.inner.lock();
        let mut holding: Vec<RunningLease> = state
            .runs
            .iter()
            .filter(|(_, r)| r.holds)
            .map(|((lease_id, epoch), _)| RunningLease {
                lease_id: *lease_id,
                epoch: *epoch,
            })
            .collect();
        holding.sort_by_key(|r| (r.lease_id.to_string(), r.epoch));
        holding
    }

    fn released(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.inner.released.notified())
    }

    fn stop_all(&self, reason: &'static str) -> BoxFuture<'_, ()> {
        let waits: Vec<watch::Receiver<bool>> = {
            let mut state = self.inner.lock();
            if reason != LEASE_LOST {
                state.closed = true;
            }
            for run in state.runs.values_mut() {
                retire(run);
            }
            state.runs.values().map(|r| r.done.clone()).collect()
        };
        self.inner.status_changed.notify_one();
        if !waits.is_empty() {
            tracing::warn!(
                reason,
                runs = waits.len(),
                "stopping every running job; their reports are dropped"
            );
        }
        Box::pin(async move {
            let all = async {
                for mut done in waits {
                    let _ = done.wait_for(|d| *d).await;
                }
            };
            if tokio::time::timeout(STOP_TIMEOUT, all).await.is_err() {
                tracing::warn!(
                    reason,
                    timeout_s = STOP_TIMEOUT.as_secs(),
                    "some jobs were not cleaned up in time; the next start removes what is left"
                );
            }
        })
    }

    fn drain(&self) -> BoxFuture<'_, ()> {
        self.inner.lock().draining = true;
        tracing::info!("draining: no new leases; the running ones finish");
        Box::pin(async {})
    }

    fn resume(&self) -> BoxFuture<'_, ()> {
        self.inner.lock().draining = false;
        tracing::info!("resumed: taking new leases again");
        Box::pin(async {})
    }
}
