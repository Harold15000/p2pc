// SPDX-License-Identifier: Apache-2.0

//! Where leases and drain commands go: the traits T10a implements on top of the sandbox driver (T08).
//!
//! The connection does the checks that must happen before any of them, so an implementation never sees a lease it
//! must not run:
//! - the lease's `account_id` is the enrolled owner (SI-1), otherwise `LeaseRejected{not_owner}`;
//! - its `job` parses strictly as a `JobSpec` with the agent's limits (§6 "must understand"), otherwise
//!   `LeaseRejected{invalid_job}`; the connection stays open.
//!
//! Calls must return quickly: they run on the connection's task (`drain`, `resume`, `cancel`, 5 s each) or under its
//! 10-second answer budget (`lease`, §6 "Two-phase assignment"). Long work belongs on the implementation's own tasks.
//!
//! **Lifetimes.** A `lease` decision belongs to the session that received the `Lease`: when the session ends, a
//! decision still in progress is aborted (its future dropped) and waited for, before the daemon goes on, and before
//! any `stop_all` it calls. An implementation must therefore commit to a lease atomically (all or nothing), never
//! from a decision that can be dropped half-way, and atomically with respect to [`LeaseSupervisor::stop_all`]: a
//! lease is either registered before a `stop_all` begins, and then stopped by it, or decided after it. **After
//! `stop_all`, refuse:** a decision in progress when it begins must not start a job, and after a terminal one
//! (`not_enrolled`, `agent_too_old`, `shutdown`) every lease is refused. Only `lease_lost` lets later leases, from a
//! server heard again, be taken.

use std::fmt;

use p2pc_proto::api::JobSpec;
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::{LeaseRejectReason, RunningLease};
use time::OffsetDateTime;

use super::BoxFuture;

/// The `reason` of [`LeaseSupervisor::stop_all`] when the agent-side lease timer expires (§6, SI-13).
pub const LEASE_LOST: &str = "lease_lost";

/// A lease that passed the owner check and the strict job parse.
#[derive(Clone)]
pub struct LeaseOffer {
    /// Lease.
    pub lease_id: LeaseId,
    /// Epoch (the attempt, a fencing token).
    pub epoch: u64,
    /// The job, parsed strictly and validated with `Limits::agent()`.
    pub job: JobSpec,
    /// The job's account: always the node's owner here.
    pub account_id: AccountId,
    /// When the lease must be done by.
    pub deadline: OffsetDateTime,
}

impl fmt::Debug for LeaseOffer {
    /// The job is left out: its `env` and `files` can hold secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseOffer")
            .field("lease_id", &self.lease_id)
            .field("epoch", &self.epoch)
            .field("account_id", &self.account_id)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// The answer to a [`LeaseOffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseDecision {
    /// `LeaseAccepted`.
    Accept,
    /// `LeaseRejected{reason}`.
    Reject(LeaseRejectReason),
}

/// Takes leases and cancels (T10a).
pub trait LeaseHandler: Send + Sync + fmt::Debug + 'static {
    /// Decides on a lease. The connection sends the answer.
    fn lease(&self, offer: LeaseOffer) -> BoxFuture<'_, LeaseDecision>;
    /// Stops a lease. A `Cancel` for a lease the handler does not know is ignored.
    fn cancel(&self, lease_id: LeaseId, epoch: u64, reason: String) -> BoxFuture<'_, ()>;
}

/// The running leases as a whole (T10a): what `Hello` and `Heartbeat` list, drain, and the SI-13 stop.
pub trait LeaseSupervisor: Send + Sync + fmt::Debug + 'static {
    /// What `Hello.running` lists (§6): the leases that are running, and the ones whose `JobFinished` the server has
    /// not confirmed yet (so that a reconnect does not make the server declare them lost).
    fn running(&self) -> Vec<RunningLease>;
    /// What `Heartbeat.running` lists (§6): every lease that still **holds resources** on the node, which is running,
    /// uploading or being cleaned up. A lease leaves this list when its resources are free, whether or not the server
    /// confirmed its `JobFinished` (T06e). By default it is [`LeaseSupervisor::running`].
    fn holding(&self) -> Vec<RunningLease> {
        self.running()
    }
    /// Resolves when a lease's resources became free after the last time it resolved (a permit is kept if nobody was
    /// waiting): the session then sends a `Heartbeat` at once, so the server learns of the free slot without waiting
    /// for the interval (§6). Never resolves by default.
    fn released(&self) -> BoxFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    /// Stops every running job with the §9 sequence (SIGTERM, 10 s of grace, SIGKILL) and forgets the leases.
    /// `reason` is [`LEASE_LOST`] when the agent-side lease timer expired; the daemon also calls it with
    /// `not_enrolled`, `agent_too_old` and `shutdown` before it exits, and waits for it. No report of a stopped job is
    /// sent afterwards: the server has already requeued it, or is about to.
    fn stop_all(&self, reason: &'static str) -> BoxFuture<'_, ()>;
    /// `Drain{}`: take no new leases.
    fn drain(&self) -> BoxFuture<'_, ()>;
    /// `Resume{}`: take new leases again.
    fn resume(&self) -> BoxFuture<'_, ()>;
}

/// The default [`LeaseHandler`] until T10a: every lease is refused with `agent_not_ready`, and a `Cancel` (which can
/// only be for a lease it does not know) is ignored.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotReady;

impl LeaseHandler for NotReady {
    fn lease(&self, offer: LeaseOffer) -> BoxFuture<'_, LeaseDecision> {
        tracing::info!(lease_id = %offer.lease_id, epoch = offer.epoch, "lease refused: no lease executor yet");
        Box::pin(async { LeaseDecision::Reject(LeaseRejectReason::AgentNotReady) })
    }

    fn cancel(&self, lease_id: LeaseId, epoch: u64, _reason: String) -> BoxFuture<'_, ()> {
        tracing::debug!(%lease_id, epoch, "cancel for an unknown lease ignored");
        Box::pin(async {})
    }
}

/// The default [`LeaseSupervisor`] until T10a: no leases, nothing to stop; drain and resume are logged.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoLeases;

impl LeaseSupervisor for NoLeases {
    fn running(&self) -> Vec<RunningLease> {
        Vec::new()
    }

    fn stop_all(&self, reason: &'static str) -> BoxFuture<'_, ()> {
        tracing::debug!(reason, "stop_all: no running leases");
        Box::pin(async {})
    }

    fn drain(&self) -> BoxFuture<'_, ()> {
        tracing::info!("drain requested by the server");
        Box::pin(async {})
    }

    fn resume(&self) -> BoxFuture<'_, ()> {
        tracing::info!("resume requested by the server");
        Box::pin(async {})
    }
}
