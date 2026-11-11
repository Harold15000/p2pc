// SPDX-License-Identifier: AGPL-3.0-only

//! Service jobs in the scheduler (H2 spec §7.2, §7.4 "Idle accounting", §6.1 `ServiceHealth`).
//!
//! - **Restart on node loss** ([`on_node_loss`]). A service whose node is lost is requeued like an H1 batch job, with
//!   two differences: `retry.max_attempts` counts consecutive attempts that never became healthy (an attempt that was
//!   healthy for 10 minutes resets the count), and node-loss restarts are capped at 5 in any 24 hours, whatever the
//!   count. With `restart: "never"` the first node loss ends the job `lost`.
//! - **Health.** The agent reports the health of a service lease in `ServiceHealth` and repeats it in every
//!   `Heartbeat`. Both are fenced like any lease message (SI-8) and stored in `service_state`. The hub's own clock
//!   decides what the policy counts: when the attempt became healthy, and for how long.
//! - **Idle cancel.** A running service with `idle_timeout_s` is asked to stop (`Cancel{reason:"idle_timeout"}`) once
//!   that long has passed with no open port connection and no traffic, counted from the later of its first `healthy`
//!   and the last activity the port relay recorded. The stop is a cancel request with a reason: the H1 cancel
//!   delivery does the rest.
//! - **Stop reasons.** A service that ends `cancelled` says why in `Job.reason`: `stopped`, `idle_timeout` or
//!   `cap_reached` (§7.2 "Ends of a service"). The reason is written with the cancel request and repeated in the
//!   `Cancel` and on the final state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use p2pc_proto::api::{
    ERROR_RESTART_LIMIT, HEALTHY_RESETS_ATTEMPTS_AFTER_S, JobKind, MAX_NODE_LOSS_RESTARTS_PER_24H, REASON_IDLE_TIMEOUT,
    REASON_STOPPED, RestartPolicy, ServiceHealth,
};
use p2pc_proto::ids::{JobId, LeaseId, NodeId};
use p2pc_proto::protocol::{self, HealthState, RunningLease, cancel_reason};
use time::{Duration, OffsetDateTime};

use super::{Effects, Result, Scheduler, TickReport, cancel, code, failed};
use crate::store::leases::{self, LeaseRow, LeaseState, ServiceState};
use crate::store::{self, Conn};

/// The window of the node-loss restart cap (H2 §7.2: "5 in any 24 hours").
pub const RESTART_WINDOW: Duration = Duration::hours(24);
/// How long an attempt must stay healthy to reset the count of attempts that never became healthy (H2 §7.2).
pub const HEALTHY_RESET: Duration = Duration::seconds(HEALTHY_RESETS_ATTEMPTS_AFTER_S as i64);

/// The port connections open now, per service: counted by the hub's port relay (T2-13, and the hub's own model pull
/// of T2-15, which counts as one), read by the idle cancel and by `GET /v1/jobs/{id}`. Cheap to clone; every clone
/// shares the same counts. A hub restart drops every connection, so starting empty is right.
#[derive(Debug, Clone, Default)]
pub struct OpenConnections(Arc<Mutex<HashMap<JobId, u32>>>);

impl OpenConnections {
    /// A connection to a port of `job` opened.
    pub fn opened(&self, job: JobId) {
        let mut open = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let n = open.entry(job).or_insert(0);
        *n = n.saturating_add(1);
    }

    /// A connection to a port of `job` closed.
    pub fn closed(&self, job: JobId) {
        let mut open = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = open.get_mut(&job) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                open.remove(&job);
            }
        }
    }

    /// How many connections to ports of `job` are open.
    #[must_use]
    pub fn count(&self, job: JobId) -> u32 {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&job)
            .copied()
            .unwrap_or(0)
    }
}

/// What a node loss does to a service (H2 §7.2 "Restart on node loss").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restart {
    /// Whether the service is requeued; otherwise it ends `lost`.
    pub requeue: bool,
    /// `Job.error` when it ends `lost` because of the 24-hour cap (`restart_limit`).
    pub error: Option<&'static str>,
    /// The new count of consecutive attempts that never became healthy.
    pub unhealthy_attempts: u32,
    /// The node-loss restarts of the last 24 h, this one included when the service is requeued.
    pub node_loss_restarts: Vec<i64>,
}

/// Decides a node loss of a service at `now`. `became_healthy` says whether the lost attempt ever became healthy;
/// `state` holds the counters before this loss (a healthy period of 10 minutes has already reset the count, on the
/// evidence of the agent's reports).
#[must_use]
pub fn on_node_loss(
    policy: RestartPolicy,
    max_attempts: u32,
    state: &ServiceState,
    became_healthy: bool,
    now: OffsetDateTime,
) -> Restart {
    let unhealthy_attempts = state.unhealthy_attempts.saturating_add(u32::from(!became_healthy));
    let mut recent: Vec<i64> = state
        .node_loss_restarts
        .iter()
        .copied()
        .filter(|at| now.unix_timestamp() - at < RESTART_WINDOW.whole_seconds())
        .collect();
    let lost = |error, recent| Restart {
        requeue: false,
        error,
        unhealthy_attempts,
        node_loss_restarts: recent,
    };
    if policy == RestartPolicy::Never || unhealthy_attempts >= max_attempts {
        return lost(None, recent);
    }
    // The node loss that would be the sixth restart within 24 hours ends the job.
    if recent.len() >= MAX_NODE_LOSS_RESTARTS_PER_24H as usize {
        return lost(Some(ERROR_RESTART_LIMIT), recent);
    }
    recent.push(now.unix_timestamp());
    Restart {
        requeue: true,
        error: None,
        unhealthy_attempts,
        node_loss_restarts: recent,
    }
}

/// The reason of a service's stop, from the `reason` its cancel request wrote: one of the H2 reasons, or `stopped`.
fn stop_reason(lease: &LeaseRow) -> &str {
    lease
        .job_reason
        .as_deref()
        .filter(|r| cancel_reason::H2.contains(r))
        .unwrap_or(REASON_STOPPED)
}

/// The `reason` of the `Cancel` that delivers a cancel request: H1's `user` for a batch job; for a service, why it is
/// being stopped (`stopped`, `idle_timeout`, `cap_reached`; informative, H2 §6.1).
pub(super) fn cancel_code(lease: &LeaseRow) -> &str {
    match lease.job_kind {
        JobKind::Batch => code::USER,
        JobKind::Service => stop_reason(lease),
    }
}

/// A service ended `cancelled`: `Job.reason` says why (H2 §7.2). Call it after the transition, which clears the
/// reason; `lease` is the row read before it. A batch job keeps H1's empty reason.
pub(super) async fn note_cancelled(tx: &mut Conn, lease: &LeaseRow) -> Result<()> {
    if lease.job_kind == JobKind::Service {
        leases::set_cancelled_reason(tx, lease.job_id, stop_reason(lease)).await?;
    }
    Ok(())
}

fn health_of(state: HealthState) -> ServiceHealth {
    match state {
        HealthState::Starting => ServiceHealth::Starting,
        HealthState::Healthy => ServiceHealth::Healthy,
        HealthState::Unhealthy => ServiceHealth::Unhealthy,
    }
}

/// Whether a health report changes anything: another health, or a healthy period that reached 10 minutes while
/// attempts that never became healthy are still counted.
fn health_due(state: &ServiceState, reported: ServiceHealth, now: OffsetDateTime) -> bool {
    state.health != Some(reported) || reset_due(state, now)
}

/// Whether the running attempt has been healthy for 10 minutes with a count left to reset.
fn reset_due(state: &ServiceState, now: OffsetDateTime) -> bool {
    state.unhealthy_attempts > 0
        && state.health == Some(ServiceHealth::Healthy)
        && state.healthy_since.is_some_and(|at| now - at >= HEALTHY_RESET)
}

impl Scheduler {
    /// The open port connections of every service, shared with the port relay.
    #[must_use]
    pub fn connections(&self) -> &OpenConnections {
        &self.inner.connections
    }

    /// `ServiceHealth` from `node_id` (H2 §6.1): fenced like every lease message (SI-8), then stored for the lease's
    /// service. A report for a lease that is not a running service lease changes nothing.
    pub(super) async fn on_service_health(&self, node_id: NodeId, msg: protocol::ServiceHealth) -> Result<()> {
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        let lease = match leases::get(&mut tx, msg.lease_id).await? {
            Some(l) if l.node_id == node_id && l.epoch == msg.epoch && l.is_current() => l,
            other => {
                let reason = if other.is_some_and(|l| l.node_id == node_id) {
                    code::STALE_EPOCH
                } else {
                    code::UNKNOWN_LEASE
                };
                fx.send.push((node_id, cancel(msg.lease_id, msg.epoch, reason)));
                drop(tx);
                self.deliver(fx);
                return Ok(());
            }
        };
        self.apply_health(&mut tx, &lease, msg.state, Some(msg.since), now)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Stores the health `lease`'s agent reported, if `lease` is a running service lease and the report changes
    /// something. `since` is the agent's time of the change, kept within the attempt; a repeat in a heartbeat has
    /// none.
    async fn apply_health(
        &self,
        tx: &mut Conn,
        lease: &LeaseRow,
        reported: HealthState,
        since: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<()> {
        if lease.job_kind != JobKind::Service || lease.state != LeaseState::Running {
            tracing::debug!(lease_id = %lease.id, "health report ignored: not a running service lease");
            return Ok(());
        }
        let reported = health_of(reported);
        let state = leases::service_state(tx, lease.job_id).await?;
        if reset_due(&state, now) {
            leases::reset_unhealthy_attempts(tx, lease.job_id, now).await?;
        }
        if state.health != Some(reported) {
            // What the API shows: the agent's time, never before the attempt started nor after now.
            let floor = lease.started_at.unwrap_or(now).min(now);
            let since = since.unwrap_or(now).clamp(floor, now);
            leases::set_health(tx, lease.job_id, reported, since, now).await?;
            tracing::info!(job_id = %lease.job_id, lease_id = %lease.id, health = ?reported, "service health changed");
        }
        Ok(())
    }

    /// `Heartbeat.running[].health` from `node_id`: each entry repeats the lease's last `ServiceHealth`, so a report
    /// that was lost is caught up here, and a healthy period that reached 10 minutes resets the restart count. Most
    /// heartbeats change nothing and take no write lock.
    pub(super) async fn heartbeat_health(&self, node_id: NodeId, running: &[RunningLease]) -> Result<()> {
        let reported: Vec<(LeaseId, u64, HealthState)> = running
            .iter()
            .filter_map(|r| r.health.map(|h| (r.lease_id, r.epoch, h)))
            .collect();
        if reported.is_empty() {
            return Ok(());
        }
        let now = self.now();
        // Read-only first.
        let mut due = Vec::new();
        {
            let mut conn = self.inner.db.acquire().await?;
            for (lease_id, epoch, health) in reported {
                if let Some(l) = self.health_target(&mut conn, node_id, lease_id, epoch).await?
                    && health_due(
                        &leases::service_state(&mut conn, l.job_id).await?,
                        health_of(health),
                        now,
                    )
                {
                    due.push((lease_id, epoch, health));
                }
            }
        }
        if due.is_empty() {
            return Ok(());
        }
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        for (lease_id, epoch, health) in due {
            // Re-read inside the transaction: the lease may have ended meanwhile.
            if let Some(l) = self.health_target(&mut tx, node_id, lease_id, epoch).await? {
                self.apply_health(&mut tx, &l, health, None, now).await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// The running service lease `(lease_id, epoch)` of `node_id`, if that is the job's current lease. Anything else
    /// in a heartbeat is not answered here: the H1 paths fence it.
    async fn health_target(
        &self,
        conn: &mut Conn,
        node_id: NodeId,
        lease_id: LeaseId,
        epoch: u64,
    ) -> Result<Option<LeaseRow>> {
        Ok(leases::get(conn, lease_id).await?.filter(|l| {
            l.node_id == node_id
                && l.epoch == epoch
                && l.is_current()
                && l.state == LeaseState::Running
                && l.job_kind == JobKind::Service
        }))
    }

    /// The idle cancel (H2 §7.4 "Idle accounting"): a running service whose `idle_timeout_s` has passed with no open
    /// connection and no traffic is asked to stop, with the reason `idle_timeout`. The pre-pass is read-only.
    pub(super) async fn stop_idle_services(&self, r: &mut TickReport) -> Result<()> {
        let now = self.now();
        let due: Vec<leases::IdleCandidate> = {
            let mut conn = self.inner.db.acquire().await?;
            leases::idle_candidates(&mut conn).await?
        };
        for c in due.into_iter().filter(|c| self.idle(c, now)) {
            if let Err(e) = self.stop_idle(c.lease_id).await {
                failed(r, "stop an idle service", &e);
            }
        }
        Ok(())
    }

    fn idle(&self, c: &leases::IdleCandidate, now: OffsetDateTime) -> bool {
        self.inner.connections.count(c.job_id) == 0
            && now >= c.last_activity_at + Duration::seconds(i64::from(c.idle_timeout_s))
    }

    async fn stop_idle(&self, lease_id: LeaseId) -> Result<()> {
        let mut fx = Effects::default();
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        let now = self.now();
        // Decided again inside the transaction: traffic, a connection, a stop or the end of the attempt may have come.
        let still = leases::idle_candidates(&mut tx)
            .await?
            .into_iter()
            .find(|c| c.lease_id == lease_id)
            .filter(|c| self.idle(c, now));
        let Some(c) = still else {
            return Ok(());
        };
        if leases::request_stop(&mut tx, c.job_id, REASON_IDLE_TIMEOUT, now).await? {
            tracing::info!(job_id = %c.job_id, %lease_id, "idle service asked to stop");
            // The cancel delivery of this same tick sends the `Cancel`.
            fx.kick = true;
        }
        tx.commit().await?;
        self.deliver(fx);
        Ok(())
    }
}
