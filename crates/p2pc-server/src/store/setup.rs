// SPDX-License-Identifier: AGPL-3.0-only

//! The state of the hub's model pull, `service.setup` (H2 spec §7.2, §7.6, §13): the `setup_*` columns of
//! `service_state`. Only [`crate::model_pull`] writes them.
//!
//! The columns always describe the **current attempt** of the service:
//! - [`attempt_started`] makes them fresh when an attempt starts (`pulling` with no try yet, for a job with a model
//!   to pull);
//! - every other write is **fenced** by the lease of the attempt that pulls: it changes nothing unless that lease is
//!   still the job's current, running lease. A pull that outlived its attempt can therefore never write into the next
//!   one.
//!
//! These are protocol-side functions (the hub's own work, not a principal's): they take the job and its lease.

use p2pc_proto::api::{ServiceHealth, ServiceSetup, SetupFailure, SetupState};
use p2pc_proto::ids::{JobId, LeaseId, NodeId};
use time::OffsetDateTime;

use super::{Conn, StoreError, from_ts_opt, parse_col, ts};

/// The `setup_*` columns of one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupRow {
    /// `pulling`, `done` or `failed`; `None` for a job without a model to pull, or before its first attempt.
    pub state: Option<SetupState>,
    /// MiB downloaded so far in the current try.
    pub completed_mb: u64,
    /// MiB to download, once the service said so.
    pub total_mb: Option<u64>,
    /// Tries begun in this attempt (at most 2).
    pub tries: u32,
    /// Why the last failed try failed.
    pub reason: Option<SetupFailure>,
    /// When the try that is running began; `None` while no try runs.
    pub try_started_at: Option<OffsetDateTime>,
}

impl SetupRow {
    /// `service.setup` as the API shows it, or `None` without one.
    #[must_use]
    pub fn view(&self) -> Option<ServiceSetup> {
        let state = self.state?;
        Some(ServiceSetup {
            state,
            completed_mb: self.completed_mb,
            total_mb: self.total_mb,
            tries: self.tries,
            // H2 §7.2: `reason` says why it failed, when it did.
            reason: self.reason.filter(|_| state == SetupState::Failed),
        })
    }
}

const fn state_str(state: SetupState) -> &'static str {
    match state {
        SetupState::Pulling => "pulling",
        SetupState::Done => "done",
        SetupState::Failed => "failed",
    }
}

/// The stored word of a failure reason.
#[must_use]
pub const fn reason_str(reason: SetupFailure) -> &'static str {
    match reason {
        SetupFailure::ErrorLine => "error_line",
        SetupFailure::BadLine => "bad_line",
        SetupFailure::Eof => "eof",
        SetupFailure::StreamBroken => "stream_broken",
        SetupFailure::Deadline => "deadline",
    }
}

fn parse_state(text: &str) -> Result<SetupState, StoreError> {
    [SetupState::Pulling, SetupState::Done, SetupState::Failed]
        .into_iter()
        .find(|s| state_str(*s) == text)
        .ok_or(StoreError::Corrupt("service_state.setup_state"))
}

fn parse_reason(text: &str) -> Result<SetupFailure, StoreError> {
    [
        SetupFailure::ErrorLine,
        SetupFailure::BadLine,
        SetupFailure::Eof,
        SetupFailure::StreamBroken,
        SetupFailure::Deadline,
    ]
    .into_iter()
    .find(|r| reason_str(*r) == text)
    .ok_or(StoreError::Corrupt("service_state.setup_reason"))
}

type SetupRaw = (Option<String>, i64, Option<i64>, i64, Option<String>, Option<i64>);

fn decode(raw: SetupRaw) -> Result<SetupRow, StoreError> {
    let (state, completed, total, tries, reason, started) = raw;
    let mib = |v: i64, column| u64::try_from(v).map_err(|_| StoreError::Corrupt(column));
    Ok(SetupRow {
        state: state.as_deref().map(parse_state).transpose()?,
        completed_mb: mib(completed, "service_state.setup_completed_mb")?,
        total_mb: total.map(|t| mib(t, "service_state.setup_total_mb")).transpose()?,
        tries: u32::try_from(tries).map_err(|_| StoreError::Corrupt("service_state.setup_tries"))?,
        reason: reason.as_deref().map(parse_reason).transpose()?,
        try_started_at: from_ts_opt(started, "service_state.setup_try_started_at")?,
    })
}

/// The setup of `job_id`; `None` for a job without a `service_state` row (a batch job).
pub async fn get(conn: &mut Conn, job_id: JobId) -> Result<Option<SetupRow>, StoreError> {
    let raw: Option<SetupRaw> = sqlx::query_as(
        "SELECT setup_state, setup_completed_mb, setup_total_mb, setup_tries, setup_reason, setup_try_started_at \
         FROM service_state WHERE job_id = ?",
    )
    .bind(job_id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    raw.map(decode).transpose()
}

/// A service attempt started (`JobStarted`): its setup is fresh (H2 §7.6 "A new attempt starts with a fresh
/// `setup`"). `pulling` with no try yet for a job with a model to pull (`template.pull`), nothing for any other
/// service. Call it in the transaction that starts the attempt, after its `service_state` row exists.
pub async fn attempt_started(conn: &mut Conn, job_id: JobId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE service_state SET \
             setup_state = (SELECT CASE WHEN json_extract(j.spec_view, '$.template.pull') IS NOT NULL \
                                        THEN 'pulling' END FROM jobs j WHERE j.job_id = ?1), \
             setup_completed_mb = 0, setup_total_mb = NULL, setup_tries = 0, setup_reason = NULL, \
             setup_try_started_at = NULL, updated_at = ?2 \
         WHERE job_id = ?1",
    )
    .bind(job_id.to_string())
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// A running template service with a model to pull, on its current lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullTarget {
    /// The service.
    pub job_id: JobId,
    /// Its current lease, which fences every write of the pull.
    pub lease_id: LeaseId,
    /// The lease's epoch.
    pub epoch: u64,
    /// The node that runs it.
    pub node_id: NodeId,
    /// `template.pull`: the model, stored with the job.
    pub model: String,
    /// The service's first port, where the pull is sent.
    pub port: u16,
    /// Whether the attempt is `healthy` now.
    pub healthy: bool,
    /// Its setup.
    pub setup: SetupRow,
}

type TargetRaw = (
    String,
    String,
    i64,
    String,
    String,
    i64,
    Option<String>,
    Option<String>,
    i64,
    Option<i64>,
    i64,
    Option<String>,
    Option<i64>,
);

fn decode_target(raw: TargetRaw) -> Result<PullTarget, StoreError> {
    let (job, lease, epoch, node, model, port, health, state, completed, total, tries, reason, started) = raw;
    Ok(PullTarget {
        job_id: parse_col(&job, "leases.job_id")?,
        lease_id: parse_col(&lease, "leases.id")?,
        epoch: u64::try_from(epoch).map_err(|_| StoreError::Corrupt("leases.epoch"))?,
        node_id: parse_col(&node, "leases.node_id")?,
        model,
        port: u16::try_from(port).map_err(|_| StoreError::Corrupt("jobs.spec_view.service.ports"))?,
        healthy: health.as_deref() == Some(health_str(ServiceHealth::Healthy)),
        setup: decode((state, completed, total, tries, reason, started))?,
    })
}

const fn health_str(h: ServiceHealth) -> &'static str {
    match h {
        ServiceHealth::Starting => "starting",
        ServiceHealth::Healthy => "healthy",
        ServiceHealth::Unhealthy => "unhealthy",
    }
}

/// The columns of a [`PullTarget`]: a template service with `template.pull`, running on its current lease, that
/// nobody asked to stop.
macro_rules! select_targets {
    ($tail:literal) => {
        concat!(
            "SELECT l.job_id, l.id, l.epoch, l.node_id, json_extract(j.spec_view, '$.template.pull'), \
                    json_extract(j.spec_view, '$.service.ports[0].port'), s.health, s.setup_state, \
                    s.setup_completed_mb, s.setup_total_mb, s.setup_tries, s.setup_reason, s.setup_try_started_at \
             FROM leases l JOIN jobs j ON j.job_id = l.job_id JOIN service_state s ON s.job_id = l.job_id \
             WHERE l.state = 'running' AND l.epoch = j.epoch AND j.status = 'running' AND j.kind = 'service' \
               AND j.cancel_requested_at IS NULL AND j.template_id IS NOT NULL \
               AND json_type(j.spec_view, '$.template.pull') = 'text' \
               AND json_type(j.spec_view, '$.service.ports[0].port') = 'integer' ",
            $tail
        )
    };
}

/// Every service the hub may have a model to pull for, oldest lease first: the pull's input, read-only.
pub async fn targets(conn: &mut Conn) -> Result<Vec<PullTarget>, StoreError> {
    let rows: Vec<TargetRaw> = sqlx::query_as(select_targets!("ORDER BY l.offered_at_ms, l.id"))
        .fetch_all(&mut *conn)
        .await?;
    rows.into_iter().map(decode_target).collect()
}

/// The pull target of `lease_id` at `epoch`, if that still is its job's current, running lease.
pub async fn target(conn: &mut Conn, lease_id: LeaseId, epoch: u64) -> Result<Option<PullTarget>, StoreError> {
    let epoch = i64::try_from(epoch).map_err(|_| StoreError::Corrupt("leases.epoch"))?;
    let row: Option<TargetRaw> = sqlx::query_as(select_targets!("AND l.id = ? AND l.epoch = ?"))
        .bind(lease_id.to_string())
        .bind(epoch)
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode_target).transpose()
}

/// What a fenced write changes: the setup of the job whose current, running lease is `(lease_id, epoch)`.
macro_rules! update_fenced {
    ($set:literal) => {
        concat!(
            "UPDATE service_state SET ",
            $set,
            ", updated_at = ?4 \
             WHERE job_id = ?1 AND EXISTS (\
                 SELECT 1 FROM leases l JOIN jobs j ON j.job_id = l.job_id \
                 WHERE l.id = ?2 AND l.job_id = ?1 AND l.epoch = ?3 AND l.epoch = j.epoch \
                   AND l.state = 'running' AND j.status = 'running')"
        )
    };
}

fn epoch_col(epoch: u64) -> Result<i64, StoreError> {
    i64::try_from(epoch).map_err(|_| StoreError::Corrupt("leases.epoch"))
}

fn mib_col(mib: u64) -> i64 {
    i64::try_from(mib).unwrap_or(i64::MAX)
}

/// A try begins: `tries` so far, `pulling`, with no progress yet. Fenced; `false` when the attempt is gone.
pub async fn begin_try(conn: &mut Conn, t: &PullTarget, tries: u32, now: OffsetDateTime) -> Result<bool, StoreError> {
    let done = sqlx::query(update_fenced!(
        "setup_state = 'pulling', setup_tries = ?5, setup_try_started_at = ?4, setup_completed_mb = 0, \
         setup_total_mb = NULL"
    ))
    .bind(t.job_id.to_string())
    .bind(t.lease_id.to_string())
    .bind(epoch_col(t.epoch)?)
    .bind(ts(now))
    .bind(i64::from(tries))
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// The progress of the running try. Fenced, and only while a try runs.
pub async fn progress(
    conn: &mut Conn,
    t: &PullTarget,
    completed_mb: u64,
    total_mb: Option<u64>,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(concat!(
        update_fenced!("setup_completed_mb = ?5, setup_total_mb = ?6"),
        " AND setup_state = 'pulling' AND setup_try_started_at IS NOT NULL"
    ))
    .bind(t.job_id.to_string())
    .bind(t.lease_id.to_string())
    .bind(epoch_col(t.epoch)?)
    .bind(ts(now))
    .bind(mib_col(completed_mb))
    .bind(total_mb.map(mib_col))
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// The running try ended with the final `success` line: `done`. Fenced.
pub async fn done(conn: &mut Conn, t: &PullTarget, now: OffsetDateTime) -> Result<bool, StoreError> {
    let done = sqlx::query(update_fenced!(
        "setup_state = 'done', setup_reason = NULL, setup_try_started_at = NULL, \
         setup_completed_mb = COALESCE(setup_total_mb, setup_completed_mb)"
    ))
    .bind(t.job_id.to_string())
    .bind(t.lease_id.to_string())
    .bind(epoch_col(t.epoch)?)
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// A try failed with `reason`. With `last`, the hub does not pull again in this attempt: `failed`. Otherwise the
/// setup stays `pulling` with no try running, and the reason is kept for the record. Fenced.
pub async fn try_failed(
    conn: &mut Conn,
    t: &PullTarget,
    reason: SetupFailure,
    last: bool,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(update_fenced!(
        "setup_state = CASE WHEN ?6 THEN 'failed' ELSE 'pulling' END, setup_reason = ?5, \
         setup_try_started_at = NULL"
    ))
    .bind(t.job_id.to_string())
    .bind(t.lease_id.to_string())
    .bind(epoch_col(t.epoch)?)
    .bind(ts(now))
    .bind(reason_str(reason))
    .bind(last)
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}
