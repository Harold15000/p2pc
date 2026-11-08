// SPDX-License-Identifier: AGPL-3.0-only

//! Leases, attempts, offer cooldowns and the usage ledger (spec §6, §7, §8, §11): the scheduler's repository.
//!
//! These are **protocol-side** functions, like the agent half of [`super::nodes`]: the scheduler runs for every
//! account, and a lease is found from the `lease_id` a node sent, then checked against that node. The REST side
//! ([`usage_report`], [`held_for_account`]) takes the principal's `account_id` (and project) and filters by it (SI-7).
//!
//! **Status never changes here.** A job's status moves only through `job_state::transition`; the bookkeeping columns
//! next to it (`epoch`, `offer_count`, `attempt`, `node_id`, `reason`, the result) are written by the functions
//! below, in the same transaction as the transition.
//!
//! **No spec here.** Candidate queries read only the columns they need from the redacted `spec_view` (resources,
//! placement, timeout), never `spec`: the scheduler reads `spec` through `jobs::load_spec`, one row at a time, only to
//! build a `Lease`.

use std::collections::BTreeMap;

use p2pc_proto::api::{JobStatus, UsageGroupBy, UsageRecord};
use p2pc_proto::ids::{AccountId, JobId, KeyId, LeaseId, NodeId, ProjectId};
use p2pc_proto::units::Units;
use time::OffsetDateTime;

use super::{Conn, StoreError, from_ts_ms, from_ts_opt, parse_col, ts, ts_ms};
use crate::scheduler::fit::{Request, Reserved};

/// The `leases.state` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseState {
    /// Sent, waiting for `LeaseAccepted` (10 s).
    Offered,
    /// Accepted; the job is `assigned`.
    Accepted,
    /// `JobStarted`; the job is `running`.
    Running,
    /// `JobFinished` received.
    Finished,
    /// Ended by the server: refused or unanswered offer, cancel on an unreachable node, watchdog.
    Revoked,
    /// Its node was lost (TTL, absent from a `Hello`, deleted).
    Lost,
}

impl LeaseState {
    /// The column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            LeaseState::Offered => "offered",
            LeaseState::Accepted => "accepted",
            LeaseState::Running => "running",
            LeaseState::Finished => "finished",
            LeaseState::Revoked => "revoked",
            LeaseState::Lost => "lost",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        Ok(match text {
            "offered" => LeaseState::Offered,
            "accepted" => LeaseState::Accepted,
            "running" => LeaseState::Running,
            "finished" => LeaseState::Finished,
            "revoked" => LeaseState::Revoked,
            "lost" => LeaseState::Lost,
            _ => return Err(StoreError::Corrupt("leases.state")),
        })
    }

    /// Offered, accepted or running: the lease has not ended.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, LeaseState::Offered | LeaseState::Accepted | LeaseState::Running)
    }
}

/// A lease, with the few columns of its job that fencing and the watchdog need.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseRow {
    /// Lease ID.
    pub id: LeaseId,
    /// Its job.
    pub job_id: JobId,
    /// Its node.
    pub node_id: NodeId,
    /// The fencing token.
    pub epoch: u64,
    /// The job's attempt this lease runs.
    pub attempt: u32,
    /// State.
    pub state: LeaseState,
    /// What it holds on the node.
    pub reserved: Reserved,
    /// When it was offered.
    pub offered_at: OffsetDateTime,
    /// When it was accepted.
    pub accepted_at: Option<OffsetDateTime>,
    /// When the job started.
    pub started_at: Option<OffsetDateTime>,
    /// When it ended.
    pub ended_at: Option<OffsetDateTime>,
    /// When its execution was confirmed dead: the reservation is held until then.
    pub confirmed_dead_at: Option<OffsetDateTime>,
    /// When a `Cancel` for a cancel request was delivered.
    pub cancel_sent_at: Option<OffsetDateTime>,
    /// The job's account.
    pub account_id: AccountId,
    /// The job's project.
    pub project_id: ProjectId,
    /// The job's last issued epoch.
    pub job_epoch: u64,
    /// The job's status.
    pub job_status: JobStatus,
    /// The job's cancel request.
    pub cancel_requested_at: Option<OffsetDateTime>,
    /// The job's `timeout_s`.
    pub timeout_s: u32,
}

impl LeaseRow {
    /// SI-8: the job's current lease is the one with the job's latest epoch, while it is active. A message for any
    /// other `(lease_id, epoch)` is fenced.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.state.is_active() && self.epoch == self.job_epoch && !self.job_status.is_terminal()
    }

    /// Whether the lease still holds its reservation.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.confirmed_dead_at.is_none()
    }
}

#[derive(sqlx::FromRow)]
struct RawLease {
    id: String,
    job_id: String,
    node_id: String,
    epoch: i64,
    attempt: i64,
    state: String,
    reserved: String,
    offered_at_ms: i64,
    accepted_at: Option<i64>,
    started_at: Option<i64>,
    ended_at: Option<i64>,
    confirmed_dead_at: Option<i64>,
    cancel_sent_at: Option<i64>,
    account_id: String,
    project_id: String,
    job_epoch: i64,
    job_status: String,
    cancel_requested_at: Option<i64>,
    timeout_s: Option<i64>,
}

macro_rules! select_leases {
    ($tail:literal) => {
        concat!(
            "SELECT l.id, l.job_id, l.node_id, l.epoch, l.attempt, l.state, l.reserved, l.offered_at_ms, l.accepted_at, \
             l.started_at, l.ended_at, l.confirmed_dead_at, l.cancel_sent_at, j.account_id, j.project_id, \
             j.epoch AS job_epoch, j.status AS job_status, j.cancel_requested_at, \
             json_extract(j.spec_view, '$.timeout_s') AS timeout_s \
             FROM leases l JOIN jobs j ON j.job_id = l.job_id ",
            $tail
        )
    };
}

fn u64_col(v: i64, column: &'static str) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt(column))
}

fn u32_col(v: i64, column: &'static str) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::Corrupt(column))
}

fn status(text: &str) -> Result<JobStatus, StoreError> {
    JobStatus::ALL
        .into_iter()
        .find(|s| s.as_str() == text)
        .ok_or(StoreError::Corrupt("jobs.status"))
}

fn decode(raw: RawLease) -> Result<LeaseRow, StoreError> {
    Ok(LeaseRow {
        id: parse_col(&raw.id, "leases.id")?,
        job_id: parse_col(&raw.job_id, "leases.job_id")?,
        node_id: parse_col(&raw.node_id, "leases.node_id")?,
        epoch: u64_col(raw.epoch, "leases.epoch")?,
        attempt: u32_col(raw.attempt, "leases.attempt")?,
        state: LeaseState::parse(&raw.state)?,
        reserved: serde_json::from_str(&raw.reserved).map_err(|_| StoreError::Corrupt("leases.reserved"))?,
        offered_at: from_ts_ms(raw.offered_at_ms, "leases.offered_at_ms")?,
        accepted_at: from_ts_opt(raw.accepted_at, "leases.accepted_at")?,
        started_at: from_ts_opt(raw.started_at, "leases.started_at")?,
        ended_at: from_ts_opt(raw.ended_at, "leases.ended_at")?,
        confirmed_dead_at: from_ts_opt(raw.confirmed_dead_at, "leases.confirmed_dead_at")?,
        cancel_sent_at: from_ts_opt(raw.cancel_sent_at, "leases.cancel_sent_at")?,
        account_id: parse_col(&raw.account_id, "jobs.account_id")?,
        project_id: parse_col(&raw.project_id, "jobs.project_id")?,
        job_epoch: u64_col(raw.job_epoch, "jobs.epoch")?,
        job_status: status(&raw.job_status)?,
        cancel_requested_at: from_ts_opt(raw.cancel_requested_at, "jobs.cancel_requested_at")?,
        timeout_s: u32_col(raw.timeout_s.unwrap_or(0), "jobs.spec_view.timeout_s")?,
    })
}

/// Decodes a listing. A row that does not decode (a database edited by hand, or corrupt) is logged and left out, so
/// one bad lease never stops the scheduler's other work; reading it by ID ([`get`]) still fails, and every step that
/// needs it is skipped and logged.
fn decode_all(rows: Vec<RawLease>) -> Result<Vec<LeaseRow>, StoreError> {
    Ok(rows
        .into_iter()
        .filter_map(|raw| {
            let id = raw.id.clone();
            decode(raw)
                .map_err(|e| tracing::warn!(error = %e, lease_id = %id, "lease row skipped: it does not decode"))
                .ok()
        })
        .collect())
}

fn json<T: serde::Serialize>(value: &T, column: &'static str) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Corrupt(column))
}

fn epoch_col(epoch: u64) -> Result<i64, StoreError> {
    i64::try_from(epoch).map_err(|_| StoreError::Corrupt("leases.epoch"))
}

/// A lease by ID.
pub async fn get(conn: &mut Conn, id: LeaseId) -> Result<Option<LeaseRow>, StoreError> {
    let raw: Option<RawLease> = sqlx::query_as(select_leases!("WHERE l.id = ?"))
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

/// The leases of a node that still hold a reservation, oldest first.
pub async fn held_on_node(conn: &mut Conn, node_id: NodeId) -> Result<Vec<LeaseRow>, StoreError> {
    let rows: Vec<RawLease> = sqlx::query_as(select_leases!(
        "WHERE l.node_id = ? AND l.confirmed_dead_at IS NULL ORDER BY l.offered_at_ms, l.id"
    ))
    .bind(node_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    decode_all(rows)
}

/// The finished leases of a node that still hold their reservation, oldest first: the node has not freed their
/// resources yet (its heartbeat still lists them, or none came since `JobFinished`).
pub async fn finished_held_on_node(conn: &mut Conn, node_id: NodeId) -> Result<Vec<LeaseRow>, StoreError> {
    let rows: Vec<RawLease> = sqlx::query_as(select_leases!(
        "WHERE l.node_id = ? AND l.state = 'finished' AND l.confirmed_dead_at IS NULL ORDER BY l.offered_at_ms, l.id"
    ))
    .bind(node_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    decode_all(rows)
}

/// Offers sent at or before `before`, unanswered.
pub async fn offers_sent_before(conn: &mut Conn, before: OffsetDateTime) -> Result<Vec<LeaseRow>, StoreError> {
    let rows: Vec<RawLease> = sqlx::query_as(select_leases!(
        "WHERE l.state = 'offered' AND l.offered_at_ms <= ? ORDER BY l.offered_at_ms, l.id"
    ))
    .bind(ts_ms(before))
    .fetch_all(&mut *conn)
    .await?;
    decode_all(rows)
}

/// Active leases whose job needs attention: a cancel request, or a terminal job (cancelled while its lease was
/// still an offer).
pub async fn needing_cancel(conn: &mut Conn) -> Result<Vec<LeaseRow>, StoreError> {
    let rows: Vec<RawLease> = sqlx::query_as(select_leases!(
        "WHERE l.state IN ('offered', 'accepted', 'running') \
           AND (j.cancel_requested_at IS NOT NULL \
                OR j.status IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost')) \
         ORDER BY l.offered_at_ms, l.id"
    ))
    .fetch_all(&mut *conn)
    .await?;
    decode_all(rows)
}

/// An execution the server ended itself (the watchdog, a cancel on an unreachable node) whose node has not
/// confirmed the end yet: it is told `Cancel` again every few seconds (T06 review).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEnded {
    /// The lease.
    pub id: LeaseId,
    /// Its node.
    pub node_id: NodeId,
    /// Its epoch.
    pub epoch: u64,
    /// Why the server ended it (the `Cancel`'s reason).
    pub end_reason: String,
    /// The latest `Cancel` sent for it.
    pub cancel_sent_at: Option<OffsetDateTime>,
}

/// Leases the server ended itself that still hold their reservation (revoked, not confirmed dead).
pub async fn server_ended_unconfirmed(conn: &mut Conn) -> Result<Vec<ServerEnded>, StoreError> {
    /// `id, node_id, epoch, end_reason, cancel_sent_at`.
    type Row = (String, String, i64, Option<String>, Option<i64>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, node_id, epoch, end_reason, cancel_sent_at FROM leases \
         WHERE state = 'revoked' AND confirmed_dead_at IS NULL ORDER BY offered_at_ms, id",
    )
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(id, node, epoch, reason, sent)| {
            Ok(ServerEnded {
                id: parse_col(&id, "leases.id")?,
                node_id: parse_col(&node, "leases.node_id")?,
                epoch: u64_col(epoch, "leases.epoch")?,
                end_reason: reason.ok_or(StoreError::Corrupt("leases.end_reason"))?,
                cancel_sent_at: from_ts_opt(sent, "leases.cancel_sent_at")?,
            })
        })
        .collect()
}

/// The IDs of the active leases (offered, accepted or running).
pub async fn active_ids(conn: &mut Conn) -> Result<Vec<LeaseId>, StoreError> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM leases WHERE state IN ('offered', 'accepted', 'running')")
            .fetch_all(&mut *conn)
            .await?;
    ids.iter().map(|s| parse_col(s, "leases.id")).collect()
}

/// Accepted and running leases (the watchdog's input).
pub async fn accepted_or_running(conn: &mut Conn) -> Result<Vec<LeaseRow>, StoreError> {
    let rows: Vec<RawLease> = sqlx::query_as(select_leases!(
        "WHERE l.state IN ('accepted', 'running') ORDER BY l.offered_at_ms, l.id"
    ))
    .fetch_all(&mut *conn)
    .await?;
    decode_all(rows)
}

/// Leases past their offer that still hold a reservation, on any node (the expiry backstop's input).
pub async fn held_after_offer(conn: &mut Conn) -> Result<Vec<LeaseRow>, StoreError> {
    let rows: Vec<RawLease> = sqlx::query_as(select_leases!(
        "WHERE l.confirmed_dead_at IS NULL AND l.state <> 'offered' ORDER BY l.offered_at_ms, l.id"
    ))
    .fetch_all(&mut *conn)
    .await?;
    decode_all(rows)
}

/// Every reservation held on the live nodes of `account_id`, by node.
pub async fn held_for_account(
    conn: &mut Conn,
    account_id: AccountId,
) -> Result<BTreeMap<NodeId, Vec<Reserved>>, StoreError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT l.node_id, l.reserved FROM leases l JOIN nodes n ON n.id = l.node_id \
         WHERE n.account_id = ? AND n.deleted_at IS NULL AND l.confirmed_dead_at IS NULL",
    )
    .bind(account_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    group_reserved(rows)
}

/// Every reservation held on any node, by node (tests and invariants).
pub async fn held_everywhere(conn: &mut Conn) -> Result<BTreeMap<NodeId, Vec<Reserved>>, StoreError> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT node_id, reserved FROM leases WHERE confirmed_dead_at IS NULL")
            .fetch_all(&mut *conn)
            .await?;
    group_reserved(rows)
}

/// Groups held reservations by node. An unreadable reservation **fails closed**: it counts as holding the whole node
/// ([`Reserved::unreadable`]), so the node gets nothing more until the row is fixed, but the other nodes still do.
fn group_reserved(rows: Vec<(String, String)>) -> Result<BTreeMap<NodeId, Vec<Reserved>>, StoreError> {
    let mut out: BTreeMap<NodeId, Vec<Reserved>> = BTreeMap::new();
    for (node, reserved) in rows {
        let node: NodeId = parse_col(&node, "leases.node_id")?;
        let r: Reserved = serde_json::from_str(&reserved).unwrap_or_else(|_| {
            tracing::warn!(node_id = %node, "unreadable lease reservation: the node counts as full");
            Reserved::unreadable()
        });
        out.entry(node).or_default().push(r);
    }
    Ok(out)
}

/// When each node of `account_id` last got or released work: its latest offer or confirmed end.
pub async fn last_activity(conn: &mut Conn, account_id: AccountId) -> Result<BTreeMap<NodeId, i64>, StoreError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT l.node_id, MAX(MAX(l.offered_at_ms / 1000, COALESCE(l.confirmed_dead_at, 0))) FROM leases l \
         JOIN nodes n ON n.id = l.node_id WHERE n.account_id = ? GROUP BY l.node_id",
    )
    .bind(account_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(n, at)| Ok((parse_col(&n, "leases.node_id")?, at)))
        .collect()
}

/// A lease to insert, `offered`.
#[derive(Debug, Clone)]
pub struct NewLease {
    /// ID.
    pub id: LeaseId,
    /// Job.
    pub job_id: JobId,
    /// Node.
    pub node_id: NodeId,
    /// The epoch (the job's new `epoch`).
    pub epoch: u64,
    /// The job's attempt.
    pub attempt: u32,
    /// The reservation.
    pub reserved: Reserved,
}

/// Inserts an `offered` lease.
pub async fn insert(conn: &mut Conn, lease: &NewLease, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO leases (id, job_id, node_id, epoch, attempt, state, reserved, offered_at_ms) \
         VALUES (?, ?, ?, ?, ?, 'offered', ?, ?)",
    )
    .bind(lease.id.to_string())
    .bind(lease.job_id.to_string())
    .bind(lease.node_id.to_string())
    .bind(epoch_col(lease.epoch)?)
    .bind(i64::from(lease.attempt))
    .bind(json(&lease.reserved, "leases.reserved")?)
    .bind(ts_ms(now))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `offered → accepted`. Whether it changed.
pub async fn mark_accepted(conn: &mut Conn, id: LeaseId, now: OffsetDateTime) -> Result<bool, StoreError> {
    let n = sqlx::query("UPDATE leases SET state = 'accepted', accepted_at = ? WHERE id = ? AND state = 'offered'")
        .bind(ts(now))
        .bind(id.to_string())
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// `accepted → running`. Whether it changed.
pub async fn mark_running(conn: &mut Conn, id: LeaseId, now: OffsetDateTime) -> Result<bool, StoreError> {
    let n = sqlx::query("UPDATE leases SET state = 'running', started_at = ? WHERE id = ? AND state = 'accepted'")
        .bind(ts(now))
        .bind(id.to_string())
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// Ends an active lease in `to` (`finished`, `revoked` or `lost`), confirmed dead now or not. Whether it changed.
pub async fn end(
    conn: &mut Conn,
    id: LeaseId,
    to: LeaseState,
    reason: &str,
    confirmed: bool,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    debug_assert!(!to.is_active());
    let n = sqlx::query(
        "UPDATE leases SET state = ?1, ended_at = ?2, end_reason = ?3, \
             confirmed_dead_at = CASE WHEN ?4 THEN ?2 ELSE NULL END \
         WHERE id = ?5 AND state IN ('offered', 'accepted', 'running')",
    )
    .bind(to.as_str())
    .bind(ts(now))
    .bind(reason)
    .bind(confirmed)
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Confirms an ended lease dead: its reservation is released. Whether it changed.
pub async fn confirm_dead(conn: &mut Conn, id: LeaseId, now: OffsetDateTime) -> Result<bool, StoreError> {
    let n = sqlx::query(
        "UPDATE leases SET confirmed_dead_at = ? WHERE id = ? AND confirmed_dead_at IS NULL AND ended_at IS NOT NULL",
    )
    .bind(ts(now))
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Records the latest attempt to send a `Cancel` for the job's cancel request (the scheduler sends it again until the
/// node reports the end).
pub async fn mark_cancel_sent(conn: &mut Conn, id: LeaseId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query("UPDATE leases SET cancel_sent_at = ? WHERE id = ?")
        .bind(ts(now))
        .bind(id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

// --- Attempts ---------------------------------------------------------------------------------------------------

/// Opens the attempt row of an accepted lease.
pub async fn open_attempt(conn: &mut Conn, lease: &LeaseRow, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO job_attempts (job_id, attempt, epoch, lease_id, node_id, accepted_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(lease.job_id.to_string())
    .bind(i64::from(lease.attempt))
    .bind(epoch_col(lease.epoch)?)
    .bind(lease.id.to_string())
    .bind(lease.node_id.to_string())
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Sets the start of an attempt.
pub async fn attempt_started(conn: &mut Conn, lease_id: LeaseId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query("UPDATE job_attempts SET started_at = ? WHERE lease_id = ? AND started_at IS NULL")
        .bind(ts(now))
        .bind(lease_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Closes an attempt with what it came to (the job state it led to, or `lost`) and a reason code.
pub async fn attempt_ended(
    conn: &mut Conn,
    lease_id: LeaseId,
    outcome: JobStatus,
    reason_code: &str,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE job_attempts SET outcome = ?, reason_code = ?, ended_at = ? WHERE lease_id = ? AND ended_at IS NULL",
    )
    .bind(outcome.as_str())
    .bind(reason_code)
    .bind(ts(now))
    .bind(lease_id.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// One row of `job_attempts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// Attempt number.
    pub attempt: u32,
    /// Its lease's epoch.
    pub epoch: u64,
    /// Its node.
    pub node_id: NodeId,
    /// What it came to.
    pub outcome: Option<String>,
    /// Why.
    pub reason_code: Option<String>,
    /// When it started running.
    pub started_at: Option<OffsetDateTime>,
    /// When it ended.
    pub ended_at: Option<OffsetDateTime>,
}

/// The attempts of a job, in order.
pub async fn attempts(conn: &mut Conn, job_id: JobId) -> Result<Vec<Attempt>, StoreError> {
    type Row = (
        i64,
        i64,
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT attempt, epoch, node_id, outcome, reason_code, started_at, ended_at FROM job_attempts \
         WHERE job_id = ? ORDER BY attempt",
    )
    .bind(job_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(attempt, epoch, node, outcome, reason_code, started, ended)| {
            Ok(Attempt {
                attempt: u32_col(attempt, "job_attempts.attempt")?,
                epoch: u64_col(epoch, "job_attempts.epoch")?,
                node_id: parse_col(&node, "job_attempts.node_id")?,
                outcome,
                reason_code,
                started_at: from_ts_opt(started, "job_attempts.started_at")?,
                ended_at: from_ts_opt(ended, "job_attempts.ended_at")?,
            })
        })
        .collect()
}

// --- Cooldowns ----------------------------------------------------------------------------------------------------

/// The (job, node) pair is not offered again before `until` (§8 "Offer cap").
pub async fn set_cooldown(
    conn: &mut Conn,
    job_id: JobId,
    node_id: NodeId,
    until: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO job_node_cooldowns (job_id, node_id, until) VALUES (?1, ?2, ?3) \
         ON CONFLICT (job_id, node_id) DO UPDATE SET until = MAX(until, ?3)",
    )
    .bind(job_id.to_string())
    .bind(node_id.to_string())
    .bind(ts(until))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The nodes `job_id` may not be offered to at `now`.
pub async fn cooling_nodes(conn: &mut Conn, job_id: JobId, now: OffsetDateTime) -> Result<Vec<NodeId>, StoreError> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT node_id FROM job_node_cooldowns WHERE job_id = ? AND until > ?")
        .bind(job_id.to_string())
        .bind(ts(now))
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|n| parse_col(n, "job_node_cooldowns.node_id"))
        .collect()
}

// --- Job bookkeeping (never the status) -------------------------------------------------------------------------

/// A queued job, as placement reads it: no `spec`, only what eligibility needs from `spec_view`.
#[derive(Debug, Clone, PartialEq)]
pub struct QueuedJob {
    /// Job.
    pub job_id: JobId,
    /// Account.
    pub account_id: AccountId,
    /// Project.
    pub project_id: ProjectId,
    /// Current attempt.
    pub attempt: u32,
    /// Last issued epoch.
    pub epoch: u64,
    /// Failed offers so far.
    pub offer_count: u32,
    /// The node that last lost the job, if any.
    pub last_lost_node_id: Option<NodeId>,
    /// What it asks for.
    pub request: Request,
    /// `timeout_s`.
    pub timeout_s: u32,
    /// Its place in the FIFO queue: `(created_at, job_id)`.
    pub position: QueuePosition,
}

/// A position in the FIFO queue of queued jobs: `(created_at, job_id)` of a job.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct QueuePosition {
    /// `created_at`, Unix seconds.
    pub created_at: i64,
    /// The job ID, as stored (the tie-break of equal `created_at`).
    pub job_id: String,
}

#[derive(sqlx::FromRow)]
struct RawQueued {
    job_id: String,
    account_id: String,
    project_id: String,
    attempt: i64,
    epoch: i64,
    offer_count: i64,
    last_lost_node_id: Option<String>,
    cpu: Option<f64>,
    memory_mb: Option<i64>,
    disk_mb: Option<i64>,
    gpu: Option<i64>,
    placement: Option<String>,
    timeout_s: Option<i64>,
    created_at: i64,
}

/// The `placement` of the redacted view.
#[derive(serde::Deserialize)]
struct PlacementCols {
    #[serde(default)]
    pools: Vec<String>,
    #[serde(default)]
    node_id: Option<NodeId>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

macro_rules! select_queued {
    ($tail:literal) => {
        concat!(
            "SELECT job_id, account_id, project_id, attempt, epoch, offer_count, last_lost_node_id, \
             json_extract(spec_view, '$.resources.cpu') AS cpu, \
             json_extract(spec_view, '$.resources.memory_mb') AS memory_mb, \
             json_extract(spec_view, '$.resources.disk_mb') AS disk_mb, \
             json_extract(spec_view, '$.resources.gpu') AS gpu, \
             json_extract(spec_view, '$.placement') AS placement, \
             json_extract(spec_view, '$.timeout_s') AS timeout_s, created_at \
             FROM jobs WHERE status = 'queued' AND offer_count < ?1 \
               AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.job_id = jobs.job_id \
                               AND l.state IN ('offered', 'accepted', 'running')) ",
            $tail
        )
    };
}

fn decode_queued(raw: RawQueued) -> Result<QueuedJob, StoreError> {
    let placement: PlacementCols = serde_json::from_str(raw.placement.as_deref().unwrap_or("{}"))
        .map_err(|_| StoreError::Corrupt("jobs.spec_view.placement"))?;
    Ok(QueuedJob {
        job_id: parse_col(&raw.job_id, "jobs.job_id")?,
        account_id: parse_col(&raw.account_id, "jobs.account_id")?,
        project_id: parse_col(&raw.project_id, "jobs.project_id")?,
        attempt: u32_col(raw.attempt, "jobs.attempt")?,
        epoch: u64_col(raw.epoch, "jobs.epoch")?,
        offer_count: u32_col(raw.offer_count, "jobs.offer_count")?,
        last_lost_node_id: raw
            .last_lost_node_id
            .map(|n| parse_col(&n, "jobs.last_lost_node_id"))
            .transpose()?,
        request: Request {
            cpu_milli: crate::scheduler::fit::cpu_milli(raw.cpu.unwrap_or(0.0)),
            memory_mb: u64_col(raw.memory_mb.unwrap_or(0), "jobs.spec_view.resources.memory_mb")?,
            disk_mb: u64_col(raw.disk_mb.unwrap_or(0), "jobs.spec_view.resources.disk_mb")?,
            gpu: u32_col(raw.gpu.unwrap_or(0), "jobs.spec_view.resources.gpu")?,
            pools: placement.pools,
            labels: placement.labels,
            node_id: placement.node_id,
        },
        timeout_s: u32_col(raw.timeout_s.unwrap_or(0), "jobs.spec_view.timeout_s")?,
        position: QueuePosition {
            created_at: raw.created_at,
            job_id: raw.job_id,
        },
    })
}

/// Queued jobs that have no active lease and are under the offer cap, FIFO by `(created_at, job_id)`, strictly after
/// `after` when given, at most `limit` of them.
pub async fn queued_page(
    conn: &mut Conn,
    offer_cap: u32,
    after: Option<&QueuePosition>,
    limit: u32,
) -> Result<Vec<QueuedJob>, StoreError> {
    let rows: Vec<RawQueued> = sqlx::query_as(select_queued!(
        "AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND job_id > ?3)) \
         ORDER BY created_at, job_id LIMIT ?4"
    ))
    .bind(i64::from(offer_cap))
    .bind(after.map(|p| p.created_at))
    .bind(after.map(|p| p.job_id.as_str()))
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode_queued).collect()
}

/// Every (job, node) pair that is cooling down at `now` (§8 "Offer cap"), for placement's read-only pre-pass.
pub async fn cooling_pairs(
    conn: &mut Conn,
    now: OffsetDateTime,
) -> Result<std::collections::HashSet<(JobId, NodeId)>, StoreError> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT job_id, node_id FROM job_node_cooldowns WHERE until > ?")
        .bind(ts(now))
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|(j, n)| {
            Ok((
                parse_col(j, "job_node_cooldowns.job_id")?,
                parse_col(n, "job_node_cooldowns.node_id")?,
            ))
        })
        .collect()
}

/// One job, if it is still queued with no active lease and under the offer cap (placement re-reads it inside its
/// transaction).
pub async fn queued_one(conn: &mut Conn, job_id: JobId, offer_cap: u32) -> Result<Option<QueuedJob>, StoreError> {
    let raw: Option<RawQueued> = sqlx::query_as(select_queued!("AND job_id = ?2"))
        .bind(i64::from(offer_cap))
        .bind(job_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode_queued).transpose()
}

/// Issues the next epoch of a job, if its last one is still `expected` (a concurrent placement makes this fail).
pub async fn bump_epoch(conn: &mut Conn, job_id: JobId, expected: u64) -> Result<bool, StoreError> {
    let n = sqlx::query("UPDATE jobs SET epoch = epoch + 1 WHERE job_id = ? AND epoch = ?")
        .bind(job_id.to_string())
        .bind(epoch_col(expected)?)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n == 1)
}

/// §8 "Offer cap" (amended 2026-11-05): an eligible node of `account_id` changed (it connected or reconnected, sent
/// an `InventoryUpdate`, was resumed, or joined). Every queued job of the account gets a fresh offer budget and loses
/// its cap reason (the only `reason` a queued job carries), so a job is never stuck once the node it waited for is
/// ready. One statement: one atomic step. Returns how many jobs were re-armed. Only this account's jobs change.
pub async fn rearm_offers(conn: &mut Conn, account_id: AccountId) -> Result<u64, StoreError> {
    Ok(sqlx::query(
        "UPDATE jobs SET offer_count = 0, reason = NULL \
         WHERE account_id = ? AND status = 'queued' AND offer_count > 0",
    )
    .bind(account_id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected())
}

/// Counts one failed offer and returns the new count.
pub async fn count_failed_offer(conn: &mut Conn, job_id: JobId) -> Result<u32, StoreError> {
    let n: i64 =
        sqlx::query_scalar("UPDATE jobs SET offer_count = offer_count + 1 WHERE job_id = ? RETURNING offer_count")
            .bind(job_id.to_string())
            .fetch_one(&mut *conn)
            .await?;
    u32_col(n, "jobs.offer_count")
}

/// Sets the user-visible `reason` (after the transition, which clears it). A terminal job keeps its own (T06 review:
/// an offer that expires after a cancel must not write the offer cap's reason onto the cancelled job).
pub async fn set_reason(conn: &mut Conn, job_id: JobId, reason: Option<&str>) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE jobs SET reason = ? WHERE job_id = ? \
         AND status NOT IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost')",
    )
    .bind(reason)
    .bind(job_id.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Records the node of the current attempt.
pub async fn set_node(conn: &mut Conn, job_id: JobId, node_id: NodeId) -> Result<(), StoreError> {
    sqlx::query("UPDATE jobs SET node_id = ? WHERE job_id = ?")
        .bind(node_id.to_string())
        .bind(job_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// After node loss with attempts left: the next attempt, avoiding the node that lost it, with a fresh offer budget
/// (§8 "Offer cap": a new attempt starts its count over).
pub async fn next_attempt(conn: &mut Conn, job_id: JobId, lost_on: NodeId) -> Result<(), StoreError> {
    sqlx::query("UPDATE jobs SET attempt = attempt + 1, last_lost_node_id = ?, offer_count = 0 WHERE job_id = ?")
        .bind(lost_on.to_string())
        .bind(job_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Records how the attempt ended, as the agent reported it.
pub async fn set_result(
    conn: &mut Conn,
    job_id: JobId,
    outcome: &str,
    exit_code: Option<i32>,
    error: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE jobs SET outcome = ?, exit_code = ?, error = ? WHERE job_id = ?")
        .bind(outcome)
        .bind(exit_code)
        .bind(error)
        .bind(job_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The key that submitted a job (for the ledger).
pub async fn job_key(conn: &mut Conn, job_id: JobId) -> Result<KeyId, StoreError> {
    let key: String = sqlx::query_scalar("SELECT key_id FROM jobs WHERE job_id = ?")
        .bind(job_id.to_string())
        .fetch_one(&mut *conn)
        .await?;
    parse_col(&key, "jobs.key_id")
}

// --- Usage ledger -------------------------------------------------------------------------------------------------

/// Appends one usage record (one finished attempt).
pub async fn insert_usage(conn: &mut Conn, lease_id: LeaseId, rec: &UsageRecord) -> Result<(), StoreError> {
    let int = |v: u64, c: &'static str| i64::try_from(v).map_err(|_| StoreError::Corrupt(c));
    sqlx::query(
        "INSERT INTO usage_records (job_id, attempt, lease_id, node_id, key_id, account_id, project_id, started_at, \
         ended_at, reserved_cpu_ms, reserved_gpu_ms, used_cpu_ms, max_rss_mb, units, estimated) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(rec.job_id.to_string())
    .bind(i64::from(rec.attempt))
    .bind(lease_id.to_string())
    .bind(rec.node_id.to_string())
    .bind(rec.key_id.to_string())
    .bind(rec.account_id.to_string())
    .bind(rec.project_id.to_string())
    .bind(ts(rec.started_at))
    .bind(ts(rec.ended_at))
    .bind(int(rec.reserved_cpu_ms, "usage_records.reserved_cpu_ms")?)
    .bind(int(rec.reserved_gpu_ms, "usage_records.reserved_gpu_ms")?)
    .bind(int(rec.used_cpu_ms, "usage_records.used_cpu_ms")?)
    .bind(int(rec.max_rss_mb, "usage_records.max_rss_mb")?)
    .bind(int(rec.units.milli(), "usage_records.units")?)
    .bind(rec.estimated)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// What a key spent on jobs created in `[from, to)` (Unix seconds), in milli-units. Every attempt that ended has a
/// usage row (reported, or estimated by the server when it ended with no report, §11), so per job:
/// - a terminal job counts its usage rows; with none, nothing if it was cancelled before it ever ran, and its
///   reservation otherwise;
/// - a job still queued or running counts the rows of its ended attempts **plus** its reservation, which the current
///   or next attempt may still use.
///
/// So the cap and `GET /v1/usage` count the same units for every attempt that ended.
pub async fn spent_between(
    conn: &mut Conn,
    account_id: AccountId,
    key_id: KeyId,
    from: i64,
    to: i64,
) -> Result<u64, StoreError> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(CASE \
             WHEN status IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost') THEN \
                 CASE \
                     WHEN EXISTS (SELECT 1 FROM usage_records u WHERE u.job_id = jobs.job_id) \
                         THEN (SELECT SUM(u.units) FROM usage_records u WHERE u.job_id = jobs.job_id) \
                     WHEN status = 'cancelled' AND NOT EXISTS \
                          (SELECT 1 FROM job_events e WHERE e.job_id = jobs.job_id AND e.to_status = 'running') THEN 0 \
                     ELSE units_reserved END \
             ELSE units_reserved \
                  + COALESCE((SELECT SUM(u.units) FROM usage_records u WHERE u.job_id = jobs.job_id), 0) \
             END), 0) \
         FROM jobs WHERE account_id = ?1 AND key_id = ?2 AND created_at >= ?3 AND created_at < ?4",
    )
    .bind(account_id.to_string())
    .bind(key_id.to_string())
    .bind(from)
    .bind(to)
    .fetch_one(&mut *conn)
    .await?;
    u64_col(total, "usage_records.units")
}

/// Totals of a group of usage records.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageTotalsRow {
    /// The group key (a job, node or key ID); empty for the grand total.
    pub key: String,
    /// Finished attempts.
    pub attempts: u64,
    /// Reserved vCPU-milliseconds.
    pub reserved_cpu_ms: u64,
    /// Reserved GPU-milliseconds.
    pub reserved_gpu_ms: u64,
    /// Used CPU milliseconds.
    pub used_cpu_ms: u64,
    /// Highest peak memory.
    pub max_rss_mb: u64,
    /// Milli-units.
    pub units: Units,
    /// How many of the attempts are server estimates.
    pub estimated_attempts: u64,
}

type TotalsRaw = (String, i64, i64, i64, i64, i64, i64, i64);

fn decode_totals(r: TotalsRaw) -> Result<UsageTotalsRow, StoreError> {
    let c = "usage_records";
    Ok(UsageTotalsRow {
        key: r.0,
        attempts: u64_col(r.1, c)?,
        reserved_cpu_ms: u64_col(r.2, c)?,
        reserved_gpu_ms: u64_col(r.3, c)?,
        used_cpu_ms: u64_col(r.4, c)?,
        max_rss_mb: u64_col(r.5, c)?,
        units: Units::from_milli(u64_col(r.6, c)?),
        estimated_attempts: u64_col(r.7, c)?,
    })
}

/// What [`usage_report`] reports.
#[derive(Debug, Clone, Copy)]
pub struct UsageQuery<'a> {
    /// Start of the range of `ended_at` (inclusive).
    pub from: OffsetDateTime,
    /// End of the range (exclusive).
    pub to: OffsetDateTime,
    /// The grouping.
    pub group_by: UsageGroupBy,
    /// The last group key of the previous page.
    pub after: Option<&'a str>,
    /// Most groups.
    pub limit: u32,
}

/// `GET /v1/usage`: the records of the principal's account and project that ended in `[from, to)`, grouped, ordered
/// by group key, after `after`, at most `limit` groups; and the grand total of the whole range.
pub async fn usage_report(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    q: &UsageQuery<'_>,
) -> Result<(Vec<UsageTotalsRow>, UsageTotalsRow), StoreError> {
    let UsageQuery {
        from,
        to,
        group_by,
        after,
        limit,
    } = *q;
    let group = match group_by {
        UsageGroupBy::Job => "job",
        UsageGroupBy::Node => "node",
        UsageGroupBy::Key => "key",
    };
    let rows: Vec<TotalsRaw> = sqlx::query_as(
        "SELECT g, COUNT(*), SUM(reserved_cpu_ms), SUM(reserved_gpu_ms), SUM(used_cpu_ms), MAX(max_rss_mb), \
                SUM(units), SUM(estimated) \
         FROM (SELECT CASE ?5 WHEN 'job' THEN job_id WHEN 'node' THEN node_id ELSE key_id END AS g, \
                      reserved_cpu_ms, reserved_gpu_ms, used_cpu_ms, max_rss_mb, units, estimated \
               FROM usage_records \
               WHERE account_id = ?1 AND project_id = ?2 AND ended_at >= ?3 AND ended_at < ?4) \
         WHERE ?6 IS NULL OR g > ?6 \
         GROUP BY g ORDER BY g LIMIT ?7",
    )
    .bind(account_id.to_string())
    .bind(project_id.to_string())
    .bind(ts(from))
    .bind(ts(to))
    .bind(group)
    .bind(after)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    let total: TotalsRaw = sqlx::query_as(
        "SELECT '', COUNT(*), COALESCE(SUM(reserved_cpu_ms), 0), COALESCE(SUM(reserved_gpu_ms), 0), \
                COALESCE(SUM(used_cpu_ms), 0), COALESCE(MAX(max_rss_mb), 0), COALESCE(SUM(units), 0), \
                COALESCE(SUM(estimated), 0) \
         FROM usage_records WHERE account_id = ?1 AND project_id = ?2 AND ended_at >= ?3 AND ended_at < ?4",
    )
    .bind(account_id.to_string())
    .bind(project_id.to_string())
    .bind(ts(from))
    .bind(ts(to))
    .fetch_one(&mut *conn)
    .await?;
    let rows = rows.into_iter().map(decode_totals).collect::<Result<Vec<_>, _>>()?;
    Ok((rows, decode_totals(total)?))
}
