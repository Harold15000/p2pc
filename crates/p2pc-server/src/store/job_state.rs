// SPDX-License-Identifier: AGPL-3.0-only

//! The job state machine (spec §7 "Job states").
//!
//! [`transition`] is the **only** code that writes `jobs.status`. It refuses every move that
//! [`p2pc_proto::api::transition_allowed`] does not allow, so terminal states are immutable and no job skips a state,
//! and it appends one `job_events` row (`job_id`, `at`, `from`, `to`, `reason`) in the same atomic step. The events
//! are append-only: the usage ledger (T15) and debugging read them.
//!
//! `tests/status_writes.rs` scans the crate's SQL and fails if anything else writes `jobs.status`.
//!
//! This is a crate-internal API: T06 (the scheduler) and T10 (the node gateway) call it from inside their own
//! `BEGIN IMMEDIATE` transactions, for placement, `JobStarted`, `JobFinished`, node loss and the watchdog.
//!
//! Besides the status, a transition sets the timestamps that belong to it, and clears `reason`:
//! - `→ running`: `started_at = now` (the start of the current attempt); `→ queued` (a requeue): `started_at` is
//!   cleared, because no attempt is running;
//! - `→` a terminal state: `finished_at = now`;
//! - `jobs.reason`, the user-visible explanation of the *previous* state (for example "10 offers failed"), is cleared.
//!   The caller sets it again if it has something to say about the new state.
//!
//! What a transition does **not** do: it does not change `attempt`, `node_id`, `exit_code`, `outcome` or `error`. T06
//! writes those next to the transition, in the same transaction (a requeue after node loss adds one to `attempt`,
//! but a lease that was not accepted does not, so only the scheduler knows).

use p2pc_proto::api::{JobStatus, transition_allowed};
use p2pc_proto::ids::JobId;
use time::OffsetDateTime;

use super::jobs::{self, JobRow};
use super::{Conn, StoreError, ts};

/// Longest `reason` of an event, in bytes (the column's CHECK).
pub const MAX_REASON_LEN: usize = 256;

/// Why a transition was refused.
#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    /// `transition_allowed(from, to)` is false: a bug in the caller, never the client's fault. It is an internal
    /// error (`500`), and nothing was changed.
    #[error("illegal job transition {from} -> {to}")]
    Illegal {
        /// The job's current state.
        from: JobStatus,
        /// The refused target.
        to: JobStatus,
    },
    /// The job is no longer in the state the caller read it in (another transaction moved it): reload and decide
    /// again. Nothing was changed.
    #[error("job is no longer {expected}")]
    Stale {
        /// The state the caller thought the job was in.
        expected: JobStatus,
    },
    /// The event reason is empty or longer than [`MAX_REASON_LEN`].
    #[error("a transition reason must be 1-{MAX_REASON_LEN} bytes")]
    InvalidReason,
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for TransitionError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::from(e).into()
    }
}

/// Moves `job` to `to` and records the event. Returns the job as stored afterwards.
///
/// `job` must be the row as the caller just read it, inside the same write transaction: the update only applies if
/// the job is still in `job.status` ([`TransitionError::Stale`] otherwise). `reason` is a stable machine-readable
/// code (`placed`, `cancelled_by_user`, `node_lost`, …), never a secret; it goes to the event.
///
/// The status update and the event are one atomic step (a savepoint inside the caller's transaction).
pub(crate) async fn transition(
    conn: &mut Conn,
    job: &JobRow,
    to: JobStatus,
    reason: &str,
    now: OffsetDateTime,
) -> Result<JobRow, TransitionError> {
    let from = job.status;
    if !transition_allowed(from, to) {
        return Err(TransitionError::Illegal { from, to });
    }
    if reason.is_empty() || reason.len() > MAX_REASON_LEN {
        return Err(TransitionError::InvalidReason);
    }
    let mut step = sqlx::Connection::begin(&mut *conn).await?;
    let changed = sqlx::query(
        "UPDATE jobs SET status = ?1, updated_at = ?2, reason = NULL, \
             started_at = CASE WHEN ?1 = 'running' THEN ?2 WHEN ?1 = 'queued' THEN NULL ELSE started_at END, \
             finished_at = CASE WHEN ?1 IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost') \
                                THEN ?2 ELSE finished_at END \
         WHERE job_id = ?3 AND account_id = ?4 AND project_id = ?5 AND status = ?6",
    )
    .bind(to.as_str())
    .bind(ts(now))
    .bind(job.job_id.to_string())
    .bind(job.account_id.to_string())
    .bind(job.project_id.to_string())
    .bind(from.as_str())
    .execute(&mut *step)
    .await?
    .rows_affected();
    if changed != 1 {
        // Dropping the savepoint rolls it back.
        return Err(TransitionError::Stale { expected: from });
    }
    append_event(&mut step, job.job_id, now, Some(from), to, reason).await?;
    step.commit().await?;
    jobs::get(conn, job.account_id, job.project_id, job.job_id)
        .await?
        .ok_or(TransitionError::Store(StoreError::Corrupt("jobs")))
}

/// The first event of a job: created `queued` (`from_status` NULL, reason `created`). Called by [`jobs::insert`].
pub(super) async fn record_creation(conn: &mut Conn, job_id: JobId, now: OffsetDateTime) -> Result<(), StoreError> {
    append_event(conn, job_id, now, None, JobStatus::Queued, "created").await
}

async fn append_event(
    conn: &mut Conn,
    job_id: JobId,
    at: OffsetDateTime,
    from: Option<JobStatus>,
    to: JobStatus,
    reason: &str,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO job_events (job_id, at, from_status, to_status, reason) VALUES (?, ?, ?, ?, ?)")
        .bind(job_id.to_string())
        .bind(ts(at))
        .bind(from.map(JobStatus::as_str))
        .bind(to.as_str())
        .bind(reason)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// One recorded status change, as read back by [`events`].
// Crate-private since T06 and read only by tests for now; the usage ledger tooling (T15) and debugging read it.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobEvent {
    /// When it happened.
    pub at: OffsetDateTime,
    /// The previous state; `None` for the creation.
    pub from: Option<JobStatus>,
    /// The new state.
    pub to: JobStatus,
    /// The machine-readable reason.
    pub reason: String,
}

/// The history of a job of `account_id` and `project_id`, oldest first (SI-7: filtered by both, like every job read).
#[cfg_attr(not(test), allow(dead_code))]
pub async fn events(
    conn: &mut Conn,
    account_id: p2pc_proto::ids::AccountId,
    project_id: p2pc_proto::ids::ProjectId,
    job_id: JobId,
) -> Result<Vec<JobEvent>, StoreError> {
    let rows: Vec<(i64, Option<String>, String, String)> = sqlx::query_as(
        "SELECT e.at, e.from_status, e.to_status, e.reason FROM job_events e \
         JOIN jobs j ON j.job_id = e.job_id \
         WHERE j.account_id = ? AND j.project_id = ? AND e.job_id = ? ORDER BY e.seq",
    )
    .bind(account_id.to_string())
    .bind(project_id.to_string())
    .bind(job_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    let status = |s: &str| {
        JobStatus::ALL
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or(StoreError::Corrupt("job_events.status"))
    };
    rows.into_iter()
        .map(|(at, from, to, reason)| {
            Ok(JobEvent {
                at: super::from_ts(at, "job_events.at")?,
                from: from.as_deref().map(status).transpose()?,
                to: status(&to)?,
                reason,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use p2pc_proto::api::{JobSpec, Scope};
    use p2pc_proto::auth::ApiKey;
    use p2pc_proto::ids::{AccountId, KeyId, ProjectId};
    use p2pc_proto::units::Units;
    use time::macros::datetime;

    use super::*;
    use crate::store::jobs::NewJob;
    use crate::store::keys::NewKey;
    use crate::store::{Db, OpenMode, accounts, keys, open};

    const T0: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);

    struct Fixture {
        _dir: tempfile::TempDir,
        db: Db,
        account: AccountId,
        project: ProjectId,
        key: KeyId,
    }

    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = open(&dir.path().join("t.db"), OpenMode::Create).await.unwrap();
        let mut conn = db.acquire().await.unwrap();
        let (account, project) = accounts::create_owner(&mut conn, T0).await.unwrap();
        let api_key = ApiKey::generate();
        let new = NewKey {
            key_id: api_key.key_id(),
            project_id: project,
            digest: api_key.hash(),
            scopes: vec![Scope::Admin],
            daily_unit_cap: None,
            allowed_images: None,
            label: None,
            expires_at: None,
        };
        keys::insert(&mut conn, account, &new, T0).await.unwrap();
        drop(conn);
        Fixture {
            _dir: dir,
            db,
            account,
            project,
            key: api_key.key_id(),
        }
    }

    fn spec() -> JobSpec {
        serde_json::from_value(serde_json::json!({
            "image": "docker.io/library/python:3.12-slim",
            "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 512},
        }))
        .unwrap()
    }

    async fn new_job(f: &Fixture) -> JobRow {
        let mut conn = f.db.acquire().await.unwrap();
        let job = NewJob {
            job_id: JobId::generate(),
            account_id: f.account,
            project_id: f.project,
            principal: p2pc_proto::api::Principal::Key(f.key),
            spec: spec(),
            files_meta: vec![],
            spec_hash: format!("sha256:{}", "0".repeat(64)),
            units_reserved: Units::from_milli(1000),
        };
        jobs::insert(&mut conn, &job, T0).await.unwrap()
    }

    /// Puts a job in `status` behind the state machine's back, as a test fixture (a `queued` job may be forced to
    /// anything; the terminal-immutability trigger only guards leaving a terminal state).
    async fn force(f: &Fixture, job: &JobRow, status: JobStatus) -> JobRow {
        sqlx::query("UPDATE jobs SET status = ? WHERE job_id = ?")
            .bind(status.as_str())
            .bind(job.job_id.to_string())
            .execute(&f.db)
            .await
            .unwrap();
        let mut conn = f.db.acquire().await.unwrap();
        jobs::get(&mut conn, f.account, f.project, job.job_id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn current(f: &Fixture, job: &JobRow) -> JobRow {
        let mut conn = f.db.acquire().await.unwrap();
        jobs::get(&mut conn, f.account, f.project, job.job_id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn history(f: &Fixture, job: &JobRow) -> Vec<JobEvent> {
        let mut conn = f.db.acquire().await.unwrap();
        events(&mut conn, f.account, f.project, job.job_id).await.unwrap()
    }

    /// The legal moves of spec §7, written out by hand so that a change to the table in `p2pc-proto` cannot pass
    /// unnoticed.
    fn legal_pairs() -> BTreeSet<(JobStatus, JobStatus)> {
        use JobStatus::*;
        [
            (Queued, Assigned),
            (Queued, Cancelled),
            (Assigned, Running),
            (Assigned, Queued),
            (Assigned, Lost),
            (Assigned, Failed),
            (Assigned, TimedOut),
            (Assigned, Cancelled),
            (Running, Succeeded),
            (Running, Failed),
            (Running, TimedOut),
            (Running, Cancelled),
            (Running, Lost),
            (Running, Queued),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn the_proto_table_is_the_one_of_the_spec() {
        let table: BTreeSet<_> = JobStatus::ALL
            .into_iter()
            .flat_map(|a| JobStatus::ALL.into_iter().map(move |b| (a, b)))
            .filter(|(a, b)| transition_allowed(*a, *b))
            .collect();
        assert_eq!(table, legal_pairs());
    }

    #[tokio::test]
    async fn every_pair_is_allowed_or_refused_as_the_table_says() {
        let f = fixture().await;
        let legal = legal_pairs();
        for from in JobStatus::ALL {
            for to in JobStatus::ALL {
                let job = force(&f, &new_job(&f).await, from).await;
                let before = history(&f, &job).await;
                let now = T0 + time::Duration::seconds(7);
                let result = transition(&mut f.db.acquire().await.unwrap(), &job, to, "test", now).await;
                if legal.contains(&(from, to)) {
                    let moved = result.unwrap_or_else(|e| panic!("{from} -> {to}: {e}"));
                    assert_eq!(moved.status, to, "{from} -> {to}");
                    assert_eq!(moved.updated_at, now);
                    let after = history(&f, &job).await;
                    assert_eq!(after.len(), before.len() + 1, "{from} -> {to}");
                    assert_eq!(
                        after.last().unwrap(),
                        &JobEvent {
                            at: now,
                            from: Some(from),
                            to,
                            reason: "test".to_string()
                        }
                    );
                } else {
                    // Illegal (including staying in the same state, and anything out of a terminal state): an
                    // internal error, and nothing changed, not even an event.
                    assert!(
                        matches!(result, Err(TransitionError::Illegal { from: a, to: b }) if a == from && b == to),
                        "{from} -> {to}: {result:?}"
                    );
                    assert_eq!(current(&f, &job).await, job, "{from} -> {to}");
                    assert_eq!(history(&f, &job).await, before, "{from} -> {to}");
                }
            }
        }
    }

    #[tokio::test]
    async fn terminal_states_are_immutable_even_around_the_state_machine() {
        let f = fixture().await;
        for terminal in JobStatus::ALL.into_iter().filter(|s| s.is_terminal()) {
            let job = force(&f, &new_job(&f).await, terminal).await;
            for to in JobStatus::ALL {
                let r = transition(&mut f.db.acquire().await.unwrap(), &job, to, "x", T0).await;
                assert!(matches!(r, Err(TransitionError::Illegal { .. })), "{terminal} -> {to}");
            }
            // The database refuses it too: a raw UPDATE cannot leave a terminal state either.
            for to in JobStatus::ALL {
                let raw = sqlx::query("UPDATE jobs SET status = ? WHERE job_id = ?")
                    .bind(to.as_str())
                    .bind(job.job_id.to_string())
                    .execute(&f.db)
                    .await;
                if to == terminal {
                    assert!(raw.is_ok(), "rewriting the same state is not a change");
                } else {
                    let err = raw.unwrap_err().to_string();
                    assert!(err.contains("immutable"), "{terminal} -> {to}: {err}");
                }
            }
            assert_eq!(current(&f, &job).await.status, terminal);
        }
    }

    #[tokio::test]
    async fn a_walk_through_the_states_records_every_event_in_order() {
        let f = fixture().await;
        let job = new_job(&f).await;
        let mut conn = f.db.acquire().await.unwrap();
        let t = |s: i64| T0 + time::Duration::seconds(s);

        let assigned = transition(&mut conn, &job, JobStatus::Assigned, "placed", t(1))
            .await
            .unwrap();
        assert_eq!((assigned.started_at, assigned.finished_at), (None, None));
        let running = transition(&mut conn, &assigned, JobStatus::Running, "job_started", t(2))
            .await
            .unwrap();
        assert_eq!(running.started_at, Some(t(2)));
        // Node loss with attempts left: back to the queue; no attempt is running any more.
        let requeued = transition(&mut conn, &running, JobStatus::Queued, "node_lost", t(3))
            .await
            .unwrap();
        assert_eq!((requeued.started_at, requeued.finished_at), (None, None));
        let again = transition(&mut conn, &requeued, JobStatus::Assigned, "placed", t(4))
            .await
            .unwrap();
        let running = transition(&mut conn, &again, JobStatus::Running, "job_started", t(5))
            .await
            .unwrap();
        let done = transition(&mut conn, &running, JobStatus::Succeeded, "exited_0", t(6))
            .await
            .unwrap();
        assert_eq!(done.status, JobStatus::Succeeded);
        assert_eq!((done.started_at, done.finished_at), (Some(t(5)), Some(t(6))));
        drop(conn);

        let ev: Vec<_> = history(&f, &job)
            .await
            .into_iter()
            .map(|e| (e.at, e.from, e.to, e.reason))
            .collect();
        use JobStatus::*;
        let step = |s: i64, from, to, reason: &str| (t(s), from, to, reason.to_string());
        assert_eq!(
            ev,
            [
                (T0, None, Queued, "created".to_string()),
                step(1, Some(Queued), Assigned, "placed"),
                step(2, Some(Assigned), Running, "job_started"),
                step(3, Some(Running), Queued, "node_lost"),
                step(4, Some(Queued), Assigned, "placed"),
                step(5, Some(Assigned), Running, "job_started"),
                step(6, Some(Running), Succeeded, "exited_0"),
            ]
        );
    }

    #[tokio::test]
    async fn a_transition_clears_the_user_visible_reason_and_leaves_the_other_columns_alone() {
        let f = fixture().await;
        let job = new_job(&f).await;
        sqlx::query("UPDATE jobs SET reason = 'no node has room', node_id = ?, attempt = 2 WHERE job_id = ?")
            .bind(p2pc_proto::ids::NodeId::generate().to_string())
            .bind(job.job_id.to_string())
            .execute(&f.db)
            .await
            .unwrap();
        let job = current(&f, &job).await;
        assert!(job.reason.is_some() && job.node_id.is_some());
        let mut conn = f.db.acquire().await.unwrap();
        let moved = transition(&mut conn, &job, JobStatus::Assigned, "placed", T0)
            .await
            .unwrap();
        assert_eq!(moved.reason, None);
        assert_eq!((moved.attempt, moved.node_id), (2, job.node_id));
    }

    #[tokio::test]
    async fn a_stale_snapshot_is_refused_and_changes_nothing() {
        let f = fixture().await;
        let job = new_job(&f).await;
        let mut conn = f.db.acquire().await.unwrap();
        // Another transaction places the job first.
        transition(&mut conn, &job, JobStatus::Assigned, "placed", T0)
            .await
            .unwrap();
        // Our snapshot still says `queued`: cancelling from it must not overwrite the placement.
        let r = transition(&mut conn, &job, JobStatus::Cancelled, "cancelled_by_user", T0).await;
        assert!(
            matches!(
                r,
                Err(TransitionError::Stale {
                    expected: JobStatus::Queued
                })
            ),
            "{r:?}"
        );
        assert_eq!(current(&f, &job).await.status, JobStatus::Assigned);
        assert_eq!(history(&f, &job).await.len(), 2);
    }

    #[tokio::test]
    async fn a_reason_is_required_and_bounded() {
        let f = fixture().await;
        let job = new_job(&f).await;
        let mut conn = f.db.acquire().await.unwrap();
        for bad in ["", &"x".repeat(MAX_REASON_LEN + 1)] {
            let r = transition(&mut conn, &job, JobStatus::Assigned, bad, T0).await;
            assert!(matches!(r, Err(TransitionError::InvalidReason)), "{} bytes", bad.len());
        }
        transition(&mut conn, &job, JobStatus::Assigned, &"x".repeat(MAX_REASON_LEN), T0)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_transition_in_a_rolled_back_transaction_leaves_no_trace() {
        let f = fixture().await;
        let job = new_job(&f).await;
        let mut tx = crate::store::begin_immediate(&f.db).await.unwrap();
        transition(&mut tx, &job, JobStatus::Cancelled, "cancelled_by_user", T0)
            .await
            .unwrap();
        drop(tx);
        assert_eq!(current(&f, &job).await.status, JobStatus::Queued);
        assert_eq!(history(&f, &job).await.len(), 1);
    }

    /// T04 review carry-over: "never ran" is sticky. A job that ran, was requeued after node loss (which clears
    /// `started_at`) and was then cancelled while queued still counts against the daily cap (`units::spent_today`);
    /// one that never ran does not.
    #[tokio::test]
    async fn a_requeued_job_cancelled_while_queued_still_counts_against_the_cap() {
        let f = fixture().await;
        let day = crate::units::utc_day(T0);
        let reserved = |f: &Fixture| {
            let db = f.db.clone();
            let (account, key) = (f.account, f.key);
            async move {
                let mut c = db.acquire().await.unwrap();
                crate::store::leases::spent(&mut c, account, p2pc_proto::api::Principal::Key(key), day.0)
                    .await
                    .unwrap()
            }
        };
        let ran = new_job(&f).await;
        let never = new_job(&f).await;
        let mut conn = f.db.acquire().await.unwrap();
        let t = |s: i64| T0 + time::Duration::seconds(s);
        let j = transition(&mut conn, &ran, JobStatus::Assigned, "placed", t(1))
            .await
            .unwrap();
        let j = transition(&mut conn, &j, JobStatus::Running, "job_started", t(2))
            .await
            .unwrap();
        let j = transition(&mut conn, &j, JobStatus::Queued, "node_lost", t(3))
            .await
            .unwrap();
        assert_eq!(j.started_at, None, "a requeue clears started_at");
        transition(&mut conn, &j, JobStatus::Cancelled, "cancelled_by_user", t(4))
            .await
            .unwrap();
        transition(&mut conn, &never, JobStatus::Cancelled, "cancelled_by_user", t(4))
            .await
            .unwrap();
        drop(conn);
        assert_eq!(reserved(&f).await, 1000, "only the job that ran counts");
    }

    #[tokio::test]
    async fn job_events_are_append_only() {
        let f = fixture().await;
        let job = new_job(&f).await;
        let update = sqlx::query("UPDATE job_events SET reason = 'rewritten'")
            .execute(&f.db)
            .await;
        assert!(update.unwrap_err().to_string().contains("append-only"));
        let delete = sqlx::query("DELETE FROM job_events").execute(&f.db).await;
        assert!(delete.unwrap_err().to_string().contains("append-only"));
        assert_eq!(history(&f, &job).await.len(), 1);
    }

    #[tokio::test]
    async fn events_of_another_account_or_project_are_not_readable() {
        let f = fixture().await;
        let job = new_job(&f).await;
        let mut conn = f.db.acquire().await.unwrap();
        let other_account = AccountId::generate();
        let other_project = ProjectId::generate();
        assert!(
            events(&mut conn, other_account, f.project, job.job_id)
                .await
                .unwrap()
                .is_empty()
        );
        // The right account with another project (SI-7: both filters count).
        assert!(
            events(&mut conn, f.account, other_project, job.job_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            events(&mut conn, f.account, f.project, job.job_id).await.unwrap().len(),
            1
        );
    }
}
