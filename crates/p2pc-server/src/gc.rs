// SPDX-License-Identifier: AGPL-3.0-only

//! The GC of logs and artifacts (spec §12). Every [`INTERVAL`], one bounded pass:
//!
//! - the logs (`<data>/logs/<job_id>/`) and artifacts (`<data>/artifacts/<job_id>/`) of terminal jobs that finished
//!   more than `[storage] retention_days` ago (default 7). The job and its rows stay; its outputs then show
//!   `expired: true` and their downloads answer `410`;
//! - the staging (`.staging`, `.incoming`) of an attempt that never finalised, an hour after its lease ended (a lease
//!   lost or cancelled before `JobFinished` loses its staged files), and of a finalised attempt whose staging could
//!   not be removed at finalisation. An attempt whose finalisation began and never ended (`finalizing_at` set: a crash,
//!   or a failed fsync that the scheduler does not retry) is finished instead of discarded: the files already moved
//!   into `files/` are published ([`crate::outputs::OutputStore::finish_interrupted`]).
//!
//! **Records.** A job's expiry is recorded first (`artifact_gc.expired_at`), so the API shows its outputs expired from
//! then on and never serves a file that is being deleted. Its `removed_at` is set only **after** the directories are
//! gone; a row where it is still NULL (a failed deletion, a crash) is deleted again by the next pass. A staging
//! directory is recorded removed (`output_attempts.staging_removed_at`, its staged rows dropped) only after it is
//! gone, and retried otherwise. A row whose deletion fails is stamped (`last_attempt_at`) and the queues are ordered
//! by it, rows never tried first: a few undeletable directories go to the back instead of using every pass's limit.
//! Each pass handles at most `limit` jobs and `limit` attempts, and deletion never follows
//! a symbolic link ([`crate::fsutil::remove_tree`], which resolves no link even in front of the directory). Time comes from the state's clock.

use std::time::Duration;

use tokio::task::JoinHandle;

use p2pc_proto::ids::JobId;

use crate::app::AppState;
use crate::store::{self, StoreError, outputs};

/// How often the GC runs.
pub const INTERVAL: Duration = Duration::from_secs(600);
/// Staging that never finalised is kept this long after its lease ended.
pub const STAGING_GRACE: time::Duration = time::Duration::hours(1);
/// Jobs, and attempts, one pass handles at most.
pub const PASS_LIMIT: u32 = 100;

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Jobs whose logs and artifacts were deleted.
    pub jobs_expired: usize,
    /// Staging directories deleted.
    pub staging_removed: usize,
    /// Steps that failed (logged); the next pass retries them.
    pub errors: usize,
}

/// Runs the GC every [`INTERVAL`] until the handle is aborted.
#[must_use]
pub fn spawn(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let r = run_pass(&state, PASS_LIMIT).await;
            if r != GcReport::default() {
                tracing::info!(
                    jobs_expired = r.jobs_expired,
                    staging_removed = r.staging_removed,
                    errors = r.errors,
                    "storage GC pass"
                );
            }
        }
    })
}

/// One pass, at most `limit` jobs and `limit` staging directories.
pub async fn run_pass(state: &AppState, limit: u32) -> GcReport {
    let mut r = GcReport::default();
    let now = state.clock.now();
    match expire_jobs(state, now, limit, &mut r).await {
        Ok(()) => {}
        Err(e) => {
            r.errors += 1;
            tracing::warn!(error = %e, "GC: cannot list expired jobs");
        }
    }
    match remove_staging(state, now, limit, &mut r).await {
        Ok(()) => {}
        Err(e) => {
            r.errors += 1;
            tracing::warn!(error = %e, "GC: cannot list abandoned staging");
        }
    }
    r
}

async fn expire_jobs(
    state: &AppState,
    now: time::OffsetDateTime,
    limit: u32,
    r: &mut GcReport,
) -> Result<(), StoreError> {
    let cutoff = now - state.config.storage.retention();
    let due = {
        let mut conn = state.db.acquire().await?;
        outputs::expirable_jobs(&mut conn, cutoff, limit).await?
    };
    for job_id in due {
        let recorded = transaction(state, |tx| Box::pin(outputs::record_expired(tx, job_id, now))).await;
        if let Err(e) = recorded {
            r.errors += 1;
            tracing::warn!(error = %e, %job_id, "GC: cannot record an expired job");
        }
    }
    // What is recorded and not deleted yet: the jobs just recorded, and any whose deletion failed before.
    let pending = {
        let mut conn = state.db.acquire().await?;
        outputs::pending_removals(&mut conn, limit).await?
    };
    for job_id in pending {
        let (logs, outputs) = (state.logs.clone(), state.outputs.clone());
        let removed = remove(move || {
            // Both are tried; the first error is the answer.
            let logs = logs.remove_job(job_id);
            outputs.remove_job(job_id).and(logs).map(|_| ())
        })
        .await;
        if !removed {
            r.errors += 1;
            // To the back of the queue: the rows behind it get their turn.
            let noted = transaction(state, |tx| Box::pin(outputs::record_removal_failed(tx, job_id, now))).await;
            if let Err(e) = noted {
                tracing::warn!(error = %e, %job_id, "GC: cannot note a failed deletion");
            }
            continue;
        }
        match transaction(state, |tx| Box::pin(outputs::record_removed(tx, job_id, now))).await {
            Ok(()) => r.jobs_expired += 1,
            Err(e) => {
                r.errors += 1;
                tracing::warn!(error = %e, %job_id, "GC: cannot record a removal; the next pass retries it");
            }
        }
    }
    Ok(())
}

async fn remove_staging(
    state: &AppState,
    now: time::OffsetDateTime,
    limit: u32,
    r: &mut GcReport,
) -> Result<(), StoreError> {
    let due = {
        let mut conn = state.db.acquire().await?;
        outputs::abandoned_staging(&mut conn, now - STAGING_GRACE, limit).await?
    };
    for (job_id, attempt) in due {
        // A finalisation that began and never ended (a crash, a failed fsync): finish it rather than discard what it
        // had already moved into `files/`.
        match state.outputs.is_interrupted(job_id, attempt).await {
            Ok(true) => {
                match state.outputs.finish_interrupted(job_id, attempt).await {
                    Ok(()) => r.staging_removed += 1,
                    Err(e) => {
                        r.errors += 1;
                        tracing::warn!(error = %e, %job_id, attempt, "GC: cannot finish an interrupted finalisation");
                        note_staging_failed(state, job_id, attempt, now).await;
                    }
                }
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                r.errors += 1;
                tracing::warn!(error = %e, %job_id, attempt, "GC: cannot read an attempt's finalisation state");
                continue;
            }
        }
        let outputs = state.outputs.clone();
        if !remove(move || outputs.remove_staging(job_id, attempt)).await {
            r.errors += 1;
            note_staging_failed(state, job_id, attempt, now).await;
            continue;
        }
        let recorded = transaction(state, |tx| {
            Box::pin(outputs::record_staging_removed(tx, job_id, attempt, now))
        })
        .await;
        match recorded {
            Ok(()) => r.staging_removed += 1,
            Err(e) => {
                r.errors += 1;
                tracing::warn!(error = %e, %job_id, attempt, "GC: cannot record a staging removal");
            }
        }
    }
    Ok(())
}

/// Sends the attempt to the back of the staging queue.
async fn note_staging_failed(state: &AppState, job_id: JobId, attempt: u32, now: time::OffsetDateTime) {
    let noted = transaction(state, |tx| {
        Box::pin(outputs::record_staging_failed(tx, job_id, attempt, now))
    })
    .await;
    if let Err(e) = noted {
        tracing::warn!(error = %e, %job_id, attempt, "GC: cannot note a failed removal");
    }
}

/// Runs `f` in a `BEGIN IMMEDIATE` transaction and commits it.
async fn transaction<F>(state: &AppState, f: F) -> Result<(), StoreError>
where
    F: for<'c> FnOnce(&'c mut store::Conn) -> crate::gateway::BoxFuture<'c, Result<(), StoreError>>,
{
    let mut tx = store::begin_immediate(&state.db).await?;
    f(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Runs a removal (which follows no link) on the blocking pool. Whether it all went.
async fn remove(removal: impl FnOnce() -> std::io::Result<()> + Send + 'static) -> bool {
    let result = tokio::task::spawn_blocking(removal)
        .await
        .map_err(std::io::Error::other)
        .and_then(|r| r);
    match result {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "GC: cannot delete a directory");
            false
        }
    }
}
