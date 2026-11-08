// SPDX-License-Identifier: AGPL-3.0-only

//! Output uploads, publication and the GC's records (spec §6 "Uploads", §7, §12; T10b).
//!
//! The REST reads take the principal's `account_id` and filter by it (SI-7). The upload, finalisation and GC
//! functions run for the node authenticated by iroh (already fenced by its lease) or for the server itself, like
//! the scheduler's.

use p2pc_proto::api::{JobStatus, OutputFile, Sha256Digest};
use p2pc_proto::ids::{AccountId, JobId, LeaseId};
use time::OffsetDateTime;

use super::{Conn, StoreError, parse_col, ts};

fn file_from(path: String, size: i64, sha256: &str) -> Result<OutputFile, StoreError> {
    Ok(OutputFile {
        path,
        size: u64::try_from(size).map_err(|_| StoreError::Corrupt("outputs.size"))?,
        sha256: parse_col::<Sha256Digest>(sha256, "outputs.sha256")?,
    })
}

fn size_col(size: u64) -> Result<i64, StoreError> {
    i64::try_from(size).map_err(|_| StoreError::Corrupt("outputs.size"))
}

// --- Uploads (protocol side) ---------------------------------------------------------------------------------------

/// What is known of an attempt's uploads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttemptUploads {
    /// `JobFinished` already published the attempt, or began to ([`begin_finalizing`]): uploads are refused.
    pub finalized: bool,
    /// Bytes staged so far.
    pub staged_bytes: u64,
    /// Files staged so far.
    pub staged_files: u64,
}

/// The uploads of attempt `attempt` of `job_id` so far.
pub async fn attempt_uploads(conn: &mut Conn, job_id: JobId, attempt: u32) -> Result<AttemptUploads, StoreError> {
    let finalized: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT COALESCE(finalized_at, finalizing_at) FROM output_attempts WHERE job_id = ? AND attempt = ?",
    )
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .fetch_optional(&mut *conn)
    .await?;
    let (bytes, files): (i64, i64) =
        sqlx::query_as("SELECT COALESCE(SUM(size), 0), COUNT(*) FROM output_staging WHERE job_id = ? AND attempt = ?")
            .bind(job_id.to_string())
            .bind(i64::from(attempt))
            .fetch_one(&mut *conn)
            .await?;
    Ok(AttemptUploads {
        finalized: finalized.flatten().is_some(),
        staged_bytes: u64::try_from(bytes).map_err(|_| StoreError::Corrupt("output_staging.size"))?,
        staged_files: u64::try_from(files).unwrap_or(0),
    })
}

/// The staged file at `path`, if any.
pub async fn staged(
    conn: &mut Conn,
    job_id: JobId,
    attempt: u32,
    path: &str,
) -> Result<Option<OutputFile>, StoreError> {
    let row: Option<(String, i64, String)> =
        sqlx::query_as("SELECT path, size, sha256 FROM output_staging WHERE job_id = ? AND attempt = ? AND path = ?")
            .bind(job_id.to_string())
            .bind(i64::from(attempt))
            .bind(path)
            .fetch_optional(&mut *conn)
            .await?;
    row.map(|(p, s, h)| file_from(p, s, &h)).transpose()
}

/// Every staged file of an attempt.
pub async fn staged_files(conn: &mut Conn, job_id: JobId, attempt: u32) -> Result<Vec<OutputFile>, StoreError> {
    let rows: Vec<(String, i64, String)> =
        sqlx::query_as("SELECT path, size, sha256 FROM output_staging WHERE job_id = ? AND attempt = ? ORDER BY path")
            .bind(job_id.to_string())
            .bind(i64::from(attempt))
            .fetch_all(&mut *conn)
            .await?;
    rows.into_iter().map(|(p, s, h)| file_from(p, s, &h)).collect()
}

/// Records a verified, fsynced staged file (inside the caller's transaction, after it re-checked the lease and
/// that the attempt is not finalised).
pub async fn stage(
    conn: &mut Conn,
    job_id: JobId,
    attempt: u32,
    lease_id: LeaseId,
    file: &OutputFile,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO output_attempts (job_id, attempt, lease_id, last_upload_at) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (job_id, attempt) DO UPDATE SET last_upload_at = ?4, lease_id = COALESCE(lease_id, ?3)",
    )
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .bind(lease_id.to_string())
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO output_staging (job_id, attempt, path, size, sha256, staged_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .bind(&file.path)
    .bind(size_col(file.size)?)
    .bind(file.sha256.to_string())
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

// --- Finalisation ---------------------------------------------------------------------------------------------------

/// `Some(note)` when the attempt is already finalised (the note it left, maybe none); `None` otherwise.
pub async fn finalized_note(
    conn: &mut Conn,
    job_id: JobId,
    attempt: u32,
) -> Result<Option<Option<String>>, StoreError> {
    let row: Option<(Option<i64>, Option<String>)> =
        sqlx::query_as("SELECT finalized_at, note FROM output_attempts WHERE job_id = ? AND attempt = ?")
            .bind(job_id.to_string())
            .bind(i64::from(attempt))
            .fetch_optional(&mut *conn)
            .await?;
    Ok(match row {
        Some((Some(_), note)) => Some(note),
        _ => None,
    })
}

/// Marks the attempt as being finalised (the first of finalisation's two short transactions): from now on no upload is
/// accepted for it, so the files staged at this moment are the whole set. Idempotent: a repeat (a finalisation that
/// died before its second transaction, or a second `JobFinished`) keeps the first time.
pub async fn begin_finalizing(
    conn: &mut Conn,
    job_id: JobId,
    attempt: u32,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO output_attempts (job_id, attempt, finalizing_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT (job_id, attempt) DO UPDATE SET finalizing_at = COALESCE(finalizing_at, ?3)",
    )
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether the attempt began finalising ([`begin_finalizing`]) and `finalized_at` was never set.
pub async fn finalization_interrupted(conn: &mut Conn, job_id: JobId, attempt: u32) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM output_attempts \
         WHERE job_id = ? AND attempt = ? AND finalizing_at IS NOT NULL AND finalized_at IS NULL",
    )
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Records the publication of an attempt: its published files, its note, and (when `staging_removed`) its staging
/// gone; otherwise the GC sweeps it.
pub async fn finalize(
    conn: &mut Conn,
    job_id: JobId,
    attempt: u32,
    published: &[OutputFile],
    note: Option<&str>,
    staging_removed: bool,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    for f in published {
        sqlx::query(
            "INSERT INTO job_outputs (job_id, attempt, path, size, sha256, published_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(job_id.to_string())
        .bind(i64::from(attempt))
        .bind(&f.path)
        .bind(size_col(f.size)?)
        .bind(f.sha256.to_string())
        .bind(ts(now))
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("DELETE FROM output_staging WHERE job_id = ? AND attempt = ?")
        .bind(job_id.to_string())
        .bind(i64::from(attempt))
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO output_attempts (job_id, attempt, finalized_at, note, staging_removed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (job_id, attempt) DO UPDATE SET finalized_at = ?3, note = ?4, staging_removed_at = ?5",
    )
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .bind(ts(now))
    .bind(note)
    .bind(staging_removed.then(|| ts(now)))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

// --- REST reads (SI-7) -------------------------------------------------------------------------------------------

/// A page of the published files of an attempt of `account_id`'s job, by path, after `after`.
pub async fn published_page(
    conn: &mut Conn,
    account_id: AccountId,
    job_id: JobId,
    attempt: u32,
    after: Option<&str>,
    limit: u32,
) -> Result<Vec<OutputFile>, StoreError> {
    let rows: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT o.path, o.size, o.sha256 FROM job_outputs o JOIN jobs j ON j.job_id = o.job_id \
         WHERE j.account_id = ?1 AND o.job_id = ?2 AND o.attempt = ?3 AND (?4 IS NULL OR o.path > ?4) \
         ORDER BY o.path LIMIT ?5",
    )
    .bind(account_id.to_string())
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .bind(after)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(|(p, s, h)| file_from(p, s, &h)).collect()
}

/// One published file of an attempt of `account_id`'s job.
pub async fn published_one(
    conn: &mut Conn,
    account_id: AccountId,
    job_id: JobId,
    attempt: u32,
    path: &str,
) -> Result<Option<OutputFile>, StoreError> {
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT o.path, o.size, o.sha256 FROM job_outputs o JOIN jobs j ON j.job_id = o.job_id \
         WHERE j.account_id = ? AND o.job_id = ? AND o.attempt = ? AND o.path = ?",
    )
    .bind(account_id.to_string())
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .bind(path)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(p, s, h)| file_from(p, s, &h)).transpose()
}

/// Whether the GC removed the logs and artifacts of `account_id`'s job.
pub async fn expired(conn: &mut Conn, account_id: AccountId, job_id: JobId) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifact_gc g JOIN jobs j ON j.job_id = g.job_id WHERE j.account_id = ? AND g.job_id = ?",
    )
    .bind(account_id.to_string())
    .bind(job_id.to_string())
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Whether attempt `attempt` of `account_id`'s job is over: the job is terminal, it moved on to a later attempt, or
/// the attempt's row has an outcome. `None` when the job is not the account's.
pub async fn attempt_over(
    conn: &mut Conn,
    account_id: AccountId,
    job_id: JobId,
    attempt: u32,
) -> Result<Option<bool>, StoreError> {
    let row: Option<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT j.status, j.attempt, \
                (SELECT a.outcome FROM job_attempts a WHERE a.job_id = j.job_id AND a.attempt = ?3) \
         FROM jobs j WHERE j.account_id = ?1 AND j.job_id = ?2",
    )
    .bind(account_id.to_string())
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .fetch_optional(&mut *conn)
    .await?;
    let Some((status, current, outcome)) = row else {
        return Ok(None);
    };
    let status = JobStatus::ALL
        .into_iter()
        .find(|s| s.as_str() == status)
        .ok_or(StoreError::Corrupt("jobs.status"))?;
    Ok(Some(
        status.is_terminal() || current > i64::from(attempt) || outcome.is_some(),
    ))
}

// --- GC (the server itself) ----------------------------------------------------------------------------------------

/// Terminal jobs that finished before `cutoff` and whose logs and artifacts are not collected yet, oldest first.
pub async fn expirable_jobs(conn: &mut Conn, cutoff: OffsetDateTime, limit: u32) -> Result<Vec<JobId>, StoreError> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT j.job_id FROM jobs j \
         WHERE j.finished_at IS NOT NULL AND j.finished_at < ?1 \
           AND j.status IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost') \
           AND NOT EXISTS (SELECT 1 FROM artifact_gc g WHERE g.job_id = j.job_id) \
         ORDER BY j.finished_at, j.job_id LIMIT ?2",
    )
    .bind(ts(cutoff))
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    ids.iter().map(|s| parse_col(s, "jobs.job_id")).collect()
}

/// Jobs recorded as expired whose files are not confirmed deleted yet (`removed_at` NULL): what the GC deletes, again
/// if a pass failed to. Rows never tried (`last_attempt_at` NULL) come first, then the ones tried longest ago (oldest expiry first among
/// equals), so a row whose deletion keeps failing goes to the back of the queue ([`record_removal_failed`]) and
/// cannot use up every pass's limit.
pub async fn pending_removals(conn: &mut Conn, limit: u32) -> Result<Vec<JobId>, StoreError> {
    let ids: Vec<String> = sqlx::query_scalar(PENDING_REMOVALS)
        .bind(i64::from(limit))
        .fetch_all(&mut *conn)
        .await?;
    ids.iter().map(|s| parse_col(s, "artifact_gc.job_id")).collect()
}

/// SQLite sorts NULL (never tried) before any value in `ASC`, so no `COALESCE` is needed, and the order is the one of
/// the partial index `artifact_gc_pending`: no sort.
const PENDING_REMOVALS: &str = "SELECT job_id FROM artifact_gc WHERE removed_at IS NULL \
     ORDER BY last_attempt_at, expired_at, job_id LIMIT ?";

/// Records that the logs and artifacts of `job_id` are deleted (after they are).
pub async fn record_removed(conn: &mut Conn, job_id: JobId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query("UPDATE artifact_gc SET removed_at = ? WHERE job_id = ? AND removed_at IS NULL")
        .bind(ts(now))
        .bind(job_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Records that the GC tried to delete the logs and artifacts of `job_id` and could not: the next pass tries the
/// other rows first.
pub async fn record_removal_failed(conn: &mut Conn, job_id: JobId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query("UPDATE artifact_gc SET last_attempt_at = ? WHERE job_id = ? AND removed_at IS NULL")
        .bind(ts(now))
        .bind(job_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Records that the GC deletes the logs and artifacts of `job_id` (before it deletes them).
pub async fn record_expired(conn: &mut Conn, job_id: JobId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query("INSERT OR IGNORE INTO artifact_gc (job_id, expired_at) VALUES (?, ?)")
        .bind(job_id.to_string())
        .bind(ts(now))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Attempts whose staging is still to be removed: finalised ones whose `.staging` could not be removed at
/// finalisation (at once: no upload is taken for them any more), and ones that never finalised, whose lease ended
/// (and whose last upload was) before `cutoff`. Attempts never tried come first, then the ones tried longest ago, so
/// one whose removal keeps failing ([`record_staging_failed`]) goes to the back of the queue.
pub async fn abandoned_staging(
    conn: &mut Conn,
    cutoff: OffsetDateTime,
    limit: u32,
) -> Result<Vec<(JobId, u32)>, StoreError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(ABANDONED_STAGING)
        .bind(ts(cutoff))
        .bind(i64::from(limit))
        .fetch_all(&mut *conn)
        .await?;
    rows.into_iter()
        .map(|(j, a)| {
            Ok((
                parse_col(&j, "output_attempts.job_id")?,
                u32::try_from(a).map_err(|_| StoreError::Corrupt("output_attempts.attempt"))?,
            ))
        })
        .collect()
}

/// The order is the one of the partial index `output_attempts_staging` (NULL, never tried, sorts first): no sort.
const ABANDONED_STAGING: &str = "SELECT o.job_id, o.attempt FROM output_attempts o LEFT JOIN leases l ON l.id = o.lease_id \
     WHERE o.staging_removed_at IS NULL \
       AND (o.finalized_at IS NOT NULL \
            OR (l.ended_at IS NOT NULL AND l.ended_at < ?1 \
                AND (o.last_upload_at IS NULL OR o.last_upload_at < ?1))) \
     ORDER BY o.last_attempt_at, o.job_id, o.attempt LIMIT ?2";

/// Records that the GC tried to remove an attempt's staging and could not: the next pass tries the others first.
pub async fn record_staging_failed(
    conn: &mut Conn,
    job_id: JobId,
    attempt: u32,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE output_attempts SET last_attempt_at = ? WHERE job_id = ? AND attempt = ?")
        .bind(ts(now))
        .bind(job_id.to_string())
        .bind(i64::from(attempt))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Records that the GC removed an attempt's staging (after it deleted it): its staged rows go too.
pub async fn record_staging_removed(
    conn: &mut Conn,
    job_id: JobId,
    attempt: u32,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE output_attempts SET staging_removed_at = ? WHERE job_id = ? AND attempt = ?")
        .bind(ts(now))
        .bind(job_id.to_string())
        .bind(i64::from(attempt))
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM output_staging WHERE job_id = ? AND attempt = ?")
        .bind(job_id.to_string())
        .bind(i64::from(attempt))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{OpenMode, open};

    /// T10d review P3-2: the GC's two queue queries are served by their partial indexes, in index order: the plan has
    /// no temporary B-tree for the `ORDER BY` (and no full scan of the table).
    #[tokio::test]
    async fn the_gc_queries_use_their_indexes_and_do_not_sort() {
        let tmp = tempfile::tempdir().unwrap();
        let db = open(&tmp.path().join("t.db"), OpenMode::Create).await.unwrap();
        let mut conn = db.acquire().await.unwrap();
        for (name, sql, index) in [
            ("pending_removals", PENDING_REMOVALS, "artifact_gc_pending"),
            ("abandoned_staging", ABANDONED_STAGING, "output_attempts_staging"),
        ] {
            let query = format!("EXPLAIN QUERY PLAN {sql}");
            // `?1`/`?2` are numbered parameters: bind exactly their count.
            let count = if sql.contains("?2") { 2 } else { 1 };
            let mut q = sqlx::query_as::<_, (i64, i64, i64, String)>(sqlx::AssertSqlSafe(query.as_str()));
            for _ in 0..count {
                q = q.bind(0_i64);
            }
            let plan: Vec<String> = q
                .fetch_all(&mut *conn)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.3)
                .collect();
            let plan = plan.join(" | ");
            assert!(plan.contains(index), "{name} does not use {index}: {plan}");
            assert!(!plan.contains("TEMP B-TREE"), "{name} sorts: {plan}");
            assert!(
                !plan.contains("SCAN output_attempts USING INDEX sqlite_autoindex"),
                "{name}: {plan}"
            );
        }
    }
}
