// SPDX-License-Identifier: AGPL-3.0-only

//! Blob rows (H2 §7.5, §5.6, §13): `blobs` (per account, with the GC tombstone `deleting_at`), the claims of
//! `blob_uploaders` and the job references of `blob_refs`.
//!
//! **A tombstoned blob is absent.** Every read that serves a client, upload deduplication and job creation filters
//! `deleting_at IS NULL`; only the GC, `DELETE` and an upload that finishes an interrupted deletion see tombstones.
//!
//! **Lifetime.** A blob expires 24 h after its upload, or, when jobs reference it, 24 h plus the artifact retention
//! after the later of its upload and the end of its last job; a non-terminal job keeps it alive ([`BlobView::
//! expires_at`]). A reference counts only for a job created since the blob's current row was (a `blob_refs` row stays
//! after its blob is deleted, and must not extend a later upload of the same digest).
//!
//! Every function takes the account and filters by it (SI-7, SI-H2-8), except [`gc_candidates`], the GC's queue over
//! every account, which returns `(account, digest)` pairs that each later call is then scoped by.

use p2pc_proto::api::{BlobInfo, BlobInput, Principal as PrincipalId, Sha256Digest};
use p2pc_proto::ids::{AccountId, DeviceId, JobId};
use time::{Duration, OffsetDateTime};

use super::{Conn, StoreError, from_ts, from_ts_opt, parse_col, ts};

/// How long a blob that no job references lives after its upload (H2 §7.5).
pub const UNREFERENCED_LIFETIME: Duration = Duration::hours(24);

/// The job states that keep a blob alive.
macro_rules! non_terminal {
    () => {
        "('queued', 'assigned', 'running')"
    };
}

/// The references of the blob row `b` that count: jobs created since that row.
macro_rules! refs_of_b {
    () => {
        "FROM blob_refs r JOIN jobs j ON j.job_id = r.job_id \
         WHERE r.account_id = b.account_id AND r.sha256 = b.sha256 AND j.created_at >= b.created_at"
    };
}

/// A blob row with what decides its lifetime, read from `blobs b`.
macro_rules! select_view {
    ($tail:literal) => {
        concat!(
            "SELECT b.sha256, b.size, b.created_at, b.deleting_at, \
             (SELECT COUNT(DISTINCT r.job_id) ",
            refs_of_b!(),
            ") AS refs, \
             EXISTS (SELECT 1 ",
            refs_of_b!(),
            " AND j.status IN ",
            non_terminal!(),
            ") AS live, \
             (SELECT MAX(COALESCE(j.finished_at, j.updated_at)) ",
            refs_of_b!(),
            ") AS last_end FROM blobs b ",
            $tail
        )
    };
}

#[derive(sqlx::FromRow)]
struct RawView {
    sha256: String,
    size: i64,
    created_at: i64,
    deleting_at: Option<i64>,
    refs: i64,
    live: i64,
    last_end: Option<i64>,
}

/// A blob row, with its references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobView {
    /// The digest.
    pub sha256: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
    /// When this row was created (the upload that stored the file).
    pub created_at: OffsetDateTime,
    /// The GC's tombstone: set, the blob is absent to every reader.
    pub deleting_at: Option<OffsetDateTime>,
    /// Jobs that reference it.
    pub referenced_by: u64,
    /// Whether one of them is not terminal (it keeps the blob alive).
    pub in_use: bool,
    /// When the last of them ended.
    pub last_end: Option<OffsetDateTime>,
}

impl BlobView {
    /// When it expires; `None` while a non-terminal job references it (H2 §7.5 "Lifetime").
    #[must_use]
    pub fn expires_at(&self, retention: Duration) -> Option<OffsetDateTime> {
        if self.in_use {
            return None;
        }
        if self.referenced_by == 0 {
            return Some(self.created_at + UNREFERENCED_LIFETIME);
        }
        let from = self.last_end.map_or(self.created_at, |end| end.max(self.created_at));
        Some(from + UNREFERENCED_LIFETIME + retention)
    }

    /// Whether the GC may delete it at `now`.
    #[must_use]
    pub fn is_expired(&self, retention: Duration, now: OffsetDateTime) -> bool {
        self.expires_at(retention).is_some_and(|at| at <= now)
    }

    /// The API view.
    #[must_use]
    pub fn info(&self, retention: Duration) -> BlobInfo {
        BlobInfo {
            sha256: self.sha256,
            size: self.size,
            created_at: self.created_at,
            referenced_by: self.referenced_by,
            expires_at: self.expires_at(retention),
        }
    }
}

fn decode(raw: RawView) -> Result<BlobView, StoreError> {
    Ok(BlobView {
        sha256: parse_col(&raw.sha256, "blobs.sha256")?,
        size: u64::try_from(raw.size).map_err(|_| StoreError::Corrupt("blobs.size"))?,
        created_at: from_ts(raw.created_at, "blobs.created_at")?,
        deleting_at: from_ts_opt(raw.deleting_at, "blobs.deleting_at")?,
        referenced_by: u64::try_from(raw.refs).map_err(|_| StoreError::Corrupt("blob_refs"))?,
        in_use: raw.live != 0,
        last_end: from_ts_opt(raw.last_end, "jobs.finished_at")?,
    })
}

fn size_col(size: u64) -> Result<i64, StoreError> {
    i64::try_from(size).map_err(|_| StoreError::Corrupt("blobs.size"))
}

fn sum_col(sum: Option<i64>, column: &'static str) -> Result<u64, StoreError> {
    u64::try_from(sum.unwrap_or(0)).map_err(|_| StoreError::Corrupt(column))
}

/// The blob row of `account`, tombstoned or not.
pub async fn get(conn: &mut Conn, account: AccountId, sha256: Sha256Digest) -> Result<Option<BlobView>, StoreError> {
    let raw: Option<RawView> = sqlx::query_as(select_view!("WHERE b.account_id = ? AND b.sha256 = ?"))
        .bind(account.to_string())
        .bind(sha256.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

/// The blob of `account` if it is live (not tombstoned).
pub async fn get_live(
    conn: &mut Conn,
    account: AccountId,
    sha256: Sha256Digest,
) -> Result<Option<BlobView>, StoreError> {
    Ok(get(conn, account, sha256).await?.filter(|b| b.deleting_at.is_none()))
}

/// A page of the live blobs of `account`, oldest first (`created_at`, then digest), after `after`.
pub async fn list(
    conn: &mut Conn,
    account: AccountId,
    after: Option<(OffsetDateTime, Sha256Digest)>,
    limit: u32,
) -> Result<Vec<BlobView>, StoreError> {
    let (at, sha) = after.map_or((i64::MIN, String::new()), |(t, s)| (ts(t), s.to_string()));
    let raws: Vec<RawView> = sqlx::query_as(select_view!(
        "WHERE b.account_id = ? AND b.deleting_at IS NULL AND (b.created_at, b.sha256) > (?, ?) \
         ORDER BY b.created_at, b.sha256 LIMIT ?"
    ))
    .bind(account.to_string())
    .bind(at)
    .bind(sha)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    raws.into_iter().map(decode).collect()
}

/// Bytes `account` stores in blobs: every row, tombstoned ones too (their files are still on disk).
pub async fn stored_bytes(conn: &mut Conn, account: AccountId) -> Result<u64, StoreError> {
    let sum: Option<i64> = sqlx::query_scalar("SELECT SUM(size) FROM blobs WHERE account_id = ?")
        .bind(account.to_string())
        .fetch_one(&mut *conn)
        .await?;
    sum_col(sum, "blobs.size")
}

/// Bytes of the blobs of `account` that `device` holds a claim on (its quota, H2 §5.2).
pub async fn device_bytes(conn: &mut Conn, account: AccountId, device: DeviceId) -> Result<u64, StoreError> {
    let sum: Option<i64> = sqlx::query_scalar(
        "SELECT SUM(b.size) FROM blob_uploaders u JOIN blobs b ON b.account_id = u.account_id AND b.sha256 = u.sha256 \
         WHERE u.account_id = ? AND u.uploaded_by_device_id = ?",
    )
    .bind(account.to_string())
    .bind(device.to_string())
    .fetch_one(&mut *conn)
    .await?;
    sum_col(sum, "blobs.size")
}

/// Inserts a new blob row of `account`.
pub async fn insert(
    conn: &mut Conn,
    account: AccountId,
    sha256: Sha256Digest,
    size: u64,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO blobs (account_id, sha256, size, created_at) VALUES (?, ?, ?, ?)")
        .bind(account.to_string())
        .bind(sha256.to_string())
        .bind(size_col(size)?)
        .bind(ts(now))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Records `principal`'s claim on the blob (once: a second one changes nothing, H2 §5.6).
pub async fn add_claim(
    conn: &mut Conn,
    account: AccountId,
    sha256: Sha256Digest,
    principal: PrincipalId,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let (key, device) = super::jobs::principal_binds(principal);
    sqlx::query(
        "INSERT OR IGNORE INTO blob_uploaders (account_id, sha256, uploaded_by_key_id, uploaded_by_device_id, \
         created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(account.to_string())
    .bind(sha256.to_string())
    .bind(key)
    .bind(device)
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether `principal` holds a claim on the blob.
pub async fn has_claim(
    conn: &mut Conn,
    account: AccountId,
    sha256: Sha256Digest,
    principal: PrincipalId,
) -> Result<bool, StoreError> {
    let (key, device) = super::jobs::principal_binds(principal);
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM blob_uploaders WHERE account_id = ? AND sha256 = ? \
         AND (uploaded_by_key_id = ? OR uploaded_by_device_id = ?)",
    )
    .bind(account.to_string())
    .bind(sha256.to_string())
    .bind(key)
    .bind(device)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.is_some())
}

/// Removes `principal`'s claim, or, with `None`, every claim. Returns how many claims remain.
pub async fn remove_claims(
    conn: &mut Conn,
    account: AccountId,
    sha256: Sha256Digest,
    principal: Option<PrincipalId>,
) -> Result<u64, StoreError> {
    match principal {
        Some(p) => {
            let (key, device) = super::jobs::principal_binds(p);
            sqlx::query(
                "DELETE FROM blob_uploaders WHERE account_id = ? AND sha256 = ? \
                 AND (uploaded_by_key_id = ? OR uploaded_by_device_id = ?)",
            )
            .bind(account.to_string())
            .bind(sha256.to_string())
            .bind(key)
            .bind(device)
            .execute(&mut *conn)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM blob_uploaders WHERE account_id = ? AND sha256 = ?")
                .bind(account.to_string())
                .bind(sha256.to_string())
                .execute(&mut *conn)
                .await?;
        }
    }
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploaders WHERE account_id = ? AND sha256 = ?")
        .bind(account.to_string())
        .bind(sha256.to_string())
        .fetch_one(&mut *conn)
        .await?;
    u64::try_from(left).map_err(|_| StoreError::Corrupt("blob_uploaders"))
}

/// Step 1 of a deletion: sets the tombstone (and the attempt time) of a live blob. The caller re-checked, in the same
/// `BEGIN IMMEDIATE` transaction, that the blob may go. Returns whether a live row was tombstoned.
pub async fn tombstone(
    conn: &mut Conn,
    account: AccountId,
    sha256: Sha256Digest,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE blobs SET deleting_at = ?, last_attempt_at = ? \
         WHERE account_id = ? AND sha256 = ? AND deleting_at IS NULL",
    )
    .bind(ts(now))
    .bind(ts(now))
    .bind(account.to_string())
    .bind(sha256.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// A deletion step failed: the blob goes to the back of the GC's queue.
pub async fn record_attempt(
    conn: &mut Conn,
    account: AccountId,
    sha256: Sha256Digest,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE blobs SET last_attempt_at = ? WHERE account_id = ? AND sha256 = ?")
        .bind(ts(now))
        .bind(account.to_string())
        .bind(sha256.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Step 3 of a deletion: deletes a tombstoned row, and its claims with it (`ON DELETE CASCADE`). A live row is never
/// deleted here. Returns whether a row went.
pub async fn delete_tombstoned(conn: &mut Conn, account: AccountId, sha256: Sha256Digest) -> Result<bool, StoreError> {
    let done = sqlx::query("DELETE FROM blobs WHERE account_id = ? AND sha256 = ? AND deleting_at IS NOT NULL")
        .bind(account.to_string())
        .bind(sha256.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// The GC's queue: up to `limit` blobs that are tombstoned (a deletion to resume) or expired at `now`, rows never
/// tried first, then by the last attempt (H1's retry-queue rule). The GC re-checks each one under its lock.
pub async fn gc_candidates(
    conn: &mut Conn,
    now: OffsetDateTime,
    retention: Duration,
    limit: u32,
) -> Result<Vec<(AccountId, Sha256Digest)>, StoreError> {
    let unreferenced_cut = ts(now - UNREFERENCED_LIFETIME);
    let referenced_cut = ts(now - UNREFERENCED_LIFETIME - retention);
    let rows: Vec<(String, String)> = sqlx::query_as(concat!(
        "SELECT account_id, sha256 FROM (",
        "SELECT b.account_id, b.sha256, b.created_at, b.deleting_at, b.last_attempt_at, \
         (SELECT COUNT(*) ",
        refs_of_b!(),
        ") AS refs, EXISTS (SELECT 1 ",
        refs_of_b!(),
        " AND j.status IN ",
        non_terminal!(),
        ") AS live, (SELECT MAX(COALESCE(j.finished_at, j.updated_at)) ",
        refs_of_b!(),
        ") AS last_end FROM blobs b WHERE b.deleting_at IS NOT NULL OR b.created_at <= ?1",
        ") WHERE deleting_at IS NOT NULL OR (live = 0 AND (refs = 0 OR MAX(created_at, COALESCE(last_end, created_at)) <= ?2)) \
         ORDER BY last_attempt_at, created_at LIMIT ?3"
    ))
    .bind(unreferenced_cut)
    .bind(referenced_cut)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(a, s)| Ok((parse_col(&a, "blobs.account_id")?, parse_col(&s, "blobs.sha256")?)))
        .collect()
}

/// Job creation (H2 §7.1 `inputs`, §7.5): the total size of the blobs `inputs` name, if every one is a live blob of
/// `account`; otherwise the index of the first that is not (`422 unknown_blob`). Call it in the job-creation
/// transaction, which then inserts the references with [`insert_refs`] (through `jobs::insert`): either the reference
/// is there before the GC's re-check, or the tombstone is there before this check.
pub async fn resolve_inputs(
    conn: &mut Conn,
    account: AccountId,
    inputs: &[BlobInput],
) -> Result<Result<u64, usize>, StoreError> {
    let mut total: u64 = 0;
    for (i, input) in inputs.iter().enumerate() {
        let size: Option<i64> =
            sqlx::query_scalar("SELECT size FROM blobs WHERE account_id = ? AND sha256 = ? AND deleting_at IS NULL")
                .bind(account.to_string())
                .bind(input.blob.0.to_string())
                .fetch_optional(&mut *conn)
                .await?;
        let Some(size) = size else {
            return Ok(Err(i));
        };
        let size = u64::try_from(size).map_err(|_| StoreError::Corrupt("blobs.size"))?;
        total = total.saturating_add(size);
    }
    Ok(Ok(total))
}

/// Records the blob `inputs` of a new job.
pub async fn insert_refs(
    conn: &mut Conn,
    account: AccountId,
    job_id: JobId,
    inputs: &[BlobInput],
) -> Result<(), StoreError> {
    for input in inputs {
        sqlx::query("INSERT INTO blob_refs (job_id, path, account_id, sha256) VALUES (?, ?, ?, ?)")
            .bind(job_id.to_string())
            .bind(&input.path)
            .bind(account.to_string())
            .bind(input.blob.0.to_string())
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Whether the job `job_id` of `account` has `sha256` among its blob inputs (`BlobFetch`, H2 §6.1).
pub async fn job_references(
    conn: &mut Conn,
    account: AccountId,
    job_id: JobId,
    sha256: Sha256Digest,
) -> Result<bool, StoreError> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM blob_refs WHERE job_id = ? AND account_id = ? AND sha256 = ? LIMIT 1")
            .bind(job_id.to_string())
            .bind(account.to_string())
            .bind(sha256.to_string())
            .fetch_optional(&mut *conn)
            .await?;
    Ok(found.is_some())
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn view(referenced_by: u64, in_use: bool, last_end: Option<OffsetDateTime>) -> BlobView {
        BlobView {
            sha256: Sha256Digest([0; 32]),
            size: 1,
            created_at: datetime!(2026-11-05 10:00:00 UTC),
            deleting_at: None,
            referenced_by,
            in_use,
            last_end,
        }
    }

    #[test]
    fn the_lifetime_follows_the_upload_and_the_last_job() {
        let week = Duration::days(7);
        assert_eq!(
            view(0, false, None).expires_at(week),
            Some(datetime!(2026-11-06 10:00:00 UTC))
        );
        assert_eq!(view(2, true, None).expires_at(week), None);
        // The later of the upload and the last job's end, plus 24 h and the retention.
        let ended = datetime!(2026-11-10 08:00:00 UTC);
        assert_eq!(
            view(1, false, Some(ended)).expires_at(week),
            Some(datetime!(2026-11-18 08:00:00 UTC))
        );
        assert_eq!(
            view(1, false, Some(datetime!(2026-11-01 00:00:00 UTC))).expires_at(week),
            Some(datetime!(2026-11-13 10:00:00 UTC))
        );
        let v = view(0, false, None);
        assert!(!v.is_expired(week, datetime!(2026-11-06 09:59:59 UTC)));
        assert!(v.is_expired(week, datetime!(2026-11-06 10:00:00 UTC)));
    }
}
