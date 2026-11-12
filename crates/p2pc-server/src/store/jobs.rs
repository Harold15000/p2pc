// SPDX-License-Identifier: AGPL-3.0-only

//! Jobs (spec §7): the rows, creation, lookups, listing and the cancel request.
//!
//! **Status never changes here.** The only code that writes `jobs.status` is [`super::job_state::transition`]; this
//! module creates a job `queued` and reads it. Every function takes the principal's `account_id` and `project_id`
//! and its SQL filters by both (SI-7).
//!
//! `spec` holds the env values and input file contents. **The read path never selects it.** Every function that serves
//! the API ([`get`], [`list`], [`find_by_idempotency_key`], and so the cancel handler) selects `spec_view` instead, the
//! redacted [`JobSpecView`] computed once by [`insert`], so a page of jobs never loads their file contents (up to
//! 512 KiB each) from SQLite. Only [`load_spec`] reads `spec`, one row at a time, for building a lease (T06). It is
//! decoded into a [`JobSpec`] (whose `Debug` redacts the values) and never logged. `tests/read_path_sql.rs` checks the
//! SQL strings of this crate for it.

use p2pc_proto::api::{FileMeta, Job, JobAttempt, JobKind, JobSpec, JobSpecView, JobStatus, Principal};
use p2pc_proto::ids::{AccountId, JobId, NodeId, ProjectId};
use p2pc_proto::units::Units;
use time::OffsetDateTime;

use super::{Conn, StoreError, from_ts, from_ts_opt, parse_col, ts};

/// A stored job.
///
/// `Debug` is safe: the spec's `Debug` prints env names and file paths, never values or contents.
#[derive(Debug, Clone, PartialEq)]
pub struct JobRow {
    /// Job ID.
    pub job_id: JobId,
    /// Owning account.
    pub account_id: AccountId,
    /// Owning project.
    pub project_id: ProjectId,
    /// The principal that submitted it: an API key or a device (H2 §5.6).
    pub principal: Principal,
    /// What the API shows of the spec (env values `<redacted>`, files as `{path, size, sha256}`, no idempotency key),
    /// read from the `spec_view` column. The row has no `spec`: it is never loaded with a job (see [`load_spec`]).
    pub spec_view: JobSpecView,
    /// `sha256:<hex>` of the canonical JSON of the spec.
    pub spec_hash: String,
    /// Current state.
    pub status: JobStatus,
    /// Current attempt, from 1.
    pub attempt: u32,
    /// Attempts allowed.
    pub max_attempts: u32,
    /// The client's idempotency key.
    pub idempotency_key: Option<String>,
    /// Milli-units reserved at creation.
    pub units_reserved: Units,
    /// Node of the current or last attempt.
    pub node_id: Option<NodeId>,
    /// Exit code, when the job exited.
    pub exit_code: Option<i32>,
    /// How the last attempt ended, as the agent reported it.
    pub outcome: Option<String>,
    /// Short error code when it failed without an exit code.
    pub error: Option<String>,
    /// User-visible explanation of the current state.
    pub reason: Option<String>,
    /// When a cancel was requested for an assigned or running job.
    pub cancel_requested_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last change.
    pub updated_at: OffsetDateTime,
    /// When the current attempt started running.
    pub started_at: Option<OffsetDateTime>,
    /// When the job reached a terminal state.
    pub finished_at: Option<OffsetDateTime>,
}

impl JobRow {
    /// The API representation. The spec is the stored `spec_view`: nothing is redacted, decoded or hashed here.
    #[must_use]
    pub fn to_job(&self) -> Job {
        // A constructor, then the fields: a field added to the shared type does not break this (CONTRIBUTING rule 7).
        // `attempts` stays `None`: only `GET /v1/jobs/{id}` adds them (`attempts`).
        let mut job = Job::new(
            self.job_id,
            self.project_id,
            self.status,
            self.attempt,
            self.spec_view.clone(),
            self.units_reserved,
            self.created_at,
        );
        job.node_id = self.node_id;
        job.reason.clone_from(&self.reason);
        job.cancel_requested_at = self.cancel_requested_at;
        job.exit_code = self.exit_code;
        job.error.clone_from(&self.error);
        job.started_at = self.started_at;
        job.finished_at = self.finished_at;
        job
    }
}

/// A job to insert. It is created `queued`, attempt 1.
#[derive(Debug, Clone)]
pub struct NewJob {
    /// The new ID.
    pub job_id: JobId,
    /// Owning account.
    pub account_id: AccountId,
    /// Owning project.
    pub project_id: ProjectId,
    /// The submitting principal: an API key or a device (H2 §5.6).
    pub principal: Principal,
    /// The validated, normalized spec.
    pub spec: JobSpec,
    /// `{path, size, sha256}` of its input files.
    pub files_meta: Vec<FileMeta>,
    /// `sha256:<hex>` of the canonical JSON of the spec.
    pub spec_hash: String,
    /// Milli-units reserved.
    pub units_reserved: Units,
}

/// The raw columns of `jobs`.
#[derive(sqlx::FromRow)]
struct Raw {
    job_id: String,
    account_id: String,
    project_id: String,
    key_id: Option<String>,
    device_id: Option<String>,
    spec_view: String,
    spec_hash: String,
    status: String,
    attempt: i64,
    max_attempts: i64,
    idempotency_key: Option<String>,
    units_reserved: i64,
    node_id: Option<String>,
    exit_code: Option<i64>,
    outcome: Option<String>,
    error: Option<String>,
    reason: Option<String>,
    cancel_requested_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
    started_at: Option<i64>,
    finished_at: Option<i64>,
}

/// Every column of `jobs` a read serves, in the order of [`Raw`] (names, so the order does not matter to `FromRow`):
/// `spec_view`, **never `spec`** (see the module docs).
macro_rules! select_jobs {
    ($tail:literal) => {
        concat!(
            "SELECT job_id, account_id, project_id, key_id, device_id, spec_view, spec_hash, status, attempt, \
             max_attempts, idempotency_key, units_reserved, node_id, exit_code, outcome, error, reason, \
             cancel_requested_at, created_at, updated_at, started_at, finished_at FROM jobs ",
            $tail
        )
    };
}

/// A stored status name.
fn parse_status(text: &str) -> Result<JobStatus, StoreError> {
    JobStatus::ALL
        .into_iter()
        .find(|s| s.as_str() == text)
        .ok_or(StoreError::Corrupt("jobs.status"))
}

fn small(value: i64, column: &'static str) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| StoreError::Corrupt(column))
}

fn decode(raw: Raw) -> Result<JobRow, StoreError> {
    Ok(JobRow {
        job_id: parse_col(&raw.job_id, "jobs.job_id")?,
        account_id: parse_col(&raw.account_id, "jobs.account_id")?,
        project_id: parse_col(&raw.project_id, "jobs.project_id")?,
        principal: principal_cols(raw.key_id.as_deref(), raw.device_id.as_deref(), "jobs.key_id/device_id")?,
        spec_view: serde_json::from_str(&raw.spec_view).map_err(|_| StoreError::Corrupt("jobs.spec_view"))?,
        spec_hash: raw.spec_hash,
        status: parse_status(&raw.status)?,
        attempt: small(raw.attempt, "jobs.attempt")?,
        max_attempts: small(raw.max_attempts, "jobs.max_attempts")?,
        idempotency_key: raw.idempotency_key,
        units_reserved: Units::from_milli(
            u64::try_from(raw.units_reserved).map_err(|_| StoreError::Corrupt("jobs.units_reserved"))?,
        ),
        node_id: raw.node_id.map(|n| parse_col(&n, "jobs.node_id")).transpose()?,
        exit_code: raw
            .exit_code
            .map(|c| i32::try_from(c).map_err(|_| StoreError::Corrupt("jobs.exit_code")))
            .transpose()?,
        outcome: raw.outcome,
        error: raw.error,
        reason: raw.reason,
        cancel_requested_at: from_ts_opt(raw.cancel_requested_at, "jobs.cancel_requested_at")?,
        created_at: from_ts(raw.created_at, "jobs.created_at")?,
        updated_at: from_ts(raw.updated_at, "jobs.updated_at")?,
        started_at: from_ts_opt(raw.started_at, "jobs.started_at")?,
        finished_at: from_ts_opt(raw.finished_at, "jobs.finished_at")?,
    })
}

/// The principal stored in a `(key_id, device_id)` pair of columns, exactly one of them set (H2 §5.6).
pub(crate) fn principal_cols(
    key_id: Option<&str>,
    device_id: Option<&str>,
    column: &'static str,
) -> Result<Principal, StoreError> {
    match (key_id, device_id) {
        (Some(k), None) => Ok(Principal::Key(parse_col(k, column)?)),
        (None, Some(d)) => Ok(Principal::Device(parse_col(d, column)?)),
        _ => Err(StoreError::Corrupt(column)),
    }
}

/// The `(key_id, device_id)` columns of a principal, for binding.
pub(crate) fn principal_binds(p: Principal) -> (Option<String>, Option<String>) {
    (p.key_id().map(|k| k.to_string()), p.device_id().map(|d| d.to_string()))
}

fn json<T: serde::Serialize>(value: &T, column: &'static str) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Corrupt(column))
}

/// Inserts a job as `queued`, attempt 1, with its creation event (`from_status` NULL, reason `created`).
///
/// Call it inside the `BEGIN IMMEDIATE` transaction that checked the idempotency key and the cap. That transaction
/// is what keeps two identical submissions from both inserting; if one ever got past it, the unique index on
/// `(key_id, idempotency_key)` or `(device_id, idempotency_key)` refuses the second insert with an error.
///
/// `kind` and `template_id` are copied from the spec into their own columns (H2 §5.6), for the `kind` filter and the
/// template view. A service also gets its `service_state` row, and blob `inputs` their `blob_refs` rows (the caller
/// checked the blobs in the same transaction, [`super::blobs::resolve_inputs`]).
pub async fn insert(conn: &mut Conn, job: &NewJob, now: OffsetDateTime) -> Result<JobRow, StoreError> {
    let units = i64::try_from(job.units_reserved.milli()).map_err(|_| StoreError::Corrupt("jobs.units_reserved"))?;
    // The redacted view that every API read will serve, built once, here, from the file metadata computed at
    // submission: env values become `<redacted>`, files `{path, size, sha256}`. No file content is decoded or hashed,
    // and the idempotency key is not part of it.
    let view = JobSpecView::from_stored_with_meta(&job.spec, &job.files_meta)
        .map_err(|_| StoreError::Corrupt("jobs.files_meta"))?;
    let (key, device) = principal_binds(job.principal);
    sqlx::query(
        "INSERT INTO jobs (job_id, account_id, project_id, key_id, device_id, kind, template_id, name, spec, \
         files_meta, spec_view, spec_hash, status, attempt, max_attempts, idempotency_key, units_reserved, \
         created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 1, ?, ?, ?, ?, ?)",
    )
    .bind(job.job_id.to_string())
    .bind(job.account_id.to_string())
    .bind(job.project_id.to_string())
    .bind(key)
    .bind(device)
    .bind(job.spec.kind.as_str())
    .bind(job.spec.template.as_ref().map(|t| t.id.clone()))
    .bind(job.spec.name.clone())
    .bind(json(&job.spec, "jobs.spec")?)
    .bind(json(&job.files_meta, "jobs.files_meta")?)
    .bind(json(&view, "jobs.spec_view")?)
    .bind(&job.spec_hash)
    .bind(i64::from(job.spec.retry.max_attempts))
    .bind(job.spec.idempotency_key.clone())
    .bind(units)
    .bind(ts(now))
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    super::job_state::record_creation(conn, job.job_id, now).await?;
    // Its blob inputs (H2 §7.5), in the same transaction as the check of the blobs: they keep them alive.
    super::blobs::insert_refs(conn, job.account_id, job.job_id, &job.spec.inputs).await?;
    // The hub's state of a service (health, restart counters, H2 §7.2), one row from the start.
    if job.spec.kind == JobKind::Service {
        super::leases::create_service_state(conn, job.job_id, now).await?;
    }
    get(conn, job.account_id, job.project_id, job.job_id)
        .await?
        .ok_or(StoreError::Corrupt("jobs"))
}

/// One job of the principal's account and project.
pub async fn get(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    job_id: JobId,
) -> Result<Option<JobRow>, StoreError> {
    let raw: Option<Raw> = sqlx::query_as(select_jobs!("WHERE account_id = ? AND project_id = ? AND job_id = ?"))
        .bind(account_id.to_string())
        .bind(project_id.to_string())
        .bind(job_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

/// The spec of one job of the principal's account and project **as submitted** (normalized, with the real env values
/// and the file contents): what building a lease needs (T06).
///
/// This is the only read of the `spec` column, and it reads one row at a time. It is for the scheduler, never for the
/// API: responses use `spec_view` (see the module docs). The value holds secrets; do not log it.
pub async fn load_spec(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    job_id: JobId,
) -> Result<Option<JobSpec>, StoreError> {
    let text: Option<String> =
        sqlx::query_scalar("SELECT spec FROM jobs WHERE account_id = ? AND project_id = ? AND job_id = ?")
            .bind(account_id.to_string())
            .bind(project_id.to_string())
            .bind(job_id.to_string())
            .fetch_optional(&mut *conn)
            .await?;
    text.map(|t| serde_json::from_str(&t).map_err(|_| StoreError::Corrupt("jobs.spec")))
        .transpose()
}

/// The job that `principal` submitted with this idempotency key, if any.
///
/// Idempotency keys are scoped to the **principal** (spec §7, H2 §5.6): a job of another key or device with the same
/// idempotency key is invisible here, so a replay can never confirm or deny anything about someone else's job. The
/// account and project filters are kept as well (SI-7). Each branch reads the column of its own partial unique index.
pub async fn find_by_idempotency_key(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    principal: Principal,
    idempotency_key: &str,
) -> Result<Option<JobRow>, StoreError> {
    let (sql, id) = match principal {
        Principal::Key(k) => (
            select_jobs!("WHERE account_id = ? AND project_id = ? AND idempotency_key = ? AND key_id = ?"),
            k.to_string(),
        ),
        Principal::Device(d) => (
            select_jobs!("WHERE account_id = ? AND project_id = ? AND idempotency_key = ? AND device_id = ?"),
            d.to_string(),
        ),
    };
    let raw: Option<Raw> = sqlx::query_as(sql)
        .bind(account_id.to_string())
        .bind(project_id.to_string())
        .bind(idempotency_key)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

/// Filters of [`list`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ListFilter {
    /// Only jobs in this state.
    pub status: Option<JobStatus>,
    /// Only jobs of this node.
    pub node_id: Option<NodeId>,
    /// Only jobs of this kind (H2 §7.2).
    pub kind: Option<JobKind>,
}

/// Which jobs of its account and project a principal reaches (H2 §5.5 "Template view").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    /// Every job of the project (H1: `jobs:read`, `jobs:write`, `services:connect`).
    Project,
    /// Only template jobs (`template` set): the ones `launched_by` launched and, when `singletons` is given, every
    /// instance of those `singleton` templates, whoever launched it.
    Template {
        /// The principal whose own launches are visible.
        launched_by: Principal,
        /// The ids of the `singleton` templates whose instances are visible too; `None` when the route shows only
        /// the principal's own launches (logs and outputs).
        singletons: Option<Vec<String>>,
    },
}

impl Visibility {
    /// Whether `row`, a job of the principal's account and project, is visible.
    #[must_use]
    pub fn allows(&self, row: &JobRow) -> bool {
        match self {
            Visibility::Project => true,
            Visibility::Template {
                launched_by,
                singletons,
            } => row.spec_view.template.as_ref().is_some_and(|t| {
                row.principal == *launched_by || singletons.as_ref().is_some_and(|ids| ids.contains(&t.id))
            }),
        }
    }
}

/// Position after which a listing continues: `(created_at, job_id)` of the last job returned. The listing order is
/// `created_at` descending, then `job_id` ascending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobCursor {
    /// `created_at` of the last job, in Unix seconds.
    pub created_at: i64,
    /// Its ID.
    pub job_id: JobId,
}

impl JobCursor {
    /// The cursor after `row`.
    #[must_use]
    pub fn after(row: &JobRow) -> Self {
        Self {
            created_at: ts(row.created_at),
            job_id: row.job_id,
        }
    }

    /// The opaque form handed to clients: unpadded base64url of `<created_at>.<job_id>`.
    #[must_use]
    pub fn encode(&self) -> String {
        data_encoding::BASE64URL_NOPAD.encode(format!("{}.{}", self.created_at, self.job_id).as_bytes())
    }

    /// Parses [`JobCursor::encode`]'s output; anything else is `None`.
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let bytes = data_encoding::BASE64URL_NOPAD.decode(text.as_bytes()).ok()?;
        let text = String::from_utf8(bytes).ok()?;
        let (at, id) = text.split_once('.')?;
        if at.is_empty() || !at.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            created_at: at.parse().ok()?,
            job_id: id.parse().ok()?,
        })
    }
}

/// The jobs of the principal's account and project that `visible` shows it (H2 §5.5), newest first (`created_at`
/// descending, then `job_id`), starting after `after`, at most `limit` of them.
///
/// The template view is part of the query, never a filter over a page: a job the principal may not see takes no
/// place in a page and moves no cursor. `template_id` is the job's own column, copied from its spec at creation.
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    visible: &Visibility,
    filter: ListFilter,
    after: Option<JobCursor>,
    limit: u32,
) -> Result<Vec<JobRow>, StoreError> {
    let (at, id) = after.map_or((None, None), |c| (Some(c.created_at), Some(c.job_id.to_string())));
    // ?9: 1 for the template view. ?10, ?11: the launcher's key or device. ?12: a JSON array of singleton ids.
    let (template_view, launcher, singletons) = match visible {
        Visibility::Project => (false, (None, None), "[]".to_string()),
        Visibility::Template {
            launched_by,
            singletons,
        } => (
            true,
            principal_binds(*launched_by),
            json(&singletons.clone().unwrap_or_default(), "jobs.template_id")?,
        ),
    };
    let rows: Vec<Raw> = sqlx::query_as(select_jobs!(
        "WHERE account_id = ?1 AND project_id = ?2 \
           AND (?3 IS NULL OR status = ?3) \
           AND (?4 IS NULL OR node_id = ?4) \
           AND (?5 IS NULL OR created_at < ?5 OR (created_at = ?5 AND job_id > ?6)) \
           AND (?8 IS NULL OR kind = ?8) \
           AND (?9 = 0 OR (template_id IS NOT NULL \
                           AND ((?10 IS NOT NULL AND key_id = ?10) OR (?11 IS NOT NULL AND device_id = ?11) \
                                OR template_id IN (SELECT value FROM json_each(?12))))) \
         ORDER BY created_at DESC, job_id ASC LIMIT ?7"
    ))
    .bind(account_id.to_string())
    .bind(project_id.to_string())
    .bind(filter.status.map(|s| s.as_str()))
    .bind(filter.node_id.map(|n| n.to_string()))
    .bind(at)
    .bind(id)
    .bind(i64::from(limit))
    .bind(filter.kind.map(JobKind::as_str))
    .bind(template_view)
    .bind(launcher.0)
    .bind(launcher.1)
    .bind(singletons)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// The attempts of one job of the principal's account and project, oldest first (§7 `GET /v1/jobs/{id}`), from
/// `job_attempts`: one row per accepted lease, so refused or unanswered offers never appear. Filtered by account
/// **and** project (SI-7): another principal gets no row. `outcome` is `running` while the attempt is in progress.
pub async fn attempts(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    job_id: JobId,
) -> Result<Vec<JobAttempt>, StoreError> {
    type Row = (i64, String, Option<String>, Option<String>, Option<i64>, Option<i64>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.attempt, a.node_id, a.outcome, a.reason_code, a.started_at, a.ended_at FROM job_attempts a \
         JOIN jobs j ON j.job_id = a.job_id \
         WHERE j.account_id = ? AND j.project_id = ? AND a.job_id = ? ORDER BY a.attempt",
    )
    .bind(account_id.to_string())
    .bind(project_id.to_string())
    .bind(job_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(attempt, node, outcome, reason, started, ended)| {
            let mut a = JobAttempt::new(
                small(attempt, "job_attempts.attempt")?,
                parse_col(&node, "job_attempts.node_id")?,
            );
            a.outcome = outcome.as_deref().map_or(Ok(JobStatus::Running), parse_status)?;
            a.reason = reason;
            a.started_at = from_ts_opt(started, "job_attempts.started_at")?;
            a.ended_at = from_ts_opt(ended, "job_attempts.ended_at")?;
            Ok(a)
        })
        .collect()
}

/// Records that a cancel was requested for an `assigned` or `running` job, once: a second request keeps the first
/// time. Returns whether this call set it.
pub async fn request_cancel(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    job_id: JobId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE jobs SET cancel_requested_at = ?1, updated_at = ?1 \
         WHERE account_id = ?2 AND project_id = ?3 AND job_id = ?4 \
           AND status IN ('assigned', 'running') AND cancel_requested_at IS NULL",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(project_id.to_string())
    .bind(job_id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_and_rejections() {
        let c = JobCursor {
            created_at: 1_793_872_800,
            job_id: JobId::generate(),
        };
        let text = c.encode();
        assert_eq!(JobCursor::decode(&text), Some(c));
        // Opaque: neither the time nor the ID shows.
        assert!(!text.contains('.') && !text.contains("job_"));
        let b64 = |s: &str| data_encoding::BASE64URL_NOPAD.encode(s.as_bytes());
        let id = c.job_id.to_string();
        for bad in [
            String::new(),
            "%%%".to_string(),
            "garbage".to_string(),
            b64("hello"),
            b64(&format!(".{id}")),
            b64(&format!("-1.{id}")),
            b64(&format!("x.{id}")),
            b64("1.job_nope"),
            b64(&format!("1.{}", id.to_uppercase())),
            // The raw (not base64) form is not a cursor.
            format!("{}.{id}", c.created_at),
        ] {
            assert_eq!(JobCursor::decode(&bad), None, "{bad}");
        }
    }

    #[test]
    fn statuses_round_trip() {
        for s in JobStatus::ALL {
            assert_eq!(parse_status(s.as_str()).unwrap(), s);
        }
        assert!(parse_status("finished").is_err());
    }
}
