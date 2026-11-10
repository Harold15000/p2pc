// SPDX-License-Identifier: AGPL-3.0-only

//! The jobs endpoints (spec §7): create, list, get, cancel and estimate.
//!
//! A job stays `queued` until the scheduler (T06) places it: nothing here places a job or talks to a node.
//!
//! **Secrets.** A job's `env` values and input file contents live in the stored spec and nowhere else. No handler
//! logs the spec, a body or a header, and every response is built with `JobSpecView`, which redacts them (§7).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{Estimate, Job, JobSpec, JobStatus, Page, Problem};
use p2pc_proto::ids::{JobId, NodeId};
use p2pc_proto::units::estimate_units;
use p2pc_proto::validate::{ErrorCode, ImageRef, Limits, image_allowed};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::app::{AppState, bad_cursor, page_limit};
use crate::auth::{Authorized, JobsReadKey, JobsWriteKey, recheck_caller};
use crate::error::ApiError;
use crate::extract::{ApiJson, ApiQuery};
use crate::spec_hash::spec_hash;
use crate::store;
use crate::store::job_state::transition;
use crate::store::jobs::{self, JobCursor, JobRow, ListFilter, NewJob};
use crate::units::{check_cap, gpu_hour_units, spent_today};

/// The header that carries an idempotency key (§7), as an alternative to the `idempotency_key` field.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// A request body checked, normalized and measured, ready to be stored.
#[derive(Debug)]
struct Prepared {
    /// The spec as it will be stored: the image in its normalized form, defaults applied, and the idempotency key
    /// (from the header or the field) in `idempotency_key`.
    spec: JobSpec,
    /// The normalized image, for the key's `allowed_images`.
    image: ImageRef,
    /// `sha256:<hex>` of the canonical JSON of `spec`.
    hash: String,
}

fn idempotency_field_error(message: &str) -> ApiError {
    ApiError::field("idempotency_key", ErrorCode::InvalidFormat, message)
}

/// The validation shared by `POST /v1/jobs` and `POST /v1/estimate`:
/// 1. the `Idempotency-Key` header and the `idempotency_key` field, if both are given, must be equal (`422`);
/// 2. every rule of the §7 table, with `Limits` from the server's configured registries (`422`, with field paths;
///    `unsupported_pool` and `too_large` have their own codes);
/// 3. the image is normalized, and the spec hashed.
fn prepare(state: &AppState, mut spec: JobSpec, headers: &HeaderMap) -> Result<Prepared, ApiError> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    if let Some(value) = values.next() {
        if values.next().is_some() {
            return Err(idempotency_field_error(
                "the Idempotency-Key header may be given only once",
            ));
        }
        let text = value
            .to_str()
            .map_err(|_| idempotency_field_error("must be printable ASCII"))?;
        match &spec.idempotency_key {
            Some(field) if field != text => {
                return Err(idempotency_field_error(
                    "the Idempotency-Key header and the `idempotency_key` field differ",
                ));
            }
            _ => spec.idempotency_key = Some(text.to_string()),
        }
    }
    let limits = Limits {
        allowed_registries: Some(state.config.allowed_registries.clone()),
        ..Limits::default()
    };
    spec.validate(&limits).map_err(|e| ApiError::validation(&e))?;
    // Validation parsed the image, so these cannot fail; a failure would be a bug, and is an internal error.
    let image = spec.normalized_image().map_err(|_| ApiError::internal())?;
    spec.image = image.to_string();
    let value = serde_json::to_value(&spec).map_err(|_| ApiError::internal())?;
    Ok(Prepared {
        hash: spec_hash(&value),
        spec,
        image,
    })
}

/// The response for a stored job.
fn job_response(status: StatusCode, row: &JobRow) -> Result<Response, ApiError> {
    let job = row.to_job();
    let mut resp = (status, Json(job)).into_response();
    if status == StatusCode::CREATED
        && let Ok(location) = HeaderValue::from_str(&format!("/v1/jobs/{}", row.job_id))
    {
        resp.headers_mut().insert(header::LOCATION, location);
    }
    Ok(resp)
}

fn parse_job_id(id: &str) -> Result<JobId, ApiError> {
    id.parse().map_err(|_| ApiError::not_found())
}

/// Submits a job. It is stored `queued` (attempt 1), and the scheduler places it later.
///
/// - The body is validated with the §7 table; the image is normalized.
/// - The key's `allowed_images` must cover the normalized image (`403 image_not_allowed`), and its `daily_unit_cap`
///   must hold the estimate on top of what the key has reserved today, UTC (`402 cap_exceeded`; exactly at the cap is
///   allowed).
/// - **Idempotency.** The key comes from `idempotency_key` or the `Idempotency-Key` header (if both are given they
///   must be equal). The same key with the same request returns the existing job (`200`); with a different request,
///   `409 idempotency_conflict`. Two concurrent identical requests create one job. Idempotency keys are scoped to
///   the **API key** that submitted the job, and no response ever contains one: another key reusing the same
///   idempotency key simply gets its own new job (`201`), so it learns nothing about this one.
/// - The caller's key is reloaded inside the transaction (§5): a key revoked or expired mid-request gets `401` and
///   no job is created.
#[utoipa::path(
    post,
    path = "/v1/jobs",
    tag = "jobs",
    request_body = JobSpec,
    params(("Idempotency-Key" = Option<String>, Header, description = "Makes the submission idempotent; must equal `idempotency_key` if both are given. 1-255 printable ASCII characters.")),
    responses(
        (status = 201, description = "The job was created and is queued.", body = Job, headers(("Location" = String, description = "`/v1/jobs/{id}`"))),
        (status = 200, description = "This API key already used the idempotency key with the same request: the existing job.", body = Job),
        (status = 401, description = "Missing or invalid key, or the key was revoked or expired while the request was in flight.", content_type = "application/problem+json", body = Problem),
        (status = 402, description = "`cap_exceeded`: the job's estimate would exceed the key's daily unit cap.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the key lacks `jobs:write`. `image_not_allowed`: the key's allowed images do not cover the image.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`idempotency_conflict`: this API key already used the idempotency key with a different request. (Idempotency keys are scoped to the API key; another key reusing it gets its own job.)", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid job: `errors` lists each field. Codes: `validation_failed`, `unsupported_pool`, `too_large` (the job does not fit its `Lease` frame), `invalid_body`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn create_job(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsWriteKey,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<JobSpec>,
) -> Result<Response, ApiError> {
    let prepared = prepare(&state, spec, &headers)?;
    // All the CPU work happens BEFORE the write lock is taken, so SQLite's single writer is never held while a
    // 512 KiB input is base64-decoded and hashed, or while the estimate is computed.
    // - the file metadata is computed once here, stored, and used by every response: listing jobs never decodes
    //   file contents again;
    // - the estimate is what the cap is checked against and what is reserved.
    let files_meta = p2pc_proto::api::FileMeta::compute_all(&prepared.spec).map_err(|_| ApiError::internal())?;
    let units = estimate_units(
        &prepared.spec.resources,
        prepared.spec.timeout_s,
        gpu_hour_units(&state.config),
    );
    let job_id = JobId::generate();
    // Reads (the caller, an earlier job with the key, the day's reservations), then writes: IMMEDIATE (see
    // `store::begin_immediate`). It also serializes concurrent submissions, so "look up the key, then insert" cannot
    // race; the unique indexes on `(key_id, idempotency_key)` and `(device_id, idempotency_key)` are the backstop.
    let mut tx = store::begin_immediate(&state.db).await?;
    // One `now`, read once the write lock is held.
    let now = state.clock.now();
    // §5 "Re-checked at the point of use": the key's current row decides, not the one read at authentication.
    let caller = recheck_caller(&mut tx, &state, &p, now).await?;
    if let Some(patterns) = &caller.allowed_images
        && !image_allowed(patterns, &prepared.image)
    {
        return Err(ApiError::image_not_allowed(&prepared.spec.image));
    }
    // A replay is answered before the cap: the job already exists and is already counted. Idempotency keys are
    // scoped to the principal (§7, H2 §5.6): only this key's or device's own jobs can answer, so a replay by another
    // principal is just a new job and says nothing about anyone else's.
    if let Some(key) = &prepared.spec.idempotency_key
        && let Some(existing) = jobs::find_by_idempotency_key(&mut tx, p.account_id, p.project_id, p.id, key).await?
    {
        return if existing.spec_hash == prepared.hash {
            job_response(StatusCode::OK, &existing)
        } else {
            Err(ApiError::idempotency_conflict())
        };
    }
    if let Some(cap) = caller.daily_unit_cap {
        let reserved = spent_today(&mut tx, p.account_id, p.id, now).await?;
        check_cap(cap, reserved, units).map_err(|c| ApiError::cap_exceeded(c.cap, c.reserved, c.estimate))?;
    }
    let new = NewJob {
        job_id,
        account_id: p.account_id,
        project_id: p.project_id,
        principal: p.id,
        spec: prepared.spec,
        files_meta,
        spec_hash: prepared.hash,
        units_reserved: units,
    };
    let row = jobs::insert(&mut tx, &new, now).await?;
    tx.commit().await?;
    // The ID and the key only: never the spec.
    tracing::info!(job_id = %row.job_id, principal = %p.id, "job created");
    state.kick.kick();
    job_response(StatusCode::CREATED, &row)
}

/// `status`, `node_id`, `limit` and `cursor`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct JobListParams {
    /// Page size, 1-100 (default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page (opaque).
    pub cursor: Option<String>,
    /// Only jobs in this state: `queued`, `assigned`, `running`, `succeeded`, `failed`, `timed_out`, `cancelled` or
    /// `lost`.
    pub status: Option<String>,
    /// Only jobs of this node.
    pub node_id: Option<String>,
}

/// Lists the caller's jobs, newest first (`created_at` descending, then `id`), with cursor pagination.
#[utoipa::path(
    get,
    path = "/v1/jobs",
    tag = "jobs",
    params(JobListParams),
    responses(
        (status = 200, description = "A page of jobs. `spec.env` values are `<redacted>` and `spec.files` have no content.", body = Page<Job>),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks `jobs:read`.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit`, `cursor`, `status` or `node_id`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_jobs(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    ApiQuery(q): ApiQuery<JobListParams>,
) -> Result<Json<Page<Job>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| JobCursor::decode(c).ok_or_else(bad_cursor))
        .transpose()?;
    let status = q
        .status
        .as_deref()
        .map(|s| {
            JobStatus::ALL
                .into_iter()
                .find(|v| v.as_str() == s)
                .ok_or_else(|| ApiError::field("status", ErrorCode::InvalidFormat, "not a job status"))
        })
        .transpose()?;
    let node_id = q
        .node_id
        .as_deref()
        .map(|n| {
            n.parse::<NodeId>()
                .map_err(|_| ApiError::field("node_id", ErrorCode::InvalidFormat, "not a node ID"))
        })
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut rows = jobs::list(
        &mut conn,
        p.account_id,
        p.project_id,
        ListFilter { status, node_id },
        after,
        limit + 1,
    )
    .await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| rows.last().map(|r| JobCursor::after(r).encode()))
        .flatten();
    let items = rows.iter().map(JobRow::to_job).collect();
    Ok(Json(Page { items, next_cursor }))
}

/// One job of the caller, with its `attempts` (§7): `[{attempt, node_id, outcome, reason, started_at, ended_at}]`,
/// oldest first. `outcome` uses the job-state words (`running` while the attempt is in progress). A job of another
/// account answers `404`, exactly like one that does not exist (SI-7).
#[utoipa::path(
    get,
    path = "/v1/jobs/{id}",
    tag = "jobs",
    params(("id" = String, Path, description = "The job ID (`job_…`).")),
    responses(
        (status = 200, description = "The job, with its `attempts` (oldest first; refused or unanswered offers are not attempts). `spec.env` values are `<redacted>` and `spec.files` have no content.", body = Job),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks `jobs:read`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_job(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    Path(id): Path<String>,
) -> Result<Json<Job>, ApiError> {
    let id = parse_job_id(&id)?;
    let mut conn = state.db.acquire().await?;
    let row = jobs::get(&mut conn, p.account_id, p.project_id, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let mut job = row.to_job();
    // Only here: lists of jobs leave the attempts out (§7).
    job.attempts = Some(jobs::attempts(&mut conn, p.account_id, p.project_id, id).await?);
    Ok(Json(job))
}

/// Cancels a job. Idempotent.
///
/// - `queued`: becomes `cancelled` at once.
/// - `assigned` or `running`: the status does not change yet. `cancel_requested_at` is set (once), and the scheduler
///   delivers the `Cancel` to the node; the job ends `cancelled` when the node reports.
/// - Already finished: `200` with the job unchanged.
#[utoipa::path(
    post,
    path = "/v1/jobs/{id}/cancel",
    tag = "jobs",
    params(("id" = String, Path, description = "The job ID (`job_…`).")),
    responses(
        (status = 200, description = "The job after the request.", body = Job),
        (status = 401, description = "Missing or invalid key, or the key was revoked or expired while the request was in flight.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks `jobs:write`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn cancel_job(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsWriteKey,
    Path(id): Path<String>,
) -> Result<Json<Job>, ApiError> {
    let id = parse_job_id(&id)?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    recheck_caller(&mut tx, &state, &p, now).await?;
    let job = jobs::get(&mut tx, p.account_id, p.project_id, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let job = match job.status {
        JobStatus::Queued => transition(&mut tx, &job, JobStatus::Cancelled, "cancelled_by_user", now).await?,
        JobStatus::Assigned | JobStatus::Running => {
            // Only the first request sets the time; asking again changes nothing.
            if jobs::request_cancel(&mut tx, p.account_id, p.project_id, id, now).await? {
                tracing::info!(job_id = %id, principal = %p.id, "job cancel requested");
            }
            jobs::get(&mut tx, p.account_id, p.project_id, id)
                .await?
                .ok_or_else(ApiError::not_found)?
        }
        // Finished: nothing to do.
        JobStatus::Succeeded | JobStatus::Failed | JobStatus::TimedOut | JobStatus::Cancelled | JobStatus::Lost => job,
    };
    tx.commit().await?;
    // The scheduler delivers the `Cancel` (or revokes an offer of a job cancelled while queued).
    state.kick.kick();
    Ok(Json(job.to_job()))
}

/// Asks what would happen to a job, without creating it. The body, the header and the validation are those of
/// `POST /v1/jobs`.
///
/// `matching_nodes` counts the enrolled nodes that could ever run the job (right pool, labels, a ready sandbox
/// driver, enough offered capacity and GPUs) and `would_queue` says whether it would wait for room right now (no
/// matching node is online, connected, not draining and with enough free capacity). With no matching node,
/// `feasible` is false and `would_queue` true, with a `reason`; a job submitted anyway stays queued, because nothing
/// expires in v0.1. When the request carries the idempotency key of a job this key already submitted with the same
/// body, and that job is held in the queue after 10 failed offers (§8 "Offer cap"), `reason` is that job's reason.
/// `units_per_hour` is the job's cost per hour, in milli-units.
#[utoipa::path(
    post,
    path = "/v1/estimate",
    tag = "jobs",
    request_body = JobSpec,
    params(("Idempotency-Key" = Option<String>, Header, description = "Accepted and validated like in `POST /v1/jobs`; an estimate creates nothing.")),
    responses(
        (status = 200, description = "The estimate.", body = Estimate),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the key lacks `jobs:read`. `image_not_allowed`: the key may not run the image.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid job, as in `POST /v1/jobs`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn estimate(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<JobSpec>,
) -> Result<Json<Estimate>, ApiError> {
    let prepared = prepare(&state, spec, &headers)?;
    if let Some(patterns) = &p.allowed_images
        && !image_allowed(patterns, &prepared.image)
    {
        return Err(ApiError::image_not_allowed(&prepared.spec.image));
    }
    let found = state.nodes.match_job(p.account_id, &prepared.spec).await;
    let feasible = found.matching_nodes > 0;
    // §8 "Offer cap": when this key already submitted this very request (same idempotency key, same body) and the
    // job is stuck after 10 failed offers, the estimate says why, like `GET /v1/jobs/{id}`.
    let submitted = match &prepared.spec.idempotency_key {
        Some(key) => {
            let mut conn = state.db.acquire().await?;
            jobs::find_by_idempotency_key(&mut conn, p.account_id, p.project_id, p.id, key)
                .await?
                .filter(|j| j.spec_hash == prepared.hash && j.status == JobStatus::Queued)
        }
        None => None,
    };
    let stuck = submitted.and_then(|j| j.reason);
    let would_queue = found.free_nodes == 0 || stuck.is_some();
    let reason = if let Some(stuck) = stuck {
        Some(stuck)
    } else if !feasible {
        Some("No enrolled node can run this job (no node matches its requirements, or no node is enrolled yet).".into())
    } else if would_queue {
        Some("Every matching node is busy or offline right now; the job would wait in the queue.".into())
    } else {
        None
    };
    Ok(Json(Estimate {
        feasible,
        matching_nodes: found.matching_nodes,
        would_queue,
        units_per_hour: estimate_units(&prepared.spec.resources, 3600, gpu_hour_units(&state.config)),
        reason,
    }))
}
