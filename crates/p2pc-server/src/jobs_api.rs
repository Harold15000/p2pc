// SPDX-License-Identifier: AGPL-3.0-only

//! The jobs endpoints (spec §7): create, list, get, cancel and estimate.
//!
//! A job stays `queued` until the scheduler (T06) places it: nothing here places a job or talks to a node.
//!
//! **Secrets.** A job's `env` values and input file contents live in the stored spec and nowhere else. No handler
//! logs the spec, a body or a header, and every response is built with `JobSpecView`, which redacts them (§7).
//!
//! **Who sees which job** (H2 §5.5 "Template view"). One function, [`job_visibility`], decides it for every job
//! route: `jobs:read`, `jobs:write` and `services:connect` keep H1's project-wide rule for their routes; a principal
//! without them but with `templates:launch` gets the narrow template view (the template jobs it launched and, except
//! for logs and outputs, the instances of `singleton` templates); anyone else gets `403`. A job outside the view
//! answers `404`, exactly like one that does not exist, and is left out of listings ([`visible_job`],
//! [`jobs::list`]).

use std::fmt;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{
    AllowedRoute, Estimate, Job, JobKind, JobSpec, JobStatus, Page, Problem, REASON_STOPPED, Scope, ServiceView,
};
use p2pc_proto::ids::{JobId, NodeId};
use p2pc_proto::units::{Units, estimate_units};
use p2pc_proto::validate::{ErrorCode, H2Features, ImageRef, Limits, image_allowed};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use utoipa::IntoParams;

use crate::app::{AppState, bad_cursor, page_limit};
use crate::auth::{AnyKey, Authorized, JobsReadKey, JobsWriteKey, Principal, recheck_caller};
use crate::error::ApiError;
use crate::extract::{ApiJson, ApiQuery};
use crate::scheduler::service::RESTART_WINDOW;
use crate::spec_hash::spec_hash;
use crate::store::job_state::transition;
use crate::store::jobs::{self, JobCursor, JobRow, ListFilter, NewJob, Visibility};
use crate::store::{self, Conn, leases};
use crate::units::{check_cap, gpu_hour_units, reserve_new_service, spent_today};

/// The header that carries an idempotency key (§7), as an alternative to the `idempotency_key` field.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Which templates are `singleton` (H2 §7.6): an instance of one is shared by every principal that may launch it, so
/// the template view shows it to all of them (§5.5). T2-15 implements this over the template bundle the hub serves.
pub trait TemplateCatalog: Send + Sync + fmt::Debug + 'static {
    /// The ids of the `singleton` templates of the bundle the hub serves now.
    fn singleton_ids(&self) -> Vec<String>;

    /// The `allowed_routes` of the template `template_id` in the bundle the hub serves now (H2 §7.4, §7.6): the
    /// requests a principal that is not `admin` may send to a service of that template. Empty when no bundle is
    /// served or the bundle has no such template, so nothing matches and the service is closed to them.
    fn allowed_routes(&self, template_id: &str) -> Vec<AllowedRoute> {
        let _ = template_id;
        Vec::new()
    }
}

/// No template bundle is loaded: no template is `singleton`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoTemplates;

impl TemplateCatalog for NoTemplates {
    fn singleton_ids(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A job route, as far as access to it goes (H2 §5.5 "Template view").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobRoute {
    /// `GET /v1/jobs` and `GET /v1/jobs/{id}`.
    State,
    /// `GET /v1/jobs/{id}/logs` and `GET /v1/jobs/{id}/outputs[/{path}]`.
    Artifacts,
    /// `POST /v1/jobs/{id}/cancel`.
    Cancel,
    /// `POST /v1/jobs/{id}/ports/{port}/connect` (T2-13).
    Port,
}

impl JobRoute {
    /// The H1 scope that gives project-wide access to the route.
    #[must_use]
    pub const fn project_scope(self) -> Scope {
        match self {
            JobRoute::State | JobRoute::Artifacts => Scope::JobsRead,
            JobRoute::Cancel => Scope::JobsWrite,
            JobRoute::Port => Scope::ServicesConnect,
        }
    }
}

/// Which jobs of its account and project `p` reaches through `route`: **the one access rule of the job routes** (H2
/// §5.5 "Template view", §7.2 "Who can stop a service").
///
/// - With the route's H1 scope (`jobs:read` for state, logs and outputs; `jobs:write` for cancel; `services:connect`
///   for ports; `admin` covers all), every job of the project, as in H1. The template view never narrows it.
/// - Without it but with `templates:launch`, the template view: the template jobs `p` launched itself and every
///   instance of a `singleton` template, whoever launched it. Logs and outputs are narrower still: only the jobs `p`
///   launched, so a singleton instance launched by someone else shows its state but not its logs or outputs.
/// - Otherwise `403 forbidden`, naming the H1 scope.
pub fn job_visibility(state: &AppState, p: &Principal, route: JobRoute) -> Result<Visibility, ApiError> {
    let scope = route.project_scope();
    if p.has_scope(scope) {
        return Ok(Visibility::Project);
    }
    if !p.has_scope(Scope::TemplatesLaunch) {
        return Err(ApiError::forbidden(scope));
    }
    Ok(Visibility::Template {
        launched_by: p.id,
        singletons: (route != JobRoute::Artifacts).then(|| state.templates.singleton_ids()),
    })
}

/// The job `id` of `p`'s account and project, if `route` lets `p` reach it ([`job_visibility`]). A job of another
/// account or project, one outside the caller's view and one that does not exist all answer the same `404` (SI-7,
/// H2 §5.5). Through the template view, a port is reachable only on a template **service** (H2 §7.4).
pub async fn visible_job(
    conn: &mut Conn,
    state: &AppState,
    p: &Principal,
    route: JobRoute,
    id: JobId,
) -> Result<JobRow, ApiError> {
    let visible = job_visibility(state, p, route)?;
    let row = jobs::get(conn, p.account_id, p.project_id, id)
        .await?
        .filter(|row| visible.allows(row))
        .ok_or_else(ApiError::not_found)?;
    if route == JobRoute::Port && visible != Visibility::Project && row.spec_view.kind != JobKind::Service {
        return Err(ApiError::not_found());
    }
    Ok(row)
}

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
        // Service jobs are served from T2-12 on, blob inputs from T2-14 on and volumes from T2-15 on. A client's
        // body is validated as `SpecContext::Create`: volumes only on a service, and never a `tpl:` name.
        h2: H2Features::ALL,
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
        (status = 422, description = "Invalid job: `errors` lists each field. Codes: `validation_failed`, `unsupported_pool`, `too_large` (the job does not fit its `Lease` frame), `invalid_body`, `unknown_blob` (an `inputs` blob the caller's account does not hold), `inputs_exceed_disk` (blob inputs and inline files over `resources.disk_mb` minus 64 MiB).", content_type = "application/problem+json", body = Problem),
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
    // H2 §12: a service reserves nothing at creation in `units_reserved` (0); a capped principal's service holds a
    // reservation for one UTC day at a time instead (below).
    let service = prepared.spec.kind == JobKind::Service;
    let units = if service {
        Units::ZERO
    } else {
        estimate_units(
            &prepared.spec.resources,
            prepared.spec.timeout_s,
            gpu_hour_units(&state.config),
        )
    };
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
    // Blob inputs (H2 §7.1, §7.5): every blob must be a live blob of the caller's account, checked in this
    // transaction, which also inserts the references (`jobs::insert`). Either the reference exists before the GC's
    // re-check, which then keeps the blob, or the tombstone exists before this check, and the job gets `422
    // unknown_blob`.
    if !prepared.spec.inputs.is_empty() {
        let blob_bytes = store::blobs::resolve_inputs(&mut tx, p.account_id, &prepared.spec.inputs)
            .await?
            .map_err(|i| {
                ApiError::unprocessable(
                    "unknown_blob",
                    format!("inputs[{i}].blob: this account has no such blob (upload it with POST /v1/blobs first)."),
                )
            })?;
        prepared
            .spec
            .check_inputs_fit_disk(blob_bytes)
            .map_err(|e| ApiError::validation(&e))?;
    }
    let mut day_hold = None;
    if let Some(cap) = caller.daily_unit_cap {
        if service {
            // H2 §12 "Caps for services": the day's reservation, refused under 15 minutes of runtime.
            let gpu_hour = gpu_hour_units(&state.config);
            let held = reserve_new_service(&mut tx, p.account_id, p.id, cap, &prepared.spec, gpu_hour, now)
                .await?
                .map_err(|c| ApiError::cap_exceeded(c.cap, c.reserved, c.estimate))?;
            day_hold = Some(held);
        } else {
            let reserved = spent_today(&mut tx, p.account_id, p.id, now).await?;
            check_cap(cap, reserved, units).map_err(|c| ApiError::cap_exceeded(c.cap, c.reserved, c.estimate))?;
        }
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
    if let Some(held) = day_hold {
        crate::units::hold(&mut tx, row.job_id, held, now).await?;
    }
    tx.commit().await?;
    // The ID and the key only: never the spec.
    tracing::info!(job_id = %row.job_id, principal = %p.id, "job created");
    state.kick.kick();
    job_response(StatusCode::CREATED, &row)
}

/// `status`, `node_id`, `kind`, `limit` and `cursor`.
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
    /// Only jobs of this kind: `batch` or `service`.
    pub kind: Option<String>,
}

/// Lists the caller's jobs, newest first (`created_at` descending, then `id`), with cursor pagination.
///
/// With `jobs:read`, every job of the project. With `templates:launch` and no `jobs:read`, the template view (H2
/// §5.5): the template jobs the caller launched and the instances of `singleton` templates; no other job is listed.
#[utoipa::path(
    get,
    path = "/v1/jobs",
    tag = "jobs",
    params(JobListParams),
    responses(
        (status = 200, description = "A page of jobs. `spec.env` values are `<redacted>` and `spec.files` have no content.", body = Page<Job>),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller has neither `jobs:read` nor `templates:launch`.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit`, `cursor`, `status`, `node_id` or `kind`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_jobs(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    ApiQuery(q): ApiQuery<JobListParams>,
) -> Result<Json<Page<Job>>, ApiError> {
    let visible = job_visibility(&state, &p, JobRoute::State)?;
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
    let kind = match q.kind.as_deref() {
        None => None,
        Some("batch") => Some(JobKind::Batch),
        Some("service") => Some(JobKind::Service),
        Some(_) => {
            return Err(ApiError::field(
                "kind",
                ErrorCode::InvalidFormat,
                "must be `batch` or `service`",
            ));
        }
    };
    let mut conn = state.db.acquire().await?;
    let mut rows = jobs::list(
        &mut conn,
        p.account_id,
        p.project_id,
        &visible,
        ListFilter { status, node_id, kind },
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

/// The `service` member of `GET /v1/jobs/{id}` (H2 §7.2), for a service: its health while it runs, its ports, the
/// open connections, the idle and wall-clock deadlines and the node-loss restarts of the last 24 h. `None` for a batch
/// job.
///
/// `last_activity_at` is what the idle timeout counts from: the attempt's first `healthy`, then the traffic the port
/// relay records. `cap_deadline` is when the day's cap reservation runs out (H2 §12), `null` for an uncapped principal
/// or while no attempt runs. `traffic` is what the port relay recorded for today, UTC (H2 §12), `null` when the day has
/// none; a connection's bytes are added at most 10 s after they were relayed. `setup` belongs to the template task and
/// stays `null` here.
async fn service_view(
    conn: &mut Conn,
    state: &AppState,
    row: &JobRow,
    now: OffsetDateTime,
) -> Result<Option<ServiceView>, ApiError> {
    let Some(spec) = row
        .spec_view
        .service
        .as_ref()
        .filter(|_| row.spec_view.kind == JobKind::Service)
    else {
        return Ok(None);
    };
    let st = leases::service_state(conn, row.job_id).await?;
    let running = row.status == JobStatus::Running;
    let open_connections = state.connections.count(row.job_id);
    let idle_deadline = spec
        .idle_timeout_s
        .zip(st.last_activity_at)
        .filter(|_| running && open_connections == 0)
        .map(|(timeout, at)| at + Duration::seconds(i64::from(timeout)));
    let deadline = row
        .started_at
        .filter(|_| running)
        .map(|at| at + Duration::seconds(i64::from(row.spec_view.timeout_s)));
    let restarts = st
        .node_loss_restarts
        .iter()
        .filter(|at| now.unix_timestamp() - **at < RESTART_WINDOW.whole_seconds())
        .count();
    Ok(Some(ServiceView {
        health: st.health.filter(|_| running),
        health_since: st.health_since.filter(|_| running),
        ports: spec.ports.clone(),
        open_connections,
        last_activity_at: st.last_activity_at,
        idle_deadline,
        deadline,
        restarts_24h: u32::try_from(restarts).unwrap_or(u32::MAX),
        cap_deadline: crate::units::cap_deadline(conn, row.job_id, gpu_hour_units(&state.config)).await?,
        traffic: store::ports::traffic_today(conn, row.job_id, now).await?,
        ..ServiceView::default()
    }))
}

/// One job of the caller, with its `attempts` (§7): `[{attempt, node_id, outcome, reason, started_at, ended_at}]`,
/// oldest first. `outcome` uses the job-state words (`running` while the attempt is in progress). A job of another
/// account answers `404`, exactly like one that does not exist (SI-7), and so does a job outside the caller's
/// template view (H2 §5.5).
///
/// A service adds `service` (H2 §7.2): `health` and `health_since` while it runs, `ports`, `open_connections`,
/// `last_activity_at`, `idle_deadline`, `deadline`, `restarts_24h` and `traffic`, today's totals of its port
/// connections (H2 §12).
#[utoipa::path(
    get,
    path = "/v1/jobs/{id}",
    tag = "jobs",
    params(("id" = String, Path, description = "The job ID (`job_…`).")),
    responses(
        (status = 200, description = "The job, with its `attempts` (oldest first; refused or unanswered offers are not attempts). `spec.env` values are `<redacted>` and `spec.files` have no content.", body = Job),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller has neither `jobs:read` nor `templates:launch`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account, or (for a caller with only `templates:launch`) not a job of its template view.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_job(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
) -> Result<Json<Job>, ApiError> {
    // The access rule before the ID: a caller with no access gets `403` whatever it asks for.
    job_visibility(&state, &p, JobRoute::State)?;
    let id = parse_job_id(&id)?;
    let mut conn = state.db.acquire().await?;
    let row = visible_job(&mut conn, &state, &p, JobRoute::State, id).await?;
    let mut job = row.to_job();
    // Only here: lists of jobs leave the attempts out (§7).
    job.attempts = Some(jobs::attempts(&mut conn, p.account_id, p.project_id, id).await?);
    job.service = service_view(&mut conn, &state, &row, state.clock.now()).await?;
    Ok(Json(job))
}

/// Cancels a job. Idempotent.
///
/// - `queued`: becomes `cancelled` at once.
/// - `assigned` or `running`: the status does not change yet. `cancel_requested_at` is set (once), and the scheduler
///   delivers the `Cancel` to the node; the job ends `cancelled` when the node reports.
/// - Already finished: `200` with the job unchanged.
///
/// A **service** stopped this way ends `cancelled` with `reason: "stopped"` (H2 §7.2).
///
/// **Who may cancel** (H2 §7.2). With `jobs:write`, any job of the caller's account and project, as in H1. Without it
/// but with `templates:launch`, the jobs of the caller's template view: a template job it launched itself, or an
/// instance of a `singleton` template (shared by every launcher, so any of them may stop it). Any other job answers
/// `404`.
#[utoipa::path(
    post,
    path = "/v1/jobs/{id}/cancel",
    tag = "jobs",
    params(("id" = String, Path, description = "The job ID (`job_…`).")),
    responses(
        (status = 200, description = "The job after the request.", body = Job),
        (status = 401, description = "Missing or invalid key, or the key was revoked or expired while the request was in flight.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller has neither `jobs:write` nor `templates:launch`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account, or (for a caller with only `templates:launch`) not a job of its template view.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn cancel_job(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
) -> Result<Json<Job>, ApiError> {
    // The access rule before the ID and before the write lock: a caller with no access gets `403` and takes nothing.
    job_visibility(&state, &p, JobRoute::Cancel)?;
    let id = parse_job_id(&id)?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    // The caller's current row decides what it may reach (§5 "Re-checked at the point of use").
    let caller = recheck_caller(&mut tx, &state, &p, now).await?;
    let job = visible_job(&mut tx, &state, &caller, JobRoute::Cancel, id).await?;
    let service = job.spec_view.kind == JobKind::Service;
    let reread = async |tx: &mut Conn| {
        jobs::get(tx, p.account_id, p.project_id, id)
            .await?
            .ok_or_else(ApiError::not_found)
    };
    let job = match job.status {
        JobStatus::Queued => {
            let cancelled = transition(&mut tx, &job, JobStatus::Cancelled, "cancelled_by_user", now).await?;
            if service {
                // H2 §7.2: stopped by a principal → `cancelled`, `reason: "stopped"`.
                leases::set_cancelled_reason(&mut tx, id, REASON_STOPPED).await?;
                reread(&mut tx).await?
            } else {
                cancelled
            }
        }
        JobStatus::Assigned | JobStatus::Running => {
            // Only the first request sets the time (and, for a service, why it stops); asking again changes nothing.
            let requested = if service {
                leases::request_stop(&mut tx, id, REASON_STOPPED, now).await?
            } else {
                jobs::request_cancel(&mut tx, p.account_id, p.project_id, id, now).await?
            };
            if requested {
                tracing::info!(job_id = %id, principal = %p.id, "job cancel requested");
            }
            reread(&mut tx).await?
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
