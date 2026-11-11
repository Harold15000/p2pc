// SPDX-License-Identifier: AGPL-3.0-only

//! The axum router: routes, handlers, fallbacks and the cross-cutting layers.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use p2pc_proto::api::{
    ApiKeyInfo, AuditEvent, AuditKind, CreateApiKey, Health, MAX_PAGE_LIMIT, NewApiKey, Page, Problem, WhoAmI,
};
use p2pc_proto::auth::{ApiKey, Secret, SecretHash, hash_secret};
use p2pc_proto::ids::{AccountId, KeyId};
use p2pc_proto::validate::{ErrorCode, PrincipalLimits, check_limits_no_escalation};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use utoipa::IntoParams;

use crate::audit_queue::AuthFailureQueue;
use crate::auth::{AdminKey, AnyKey, Authorized, recheck_caller, require_api_key, require_device};
use crate::clock::Clock;
use crate::config::Config;
use crate::error::{self, ApiError};
use crate::extract::{ApiJson, ApiQuery};
use crate::gateway::{NodeHub, ServerIdentity};
use crate::node_directory::{EmptyNodeDirectory, NodeDirectory};
use crate::nodes_api;
use crate::store::audit::NewEvent;
use crate::store::keys::{KeyCursor, MAX_DAILY_UNIT_CAP_MILLI, NewKey, Revoke};
use crate::store::{self, Db, StoreError};
use crate::{devices_api, jobs_api, join_requests_api};

/// Default page size of list endpoints.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// Shared state of every handler.
#[derive(Debug, Clone)]
pub struct AppState {
    /// The database.
    pub db: Db,
    /// The validated configuration.
    pub config: Arc<Config>,
    /// The clock (injectable for tests).
    pub clock: Arc<dyn Clock>,
    /// Digest compared against on a key lookup miss, so that path costs the same as a wrong secret (§5).
    pub dummy_digest: SecretHash,
    /// The server owner's account, read once at start. Failed authentications that match no key are recorded there
    /// without a database read on the request path.
    pub owner_account: Option<AccountId>,
    /// Where failed authentications go: a bounded queue to one writer task (§5 "Audit").
    pub auth_failures: AuthFailureQueue,
    /// The server's iroh identity and relays (`server.key`, `[iroh] relays`).
    pub server: Arc<ServerIdentity>,
    /// Live agent connections (filled by the node gateway; empty when it does not run).
    pub hub: NodeHub,
    /// What the API may ask about the nodes (`POST /v1/estimate`). Until the node registry exists (T05, T06) it is
    /// [`EmptyNodeDirectory`], which knows no node.
    pub nodes: Arc<dyn NodeDirectory>,
    /// Wakes the scheduler (T06): a job was created or cancelled, a node resumed or changed its inventory.
    pub kick: crate::scheduler::Kick,
    /// Stored job logs (T10b): the scheduler's `LogSink`, read by `GET /v1/jobs/{id}/logs`.
    pub logs: crate::logs::LogStore,
    /// Staged and published outputs (T10b): the gateway's uploads, the scheduler's `OutputsFinalizer`, and the
    /// outputs endpoints.
    pub outputs: crate::outputs::OutputStore,
    /// Live device connections (H2 §5.5): a revocation and the liveness sweep close them.
    pub devices: crate::devices_api::DeviceSessions,
    /// The open port connections of every service (H2 §7.4): counted by the port relay (T2-13), read by the
    /// scheduler's idle cancel and by `GET /v1/jobs/{id}`.
    pub connections: crate::scheduler::OpenConnections,
    /// Which templates are `singleton` (H2 §7.6), for the template view of the job routes (§5.5). Until the template
    /// bundle is loaded (T2-15) it is [`jobs_api::NoTemplates`]: no template, so no singleton instance.
    pub templates: Arc<dyn jobs_api::TemplateCatalog>,
}

impl AppState {
    /// Builds the state: reads the owner account and starts the auth-failure writer. The dummy digest is random per
    /// process.
    pub async fn load(db: Db, config: Config, clock: Arc<dyn Clock>) -> Result<Self, LoadError> {
        Self::load_with_queue(db, config, clock, crate::audit_queue::DEFAULT_CAPACITY).await
    }

    /// [`AppState::load`] with a given auth-failure queue capacity.
    pub async fn load_with_queue(
        db: Db,
        config: Config,
        clock: Arc<dyn Clock>,
        queue_capacity: usize,
    ) -> Result<Self, LoadError> {
        let key = crate::identity::load(&config.data_dir)?;
        let server = Arc::new(ServerIdentity::new(key, &config.iroh.relays));
        let mut conn = db.acquire().await.map_err(StoreError::from)?;
        let owner_account = store::accounts::owner(&mut conn).await?;
        drop(conn);
        let logs = crate::logs::LogStore::new(&config.data_dir);
        let outputs = crate::outputs::OutputStore::new(&config.data_dir, db.clone(), clock.clone(), logs.clone());
        Ok(Self {
            logs,
            outputs,
            auth_failures: AuthFailureQueue::spawn(db.clone(), queue_capacity),
            db,
            config: Arc::new(config),
            clock,
            dummy_digest: hash_secret(&Secret::generate()),
            owner_account,
            server,
            hub: NodeHub::new(),
            nodes: Arc::new(EmptyNodeDirectory),
            kick: crate::scheduler::Kick::default(),
            devices: crate::devices_api::DeviceSessions::default(),
            connections: crate::scheduler::OpenConnections::default(),
            templates: Arc::new(jobs_api::NoTemplates),
        })
    }
}

/// Why the app state could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// `server.key` is missing or unusable.
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
}

/// Which transport a router serves, and so how its requests are authenticated (H2 §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// The TCP REST listener and `p2pc/http/1`: API keys only.
    Keys,
    /// `p2pc/device/1`, served in-process: the device the transport attached, never a header.
    Devices,
}

/// The full router with its layers, for the TCP REST listener and `p2pc/http/1`: every request is authenticated by
/// API key ([`require_api_key`]). No header can turn a request into a device request (SI-H2-3).
pub fn router(state: AppState) -> Router {
    build(state, Transport::Keys)
}

/// The same API for requests of `p2pc/device/1` streams (H2 §6.3), which the device transport (T2-11) serves
/// in-process after attaching a [`crate::auth::DeviceConnection`] to each request: authenticated by
/// [`require_device`], with the same routes, limits and layers as [`router`].
pub fn device_router(state: AppState) -> Router {
    build(state, Transport::Devices)
}

fn build(state: AppState, transport: Transport) -> Router {
    let authenticated: Router<AppState> = Router::new()
        .route("/v1/whoami", get(whoami))
        .route("/v1/keys", get(list_keys).post(create_key))
        .route("/v1/keys/{key_id}", delete(revoke_key))
        .route("/v1/audit", get(list_audit))
        .route("/v1/server", get(nodes_api::get_server))
        .route(
            "/v1/nodes/join-tokens",
            get(nodes_api::list_join_tokens).post(nodes_api::create_join_token),
        )
        .route("/v1/nodes/join-tokens/{id}", delete(nodes_api::revoke_join_token))
        .route(
            "/v1/nodes/join-requests",
            get(join_requests_api::list_join_requests).post(join_requests_api::create_join_request),
        )
        .route(
            "/v1/nodes/join-requests/{id}",
            get(join_requests_api::get_join_request).delete(join_requests_api::reject_join_request),
        )
        .route(
            "/v1/nodes/join-requests/{id}/reveal",
            post(join_requests_api::reveal_join_request),
        )
        .route(
            "/v1/nodes/join-requests/{id}/approve",
            post(join_requests_api::approve_join_request),
        )
        .route(
            "/v1/nodes/join-requests/{id}/token",
            post(join_requests_api::join_request_token),
        )
        .route("/v1/nodes", get(nodes_api::list_nodes))
        .route(
            "/v1/nodes/{id}",
            get(nodes_api::get_node).delete(nodes_api::delete_node),
        )
        .route("/v1/nodes/{id}/drain", post(nodes_api::drain_node))
        .route("/v1/nodes/{id}/resume", post(nodes_api::resume_node))
        .route("/v1/nodes/{id}/approve", post(nodes_api::approve_node))
        .route(
            "/v1/devices/pairing-tickets",
            get(devices_api::list_pairing_tickets).post(devices_api::create_pairing_ticket),
        )
        .route(
            "/v1/devices/pairing-tickets/{id}",
            delete(devices_api::revoke_pairing_ticket),
        )
        .route("/v1/devices", get(devices_api::list_devices))
        .route(
            "/v1/devices/{id}",
            get(devices_api::get_device).delete(devices_api::revoke_device),
        )
        .route("/v1/jobs", get(jobs_api::list_jobs).post(jobs_api::create_job))
        .route("/v1/jobs/{id}", get(jobs_api::get_job))
        .route("/v1/jobs/{id}/cancel", post(jobs_api::cancel_job))
        .route("/v1/jobs/{id}/outputs", get(crate::artifacts_api::list_outputs))
        .route("/v1/estimate", post(jobs_api::estimate))
        .route("/v1/usage", get(crate::usage_api::get_usage));
    // Streaming routes opt out of the whole-request limit by being added here instead of to `bounded`. Each bounds
    // itself with an idle limit (`http.keepalive_idle_ms`): no data taken or sent for that long ends the stream
    // (§10, see `artifacts_api`). Logs in both modes (a 64 MiB page can outlast 30 s on a slow link) and downloads.
    let streaming: Router<AppState> = Router::new()
        .route("/v1/jobs/{id}/logs", get(crate::artifacts_api::get_logs))
        .route(
            "/v1/jobs/{id}/outputs/{*path}",
            get(crate::artifacts_api::download_output),
        );
    let (authenticated, streaming) = match transport {
        Transport::Keys => (
            authenticated.route_layer(middleware::from_fn_with_state(state.clone(), require_api_key)),
            streaming.route_layer(middleware::from_fn_with_state(state.clone(), require_api_key)),
        ),
        Transport::Devices => (
            authenticated.route_layer(middleware::from_fn_with_state(state.clone(), require_device)),
            streaming.route_layer(middleware::from_fn_with_state(state.clone(), require_device)),
        ),
    };
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/openapi.json", get(openapi_json));
    let http = &state.config.http;
    // §10 "Slow clients": every ordinary route gets the whole-request limit (the 408 becomes problem+json in
    // `with_layers`).
    let bounded = public.merge(authenticated).layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        http.request_timeout(),
    ));
    let app = bounded
        .merge(streaming)
        // After routing, so `MatchedPath` is known: hands the route template to the request log (see `log_request`).
        .route_layer(middleware::from_fn(record_route))
        // Every route, streaming ones included: a body that stops arriving for this long fails with 408. The
        // limit is between body frames; the whole-request limit above bounds a body that trickles.
        .layer(RequestBodyTimeoutLayer::new(http.body_read_timeout()))
        .with_state(state);
    with_layers(app)
}

/// Adds the fallbacks and the cross-cutting layers (panics → 500 problem+json, bare timeouts → 408
/// problem+json, request logging).
pub fn with_layers(router: Router) -> Router {
    router
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(middleware::map_response(problem_for_bare_timeout))
        .layer(middleware::from_fn(log_request))
}

/// `TimeoutLayer` answers an empty `408`; give it the API's problem+json body.
async fn problem_for_bare_timeout(resp: Response) -> Response {
    if resp.status() == StatusCode::REQUEST_TIMEOUT && !resp.headers().contains_key(header::CONTENT_TYPE) {
        ApiError::request_timeout().into_response()
    } else {
        resp
    }
}

/// A handler panicked: log that it did, without the request or the panic payload (which could hold data), and
/// answer `500` problem+json.
fn panic_response(_payload: Box<dyn std::any::Any + Send + 'static>) -> Response {
    tracing::error!("request handler panicked");
    ApiError::internal().into_response()
}

/// The matched route template of a request (`/v1/keys/{key_id}`), carried from the router to the request log in
/// the response extensions.
#[derive(Debug, Clone)]
struct RouteTemplate(String);

/// Placeholder logged for a request that matched no route.
const UNMATCHED_ROUTE: &str = "<unmatched>";

/// Route layer: copies the request's [`MatchedPath`] into the response extensions, where [`log_request`] reads it.
async fn record_route(matched: MatchedPath, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.extensions_mut()
        .insert(RouteTemplate(matched.as_str().to_string()));
    resp
}

/// Logs one line per request: method, the matched route template, status and latency. The raw URI path is never
/// logged, because it can hold a secret (`/v1/keys/p2pc_sk_…`) or an object ID, and neither are the query string,
/// headers or bodies, so API keys stay out of the log too (SI-6). A request that matched no route logs
/// `<unmatched>`.
async fn log_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let start = Instant::now();
    let resp = next.run(req).await;
    let route = resp
        .extensions()
        .get::<RouteTemplate>()
        .map_or(UNMATCHED_ROUTE, |r| r.0.as_str());
    tracing::info!(
        %method,
        route,
        status = resp.status().as_u16(),
        ms = start.elapsed().as_millis() as u64,
        "request"
    );
    resp
}

/// Liveness only, with no data.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "meta",
    security(()),
    responses((status = 200, description = "The server is up.", body = Health))
)]
pub async fn healthz() -> Json<Health> {
    Json(Health::ok())
}

/// The OpenAPI 3.1 document of this API.
#[utoipa::path(
    get,
    path = "/v1/openapi.json",
    tag = "meta",
    security(()),
    responses((status = 200, description = "The OpenAPI document.", content_type = "application/json", body = Object))
)]
pub async fn openapi_json() -> Response {
    let mut resp = crate::openapi::document().into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// Who the caller is, and its limits. `daily_unit_cap: null` means the caller is uncapped; `p2pc mcp` refuses such a
/// key. Never contains the secret.
///
/// `principal` names the caller, `{kind, id}` (H2 §5.5). `key_id` stays: the key for an API key, `null` for a device.
#[utoipa::path(
    get,
    path = "/v1/whoami",
    tag = "auth",
    responses(
        (status = 200, description = "The caller's account, project, ID, scopes and limits (`label`, `daily_unit_cap`, `allowed_images`, `expires_at`; `null` means no limit), and `principal` (`{kind, id}`, H2 §5.5). `key_id` is `null` for a device. Never the secret.", body = WhoAmI),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn whoami(Authorized { principal: p, .. }: AnyKey) -> Json<WhoAmI> {
    Json(WhoAmI {
        account_id: p.account_id,
        project_id: p.project_id,
        key_id: p.id.key_id(),
        scopes: p.scopes,
        label: p.label,
        daily_unit_cap: p.daily_unit_cap,
        allowed_images: p.allowed_images,
        expires_at: p.expires_at,
        principal: Some(p.id),
    })
}

/// `limit` and `cursor`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct PageParams {
    /// Page size, 1-100 (default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

pub(crate) fn page_limit(limit: Option<u32>) -> Result<u32, ApiError> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if (1..=MAX_PAGE_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(ApiError::field(
            "limit",
            ErrorCode::OutOfRange,
            format!("must be 1-{MAX_PAGE_LIMIT}"),
        ))
    }
}

pub(crate) fn bad_cursor() -> ApiError {
    ApiError::field(
        "cursor",
        ErrorCode::InvalidFormat,
        "not a cursor returned by this endpoint",
    )
}

/// The §5 "No escalation" rule for a key-creation request by a key: `403 escalation_denied` listing every field that
/// exceeds the creator. See [`ensure_limits_no_escalation`], which serves every principal.
pub fn ensure_no_escalation(creator: &ApiKeyInfo, request: &CreateApiKey) -> Result<(), ApiError> {
    ensure_limits_no_escalation(&creator.into(), &request.into())
}

/// The §5 "No escalation" rule for any principal (H2 §5.2, §5.5), with `p2pc-proto`'s [`check_limits_no_escalation`]:
/// `403 escalation_denied` listing every field of `asked` that exceeds `creator`.
pub fn ensure_limits_no_escalation(creator: &PrincipalLimits, asked: &PrincipalLimits) -> Result<(), ApiError> {
    check_limits_no_escalation(creator, asked).map_err(|denied| ApiError::escalation_denied(&denied))
}

/// Validates a key-creation body at `now`: the `p2pc-proto` rules, a storable `daily_unit_cap`, and an `expires_at`
/// in whole seconds.
///
/// Expiry is stored as Unix seconds. A fraction would be truncated silently, and the truncated value, not the one
/// the caller sent, would then be compared with the creator's own expiry; so a fraction is refused (`422`) instead
/// of rounded, and the caller learns the exact instant the key will stop working.
fn check_new_key(body: &CreateApiKey, now: OffsetDateTime) -> Result<(), ApiError> {
    body.validate(now).map_err(|e| ApiError::validation(&e))?;
    if body.expires_at.is_some_and(|t| t.nanosecond() != 0) {
        return Err(ApiError::field(
            "expires_at",
            ErrorCode::InvalidFormat,
            "must be a whole number of seconds (no fractional part)",
        ));
    }
    Ok(())
}

/// A JSON object for an audit `detail`.
fn detail(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// Creates an API key in the caller's project. The full key is in the response, once.
///
/// A key can never create a more powerful key (§5 "No escalation"): the scopes, `daily_unit_cap`,
/// `allowed_images` and `expires_at` of the new key are bounded by the caller's.
#[utoipa::path(
    post,
    path = "/v1/keys",
    tag = "keys",
    request_body = CreateApiKey,
    responses(
        (status = 201, description = "The key, shown only this once, and its metadata (flat).", body = NewApiKey),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the key lacks the admin scope. `escalation_denied`: the request asks for more than the calling key has (scopes, `daily_unit_cap`, `allowed_images` or `expires_at`); `errors` lists the fields.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid body. `expires_at` must be in the future and in whole seconds (no fractional part).", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn create_key(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    ApiJson(body): ApiJson<CreateApiKey>,
) -> Result<Response, ApiError> {
    // Cheap checks first, without the write lock; they are repeated below with the time read once the lock is held.
    check_new_key(&body, state.clock.now())?;
    if body
        .daily_unit_cap
        .is_some_and(|c| c.milli() > MAX_DAILY_UNIT_CAP_MILLI)
    {
        return Err(ApiError::field(
            "daily_unit_cap",
            ErrorCode::OutOfRange,
            format!("must be at most {MAX_DAILY_UNIT_CAP_MILLI} milli-units"),
        ));
    }
    let key = ApiKey::generate();
    let new = NewKey {
        key_id: key.key_id(),
        project_id: p.project_id,
        digest: key.hash(),
        scopes: body.scopes.clone(),
        daily_unit_cap: body.daily_unit_cap,
        allowed_images: body.allowed_images.clone(),
        label: body.label.clone(),
        expires_at: body.expires_at,
    };
    // Reads the creator, then writes: IMMEDIATE (see `store::begin_immediate`).
    let mut tx = store::begin_immediate(&state.db).await?;
    // One `now`, read once the write lock is held (T03 review): the lock may have been waited for, so an earlier
    // reading could be stale. It is used for the re-check, the new key's `created_at` and the audit event alike.
    let now = state.clock.now();
    // §5 "Re-checked at the point of use": the creator must still be live now, and its current limits apply. A
    // creator that expired while waiting for the lock is refused, and so is an `expires_at` that has passed.
    let creator = recheck_caller(&mut tx, &state, &p, now).await?;
    check_new_key(&body, now)?;
    ensure_limits_no_escalation(&creator.limits(), &PrincipalLimits::from(&body))?;
    let row = store::keys::insert(&mut tx, p.account_id, &new, now).await?;
    let event = NewEvent::new(
        AuditKind::KeyCreated,
        Some(p.id),
        Some(row.key_id.to_string()),
        detail(serde_json::json!({ "scopes": row.scopes, "project_id": row.project_id })),
    );
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    tx.commit().await?;
    tracing::info!(key_id = %row.key_id, "API key created");
    let mut resp = (StatusCode::CREATED, Json(NewApiKey { key, info: row.info() })).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// The caller's account's keys, in creation order, revoked ones included. Never contains a secret.
#[utoipa::path(
    get,
    path = "/v1/keys",
    tag = "keys",
    params(PageParams),
    responses(
        (status = 200, description = "A page of keys.", body = Page<ApiKeyInfo>),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_keys(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    ApiQuery(q): ApiQuery<PageParams>,
) -> Result<Json<Page<ApiKeyInfo>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| KeyCursor::decode(c).ok_or_else(bad_cursor))
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut rows = store::keys::list(&mut conn, p.account_id, after, limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| rows.last().map(|r| KeyCursor::after(r).encode()))
        .flatten();
    Ok(Json(Page {
        items: rows.iter().map(store::keys::KeyRow::info).collect(),
        next_cursor,
    }))
}

/// The attributes of an existing key, as the creation request that would have made it. Revocation reuses the
/// no-escalation check with it (§5 "Revoking").
fn as_request(target: &store::keys::KeyRow) -> CreateApiKey {
    CreateApiKey {
        label: None,
        scopes: target.scopes.clone(),
        expires_at: target.expires_at,
        daily_unit_cap: target.daily_unit_cap,
        allowed_images: target.allowed_images.clone(),
    }
}

/// Revokes a key of the caller's account. Idempotent.
///
/// A key can revoke itself, or any key it could have created (§5 "Revoking"). The account's last live unrestricted
/// admin key (no expiry, no cap, no image list) cannot be revoked.
#[utoipa::path(
    delete,
    path = "/v1/keys/{key_id}",
    tag = "keys",
    params(("key_id" = String, Path, description = "The key's public ID (12 characters).")),
    responses(
        (status = 204, description = "Revoked (or already revoked)."),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the key lacks the admin scope. `escalation_denied`: the target has more power than the calling key, so the calling key could not have created it; `errors` lists the fields.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such key in this account.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`last_admin_key`: it is the account's last live unrestricted admin key (no expiry, no cap, no image list). Recover with `p2pc-server keys recover` if every admin key is lost.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn revoke_key(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    Path(key_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let key_id: KeyId = key_id.parse().map_err(|_| ApiError::not_found())?;
    // Reads the target and the caller, then writes: IMMEDIATE (see `store::begin_immediate`).
    let mut tx = store::begin_immediate(&state.db).await?;
    // One `now`, read once the write lock is held, for the re-check, `revoked_at` and the audit event.
    let now = state.clock.now();
    // §5 "Re-checked at the point of use", first: a caller revoked or expired since authentication learns nothing,
    // not even whether the target exists.
    let caller = recheck_caller(&mut tx, &state, &p, now).await?;
    let target = store::keys::get(&mut tx, p.account_id, key_id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if p.key_id() != Some(target.key_id) {
        ensure_limits_no_escalation(&caller.limits(), &PrincipalLimits::from(&as_request(&target)))?;
    }
    match store::keys::revoke(&mut tx, p.account_id, key_id, now).await? {
        Revoke::Revoked => {
            let event = NewEvent::new(AuditKind::KeyRevoked, Some(p.id), Some(key_id.to_string()), Map::new());
            store::audit::append(&mut tx, p.account_id, &event, now).await?;
            tx.commit().await?;
            tracing::info!(%key_id, "API key revoked");
            Ok(StatusCode::NO_CONTENT)
        }
        Revoke::AlreadyRevoked => Ok(StatusCode::NO_CONTENT),
        Revoke::NotFound => Err(ApiError::not_found()),
        Revoke::LastAdmin => Err(ApiError::conflict(
            "last_admin_key",
            "This is the account's last live unrestricted admin key; create another one (no expiry, cap or image \
             list) first.",
        )),
    }
}

/// `limit`, `cursor` and `kind`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct AuditParams {
    /// Page size, 1-100 (default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// Only events of this kind, for example `key_created`.
    pub kind: Option<String>,
}

/// The caller's account's audit events, newest first.
#[utoipa::path(
    get,
    path = "/v1/audit",
    tag = "audit",
    params(AuditParams),
    responses(
        (status = 200, description = "A page of events.", body = Page<AuditEvent>),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit`, `cursor` or `kind`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_audit(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    ApiQuery(q): ApiQuery<AuditParams>,
) -> Result<Json<Page<AuditEvent>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let before = q
        .cursor
        .as_deref()
        .map(|c| {
            // The cursor is the internal sequence number of the last event returned (opaque to clients).
            c.parse::<i64>()
                .ok()
                .filter(|_| c.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(bad_cursor)
        })
        .transpose()?;
    let kind = q
        .kind
        .as_deref()
        .map(|k| {
            store::audit::parse_kind(k)
                .ok_or_else(|| ApiError::field("kind", ErrorCode::InvalidFormat, "unknown event kind"))
        })
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut events = store::audit::list(&mut conn, p.account_id, kind, before, limit + 1).await?;
    let more = events.len() > limit as usize;
    events.truncate(limit as usize);
    let next_cursor = more.then(|| events.last().map(|e| e.seq.to_string())).flatten();
    Ok(Json(Page {
        items: events.into_iter().map(|e| e.event).collect(),
        next_cursor,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn a_panicking_handler_becomes_a_500_problem() {
        async fn boom() -> &'static str {
            panic!("boom with p2pc_sk_should_not_leak");
        }
        let app = with_layers(Router::new().route("/boom", get(boom)));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/boom")
                    .body(Body::from("request body"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            crate::error::PROBLEM_JSON
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "internal");
        assert_eq!(v["status"], 500);
        assert!(!String::from_utf8_lossy(&body).contains("boom"));
    }

    #[test]
    fn page_limits() {
        assert_eq!(page_limit(None).unwrap(), DEFAULT_PAGE_LIMIT);
        assert_eq!(page_limit(Some(1)).unwrap(), 1);
        assert_eq!(page_limit(Some(100)).unwrap(), 100);
        assert!(page_limit(Some(0)).is_err());
        assert!(page_limit(Some(101)).is_err());
    }
}
