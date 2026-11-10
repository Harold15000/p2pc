// SPDX-License-Identifier: AGPL-3.0-only

//! Pairing tickets and devices (H2 spec §5.2, §5.5, §7.3), and the registry of live device connections that a
//! revocation and the 2 s liveness sweep close (§5.5, SI-H2-4).
//!
//! Every query is filtered by the caller's account (SI-7). Creating a ticket and revoking a ticket or a device grant
//! or remove power, so they re-check the caller inside their own transaction (H1 §5 "Re-checked at the point of
//! use"). A device without `admin` sees only itself: `GET /v1/devices` is a one-item list and any other device ID is
//! `404`, as an unknown one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{
    AuditKind, CreatePairingTicket, DeviceInfo, H2ErrorCode, Page, PairingTicketCreated, PairingTicketInfo, Problem,
    Scope,
};
use p2pc_proto::ids::{DeviceId, PairingTicketId};
use p2pc_proto::pair::{EndpointKey, PairingTicket};
use p2pc_proto::validate::ErrorCode;
use serde_json::{Map, Value, json};
use time::Duration;
use tokio::sync::watch;

use crate::app::{AppState, PageParams, bad_cursor, ensure_limits_no_escalation, page_limit};
use crate::auth::{AdminKey, AnyKey, Authorized, Principal, recheck_caller};
use crate::error::ApiError;
use crate::extract::{ApiJson, ApiQuery};
use crate::store::audit::NewEvent;
use crate::store::devices::{Cursor, NewTicket, Revoke, RevokeTicket};
use crate::store::keys::MAX_DAILY_UNIT_CAP_MILLI;
use crate::store::{self, StoreError};

/// The error code when `devices.web_app_origin` is not configured, so no pairing link can be built.
pub const WEB_APP_ORIGIN_UNSET: &str = "web_app_origin_unset";

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Whether `text` is an iroh NodeId: 64 lowercase hex characters that decode to an Ed25519 curve point (H2 §5.4
/// step 3, §5.3). The key itself, when it is one.
#[must_use]
pub fn ed25519_node_id(text: &str) -> Option<EndpointKey> {
    let key: EndpointKey = text.parse().ok()?;
    iroh::PublicKey::from_bytes(key.as_bytes()).ok()?;
    Some(key)
}

/// The hub's own iroh NodeId, as the pairing tickets and the check phrases name it.
pub(crate) fn hub_key(state: &AppState) -> Result<EndpointKey, ApiError> {
    state.server.node_id().to_string().parse().map_err(|_| {
        tracing::error!("the server's NodeId is not 64 hex characters");
        ApiError::internal()
    })
}

// --- Live device connections -----------------------------------------------------------------------------------

/// The device connections and service streams that are open now, by device (H2 §5.5, §6.3).
///
/// The `p2pc/device/1` transport (T2-11) registers each connection of a device that passed the device check, and
/// each stream it serves watches the registration. [`DeviceSessions::close`] (a `DELETE /v1/devices/{id}`) and the
/// 2 s liveness sweep ([`sweep_once`]) tell every registration of a device that is no longer live to close, which
/// is how SI-H2-4's 5 s hold for an online revocation, an offline one (`p2pc-server devices revoke`) and an expiry.
#[derive(Debug, Clone, Default)]
pub struct DeviceSessions {
    inner: Arc<Mutex<SessionMap>>,
    next: Arc<AtomicU64>,
}

/// The registered connections of each device: registration ID → the sender that tells it to close.
type SessionMap = HashMap<DeviceId, HashMap<u64, watch::Sender<bool>>>;

/// One registered device connection. Dropping it unregisters it.
#[derive(Debug)]
pub struct DeviceSession {
    sessions: DeviceSessions,
    device_id: DeviceId,
    id: u64,
    closed: watch::Receiver<bool>,
}

impl DeviceSessions {
    fn map(&self) -> MutexGuard<'_, SessionMap> {
        // A panic while holding the lock leaves a consistent map (every operation is a single insert or remove).
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers a connection of `device_id`.
    #[must_use]
    pub fn register(&self, device_id: DeviceId) -> DeviceSession {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = watch::channel(false);
        self.map().entry(device_id).or_default().insert(id, tx);
        DeviceSession {
            sessions: self.clone(),
            device_id,
            id,
            closed: rx,
        }
    }

    /// Tells every registered connection of `device_id` to close; returns how many there were.
    pub fn close(&self, device_id: DeviceId) -> usize {
        let removed = self.map().remove(&device_id);
        let n = removed.as_ref().map_or(0, HashMap::len);
        for tx in removed.into_iter().flat_map(HashMap::into_values) {
            let _ = tx.send(true);
        }
        n
    }

    /// The devices that hold at least one registered connection.
    #[must_use]
    pub fn devices(&self) -> Vec<DeviceId> {
        self.map().keys().copied().collect()
    }

    /// How many connections of `device_id` are registered.
    #[must_use]
    pub fn count(&self, device_id: DeviceId) -> usize {
        self.map().get(&device_id).map_or(0, HashMap::len)
    }
}

impl DeviceSession {
    /// The device of this connection.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Whether the connection has been told to close.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// A receiver for the streams of this connection: it turns `true` when they must close.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.closed.clone()
    }

    /// Completes when the connection must close.
    pub async fn closed(&mut self) {
        // An error means the sender is gone, which only `close` does, after sending `true`.
        let _ = self.closed.wait_for(|c| *c).await;
    }
}

impl Drop for DeviceSession {
    fn drop(&mut self) {
        let mut map = self.sessions.map();
        if let Some(conns) = map.get_mut(&self.device_id) {
            conns.remove(&self.id);
            if conns.is_empty() {
                map.remove(&self.device_id);
            }
        }
    }
}

/// One pass of the liveness sweep (H2 §5.5): re-reads the `revoked_at` and `expires_at` of every device that holds a
/// live connection and closes the connections of each one that is revoked (by any process) or has `expires_at <=
/// now`. It also marks join requests past their 15 minutes `expired` (approval and token minting never depend on it:
/// they check `created_at`). Returns the devices it closed.
pub async fn sweep_once(state: &AppState) -> Result<Vec<DeviceId>, StoreError> {
    let now = state.clock.now();
    let devices = state.devices.devices();
    let mut conn = state.db.acquire().await?;
    let dead = if devices.is_empty() {
        Vec::new()
    } else {
        store::devices::not_live(&mut conn, &devices, now).await?
    };
    for id in &dead {
        let n = state.devices.close(*id);
        tracing::info!(device_id = %id, connections = n, "closed the connections of a device that is no longer live");
    }
    store::join_requests::expire(&mut conn, now).await?;
    Ok(dead)
}

/// Runs [`sweep_once`] every [`p2pc_proto::device::LIVENESS_SWEEP_INTERVAL`] (2 s) until the task is aborted.
pub fn spawn_liveness_sweep(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(p2pc_proto::device::LIVENESS_SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = sweep_once(&state).await {
                tracing::warn!(error = %e, "device liveness sweep failed; retrying");
            }
        }
    })
}

// --- Pairing tickets ----------------------------------------------------------------------------------------------

/// Validates a ticket body at `now`: the `p2pc-proto` rules, then what the database stores.
fn check_ticket(body: &CreatePairingTicket, now: time::OffsetDateTime) -> Result<(), ApiError> {
    body.validate(now).map_err(|e| ApiError::validation(&e))?;
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
    if body.blobs_quota_mb.is_some_and(|q| i64::try_from(q).is_err()) {
        return Err(ApiError::field("blobs_quota_mb", ErrorCode::OutOfRange, "too large"));
    }
    Ok(())
}

/// Creates a one-time pairing ticket (H2 §5.2). The ticket and its link are in the response, once.
///
/// The device it pairs gets the body's scopes (default: the phone profile), cap, image list, expiry and blob quota,
/// none of which may exceed the creator's (`403 escalation_denied`), and the creator's project.
#[utoipa::path(
    post,
    path = "/v1/devices/pairing-tickets",
    tag = "devices",
    request_body = CreatePairingTicket,
    responses(
        (status = 201, description = "The ticket (`p2pc_pair_…`) and its QR link, shown only this once.", body = PairingTicketCreated),
        (status = 401, description = "Missing or invalid credentials (also when the caller was revoked or expired during the request).", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the caller lacks the admin scope. `escalation_denied`: the ticket asks for more than the caller has (scopes, `daily_unit_cap`, `allowed_images`, `expires_at` through `device_expires_in_s`, `blobs_quota_mb`); `errors` lists the fields.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid body: `expires_in_s` 1-3600; `device_expires_in_s` above `expires_in_s` and representable.", content_type = "application/problem+json", body = Problem),
        (status = 503, description = "`web_app_origin_unset`: the server has no `[devices] web_app_origin` to build the pairing link with.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn create_pairing_ticket(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    ApiJson(body): ApiJson<CreatePairingTicket>,
) -> Result<Response, ApiError> {
    check_ticket(&body, state.clock.now())?;
    let Some(origin) = state.config.devices.web_app_origin() else {
        return Err(ApiError::service_unavailable(
            WEB_APP_ORIGIN_UNSET,
            "Set `[devices] web_app_origin` in server.toml to the web app's origin; pairing links point there.",
        ));
    };
    let hub = hub_key(&state)?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    let creator = recheck_caller(&mut tx, &state, &p, now).await?;
    check_ticket(&body, now)?;
    if !creator.is_admin() {
        return Err(ApiError::forbidden(Scope::Admin));
    }
    let asked = body
        .requested_limits(now)
        .ok_or_else(|| ApiError::field("device_expires_in_s", ErrorCode::OutOfRange, "must be representable"))?;
    ensure_limits_no_escalation(&creator.limits(), &asked)?;
    let ticket = PairingTicket::generate(
        hub,
        state.server.relays().to_vec(),
        Duration::seconds(i64::from(body.ttl_s())),
        now,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "cannot build a pairing ticket");
        ApiError::internal()
    })?;
    let (text, url) = match (ticket.encode(), ticket.link(&origin)) {
        (Ok(t), Ok(u)) => (t, u),
        _ => {
            tracing::error!("cannot encode a pairing ticket or its link");
            return Err(ApiError::internal());
        }
    };
    let new = NewTicket {
        id: PairingTicketId::generate(),
        project_id: p.project_id,
        code_digest: ticket.code_hash(),
        label: body.label.clone(),
        scopes: asked.scopes.clone(),
        daily_unit_cap: asked.daily_unit_cap,
        allowed_images: asked.allowed_images.clone(),
        blobs_quota_mb: asked.blobs_quota_mb,
        device_expires_at: asked.expires_at,
        created_by: p.id,
        expires_at: ticket.expires_at,
    };
    let row = store::devices::insert_ticket(&mut tx, p.account_id, &new, now).await?;
    let event = NewEvent::new(
        AuditKind::PairingTicketCreated,
        Some(p.id),
        Some(row.id.to_string()),
        detail(json!({
            "scopes": row.scopes,
            "project_id": row.project_id,
            "expires_in_s": body.ttl_s(),
            "device_expires_at": row.device_expires_at.map(|t| t.unix_timestamp()),
        })),
    );
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    tx.commit().await.map_err(StoreError::from)?;
    tracing::info!(pairing_ticket_id = %row.id, "pairing ticket created");
    let body = PairingTicketCreated {
        id: row.id,
        ticket: text,
        url: url.to_string(),
        expires_at: row.expires_at,
    };
    Ok(no_store((StatusCode::CREATED, Json(body)).into_response()))
}

fn detail(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The account's pairing tickets, in creation order. Never contains a ticket or a code.
#[utoipa::path(
    get,
    path = "/v1/devices/pairing-tickets",
    tag = "devices",
    params(PageParams),
    responses(
        (status = 200, description = "A page of pairing tickets.", body = Page<PairingTicketInfo>),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_pairing_tickets(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    ApiQuery(q): ApiQuery<PageParams>,
) -> Result<Json<Page<PairingTicketInfo>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| Cursor::decode::<PairingTicketId>(c).ok_or_else(bad_cursor))
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut rows = store::devices::list_tickets(&mut conn, p.account_id, after.as_ref(), limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| {
            rows.last().map(|r| {
                Cursor {
                    created_at: r.created_at.unix_timestamp(),
                    id: r.id.to_string(),
                }
                .encode()
            })
        })
        .flatten();
    Ok(Json(Page {
        items: rows.iter().map(store::devices::TicketRow::info).collect(),
        next_cursor,
    }))
}

/// Revokes an unused pairing ticket (the desktop app does it when its QR screen closes). Idempotent; a consumed
/// ticket is left as it is (revoke its device instead).
#[utoipa::path(
    delete,
    path = "/v1/devices/pairing-tickets/{id}",
    tag = "devices",
    params(("id" = String, Path, description = "The ticket's row ID (`ptk_…`).")),
    responses(
        (status = 204, description = "Revoked (or already revoked, or consumed)."),
        (status = 401, description = "Missing or invalid credentials (also when the caller was revoked or expired during the request).", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such ticket in this account.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn revoke_pairing_ticket(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id: PairingTicketId = id.parse().map_err(|_| ApiError::not_found())?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    recheck_caller(&mut tx, &state, &p, now).await?;
    match store::devices::revoke_ticket(&mut tx, p.account_id, id, now).await? {
        RevokeTicket::Revoked => {
            let event = NewEvent::new(
                AuditKind::PairingTicketRevoked,
                Some(p.id),
                Some(id.to_string()),
                Map::new(),
            );
            store::audit::append(&mut tx, p.account_id, &event, now).await?;
            tx.commit().await.map_err(StoreError::from)?;
            tracing::info!(pairing_ticket_id = %id, "pairing ticket revoked");
            Ok(StatusCode::NO_CONTENT)
        }
        RevokeTicket::Unchanged => Ok(StatusCode::NO_CONTENT),
        RevokeTicket::NotFound => Err(ApiError::not_found()),
    }
}

// --- Devices ------------------------------------------------------------------------------------------------------

/// Who may read or revoke `target`: an `admin` principal, or the device itself (H2 §7.3). Any other device gets
/// `404`, as for an unknown ID; a non-`admin` API key gets `403`.
fn may_see(p: &Principal, target: DeviceId) -> Result<(), ApiError> {
    if p.is_admin() || p.device_id() == Some(target) {
        Ok(())
    } else if p.device_id().is_some() {
        Err(ApiError::not_found())
    } else {
        Err(ApiError::forbidden(Scope::Admin))
    }
}

/// The account's devices, in pairing order, revoked ones included. For a device without `admin`, the list holds
/// that device alone.
#[utoipa::path(
    get,
    path = "/v1/devices",
    tag = "devices",
    params(PageParams),
    responses(
        (status = 200, description = "A page of devices (for a non-admin device: itself only).", body = Page<DeviceInfo>),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "An API key without the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_devices(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    ApiQuery(q): ApiQuery<PageParams>,
) -> Result<Json<Page<DeviceInfo>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| Cursor::decode::<DeviceId>(c).ok_or_else(bad_cursor))
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    if !p.is_admin() {
        let Some(own) = p.device_id() else {
            return Err(ApiError::forbidden(Scope::Admin));
        };
        // A one-item list: the device itself (a cursor after it gives an empty page).
        let row = store::devices::get(&mut conn, p.account_id, own).await?;
        let items = row.filter(|_| after.is_none()).map(|r| r.info()).into_iter().collect();
        return Ok(Json(Page {
            items,
            next_cursor: None,
        }));
    }
    let mut rows = store::devices::list(&mut conn, p.account_id, after.as_ref(), limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| {
            rows.last().map(|r| {
                Cursor {
                    created_at: r.created_at.unix_timestamp(),
                    id: r.device_id.to_string(),
                }
                .encode()
            })
        })
        .flatten();
    Ok(Json(Page {
        items: rows.iter().map(store::devices::DeviceRow::info).collect(),
        next_cursor,
    }))
}

/// One device of the account: any device for an `admin`, itself for a device.
#[utoipa::path(
    get,
    path = "/v1/devices/{id}",
    tag = "devices",
    params(("id" = String, Path, description = "The device ID (`dev_…`).")),
    responses(
        (status = 200, description = "The device.", body = DeviceInfo),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "An API key without the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such device in this account, or another device than the calling non-admin device.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_device(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
) -> Result<Json<DeviceInfo>, ApiError> {
    let id: DeviceId = id.parse().map_err(|_| ApiError::not_found())?;
    may_see(&p, id)?;
    let mut conn = state.db.acquire().await?;
    let row = store::devices::get(&mut conn, p.account_id, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(row.info()))
}

/// Revokes a device (H2 §5.5): sets `revoked_at` and closes its live connections and service streams. Idempotent.
///
/// An `admin` may revoke only a device it could have created (no escalation over its scopes, cap, image list,
/// expiry and blob quota); a device may revoke itself ("Forget this cloud"). The account's last live unrestricted
/// `admin` principal cannot be revoked.
#[utoipa::path(
    delete,
    path = "/v1/devices/{id}",
    tag = "devices",
    params(("id" = String, Path, description = "The device ID (`dev_…`).")),
    responses(
        (status = 204, description = "Revoked (or already revoked)."),
        (status = 401, description = "Missing or invalid credentials (also when the caller was revoked or expired during the request).", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: an API key without the admin scope. `escalation_denied`: the device has more power than the calling admin; `errors` lists the fields.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such device in this account, or another device than the calling non-admin device.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`last_admin_device`: it is the account's last live unrestricted admin principal (admin, no expiry, cap, image list or blob quota). Recover with `p2pc-server devices add` or `keys recover`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn revoke_device(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id: DeviceId = id.parse().map_err(|_| ApiError::not_found())?;
    may_see(&p, id)?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    // First: a caller revoked or expired since authentication learns nothing, not even whether the target exists.
    let caller = recheck_caller(&mut tx, &state, &p, now).await?;
    let target = store::devices::get(&mut tx, p.account_id, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if caller.device_id() != Some(id) {
        ensure_limits_no_escalation(&caller.limits(), &target.limits())?;
    }
    match store::devices::revoke(&mut tx, p.account_id, id, now).await? {
        Revoke::Revoked => {
            let event = NewEvent::new(AuditKind::DeviceRevoked, Some(p.id), Some(id.to_string()), Map::new());
            store::audit::append(&mut tx, p.account_id, &event, now).await?;
            tx.commit().await.map_err(StoreError::from)?;
            // After the commit: a connection that registers from now on is refused by the device check, and every
            // one registered before is closed here.
            let closed = state.devices.close(id);
            tracing::info!(device_id = %id, connections = closed, "device revoked");
            Ok(StatusCode::NO_CONTENT)
        }
        Revoke::AlreadyRevoked => {
            state.devices.close(id);
            Ok(StatusCode::NO_CONTENT)
        }
        Revoke::NotFound => Err(ApiError::not_found()),
        Revoke::LastAdmin => Err(ApiError::conflict(
            H2ErrorCode::LastAdminDevice.as_str(),
            "This is the account's last live unrestricted admin principal; pair another admin device or create an \
             unrestricted admin key first.",
        )),
    }
}
