// SPDX-License-Identifier: AGPL-3.0-only

//! Join requests (H2 spec §5.4, §7.3): the phone-assisted way for a new PC to join, approved on the hub PC against
//! the approval phrase.
//!
//! The order of the steps is what defeats an offline search for a matching phrase (SI-H2-16):
//! 1. `POST /v1/nodes/join-requests` stores the agent NodeId and the listener commitment, then draws the hub nonce;
//! 2. `POST …/{id}/reveal` (the requesting principal, once) checks the listener nonce against the commitment in
//!    constant time; a mismatch ends the request `rejected`;
//! 3. only then does the request show its approval phrase, and `POST …/{id}/approve` (an `admin`) records the
//!    approval, minting nothing;
//! 4. `POST …/{id}/token` (the requesting principal, once) mints a 15-minute, single-use join token on behalf of the
//!    approving principal, reloaded in the minting transaction, **bound to the request's agent NodeId**.
//!
//! Reveal, approval and token minting are refused for a request created 15 minutes ago or more, judged by its
//! `created_at` whatever state the expiry sweep has left it in.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{
    AuditKind, CreateJoinRequest, H2ErrorCode, JoinRequestCreated, JoinRequestInfo, JoinRequestState, JoinRequestToken,
    Page, Problem, RevealJoinRequest, Scope,
};
use p2pc_proto::auth::{DEFAULT_JOIN_TOKEN_TTL, JoinToken};
use p2pc_proto::ids::{JoinRequestId, JoinTokenId};
use p2pc_proto::invite::{HubNonce, ListenerCommitment, ListenerNonce, approval_phrase};
use p2pc_proto::validate::h2_api::JOIN_REQUEST_TTL_S;
use serde_json::{Map, Value, json};
use time::Duration;

use crate::app::{AppState, PageParams, bad_cursor, page_limit};
use crate::auth::{AdminKey, AnyKey, Authorized, Principal, recheck_caller, reload};
use crate::devices_api::{ed25519_node_id, hub_key};
use crate::error::ApiError;
use crate::extract::{ApiJson, ApiQuery};
use crate::store::audit::NewEvent;
use crate::store::join_requests::{JoinRequestRow, NewJoinRequest};
use crate::store::join_tokens::NewJoinToken;
use crate::store::{self, StoreError};

/// Most open join requests per account (§5.4 step 3).
pub const MAX_OPEN_PER_ACCOUNT: i64 = 4;
/// Most open join requests per requesting principal.
pub const MAX_OPEN_PER_PRINCIPAL: i64 = 2;
/// Most join requests a principal creates per hour.
pub const MAX_CREATED_PER_HOUR: i64 = 6;
/// The code of the `429` beyond those limits.
pub const TOO_MANY_JOIN_REQUESTS: &str = "too_many_join_requests";

fn closed() -> ApiError {
    ApiError::conflict(
        H2ErrorCode::JoinRequestClosed.as_str(),
        "This join request is not in a state, or no longer within the 15 minutes, that allows this call.",
    )
}

fn invalid(detail: &str) -> ApiError {
    ApiError::unprocessable(H2ErrorCode::InvalidJoinRequest.as_str(), detail.to_string())
}

fn detail(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn hex32<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_value(Value::String(text.to_string())).ok()
}

/// The API view at `now`: the approval phrase only once the listener nonce is revealed, from the hub's own NodeId,
/// the agent NodeId and both nonces (§5.4 step 5).
fn info(state: &AppState, row: &JoinRequestRow, now: time::OffsetDateTime) -> Result<JoinRequestInfo, ApiError> {
    let phrase = match (&row.listener_nonce, row.state) {
        (Some(nonce), s) if s != JoinRequestState::AwaitingReveal => {
            let hub = hub_key(state)?;
            let agent = row.iroh_node_id.parse().map_err(|_| ApiError::internal())?;
            let listener: ListenerNonce = hex32(nonce).ok_or_else(ApiError::internal)?;
            let hub_nonce: HubNonce = hex32(&row.hub_nonce).ok_or_else(ApiError::internal)?;
            Some(approval_phrase(&hub, &agent, &listener, &hub_nonce).to_string())
        }
        _ => None,
    };
    Ok(JoinRequestInfo {
        id: row.id,
        requested_by: row.requested_by,
        listener_node_id: row.listener_node_id.clone(),
        iroh_node_id: row.iroh_node_id.clone(),
        approval_phrase: phrase,
        state: row.state_at(now),
        created_at: row.created_at,
        expires_at: row.expires_at,
    })
}

/// The request `id` as `p` may see it: every request for an `admin`, its own for anyone else (`404` otherwise, as
/// for an unknown ID).
async fn visible(conn: &mut store::Conn, p: &Principal, id: &str) -> Result<JoinRequestRow, ApiError> {
    let id: JoinRequestId = id.parse().map_err(|_| ApiError::not_found())?;
    let row = store::join_requests::get(conn, p.account_id, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if p.is_admin() || row.requested_by == p.id {
        Ok(row)
    } else {
        Err(ApiError::not_found())
    }
}

/// The request `id` when `p` opened it (`404` otherwise): reveal and token are for the requesting principal only.
async fn own(conn: &mut store::Conn, p: &Principal, id: &str) -> Result<JoinRequestRow, ApiError> {
    let id: JoinRequestId = id.parse().map_err(|_| ApiError::not_found())?;
    store::join_requests::get(conn, p.account_id, id)
        .await?
        .filter(|row| row.requested_by == p.id)
        .ok_or_else(ApiError::not_found)
}

/// Opens a join request from an invite QR (H2 §5.4 step 3). It carries no secret and gives nothing yet.
#[utoipa::path(
    post,
    path = "/v1/nodes/join-requests",
    tag = "nodes",
    request_body = CreateJoinRequest,
    responses(
        (status = 201, description = "The request, `awaiting_reveal`, with the hub nonce for `InviteOpen`.", body = JoinRequestCreated),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks the nodes:invite scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "`invalid_join_request`: `invite_expires_at` not within (now, now + 15 min + 120 s], a NodeId that is not an Ed25519 public key, or a commitment that is not 32 bytes.", content_type = "application/problem+json", body = Problem),
        (status = 429, description = "`too_many_join_requests`: 4 open per account, 2 open per requester, or 6 created per requester in the last hour.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn create_join_request(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    ApiJson(body): ApiJson<CreateJoinRequest>,
) -> Result<Response, ApiError> {
    if !p.has_scope(Scope::NodesInvite) {
        return Err(ApiError::forbidden(Scope::NodesInvite));
    }
    let check = |now| -> Result<(), ApiError> {
        if body.validate(now).is_err()
            || ed25519_node_id(&body.listener_node_id).is_none()
            || ed25519_node_id(&body.iroh_node_id).is_none()
            || hex32::<ListenerCommitment>(&body.listener_commitment).is_none()
        {
            return Err(invalid(
                "invite_expires_at must be within (now, now + 15 min + 120 s], both NodeIds Ed25519 public keys and \
                 the commitment 32 bytes of lowercase hex.",
            ));
        }
        Ok(())
    };
    check(state.clock.now())?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    let caller = recheck_caller(&mut tx, &state, &p, now).await?;
    check(now)?;
    if !caller.has_scope(Scope::NodesInvite) {
        return Err(ApiError::forbidden(Scope::NodesInvite));
    }
    let (open, mine, last_hour) = store::join_requests::counts(&mut tx, p.account_id, p.id, now).await?;
    if open >= MAX_OPEN_PER_ACCOUNT || mine >= MAX_OPEN_PER_PRINCIPAL || last_hour >= MAX_CREATED_PER_HOUR {
        return Err(ApiError::too_many_requests(
            TOO_MANY_JOIN_REQUESTS,
            "Too many join requests: at most 4 open per cloud, 2 open per device and 6 a device per hour.",
        ));
    }
    // The inputs are fixed (validated, and stored in this transaction) before the nonce is drawn (§5.4 step 3).
    let hub_nonce = HubNonce::generate();
    let new = NewJoinRequest {
        id: JoinRequestId::generate(),
        project_id: p.project_id,
        requested_by: p.id,
        listener_node_id: body.listener_node_id.clone(),
        iroh_node_id: body.iroh_node_id.clone(),
        invite_expires_at: body.invite_expires_at,
        listener_commitment: body.listener_commitment.clone(),
        hub_nonce: hub_nonce.to_string(),
        expires_at: now + Duration::seconds(JOIN_REQUEST_TTL_S),
    };
    let row = store::join_requests::insert(&mut tx, p.account_id, &new, now).await?;
    let event = NewEvent::new(
        AuditKind::JoinRequestCreated,
        Some(p.id),
        Some(row.id.to_string()),
        detail(json!({"iroh_node_id": row.iroh_node_id, "listener_node_id": row.listener_node_id})),
    );
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    tx.commit().await.map_err(StoreError::from)?;
    tracing::info!(join_request_id = %row.id, "join request created");
    let body = JoinRequestCreated {
        id: row.id,
        expires_at: row.expires_at,
        hub_nonce: row.hub_nonce,
    };
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// Reveals the listener nonce (H2 §5.4 step 4): the requesting principal only, once, while `awaiting_reveal` and
/// within the 15 minutes. A nonce that matches the commitment makes the request `pending`; one that does not ends
/// it `rejected` (`409 join_request_closed`), with no second try.
#[utoipa::path(
    post,
    path = "/v1/nodes/join-requests/{id}/reveal",
    tag = "nodes",
    params(("id" = String, Path, description = "The request ID (`jrq_…`).")),
    request_body = RevealJoinRequest,
    responses(
        (status = 200, description = "The request, now `pending`, with its approval phrase.", body = JoinRequestInfo),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such request opened by the caller.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`join_request_closed`: the nonce does not match the commitment (the request is now rejected), the request is not `awaiting_reveal`, or it was created 15 minutes ago or more.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "`listener_nonce` is not 32 bytes of lowercase hex.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn reveal_join_request(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<RevealJoinRequest>,
) -> Result<Json<JoinRequestInfo>, ApiError> {
    body.validate().map_err(|e| ApiError::validation(&e))?;
    let nonce: ListenerNonce = hex32(&body.listener_nonce).ok_or_else(|| invalid("bad listener_nonce"))?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    recheck_caller(&mut tx, &state, &p, now).await?;
    let row = own(&mut tx, &p, &id).await?;
    if row.state != JoinRequestState::AwaitingReveal || !row.is_within_ttl(now) {
        return Err(closed());
    }
    let commitment: ListenerCommitment = hex32(&row.listener_commitment).ok_or_else(ApiError::internal)?;
    if !commitment.verify(&nonce) {
        store::join_requests::reject(&mut tx, p.account_id, row.id, &[JoinRequestState::AwaitingReveal], now).await?;
        let event = NewEvent::new(
            AuditKind::JoinRequestRevealFailed,
            Some(p.id),
            Some(row.id.to_string()),
            Map::new(),
        );
        store::audit::append(&mut tx, p.account_id, &event, now).await?;
        tx.commit().await.map_err(StoreError::from)?;
        tracing::info!(join_request_id = %row.id, "join request reveal did not match its commitment");
        return Err(closed());
    }
    // The nonce is public from here on (it is half of what the approval phrase hashes).
    if !store::join_requests::reveal(&mut tx, p.account_id, row.id, &body.listener_nonce, now).await? {
        return Err(closed());
    }
    let event = NewEvent::new(
        AuditKind::JoinRequestRevealed,
        Some(p.id),
        Some(row.id.to_string()),
        Map::new(),
    );
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    let row = store::join_requests::get(&mut tx, p.account_id, row.id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await.map_err(StoreError::from)?;
    Ok(Json(info(&state, &row, now)?))
}

/// The account's join requests for an `admin`, or the caller's own requests, in creation order.
#[utoipa::path(
    get,
    path = "/v1/nodes/join-requests",
    tag = "nodes",
    params(PageParams),
    responses(
        (status = 200, description = "A page of join requests (for a non-admin caller: its own).", body = Page<JoinRequestInfo>),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller has neither admin nor nodes:invite.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_join_requests(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    ApiQuery(q): ApiQuery<PageParams>,
) -> Result<Json<Page<JoinRequestInfo>>, ApiError> {
    if !p.has_scope(Scope::NodesInvite) {
        return Err(ApiError::forbidden(Scope::NodesInvite));
    }
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| {
            store::devices::Cursor::decode::<JoinRequestId>(c)
                .map(|c| (c.created_at, c.id))
                .ok_or_else(bad_cursor)
        })
        .transpose()?;
    let mine = (!p.is_admin()).then_some(p.id);
    let now = state.clock.now();
    let mut conn = state.db.acquire().await?;
    let mut rows = store::join_requests::list(&mut conn, p.account_id, mine, after, limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| {
            rows.last().map(|r| {
                store::devices::Cursor {
                    created_at: r.created_at.unix_timestamp(),
                    id: r.id.to_string(),
                }
                .encode()
            })
        })
        .flatten();
    let items = rows.iter().map(|r| info(&state, r, now)).collect::<Result<_, _>>()?;
    Ok(Json(Page { items, next_cursor }))
}

/// One join request: any for an `admin`, its own for the requesting principal.
#[utoipa::path(
    get,
    path = "/v1/nodes/join-requests/{id}",
    tag = "nodes",
    params(("id" = String, Path, description = "The request ID (`jrq_…`).")),
    responses(
        (status = 200, description = "The request.", body = JoinRequestInfo),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such request visible to the caller.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_join_request(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
) -> Result<Json<JoinRequestInfo>, ApiError> {
    let now = state.clock.now();
    let mut conn = state.db.acquire().await?;
    let row = visible(&mut conn, &p, &id).await?;
    Ok(Json(info(&state, &row, now)?))
}

/// Approves a `pending` join request (H2 §5.4 step 5): records the approving principal and mints nothing.
#[utoipa::path(
    post,
    path = "/v1/nodes/join-requests/{id}/approve",
    tag = "nodes",
    params(("id" = String, Path, description = "The request ID (`jrq_…`).")),
    responses(
        (status = 200, description = "The request, now `approved`.", body = JoinRequestInfo),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such request in this account.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`join_request_closed`: the request is not `pending`, or was created 15 minutes ago or more.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn approve_join_request(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    Path(id): Path<String>,
) -> Result<Json<JoinRequestInfo>, ApiError> {
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    recheck_caller(&mut tx, &state, &p, now).await?;
    let row = visible(&mut tx, &p, &id).await?;
    if !store::join_requests::approve(&mut tx, p.account_id, row.id, p.id, now).await? {
        return Err(closed());
    }
    let event = NewEvent::new(
        AuditKind::JoinRequestApproved,
        Some(p.id),
        Some(row.id.to_string()),
        Map::new(),
    );
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    let row = store::join_requests::get(&mut tx, p.account_id, row.id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    tx.commit().await.map_err(StoreError::from)?;
    tracing::info!(join_request_id = %row.id, "join request approved");
    Ok(Json(info(&state, &row, now)?))
}

/// Mints the join token of an approved request (H2 §5.4 step 6): the requesting principal only, once, within the
/// 15 minutes. The token lives 15 minutes, is single-use, is minted on behalf of the approving principal (reloaded
/// here: revoked or expired since, `409`), enrolls only the request's agent NodeId, and is returned once; only its
/// hash is stored.
#[utoipa::path(
    post,
    path = "/v1/nodes/join-requests/{id}/token",
    tag = "nodes",
    params(("id" = String, Path, description = "The request ID (`jrq_…`).")),
    responses(
        (status = 200, description = "The join token (`p2pc_join_…`), shown only this once.", body = JoinRequestToken),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such request opened by the caller.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`join_request_closed`: not `approved`, already delivered, created 15 minutes ago or more, or the approving principal is no longer live.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn join_request_token(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    recheck_caller(&mut tx, &state, &p, now).await?;
    let row = own(&mut tx, &p, &id).await?;
    if row.state != JoinRequestState::Approved || !row.is_within_ttl(now) {
        return Err(closed());
    }
    // H1 §5: power is re-checked at the point of use; the token carries the approving principal's approval.
    let approver = row.approved_by.ok_or_else(closed)?;
    let Some(approver) = reload(&mut tx, p.account_id, approver, now).await? else {
        return Err(closed());
    };
    if !approver.is_admin() {
        return Err(closed());
    }
    let token = JoinToken::generate(
        state.server.node_id().to_string(),
        state.server.relays().to_vec(),
        DEFAULT_JOIN_TOKEN_TTL,
        now,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "cannot build a join token");
        ApiError::internal()
    })?;
    let new = NewJoinToken {
        id: JoinTokenId::generate(),
        project_id: approver.project_id,
        code_digest: token.code_hash(),
        label: None,
        created_by: approver.id,
        bound_iroh_node_id: Some(row.iroh_node_id.clone()),
        pre_approved: false,
        expires_at: token.expires_at,
    };
    let minted = store::join_tokens::insert(&mut tx, p.account_id, &new, now).await?;
    if !store::join_requests::deliver(&mut tx, p.account_id, row.id, minted.id, now).await? {
        return Err(closed());
    }
    for event in [
        NewEvent::new(
            AuditKind::JoinTokenCreated,
            Some(approver.id),
            Some(minted.id.to_string()),
            detail(json!({"join_request_id": row.id, "project_id": minted.project_id})),
        ),
        NewEvent::new(
            AuditKind::JoinRequestDelivered,
            Some(p.id),
            Some(row.id.to_string()),
            detail(json!({"join_token_id": minted.id})),
        ),
    ] {
        store::audit::append(&mut tx, p.account_id, &event, now).await?;
    }
    tx.commit().await.map_err(StoreError::from)?;
    tracing::info!(join_request_id = %row.id, join_token_id = %minted.id, "join request delivered");
    let body = JoinRequestToken {
        join_token: token,
        expires_at: minted.expires_at,
    };
    let mut resp = Json(body).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// Rejects (an `admin`) or withdraws (the requesting principal) an `awaiting_reveal` or `pending` request. Nothing is
/// minted. Idempotent for a request already rejected.
#[utoipa::path(
    delete,
    path = "/v1/nodes/join-requests/{id}",
    tag = "nodes",
    params(("id" = String, Path, description = "The request ID (`jrq_…`).")),
    responses(
        (status = 204, description = "Rejected (or already rejected)."),
        (status = 401, description = "Missing or invalid credentials.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such request visible to the caller.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`join_request_closed`: the request is approved, delivered or expired.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn reject_join_request(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    recheck_caller(&mut tx, &state, &p, now).await?;
    let row = visible(&mut tx, &p, &id).await?;
    match row.state_at(now) {
        JoinRequestState::Rejected => return Ok(StatusCode::NO_CONTENT),
        JoinRequestState::AwaitingReveal | JoinRequestState::Pending => {}
        _ => return Err(closed()),
    }
    let from = [JoinRequestState::AwaitingReveal, JoinRequestState::Pending];
    if !store::join_requests::reject(&mut tx, p.account_id, row.id, &from, now).await? {
        return Err(closed());
    }
    let event = NewEvent::new(
        AuditKind::JoinRequestRejected,
        Some(p.id),
        Some(row.id.to_string()),
        Map::new(),
    );
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    tx.commit().await.map_err(StoreError::from)?;
    tracing::info!(join_request_id = %row.id, "join request rejected");
    Ok(StatusCode::NO_CONTENT)
}
