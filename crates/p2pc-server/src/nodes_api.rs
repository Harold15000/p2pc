// SPDX-License-Identifier: AGPL-3.0-only

//! REST handlers for the server's iroh identity, join tokens and nodes (spec §5, §7).
//!
//! Every query is filtered by the caller's account (SI-7). Creating and revoking join tokens grant and remove power,
//! so they re-check the caller's key inside their own transaction (§5 "Re-checked at the point of use").

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{
    AuditKind, CreateJoinToken, JoinTokenInfo, JoinTokenResponse, Node, NodeState, Page, Problem, ServerInfo,
};
use p2pc_proto::auth::{DEFAULT_JOIN_TOKEN_TTL, JoinToken, MAX_JOIN_TOKEN_TTL};
use p2pc_proto::ids::{JoinTokenId, NodeId};
use p2pc_proto::protocol::ServerMsg;
use p2pc_proto::validate::ErrorCode;
use serde::Deserialize;
use serde_json::{Map, Value};
use time::Duration;
use utoipa::IntoParams;

use crate::app::{AppState, PageParams, bad_cursor, page_limit};
use crate::auth::{AdminKey, AnyKey, Authorized, NodesReadScope, NodesWriteScope, recheck_caller};
use crate::error::ApiError;
use crate::extract::{ApiJson, ApiQuery};
use crate::gateway::{OfflineReason, SendError};
use crate::store::audit::NewEvent;
use crate::store::join_tokens::{NewJoinToken, Revoke, TokenCursor};
use crate::store::nodes::NodeCursor;
use crate::store::{self};

/// Longest join token label.
pub const MAX_LABEL_LEN: usize = 256;

fn detail(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The server's iroh NodeId, relays, address (`p2pc_srv_…`) and version.
#[utoipa::path(
    get,
    path = "/v1/server",
    tag = "server",
    responses(
        (status = 200, description = "How to reach this server over iroh.", body = ServerInfo),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_server(State(state): State<AppState>, _key: AnyKey) -> Json<ServerInfo> {
    Json(state.server.info())
}

/// Creates a single-use join token. The token is in the response, once.
#[utoipa::path(
    post,
    path = "/v1/nodes/join-tokens",
    tag = "nodes",
    request_body = CreateJoinToken,
    responses(
        (status = 201, description = "The token (`p2pc_join_…`), shown only this once.", body = JoinTokenResponse),
        (status = 401, description = "Missing or invalid key (also when the key was revoked or expired during the request).", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `label` or `ttl_s` (1-86400, default 900).", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn create_join_token(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    ApiJson(body): ApiJson<CreateJoinToken>,
) -> Result<Response, ApiError> {
    let ttl_s = body.ttl_s.unwrap_or(DEFAULT_JOIN_TOKEN_TTL.whole_seconds() as u32);
    if ttl_s == 0 || i64::from(ttl_s) > MAX_JOIN_TOKEN_TTL.whole_seconds() {
        return Err(ApiError::field(
            "ttl_s",
            ErrorCode::OutOfRange,
            format!("must be 1-{}", MAX_JOIN_TOKEN_TTL.whole_seconds()),
        ));
    }
    if let Some(label) = &body.label
        && (label.is_empty() || label.len() > MAX_LABEL_LEN || label.chars().any(char::is_control))
    {
        return Err(ApiError::field(
            "label",
            ErrorCode::InvalidFormat,
            format!("must be 1-{MAX_LABEL_LEN} bytes with no control characters"),
        ));
    }
    let mut tx = store::begin_immediate(&state.db).await?;
    // §5 "Re-checked at the point of use", with the time read once the write lock is held.
    let now = state.clock.now();
    recheck_caller(&mut tx, &state, &p, now).await?;
    let token = JoinToken::generate(
        state.server.node_id().to_string(),
        state.server.relays().to_vec(),
        Duration::seconds(i64::from(ttl_s)),
        now,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "cannot build a join token");
        ApiError::internal()
    })?;
    let new = NewJoinToken {
        id: JoinTokenId::generate(),
        project_id: p.project_id,
        code_digest: token.code_hash(),
        label: body.label.clone(),
        created_by_key_id: p.key_id,
        expires_at: token.expires_at,
    };
    let row = store::join_tokens::insert(&mut tx, p.account_id, &new, now).await?;
    let event = NewEvent {
        kind: AuditKind::JoinTokenCreated,
        actor_key_id: Some(p.key_id),
        subject_id: Some(row.id.to_string()),
        detail: detail(serde_json::json!({ "ttl_s": ttl_s, "project_id": row.project_id })),
    };
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    tx.commit().await.map_err(store::StoreError::from)?;
    tracing::info!(join_token_id = %row.id, "join token created");
    // The token carries the row's expiry (both come from the same `JoinToken::generate`).
    debug_assert_eq!(token.expires_at, row.expires_at);
    let body = JoinTokenResponse::new(row.id, token);
    Ok(no_store((StatusCode::CREATED, Json(body)).into_response()))
}

/// The account's join tokens, in creation order. Never contains a token or a code.
#[utoipa::path(
    get,
    path = "/v1/nodes/join-tokens",
    tag = "nodes",
    params(PageParams),
    responses(
        (status = 200, description = "A page of join tokens.", body = Page<JoinTokenInfo>),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_join_tokens(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    ApiQuery(q): ApiQuery<PageParams>,
) -> Result<Json<Page<JoinTokenInfo>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| TokenCursor::decode(c).ok_or_else(bad_cursor))
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut rows = store::join_tokens::list(&mut conn, p.account_id, after, limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| rows.last().map(|r| TokenCursor::after(r).encode()))
        .flatten();
    Ok(Json(Page {
        items: rows.iter().map(store::join_tokens::JoinTokenRow::info).collect(),
        next_cursor,
    }))
}

/// Revokes an unused join token. Idempotent.
#[utoipa::path(
    delete,
    path = "/v1/nodes/join-tokens/{id}",
    tag = "nodes",
    params(("id" = String, Path, description = "The token's row ID (`jtk_…`).")),
    responses(
        (status = 204, description = "Revoked (or already revoked)."),
        (status = 401, description = "Missing or invalid key (also when the key was revoked or expired during the request).", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such token in this account.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`token_consumed`: a node already joined with it; delete the node instead.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn revoke_join_token(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id: JoinTokenId = id.parse().map_err(|_| ApiError::not_found())?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    // First: a caller revoked or expired since authentication learns nothing, not even whether the token exists.
    recheck_caller(&mut tx, &state, &p, now).await?;
    match store::join_tokens::revoke(&mut tx, p.account_id, id, now).await? {
        Revoke::Revoked => {
            let event = NewEvent {
                kind: AuditKind::JoinTokenRevoked,
                actor_key_id: Some(p.key_id),
                subject_id: Some(id.to_string()),
                detail: Map::new(),
            };
            store::audit::append(&mut tx, p.account_id, &event, now).await?;
            tx.commit().await.map_err(store::StoreError::from)?;
            tracing::info!(join_token_id = %id, "join token revoked");
            Ok(StatusCode::NO_CONTENT)
        }
        Revoke::AlreadyRevoked => Ok(StatusCode::NO_CONTENT),
        Revoke::NotFound => Err(ApiError::not_found()),
        Revoke::Consumed => Err(ApiError::conflict(
            "token_consumed",
            "A node already joined with this token; delete the node to remove it.",
        )),
    }
}

/// `limit`, `cursor` and `state`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct NodeListParams {
    /// Page size, 1-100 (default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// Only nodes in this state: `online` (draining nodes included) or `offline`.
    #[param(value_type = Option<String>)]
    pub state: Option<NodeState>,
}

/// The account's nodes, in enrollment order.
#[utoipa::path(
    get,
    path = "/v1/nodes",
    tag = "nodes",
    params(NodeListParams),
    responses(
        (status = 200, description = "A page of nodes.", body = Page<Node>),
        (status = 400, description = "Invalid query string (for example an unknown `state`).", content_type = "application/problem+json", body = Problem),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the nodes:read scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_nodes(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: Authorized<NodesReadScope>,
    ApiQuery(q): ApiQuery<NodeListParams>,
) -> Result<Json<Page<Node>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| NodeCursor::decode(c).ok_or_else(bad_cursor))
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut rows = store::nodes::list(&mut conn, p.account_id, q.state, after, limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| rows.last().map(|r| NodeCursor::after(r).encode()))
        .flatten();
    let held = store::leases::held_for_account(&mut conn, p.account_id).await?;
    Ok(Json(Page {
        items: rows.iter().map(|r| view(&state, r, &held)).collect(),
        next_cursor,
    }))
}

/// The API view of a node: `free` is what it offers minus every reservation its leases hold (§8), and `last_seen`
/// the freshest real contact.
fn view(
    state: &AppState,
    row: &store::nodes::NodeRow,
    held: &std::collections::BTreeMap<NodeId, Vec<crate::scheduler::fit::Reserved>>,
) -> Node {
    let mut h = crate::scheduler::fit::Held::default();
    for r in held.get(&row.id).into_iter().flatten() {
        h.add(r);
    }
    let mut node = row.api();
    node.free = crate::scheduler::fit::free_capacity(&row.inventory, &h);
    with_live_seen(state, node)
}

/// The in-memory last contact is fresher than the one flushed to SQLite (at most every 15 s).
fn with_live_seen(state: &AppState, mut node: Node) -> Node {
    if let Some(seen) = state.hub.last_seen(node.id) {
        node.last_seen = Some(node.last_seen.map_or(seen, |s| s.max(seen)));
    }
    node
}

fn parse_node_id(id: &str) -> Result<NodeId, ApiError> {
    id.parse().map_err(|_| ApiError::not_found())
}

/// One node of the account.
#[utoipa::path(
    get,
    path = "/v1/nodes/{id}",
    tag = "nodes",
    params(("id" = String, Path, description = "The node ID (`node_…`).")),
    responses(
        (status = 200, description = "The node.", body = Node),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the nodes:read scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such node in this account.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_node(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: Authorized<NodesReadScope>,
    Path(id): Path<String>,
) -> Result<Json<Node>, ApiError> {
    let id = parse_node_id(&id)?;
    let mut conn = state.db.acquire().await?;
    let row = store::nodes::get(&mut conn, p.account_id, id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let held = store::leases::held_for_account(&mut conn, p.account_id).await?;
    Ok(Json(view(&state, &row, &held)))
}

async fn set_draining(
    state: &AppState,
    p: &crate::auth::Principal,
    id: &str,
    draining: bool,
) -> Result<Json<Node>, ApiError> {
    let id = parse_node_id(id)?;
    let mut conn = state.db.acquire().await?;
    let row = store::nodes::set_draining(&mut conn, p.account_id, id, draining)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let held = store::leases::held_for_account(&mut conn, p.account_id).await?;
    drop(conn);
    let msg = if draining {
        ServerMsg::Drain {}
    } else {
        ServerMsg::Resume {}
    };
    match state.hub.send(id, msg) {
        // Not connected: the flag is stored, and the next `Welcome` is followed by `Drain`.
        Ok(()) | Err(SendError::NotConnected) => {}
        Err(SendError::Full) => tracing::warn!(node_id = %id, "drain/resume not sent: the node's queue is full"),
    }
    tracing::info!(node_id = %id, draining, "node drain state changed");
    if !draining {
        // A resumed node is an eligible node changing: the offer cap re-arms (§8).
        crate::scheduler::node_changed(&state.db, &state.kick, p.account_id).await;
    }
    Ok(Json(view(state, &row, &held)))
}

/// Stops giving the node new leases, and tells it `Drain` when it is connected. Idempotent.
#[utoipa::path(
    post,
    path = "/v1/nodes/{id}/drain",
    tag = "nodes",
    params(("id" = String, Path, description = "The node ID (`node_…`).")),
    responses(
        (status = 200, description = "The node, now draining.", body = Node),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the nodes:write scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such node in this account.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn drain_node(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: Authorized<NodesWriteScope>,
    Path(id): Path<String>,
) -> Result<Json<Node>, ApiError> {
    set_draining(&state, &p, &id, true).await
}

/// Lets the node take leases again, and tells it `Resume` when it is connected. Idempotent.
#[utoipa::path(
    post,
    path = "/v1/nodes/{id}/resume",
    tag = "nodes",
    params(("id" = String, Path, description = "The node ID (`node_…`).")),
    responses(
        (status = 200, description = "The node, no longer draining.", body = Node),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the nodes:write scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such node in this account.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn resume_node(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: Authorized<NodesWriteScope>,
    Path(id): Path<String>,
) -> Result<Json<Node>, ApiError> {
    set_draining(&state, &p, &id, false).await
}

/// Deletes the node: closes its live connection, and its NodeId is no longer enrolled (`not_enrolled`).
#[utoipa::path(
    delete,
    path = "/v1/nodes/{id}",
    tag = "nodes",
    params(("id" = String, Path, description = "The node ID (`node_…`).")),
    responses(
        (status = 204, description = "Deleted."),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks the nodes:write scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such node in this account.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn delete_node(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: Authorized<NodesWriteScope>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id = parse_node_id(&id)?;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    if !store::nodes::soft_delete(&mut tx, p.account_id, id, now).await? {
        return Err(ApiError::not_found());
    }
    let event = NewEvent {
        kind: AuditKind::NodeDeleted,
        actor_key_id: Some(p.key_id),
        subject_id: Some(id.to_string()),
        detail: Map::new(),
    };
    store::audit::append(&mut tx, p.account_id, &event, now).await?;
    tx.commit().await.map_err(store::StoreError::from)?;
    // Ordering, against the gateway's sessions (see `gateway::hub`): `deleted_at` is committed **before** the
    // disconnect. A session that registers after this point re-reads its row and sees the deletion; one registered
    // before is closed here. A reconnect finds no live node and gets `not_enrolled`.
    state.hub.disconnect(id);
    // The scheduler (T06) requeues the node's leases, as for a lost node.
    state
        .hub
        .node_events()
        .on_node_offline(id, OfflineReason::Deleted)
        .await;
    tracing::info!(node_id = %id, "node deleted");
    Ok(StatusCode::NO_CONTENT)
}
