// SPDX-License-Identifier: AGPL-3.0-only

//! Volumes (H2 spec §6.1, §7.3, §11.3): what the nodes report, `GET /v1/volumes` and
//! `DELETE /v1/volumes/{node_id}/{name}`.
//!
//! A volume lives on one node, in a directory the agent derives from its name. The hub never sees a path: it keeps
//! each node's latest `VolumeReport` ([`on_report`]) and can ask a node to delete one (`VolumeDelete`).
//!
//! - **Reports.** Only an agent that declared the `volumes` capability is listened to, and only names that pass the
//!   JobSpec's name rule (§7.1) are kept. A report replaces the node's previous one.
//! - **Listing** (`nodes:read`): the volumes of the caller's account, with cursor pagination.
//! - **Deleting** (`admin`): `{name}` is **one percent-encoded path segment**. A template volume
//!   `tpl:private-chat/models` is sent as `tpl%3Aprivate-chat%2Fmodels`; the router splits the path before decoding,
//!   the segment is decoded once, and the result must pass the name rule, so nothing in a name can add a segment.
//!   The hub refuses while a job holds the volume (`409 volume_in_use`) and when the node is offline
//!   (`503 node_offline`: a deletion is never queued). Otherwise it sends `VolumeDelete`; the agent deletes the
//!   directory and answers with a fresh report, which is what removes the volume from the listing.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use p2pc_proto::api::{H2ErrorCode, Page, Problem, VolumeInfo};
use p2pc_proto::ids::NodeId;
use p2pc_proto::protocol::{self, ServerMsg, VolumeDelete, capability};
use p2pc_proto::validate::VolumeName;

use crate::app::{AppState, PageParams, bad_cursor, page_limit};
use crate::auth::{AdminKey, Authorized, NodesReadScope, recheck_caller};
use crate::error::ApiError;
use crate::extract::ApiQuery;
use crate::store::volumes::{self, VolumeCursor, VolumeRow};
use crate::store::{self, StoreError};

fn info(row: &VolumeRow) -> VolumeInfo {
    VolumeInfo {
        name: row.name.clone(),
        node_id: row.node_id,
        size_mb: row.size_mb,
        max_mb: row.max_mb,
        last_used_at: row.last_used_at,
        in_use_by: row.in_use_by,
    }
}

/// A `VolumeReport` from `node_id` (H2 §6.1): stored as the node's whole list. Returns `false` when the agent did
/// not declare the `volumes` capability, so the gateway answers it as a message it does not serve.
///
/// A name that is not a volume name of §7.1 is dropped: the agent derives its directories from the names of the
/// jobs it ran, so such a name never came from the hub.
pub async fn on_report(state: &AppState, node_id: NodeId, report: protocol::VolumeReport) -> Result<bool, StoreError> {
    let mut tx = store::begin_immediate(&state.db).await?;
    let declared = store::nodes::by_id(&mut tx, node_id)
        .await?
        .is_some_and(|node| node.features.iter().any(|f| f == capability::VOLUMES));
    if !declared {
        return Ok(false);
    }
    let (kept, dropped): (Vec<_>, Vec<_>) = report
        .volumes
        .into_iter()
        .partition(|v| VolumeName::parse(&v.name).is_ok());
    if !dropped.is_empty() {
        tracing::debug!(%node_id, dropped = dropped.len(), "volume names that are not volume names were ignored");
    }
    volumes::replace_report(&mut tx, node_id, &kept, state.clock.now()).await?;
    tx.commit().await?;
    Ok(true)
}

/// The volumes on the caller's nodes, from each node's latest report (H2 §11.3): by node, then by name.
///
/// `max_mb` is the limit of the job that mounted the volume on that node last (`0` when the hub knows no such job),
/// and `in_use_by` the job whose lease holds it now.
#[utoipa::path(
    get,
    path = "/v1/volumes",
    tag = "volumes",
    params(PageParams),
    responses(
        (status = 200, description = "A page of volumes.", body = Page<VolumeInfo>),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks the nodes:read scope.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_volumes(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: Authorized<NodesReadScope>,
    ApiQuery(q): ApiQuery<PageParams>,
) -> Result<Json<Page<VolumeInfo>>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| VolumeCursor::decode(c).ok_or_else(bad_cursor))
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut rows = volumes::list(&mut conn, p.account_id, after.as_ref(), limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| rows.last().map(|r| VolumeCursor::after(r).encode()))
        .flatten();
    Ok(Json(Page {
        items: rows.iter().map(info).collect(),
        next_cursor,
    }))
}

fn node_offline() -> ApiError {
    ApiError::service_unavailable(
        H2ErrorCode::NodeOffline.as_str(),
        "The node is not connected, so it cannot delete the volume now. The deletion is not queued: ask again \
         when the node is online.",
    )
}

/// Deletes a volume from the node that holds it: the hub sends `VolumeDelete`, and the node's next report no
/// longer lists the volume.
///
/// `{name}` is **one** percent-encoded path segment: `tpl:private-chat/models` is sent as
/// `tpl%3Aprivate-chat%2Fmodels`. The hub decodes the segment once and checks the result with the JobSpec's volume
/// name rule; anything else, like a volume the node did not report, is `404`.
#[utoipa::path(
    delete,
    path = "/v1/volumes/{node_id}/{name}",
    tag = "volumes",
    params(
        ("node_id" = String, Path, description = "The node that holds the volume (`node_…`)."),
        ("name" = String, Path, description = "The volume's name as one percent-encoded path segment: `tpl:private-chat/models` is `tpl%3Aprivate-chat%2Fmodels`."),
    ),
    responses(
        (status = 204, description = "The node was told to delete the volume."),
        (status = 401, description = "Missing or invalid key, or the caller was revoked or expired while the request was in flight.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks the admin scope.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such node in this account, or the node reported no volume of that name.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`volume_in_use`: a job holds the volume.", content_type = "application/problem+json", body = Problem),
        (status = 503, description = "`node_offline`: the node is not connected. The deletion is not queued.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn delete_volume(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AdminKey,
    // axum splits the path into segments first and percent-decodes each one once.
    Path((node_id, name)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let node_id: NodeId = node_id.parse().map_err(|_| ApiError::not_found())?;
    // The name rule of the JobSpec (§7.1), on the decoded segment: what does not pass names no volume.
    if VolumeName::parse(&name).is_err() {
        return Err(ApiError::not_found());
    }
    let node = {
        let mut conn = state.db.acquire().await?;
        // Deleting what a node keeps is the owner's decision: the caller must still be live (§5).
        recheck_caller(&mut conn, &state, &p, state.clock.now()).await?;
        // The volume through its node, and the node through the caller's account (SI-7).
        let volume = volumes::get(&mut conn, p.account_id, node_id, &name)
            .await?
            .ok_or_else(ApiError::not_found)?;
        if volume.in_use_by.is_some() || volumes::held_by_lease(&mut conn, node_id, &name).await? {
            return Err(ApiError::conflict(
                H2ErrorCode::VolumeInUse.as_str(),
                "A job holds this volume. Stop the job first.",
            ));
        }
        store::nodes::get(&mut conn, p.account_id, node_id)
            .await?
            .ok_or_else(ApiError::not_found)?
    };
    // §6.1: `VolumeDelete` goes only to an agent that declared `volumes`, and only over a live connection.
    if !node.features.iter().any(|f| f == capability::VOLUMES) || !state.hub.is_connected(node_id) {
        return Err(node_offline());
    }
    state
        .hub
        .send(node_id, ServerMsg::VolumeDelete(VolumeDelete { name: name.clone() }))
        .map_err(|_| node_offline())?;
    tracing::info!(%node_id, principal = %p.id, "volume deletion sent to its node");
    Ok(StatusCode::NO_CONTENT)
}
