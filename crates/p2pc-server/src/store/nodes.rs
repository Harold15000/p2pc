// SPDX-License-Identifier: AGPL-3.0-only

//! The node registry and the disconnection log (spec §5 "Node identity", §6, §8 "Disconnection log").
//!
//! Two kinds of functions live here:
//! - REST-side ones take the principal's `account_id` and filter by it (SI-7);
//! - protocol-side ones ([`find_live_by_iroh_id`] and those that take a [`NodeId`] the gateway resolved from an
//!   authenticated connection) are keyed by the node itself: on the agent protocol the principal **is** the node,
//!   whose iroh NodeId iroh's TLS authenticated.

use p2pc_proto::api::{Capacity, Inventory, Node, NodeApproval, NodeState, Principal};
use p2pc_proto::ids::{AccountId, JoinTokenId, NodeId, ProjectId};
use p2pc_proto::invite::node_phrase;
use p2pc_proto::pair::EndpointKey;
use time::OffsetDateTime;

use super::{Conn, StoreError, from_ts, from_ts_opt, parse_col, ts};

/// Longest node name (a DNS label).
pub const MAX_NAME_LEN: usize = 63;
/// Base name used when a hostname has nothing usable.
pub const FALLBACK_NAME: &str = "node";
/// Most suffixes tried when making a name unique (`base-1` … `base-N`).
const MAX_NAME_SUFFIX: u32 = 10_000;

/// The stored `state` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbState {
    /// Connected (or within its TTL) and taking leases.
    Online,
    /// Not connected, or its TTL expired.
    Offline,
    /// Connected and draining.
    Draining,
}

impl DbState {
    /// The column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DbState::Online => "online",
            DbState::Offline => "offline",
            DbState::Draining => "draining",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "online" => Ok(DbState::Online),
            "offline" => Ok(DbState::Offline),
            "draining" => Ok(DbState::Draining),
            _ => Err(StoreError::Corrupt("nodes.state")),
        }
    }

    /// The API's connection state: `draining` is an online node.
    #[must_use]
    pub const fn api(self) -> NodeState {
        match self {
            DbState::Online | DbState::Draining => NodeState::Online,
            DbState::Offline => NodeState::Offline,
        }
    }
}

/// A stored node.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeRow {
    /// Node ID.
    pub id: NodeId,
    /// Owning account (from the join token, never from the agent).
    pub account_id: AccountId,
    /// Project.
    pub project_id: ProjectId,
    /// The agent's iroh NodeId (lowercase hex).
    pub iroh_node_id: String,
    /// Unique (per account) derived name.
    pub name: String,
    /// Hostname as reported.
    pub hostname: String,
    /// Last validated inventory.
    pub inventory: Inventory,
    /// Agent version from the last `Hello` (or the `Join` inventory).
    pub agent_version: String,
    /// Capabilities from the last `Hello`.
    pub features: Vec<String>,
    /// The state column.
    pub state: DbState,
    /// Whether the owner asked it to drain.
    pub draining: bool,
    /// Last contact flushed to the database.
    pub last_seen_at: Option<OffsetDateTime>,
    /// The token that enrolled it.
    pub enrolled_via_token_id: JoinTokenId,
    /// Enrollment time.
    pub created_at: OffsetDateTime,
    /// Soft-deletion time.
    pub deleted_at: Option<OffsetDateTime>,
    /// `approved` or `pending_approval` (H2 §5.5).
    pub approval: NodeApproval,
    /// The principal that minted the token that enrolled it; `None` for H1 nodes.
    pub enrolled_by: Option<Principal>,
}

impl NodeRow {
    /// The API view. `free` is the offered capacity: the caller subtracts the held reservations
    /// ([`crate::store::leases::held_for_account`], then `scheduler::fit::free_capacity`).
    #[must_use]
    pub fn api(&self) -> Node {
        // A constructor, then the fields: a field added to the shared type does not break this (CONTRIBUTING rule 7).
        let mut node = Node::new(
            self.id,
            self.name.clone(),
            self.hostname.clone(),
            self.state.api(),
            self.inventory.clone(),
            self.created_at,
        );
        node.draining = self.draining;
        node.free = offered(&self.inventory);
        node.last_seen = self.last_seen_at;
        node.approval = self.approval;
        node.enrolled_by = self.enrolled_by;
        node.node_phrase = self.node_phrase();
        node
    }

    /// The node phrase (H2 §5.5): 6 words derived from the node's iroh NodeId, which the hub PC shows before
    /// approving it and the joined PC shows too. `None` only if the stored NodeId is not 64 hex characters, which the
    /// table's CHECK forbids.
    #[must_use]
    pub fn node_phrase(&self) -> Option<String> {
        let key: EndpointKey = self.iroh_node_id.parse().ok()?;
        Some(node_phrase(&key).to_string())
    }
}

/// The capacity a node offers (§8): what the agent reported in `offered`, which `p2pc-proto` validated against the
/// hardware.
#[must_use]
pub fn offered(inventory: &Inventory) -> Capacity {
    inventory.offered.clone()
}

/// A node to insert.
#[derive(Debug, Clone)]
pub struct NewNode {
    /// Node ID.
    pub id: NodeId,
    /// Account and project, from the token row.
    pub account_id: AccountId,
    /// Project.
    pub project_id: ProjectId,
    /// The agent's iroh NodeId.
    pub iroh_node_id: String,
    /// Validated inventory.
    pub inventory: Inventory,
    /// The token that enrolls it.
    pub token_id: JoinTokenId,
}

/// The raw columns of `nodes`, in the order of `select_nodes!`.
#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    account_id: String,
    project_id: String,
    iroh_node_id: String,
    name: String,
    hostname: String,
    inventory: String,
    agent_version: String,
    features: String,
    state: String,
    draining: i64,
    last_seen_at: Option<i64>,
    enrolled_via_token_id: String,
    created_at: i64,
    deleted_at: Option<i64>,
    approval: String,
    enrolled_by_key_id: Option<String>,
    enrolled_by_device_id: Option<String>,
}

macro_rules! select_nodes {
    ($tail:literal) => {
        concat!(
            "SELECT id, account_id, project_id, iroh_node_id, name, hostname, inventory, agent_version, features, \
             state, draining, last_seen_at, enrolled_via_token_id, created_at, deleted_at, approval, \
             enrolled_by_key_id, enrolled_by_device_id FROM nodes ",
            $tail
        )
    };
}

fn decode(row: Row) -> Result<NodeRow, StoreError> {
    let Row {
        id,
        account_id: account,
        project_id: project,
        iroh_node_id: iroh,
        name,
        hostname: host,
        inventory: inv,
        agent_version: ver,
        features: feat,
        state,
        draining: drain,
        last_seen_at: seen,
        enrolled_via_token_id: token,
        created_at: created,
        deleted_at: deleted,
        approval,
        enrolled_by_key_id: by_key,
        enrolled_by_device_id: by_device,
    } = row;
    Ok(NodeRow {
        id: parse_col(&id, "nodes.id")?,
        account_id: parse_col(&account, "nodes.account_id")?,
        project_id: parse_col(&project, "nodes.project_id")?,
        iroh_node_id: iroh,
        name,
        hostname: host,
        inventory: serde_json::from_str(&inv).map_err(|_| StoreError::Corrupt("nodes.inventory"))?,
        agent_version: ver,
        features: serde_json::from_str(&feat).map_err(|_| StoreError::Corrupt("nodes.features"))?,
        state: DbState::parse(&state)?,
        draining: drain != 0,
        last_seen_at: from_ts_opt(seen, "nodes.last_seen_at")?,
        enrolled_via_token_id: parse_col(&token, "nodes.enrolled_via_token_id")?,
        created_at: from_ts(created, "nodes.created_at")?,
        deleted_at: from_ts_opt(deleted, "nodes.deleted_at")?,
        approval: match approval.as_str() {
            "approved" => NodeApproval::Approved,
            "pending_approval" => NodeApproval::PendingApproval,
            _ => return Err(StoreError::Corrupt("nodes.approval")),
        },
        enrolled_by: match (by_key, by_device) {
            (None, None) => None,
            (k, d) => Some(super::jobs::principal_cols(
                k.as_deref(),
                d.as_deref(),
                "nodes.enrolled_by",
            )?),
        },
    })
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Corrupt("json"))
}

/// The base of a node's name (§5 "Names"): the hostname's first label, lowercased, with every character outside
/// `[a-z0-9-]` replaced by `-`, runs of `-` collapsed, no leading or trailing `-`, at most 63 characters (keeping
/// room for a `-N` suffix). [`FALLBACK_NAME`] if nothing is left.
#[must_use]
pub fn base_name(hostname: &str) -> String {
    let label = hostname.split('.').next().unwrap_or_default();
    let mut out = String::new();
    for c in label.chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() {
            c
        } else {
            '-'
        };
        if c == '-' && (out.is_empty() || out.ends_with('-')) {
            continue;
        }
        out.push(c);
    }
    // Room for "-10000".
    out.truncate(MAX_NAME_LEN - 6);
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { FALLBACK_NAME.to_string() } else { out }
}

/// Whether a live node of `account_id` is called `name` (case-insensitively).
async fn name_taken(conn: &mut Conn, account_id: AccountId, name: &str) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE account_id = ? AND deleted_at IS NULL AND name = ? COLLATE NOCASE",
    )
    .bind(account_id.to_string())
    .bind(name)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// A name for a new node of `account_id`: `base`, then `base-1`, `base-2`, … until one is free. Run it in the
/// transaction that inserts the node; the unique index is the final guard.
pub async fn unique_name(conn: &mut Conn, account_id: AccountId, hostname: &str) -> Result<String, StoreError> {
    let base = base_name(hostname);
    if !name_taken(conn, account_id, &base).await? {
        return Ok(base);
    }
    for i in 1..=MAX_NAME_SUFFIX {
        let candidate = format!("{base}-{i}");
        if !name_taken(conn, account_id, &candidate).await? {
            return Ok(candidate);
        }
    }
    Err(StoreError::Corrupt("nodes.name (no free suffix)"))
}

/// Inserts a node, `offline` until its connection is registered, and returns the row.
///
/// Its `approval` and `enrolled_by` come from the token row `node.token_id` (H2 §5.5), in the same statement: the
/// node is `approved` iff the token has `pre_approved = 1`, or a `bound_iroh_node_id` (only tokens of approved join
/// requests have one), or was minted by an API key with the `admin` scope (H1 behaviour); otherwise it is
/// `pending_approval`, and the scheduler offers it no lease until an `admin` approves it. `enrolled_by` is the
/// token's minter.
pub async fn insert(conn: &mut Conn, node: &NewNode, now: OffsetDateTime) -> Result<NodeRow, StoreError> {
    let name = unique_name(conn, node.account_id, &node.inventory.hostname).await?;
    let done = sqlx::query(
        "INSERT INTO nodes (id, account_id, project_id, iroh_node_id, name, hostname, inventory, agent_version, \
         state, last_seen_at, enrolled_via_token_id, created_at, approval, enrolled_by_key_id, enrolled_by_device_id) \
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'offline', ?9, ?10, ?11, \
                CASE WHEN t.pre_approved = 1 OR t.bound_iroh_node_id IS NOT NULL \
                          OR EXISTS (SELECT 1 FROM api_keys k, json_each(k.scopes) s \
                                     WHERE k.key_id = t.created_by_key_id AND s.value = 'admin') \
                     THEN 'approved' ELSE 'pending_approval' END, \
                t.created_by_key_id, t.created_by_device_id \
         FROM join_tokens t WHERE t.id = ?10 AND t.account_id = ?2",
    )
    .bind(node.id.to_string())
    .bind(node.account_id.to_string())
    .bind(node.project_id.to_string())
    .bind(&node.iroh_node_id)
    .bind(name)
    .bind(&node.inventory.hostname)
    .bind(json(&node.inventory)?)
    .bind(&node.inventory.agent_version)
    .bind(ts(now))
    .bind(node.token_id.to_string())
    .bind(ts(now))
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done != 1 {
        return Err(StoreError::Corrupt("nodes.enrolled_via_token_id"));
    }
    by_id(conn, node.id).await?.ok_or(StoreError::Corrupt("nodes"))
}

/// Approves a live node of `account_id` (H2 §5.5, `POST /v1/nodes/{id}/approve`). Idempotent: `Some(true)` when this
/// call changed it, `Some(false)` when it already was approved, `None` when no live node of that account has that id.
pub async fn approve(conn: &mut Conn, account_id: AccountId, id: NodeId) -> Result<Option<bool>, StoreError> {
    let done = sqlx::query(
        "UPDATE nodes SET approval = 'approved' \
         WHERE account_id = ? AND id = ? AND deleted_at IS NULL AND approval = 'pending_approval'",
    )
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done == 1 {
        return Ok(Some(true));
    }
    Ok(get(conn, account_id, id).await?.map(|_| false))
}

/// Re-enrolls the live node `id` of `account_id` with a new join token (§5 "Re-enrolling the same machine"): the
/// same node id and name, the inventory (hostname, agent version) refreshed, the project taken from the token, and
/// the token recorded as the one it was enrolled through. Run it in the `Join` transaction, which then consumes the
/// token. `None` when no live node of that account has that id (nothing changed).
pub async fn reenroll(
    conn: &mut Conn,
    account_id: AccountId,
    id: NodeId,
    project_id: ProjectId,
    inventory: &Inventory,
    token_id: JoinTokenId,
) -> Result<Option<NodeRow>, StoreError> {
    let done = sqlx::query(
        "UPDATE nodes SET project_id = ?, hostname = ?, inventory = ?, agent_version = ?, enrolled_via_token_id = ? \
         WHERE id = ? AND account_id = ? AND deleted_at IS NULL",
    )
    .bind(project_id.to_string())
    .bind(&inventory.hostname)
    .bind(json(inventory)?)
    .bind(&inventory.agent_version)
    .bind(token_id.to_string())
    .bind(id.to_string())
    .bind(account_id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done != 1 {
        return Ok(None);
    }
    by_id(conn, id).await
}

/// A node by ID, deleted or not. Protocol side.
pub async fn by_id(conn: &mut Conn, id: NodeId) -> Result<Option<NodeRow>, StoreError> {
    let row: Option<Row> = sqlx::query_as(select_nodes!("WHERE id = ?"))
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode).transpose()
}

/// The live (not deleted) node with this iroh NodeId. Protocol side: iroh's TLS authenticated the NodeId.
pub async fn find_live_by_iroh_id(conn: &mut Conn, iroh_node_id: &str) -> Result<Option<NodeRow>, StoreError> {
    let row: Option<Row> = sqlx::query_as(select_nodes!("WHERE iroh_node_id = ? AND deleted_at IS NULL"))
        .bind(iroh_node_id)
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode).transpose()
}

/// A live node of `account_id`.
pub async fn get(conn: &mut Conn, account_id: AccountId, id: NodeId) -> Result<Option<NodeRow>, StoreError> {
    let row: Option<Row> = sqlx::query_as(select_nodes!("WHERE account_id = ? AND id = ? AND deleted_at IS NULL"))
        .bind(account_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode).transpose()
}

/// Position after which a node list continues: `(created_at, id)` of the last node returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeCursor {
    /// `created_at` of the last node, in Unix seconds.
    pub created_at: i64,
    /// Its ID.
    pub id: NodeId,
}

impl NodeCursor {
    /// The cursor after `row`.
    #[must_use]
    pub fn after(row: &NodeRow) -> Self {
        Self {
            created_at: ts(row.created_at),
            id: row.id,
        }
    }

    /// The opaque text form, `<created_at>.<id>`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}.{}", self.created_at, self.id)
    }

    /// Parses [`NodeCursor::encode`]'s output.
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let (at, id) = text.split_once('.')?;
        if at.is_empty() || !at.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            created_at: at.parse().ok()?,
            id: id.parse().ok()?,
        })
    }
}

/// Live nodes of `account_id` in enrollment order, optionally in one API state, after `after`, at most `limit`.
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    state: Option<NodeState>,
    after: Option<NodeCursor>,
    limit: u32,
) -> Result<Vec<NodeRow>, StoreError> {
    let (at, id) = after.map_or((None, None), |c| (Some(c.created_at), Some(c.id.to_string())));
    let state = state.map(|s| match s {
        NodeState::Online => "online",
        NodeState::Offline => "offline",
    });
    let rows: Vec<Row> = sqlx::query_as(select_nodes!(
        "WHERE account_id = ?1 AND deleted_at IS NULL \
         AND (?5 IS NULL OR (?5 = 'online' AND state IN ('online', 'draining')) OR (?5 = 'offline' AND state = 'offline')) \
         AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND id > ?3)) \
         ORDER BY created_at, id LIMIT ?4"
    ))
    .bind(account_id.to_string())
    .bind(at)
    .bind(id)
    .bind(i64::from(limit))
    .bind(state)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// Every live node of `account_id`, in enrollment order: the scheduler's candidates and the estimate's (§8). An
/// account has a handful of nodes, so this is not paginated.
pub async fn live_of_account(conn: &mut Conn, account_id: AccountId) -> Result<Vec<NodeRow>, StoreError> {
    let rows: Vec<Row> = sqlx::query_as(select_nodes!(
        "WHERE account_id = ? AND deleted_at IS NULL ORDER BY created_at, id"
    ))
    .bind(account_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// Marks the latest disconnection of `id` as `requeued` when the scheduler requeued its leases (§8 "Disconnection
/// log"): the open one (a reconnect whose `Hello` lacked leases), or the one the liveness sweep just resolved as
/// `offline` (TTL expiry). An older, `recovered` row is left alone.
pub async fn disconnection_requeued(conn: &mut Conn, id: NodeId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE node_disconnections SET outcome = 'requeued', resolved_at = COALESCE(resolved_at, ?1) \
         WHERE id = (SELECT MAX(id) FROM node_disconnections WHERE node_id = ?2) \
           AND (outcome IS NULL OR outcome = 'offline')",
    )
    .bind(ts(now))
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// After a `Hello`: stores the inventory, version and features, and marks the node `online` (or `draining`, when the
/// owner drained it). Protocol side. Returns the node's `draining` flag when it is still live (exactly one row
/// changed); `None` means it was deleted meanwhile, and the session answers `not_enrolled`.
pub async fn mark_online(
    conn: &mut Conn,
    id: NodeId,
    inventory: &Inventory,
    agent_version: &str,
    features: &[String],
    now: OffsetDateTime,
) -> Result<Option<bool>, StoreError> {
    let draining: Option<i64> = sqlx::query_scalar(
        "UPDATE nodes SET inventory = ?, hostname = ?, agent_version = ?, features = ?, last_seen_at = ?, \
         state = CASE WHEN draining = 1 THEN 'draining' ELSE 'online' END \
         WHERE id = ? AND deleted_at IS NULL RETURNING draining",
    )
    .bind(json(inventory)?)
    .bind(&inventory.hostname)
    .bind(agent_version)
    .bind(json(&features)?)
    .bind(ts(now))
    .bind(id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(draining.map(|d| d != 0))
}

/// Marks a freshly enrolled node `online` (after `Join`). Protocol side. Returns its `draining` flag when it is
/// still live (exactly one row changed), `None` when it was deleted.
pub async fn mark_connected(conn: &mut Conn, id: NodeId, now: OffsetDateTime) -> Result<Option<bool>, StoreError> {
    let draining: Option<i64> = sqlx::query_scalar(
        "UPDATE nodes SET last_seen_at = ?, state = CASE WHEN draining = 1 THEN 'draining' ELSE 'online' END \
         WHERE id = ? AND deleted_at IS NULL RETURNING draining",
    )
    .bind(ts(now))
    .bind(id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(draining.map(|d| d != 0))
}

/// What [`update_inventory`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryUpdate {
    /// The inventory differs from the stored one once both are normalized ([`normalized`]); it was stored.
    pub changed: bool,
    /// The owner's drain request on the node.
    pub draining: bool,
}

/// An inventory in a canonical order, so two reports of the same machine compare equal: GPUs by index then UUID,
/// sandbox drivers by name, and their runtimes and problems sorted. The agent's detection may list them in any order.
#[must_use]
pub fn normalized(inventory: &Inventory) -> Inventory {
    let mut inv = inventory.clone();
    inv.gpus.sort_by(|a, b| (a.index, &a.uuid).cmp(&(b.index, &b.uuid)));
    inv.sandbox.sort_by(|a, b| a.driver.cmp(&b.driver));
    for sb in &mut inv.sandbox {
        sb.runtimes.sort();
        sb.problems.sort();
    }
    inv
}

/// Replaces the inventory (`InventoryUpdate`) when it changed, compared normalized. Protocol side. `None` for a
/// deleted node. The scheduler re-arms the offer cap only for a real change on a node that is not draining (§8).
pub async fn update_inventory(
    conn: &mut Conn,
    id: NodeId,
    inventory: &Inventory,
) -> Result<Option<InventoryUpdate>, StoreError> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT inventory, draining FROM nodes WHERE id = ? AND deleted_at IS NULL")
            .bind(id.to_string())
            .fetch_optional(&mut *conn)
            .await?;
    let Some((stored, draining)) = row else {
        return Ok(None);
    };
    // An unreadable stored inventory is replaced, and counts as a change.
    let changed =
        serde_json::from_str::<Inventory>(&stored).map_or(true, |old| normalized(&old) != normalized(inventory));
    if changed {
        sqlx::query("UPDATE nodes SET inventory = ?, hostname = ? WHERE id = ? AND deleted_at IS NULL")
            .bind(json(inventory)?)
            .bind(&inventory.hostname)
            .bind(id.to_string())
            .execute(&mut *conn)
            .await?;
    }
    Ok(Some(InventoryUpdate {
        changed,
        draining: draining != 0,
    }))
}

/// Flushes the in-memory last contact. Protocol side.
pub async fn touch_last_seen(conn: &mut Conn, id: NodeId, at: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query("UPDATE nodes SET last_seen_at = MAX(COALESCE(last_seen_at, 0), ?) WHERE id = ?")
        .bind(ts(at))
        .bind(id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The last contact stored for a node: `last_seen_at`, or its enrollment time if it never had one. Protocol side.
pub async fn last_contact(conn: &mut Conn, id: NodeId) -> Result<Option<OffsetDateTime>, StoreError> {
    let at: Option<i64> = sqlx::query_scalar("SELECT COALESCE(last_seen_at, created_at) FROM nodes WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    at.map(|t| from_ts(t, "nodes.last_seen_at")).transpose()
}

/// Marks a live node `offline` (TTL expired). Protocol side. Returns whether a row changed: `false` for a deleted
/// node, which then gets no `Lost` (it already got `Deleted`).
pub async fn mark_offline(conn: &mut Conn, id: NodeId) -> Result<bool, StoreError> {
    let done = sqlx::query("UPDATE nodes SET state = 'offline' WHERE id = ? AND deleted_at IS NULL")
        .bind(id.to_string())
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(done == 1)
}

/// Live nodes in state `online` or `draining`, of every account: what the server treats as seen at boot (§6
/// "Server restart"). Protocol side.
pub async fn connected_at_boot(conn: &mut Conn) -> Result<Vec<NodeId>, StoreError> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM nodes WHERE deleted_at IS NULL AND state IN ('online', 'draining')")
            .fetch_all(&mut *conn)
            .await?;
    ids.iter().map(|s| parse_col(s, "nodes.id")).collect()
}

/// At boot (§6 "Server restart"): the live nodes that were `online` or `draining` ([`connected_at_boot`]), now marked
/// `offline` until their agent connects again (T05b real run: the API must never show a node as connected, with its
/// last-known data, before its agent's `Hello`). The owner's drain request (`draining`) is kept for when it comes
/// back. Protocol side; run it in the boot transaction.
pub async fn offline_at_boot(conn: &mut Conn) -> Result<Vec<NodeId>, StoreError> {
    let ids = connected_at_boot(conn).await?;
    sqlx::query("UPDATE nodes SET state = 'offline' WHERE deleted_at IS NULL AND state IN ('online', 'draining')")
        .execute(&mut *conn)
        .await?;
    Ok(ids)
}

/// Sets or clears the owner's drain request on a live node of `account_id`, and returns the updated row.
pub async fn set_draining(
    conn: &mut Conn,
    account_id: AccountId,
    id: NodeId,
    draining: bool,
) -> Result<Option<NodeRow>, StoreError> {
    sqlx::query(
        "UPDATE nodes SET draining = ?1, \
         state = CASE WHEN state = 'offline' THEN 'offline' WHEN ?1 = 1 THEN 'draining' ELSE 'online' END \
         WHERE account_id = ?2 AND id = ?3 AND deleted_at IS NULL",
    )
    .bind(i64::from(draining))
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?;
    get(conn, account_id, id).await
}

/// Soft-deletes a live node of `account_id`. Returns whether it existed.
pub async fn soft_delete(
    conn: &mut Conn,
    account_id: AccountId,
    id: NodeId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE nodes SET deleted_at = ?, state = 'offline' WHERE account_id = ? AND id = ? AND deleted_at IS NULL",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// How a disconnection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectOutcome {
    /// The node came back within its TTL.
    Recovered,
    /// The TTL expired.
    Offline,
    /// The node's leases were requeued (written by T06's scheduler).
    Requeued,
}

impl DisconnectOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            DisconnectOutcome::Recovered => "recovered",
            DisconnectOutcome::Offline => "offline",
            DisconnectOutcome::Requeued => "requeued",
        }
    }
}

/// Opens a disconnection for `id` (its last contact was `last_contact`), unless one is already open.
pub async fn open_disconnection(conn: &mut Conn, id: NodeId, last_contact: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO node_disconnections (node_id, last_contact_at) VALUES (?, ?) \
         ON CONFLICT (node_id) WHERE resolved_at IS NULL DO NOTHING",
    )
    .bind(id.to_string())
    .bind(ts(last_contact))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Resolves the open disconnection of `id`, if any, with `outcome`. Returns whether one was open.
pub async fn resolve_disconnection(
    conn: &mut Conn,
    id: NodeId,
    outcome: DisconnectOutcome,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE node_disconnections SET resolved_at = ?, outcome = ? WHERE node_id = ? AND resolved_at IS NULL",
    )
    .bind(ts(now))
    .bind(outcome.as_str())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// One row of the disconnection log, for tests and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnection {
    /// Last contact before the disconnection.
    pub last_contact_at: OffsetDateTime,
    /// When it was resolved.
    pub resolved_at: Option<OffsetDateTime>,
    /// `recovered` or `offline`.
    pub outcome: Option<String>,
}

/// The disconnection log of a node, oldest first.
pub async fn disconnections(conn: &mut Conn, id: NodeId) -> Result<Vec<Disconnection>, StoreError> {
    let rows: Vec<(i64, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT last_contact_at, resolved_at, outcome FROM node_disconnections WHERE node_id = ? ORDER BY id",
    )
    .bind(id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(last, resolved, outcome)| {
            Ok(Disconnection {
                last_contact_at: from_ts(last, "node_disconnections.last_contact_at")?,
                resolved_at: from_ts_opt(resolved, "node_disconnections.resolved_at")?,
                outcome,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_names_are_sanitized() {
        for (host, want) in [
            ("node-1", "node-1"),
            ("Node-1.example.invalid", "node-1"),
            ("MY_LAPTOP", "my-laptop"),
            ("--a__b--", "a-b"),
            ("...", "node"),
            ("", "node"),
            ("_", "node"),
            ("x".repeat(80).as_str(), &"x".repeat(57)),
        ] {
            assert_eq!(base_name(host), want, "{host}");
        }
        let long = format!("{}-{}", "a".repeat(56), "b".repeat(10));
        let got = base_name(&long);
        assert!(got.len() <= MAX_NAME_LEN - 6 && !got.ends_with('-'), "{got}");
    }

    /// Two reports of the same machine compare equal once normalized, whatever the order of their lists; a real
    /// change does not.
    #[test]
    fn normalized_inventories_ignore_list_order() {
        let inv = |gpus: &[u32], drivers: &[&str], runtimes: &[&str], offered_mb: u64| -> Inventory {
            serde_json::from_value(serde_json::json!({
                "hostname": "n", "platform": "linux", "cpu": {"model": "Example CPU", "cores": 8},
                "memory_mb": 16384, "os": "Ubuntu 24.04", "arch": "x86_64",
                "gpus": gpus.iter().map(|i| serde_json::json!({"uuid": format!("GPU-{i}"), "index": i,
                    "name": "Example GPU", "driver_version": "1", "vram_mb": 1024})).collect::<Vec<_>>(),
                "gpu_status": {"status": "ok"},
                "sandbox": drivers.iter().map(|d| serde_json::json!({"driver": d, "class": "container",
                    "runtimes": runtimes, "ready": true})).collect::<Vec<_>>(),
                "offered": {"cpu": 4.0, "memory_mb": offered_mb, "gpu": 0}, "agent_version": "0.1.0",
            }))
            .unwrap()
        };
        let a = inv(&[0, 1], &["podman", "other"], &["crun", "runsc"], 8192);
        let b = inv(&[1, 0], &["other", "podman"], &["runsc", "crun"], 8192);
        assert_ne!(a, b);
        assert_eq!(normalized(&a), normalized(&b));
        assert_ne!(
            normalized(&a),
            normalized(&inv(&[0, 1], &["podman", "other"], &["crun", "runsc"], 4096))
        );
    }

    #[test]
    fn cursor_round_trip() {
        let c = NodeCursor {
            created_at: 1_793_872_800,
            id: NodeId::generate(),
        };
        assert_eq!(NodeCursor::decode(&c.encode()), Some(c));
        assert_eq!(NodeCursor::decode("1.jtk_01ARZ3NDEKTSV4RRFFQ69G5FAV"), None);
    }
}
