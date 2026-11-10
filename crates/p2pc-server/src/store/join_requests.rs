// SPDX-License-Identifier: AGPL-3.0-only

//! Join requests (H2 spec §5.4): an invite relayed by a phone, revealed against its listener commitment, approved on
//! the hub PC, and turned into a join token bound to the request's agent NodeId.
//!
//! **The 15-minute rule is judged by `created_at`, never by `state`.** Every transition that needs a live request
//! (reveal, approve, token) checks `now < expires_at` (`expires_at = created_at + 15 min`) in its own `UPDATE`, so
//! how long a request can be revealed, approved or turned into a token never depends on when the expiry sweep
//! ([`expire`]) last ran. Every function filters by the caller's `account_id` (SI-7).

use p2pc_proto::api::{JoinRequestState, Principal};
use p2pc_proto::ids::{AccountId, JoinRequestId, JoinTokenId, ProjectId};
use time::OffsetDateTime;

use super::jobs::{principal_binds, principal_cols};
use super::{Conn, StoreError, from_ts, from_ts_opt, parse_col, ts};

/// A stored join request. Holds no secret (the listener nonce is stored only once revealed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequestRow {
    /// Request ID.
    pub id: JoinRequestId,
    /// Owning account.
    pub account_id: AccountId,
    /// The requester's project.
    pub project_id: ProjectId,
    /// The requesting principal (a `nodes:invite` device in practice).
    pub requested_by: Principal,
    /// The invite listener's NodeId (64 hex).
    pub listener_node_id: String,
    /// The joining agent's NodeId (64 hex): the token will be bound to it.
    pub iroh_node_id: String,
    /// The invite's expiry, from the QR.
    pub invite_expires_at: OffsetDateTime,
    /// The listener commitment (64 hex).
    pub listener_commitment: String,
    /// The hub nonce (64 hex).
    pub hub_nonce: String,
    /// The revealed listener nonce (64 hex), once the reveal matched.
    pub listener_nonce: Option<String>,
    /// The stored state ([`JoinRequestRow::state_at`] applies the 15 minutes).
    pub state: JoinRequestState,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// `created_at` + 15 minutes.
    pub expires_at: OffsetDateTime,
    /// When the approving principal approved it.
    pub approved_at: Option<OffsetDateTime>,
    /// The approving principal.
    pub approved_by: Option<Principal>,
    /// The join token it yielded.
    pub join_token_id: Option<JoinTokenId>,
}

impl JoinRequestRow {
    /// The state as the API reports it at `now`: an open request (`awaiting_reveal`, `pending` or `approved`) whose 15
    /// minutes have passed is `expired`, whatever the sweep has written.
    #[must_use]
    pub fn state_at(&self, now: OffsetDateTime) -> JoinRequestState {
        match self.state {
            JoinRequestState::AwaitingReveal | JoinRequestState::Pending | JoinRequestState::Approved
                if !self.is_within_ttl(now) =>
            {
                JoinRequestState::Expired
            }
            s => s,
        }
    }

    /// Whether the request was created less than 15 minutes before `now` (an instant equal to `expires_at` counts
    /// as past it).
    #[must_use]
    pub fn is_within_ttl(&self, now: OffsetDateTime) -> bool {
        now < self.expires_at
    }
}

/// A request to insert, created `awaiting_reveal`.
#[derive(Debug, Clone)]
pub struct NewJoinRequest {
    /// Request ID.
    pub id: JoinRequestId,
    /// The requester's project.
    pub project_id: ProjectId,
    /// The requesting principal.
    pub requested_by: Principal,
    /// The listener NodeId (64 hex, a checked Ed25519 point).
    pub listener_node_id: String,
    /// The agent NodeId (64 hex, a checked Ed25519 point).
    pub iroh_node_id: String,
    /// The invite's expiry.
    pub invite_expires_at: OffsetDateTime,
    /// The listener commitment (64 hex).
    pub listener_commitment: String,
    /// The hub nonce (64 hex), drawn for this request.
    pub hub_nonce: String,
    /// `created_at` + 15 minutes.
    pub expires_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct Raw {
    id: String,
    account_id: String,
    project_id: String,
    requested_by_key_id: Option<String>,
    requested_by_device_id: Option<String>,
    listener_node_id: String,
    iroh_node_id: String,
    invite_expires_at: i64,
    listener_commitment: String,
    hub_nonce: String,
    listener_nonce: Option<String>,
    state: String,
    created_at: i64,
    expires_at: i64,
    approved_at: Option<i64>,
    approved_by_key_id: Option<String>,
    approved_by_device_id: Option<String>,
    join_token_id: Option<String>,
}

macro_rules! select_requests {
    ($tail:literal) => {
        concat!(
            "SELECT id, account_id, project_id, requested_by_key_id, requested_by_device_id, listener_node_id, \
             iroh_node_id, invite_expires_at, listener_commitment, hub_nonce, listener_nonce, state, created_at, \
             expires_at, approved_at, approved_by_key_id, approved_by_device_id, join_token_id FROM join_requests ",
            $tail
        )
    };
}

/// The storage name of a state.
#[must_use]
pub fn state_name(s: JoinRequestState) -> &'static str {
    match s {
        JoinRequestState::AwaitingReveal => "awaiting_reveal",
        JoinRequestState::Pending => "pending",
        JoinRequestState::Approved => "approved",
        JoinRequestState::Rejected => "rejected",
        JoinRequestState::Expired => "expired",
        JoinRequestState::Delivered => "delivered",
    }
}

fn parse_state(text: &str) -> Result<JoinRequestState, StoreError> {
    Ok(match text {
        "awaiting_reveal" => JoinRequestState::AwaitingReveal,
        "pending" => JoinRequestState::Pending,
        "approved" => JoinRequestState::Approved,
        "rejected" => JoinRequestState::Rejected,
        "expired" => JoinRequestState::Expired,
        "delivered" => JoinRequestState::Delivered,
        _ => return Err(StoreError::Corrupt("join_requests.state")),
    })
}

fn decode(r: Raw) -> Result<JoinRequestRow, StoreError> {
    Ok(JoinRequestRow {
        id: parse_col(&r.id, "join_requests.id")?,
        account_id: parse_col(&r.account_id, "join_requests.account_id")?,
        project_id: parse_col(&r.project_id, "join_requests.project_id")?,
        requested_by: principal_cols(
            r.requested_by_key_id.as_deref(),
            r.requested_by_device_id.as_deref(),
            "join_requests.requested_by",
        )?,
        listener_node_id: r.listener_node_id,
        iroh_node_id: r.iroh_node_id,
        invite_expires_at: from_ts(r.invite_expires_at, "join_requests.invite_expires_at")?,
        listener_commitment: r.listener_commitment,
        hub_nonce: r.hub_nonce,
        listener_nonce: r.listener_nonce,
        state: parse_state(&r.state)?,
        created_at: from_ts(r.created_at, "join_requests.created_at")?,
        expires_at: from_ts(r.expires_at, "join_requests.expires_at")?,
        approved_at: from_ts_opt(r.approved_at, "join_requests.approved_at")?,
        approved_by: match (r.approved_by_key_id, r.approved_by_device_id) {
            (None, None) => None,
            (k, d) => Some(principal_cols(k.as_deref(), d.as_deref(), "join_requests.approved_by")?),
        },
        join_token_id: r
            .join_token_id
            .map(|t| parse_col(&t, "join_requests.join_token_id"))
            .transpose()?,
    })
}

/// Inserts a request for `account_id`, `awaiting_reveal`.
pub async fn insert(
    conn: &mut Conn,
    account_id: AccountId,
    r: &NewJoinRequest,
    now: OffsetDateTime,
) -> Result<JoinRequestRow, StoreError> {
    let (by_key, by_device) = principal_binds(r.requested_by);
    sqlx::query(
        "INSERT INTO join_requests (id, account_id, project_id, requested_by_key_id, requested_by_device_id, \
         listener_node_id, iroh_node_id, invite_expires_at, listener_commitment, hub_nonce, state, created_at, \
         expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'awaiting_reveal', ?, ?)",
    )
    .bind(r.id.to_string())
    .bind(account_id.to_string())
    .bind(r.project_id.to_string())
    .bind(by_key)
    .bind(by_device)
    .bind(&r.listener_node_id)
    .bind(&r.iroh_node_id)
    .bind(ts(r.invite_expires_at))
    .bind(&r.listener_commitment)
    .bind(&r.hub_nonce)
    .bind(ts(now))
    .bind(ts(r.expires_at))
    .execute(&mut *conn)
    .await?;
    get(conn, account_id, r.id)
        .await?
        .ok_or(StoreError::Corrupt("join_requests"))
}

/// One request of `account_id`.
pub async fn get(
    conn: &mut Conn,
    account_id: AccountId,
    id: JoinRequestId,
) -> Result<Option<JoinRequestRow>, StoreError> {
    let raw: Option<Raw> = sqlx::query_as(select_requests!("WHERE account_id = ? AND id = ?"))
        .bind(account_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

/// `account_id`'s requests in creation order, after `(created_at, id)`, at most `limit`; only those of
/// `requested_by` when it is given (a non-`admin` caller sees its own requests only).
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    requested_by: Option<Principal>,
    after: Option<(i64, String)>,
    limit: u32,
) -> Result<Vec<JoinRequestRow>, StoreError> {
    let (by_key, by_device) = requested_by.map(principal_binds).unwrap_or_default();
    let filtered = requested_by.is_some();
    let (at, id) = after.map_or((None, None), |(a, i)| (Some(a), Some(i)));
    let rows: Vec<Raw> = sqlx::query_as(select_requests!(
        "WHERE account_id = ?1 \
           AND (?2 = 0 OR (?3 IS NOT NULL AND requested_by_key_id = ?3) \
                OR (?4 IS NOT NULL AND requested_by_device_id = ?4)) \
           AND (?5 IS NULL OR created_at > ?5 OR (created_at = ?5 AND id > ?6)) \
         ORDER BY created_at, id LIMIT ?7"
    ))
    .bind(account_id.to_string())
    .bind(filtered)
    .bind(by_key)
    .bind(by_device)
    .bind(at)
    .bind(id)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// The limits' counts (§5.4 step 3) at `now`: requests of `account_id` still open (`awaiting_reveal`, `pending` or
/// `approved`, within their 15 minutes), those of them opened by `by`, and the requests `by` created in the last
/// hour, whatever became of them.
pub async fn counts(
    conn: &mut Conn,
    account_id: AccountId,
    by: Principal,
    now: OffsetDateTime,
) -> Result<(i64, i64, i64), StoreError> {
    let (by_key, by_device) = principal_binds(by);
    let row: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
           COALESCE(SUM(state IN ('awaiting_reveal', 'pending', 'approved') AND expires_at > ?2), 0), \
           COALESCE(SUM(state IN ('awaiting_reveal', 'pending', 'approved') AND expires_at > ?2 AND mine), 0), \
           COALESCE(SUM(created_at > ?2 - 3600 AND mine), 0) \
         FROM (SELECT state, expires_at, created_at, \
                      ((?3 IS NOT NULL AND requested_by_key_id = ?3) \
                       OR (?4 IS NOT NULL AND requested_by_device_id = ?4)) AS mine \
               FROM join_requests WHERE account_id = ?1)",
    )
    .bind(account_id.to_string())
    .bind(ts(now))
    .bind(by_key)
    .bind(by_device)
    .fetch_one(&mut *conn)
    .await?;
    Ok(row)
}

/// The reveal matched the commitment: `awaiting_reveal` → `pending`, with the nonce, within the 15 minutes. Returns
/// whether it applied.
pub async fn reveal(
    conn: &mut Conn,
    account_id: AccountId,
    id: JoinRequestId,
    listener_nonce: &str,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE join_requests SET state = 'pending', listener_nonce = ?1, revealed_at = ?2 \
         WHERE account_id = ?3 AND id = ?4 AND state = 'awaiting_reveal' AND expires_at > ?2",
    )
    .bind(listener_nonce)
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Ends an open request `rejected` (a wrong reveal, a rejection, a withdrawal) when its stored state is one of
/// `from`. Returns whether it applied.
pub async fn reject(
    conn: &mut Conn,
    account_id: AccountId,
    id: JoinRequestId,
    from: &[JoinRequestState],
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let from: Vec<&str> = from.iter().map(|s| state_name(*s)).collect();
    let from = serde_json::to_string(&from).map_err(|_| StoreError::Corrupt("join_requests.state"))?;
    let done = sqlx::query(
        "UPDATE join_requests SET state = 'rejected', closed_at = ?1 \
         WHERE account_id = ?2 AND id = ?3 AND state IN (SELECT value FROM json_each(?4))",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(id.to_string())
    .bind(from)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// `pending` → `approved` by `approver`, within the 15 minutes (checked against `created_at`). Mints nothing.
pub async fn approve(
    conn: &mut Conn,
    account_id: AccountId,
    id: JoinRequestId,
    approver: Principal,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let (by_key, by_device) = principal_binds(approver);
    let done = sqlx::query(
        "UPDATE join_requests SET state = 'approved', approved_at = ?1, approved_by_key_id = ?2, \
         approved_by_device_id = ?3 \
         WHERE account_id = ?4 AND id = ?5 AND state = 'pending' AND expires_at > ?1",
    )
    .bind(ts(now))
    .bind(by_key)
    .bind(by_device)
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// `approved` → `delivered` with the token just minted, within the 15 minutes. Run it in the transaction that
/// inserts the token: if it does not apply, the caller drops the transaction and the token goes with it.
pub async fn deliver(
    conn: &mut Conn,
    account_id: AccountId,
    id: JoinRequestId,
    token: JoinTokenId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE join_requests SET state = 'delivered', delivered_at = ?1, join_token_id = ?2, closed_at = ?1 \
         WHERE account_id = ?3 AND id = ?4 AND state = 'approved' AND expires_at > ?1",
    )
    .bind(ts(now))
    .bind(token.to_string())
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// The expiry sweep: every open request past its 15 minutes becomes `expired`. Bookkeeping only: no transition
/// depends on it (see the module docs). Returns how many it closed.
pub async fn expire(conn: &mut Conn, now: OffsetDateTime) -> Result<u64, StoreError> {
    let done = sqlx::query(
        "UPDATE join_requests SET state = 'expired', closed_at = ?1 \
         WHERE state IN ('awaiting_reveal', 'pending', 'approved') AND expires_at <= ?1",
    )
    .bind(ts(now))
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done)
}
