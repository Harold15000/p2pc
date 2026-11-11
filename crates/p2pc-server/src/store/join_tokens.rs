// SPDX-License-Identifier: AGPL-3.0-only

//! Join tokens (spec §5 "Join tokens"). Only the versioned SHA-256 digest of the 16-byte code is stored; the token
//! string is returned once by `POST /v1/nodes/join-tokens` and never again.

use p2pc_proto::api::Principal;
use p2pc_proto::auth::SecretHash;
use p2pc_proto::ids::{AccountId, JoinTokenId, NodeId, ProjectId};
use time::OffsetDateTime;

use super::{Conn, StoreError, decode_digest, from_ts, from_ts_opt, parse_col, ts};

/// A stored join token. `Debug` is safe: the digest prints as `SecretHash(…)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTokenRow {
    /// Row ID.
    pub id: JoinTokenId,
    /// Owning account: the account a node enrolled with this token belongs to.
    pub account_id: AccountId,
    /// Project the node goes into.
    pub project_id: ProjectId,
    /// SHA-256 of the code.
    pub code_digest: SecretHash,
    /// Optional label.
    pub label: Option<String>,
    /// The principal that minted it: an API key or a device (H2 §5.6).
    pub created_by: Principal,
    /// The agent NodeId it is bound to, for the token of a join request (H2 §5.4): it enrolls no other.
    pub bound_iroh_node_id: Option<String>,
    /// Minted with the `admin`-only `pre_approved` option: its node starts `approved` (H2 §5.4).
    pub pre_approved: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry: the only one that counts.
    pub expires_at: OffsetDateTime,
    /// When a `Join` consumed it.
    pub consumed_at: Option<OffsetDateTime>,
    /// The node it enrolled.
    pub consumed_by_node_id: Option<NodeId>,
    /// When it was revoked unused.
    pub revoked_at: Option<OffsetDateTime>,
}

impl JoinTokenRow {
    /// Whether a `Join` may consume it at `now`: unused, not revoked and not expired (an expiry equal to `now` counts
    /// as expired).
    #[must_use]
    pub fn is_redeemable(&self, now: OffsetDateTime) -> bool {
        self.consumed_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A token to insert.
#[derive(Debug, Clone)]
pub struct NewJoinToken {
    /// Row ID.
    pub id: JoinTokenId,
    /// Project the node will go into.
    pub project_id: ProjectId,
    /// SHA-256 of the code.
    pub code_digest: SecretHash,
    /// Optional label.
    pub label: Option<String>,
    /// The minting principal.
    pub created_by: Principal,
    /// The agent NodeId the token is bound to (join requests only, H2 §5.4).
    pub bound_iroh_node_id: Option<String>,
    /// The `admin`-only option: the node starts `approved` (H2 §5.4).
    pub pre_approved: bool,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// Position after which a token list continues: `(created_at, id)` of the last token returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCursor {
    /// `created_at` of the last token, in Unix seconds.
    pub created_at: i64,
    /// Its ID.
    pub id: JoinTokenId,
}

impl TokenCursor {
    /// The cursor after `row`.
    #[must_use]
    pub fn after(row: &JoinTokenRow) -> Self {
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

    /// Parses [`TokenCursor::encode`]'s output.
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

type Row = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
);

macro_rules! select_tokens {
    ($tail:literal) => {
        concat!(
            "SELECT id, account_id, project_id, code_digest, label, created_by_key_id, created_by_device_id, \
             bound_iroh_node_id, pre_approved, created_at, expires_at, consumed_at, consumed_by_node_id, revoked_at \
             FROM join_tokens ",
            $tail
        )
    };
}

fn decode(row: Row) -> Result<JoinTokenRow, StoreError> {
    let (id, account, project, digest, label, by_key, by_device, bound, pre, created, expires, consumed, node, revoked) =
        row;
    Ok(JoinTokenRow {
        id: parse_col(&id, "join_tokens.id")?,
        account_id: parse_col(&account, "join_tokens.account_id")?,
        project_id: parse_col(&project, "join_tokens.project_id")?,
        code_digest: decode_digest(&digest, "join_tokens.code_digest")?,
        label,
        created_by: super::jobs::principal_cols(by_key.as_deref(), by_device.as_deref(), "join_tokens.created_by")?,
        bound_iroh_node_id: bound,
        pre_approved: pre != 0,
        created_at: from_ts(created, "join_tokens.created_at")?,
        expires_at: from_ts(expires, "join_tokens.expires_at")?,
        consumed_at: from_ts_opt(consumed, "join_tokens.consumed_at")?,
        consumed_by_node_id: node
            .map(|n| parse_col(&n, "join_tokens.consumed_by_node_id"))
            .transpose()?,
        revoked_at: from_ts_opt(revoked, "join_tokens.revoked_at")?,
    })
}

/// Inserts a token for `account_id` and returns the stored row.
pub async fn insert(
    conn: &mut Conn,
    account_id: AccountId,
    token: &NewJoinToken,
    now: OffsetDateTime,
) -> Result<JoinTokenRow, StoreError> {
    let (by_key, by_device) = super::jobs::principal_binds(token.created_by);
    sqlx::query(
        "INSERT INTO join_tokens (id, account_id, project_id, code_digest, label, created_by_key_id, \
         created_by_device_id, bound_iroh_node_id, pre_approved, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token.id.to_string())
    .bind(account_id.to_string())
    .bind(token.project_id.to_string())
    .bind(token.code_digest.to_stored())
    .bind(token.label.clone())
    .bind(by_key)
    .bind(by_device)
    .bind(token.bound_iroh_node_id.clone())
    .bind(token.pre_approved)
    .bind(ts(now))
    .bind(ts(token.expires_at))
    .execute(&mut *conn)
    .await?;
    get(conn, account_id, token.id)
        .await?
        .ok_or(StoreError::Corrupt("join_tokens"))
}

/// One token of `account_id`.
pub async fn get(conn: &mut Conn, account_id: AccountId, id: JoinTokenId) -> Result<Option<JoinTokenRow>, StoreError> {
    let row: Option<Row> = sqlx::query_as(select_tokens!("WHERE account_id = ? AND id = ?"))
        .bind(account_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode).transpose()
}

/// Looks a token up by the digest of its code, for a `Join`.
///
/// Like `keys::lookup_for_auth`, this is a read before there is a principal (SI-7): the presented code is the
/// credential, and the returned row (its account above all) is only trusted once the caller has compared its
/// digest with the presented one in constant time.
pub async fn find_by_digest(conn: &mut Conn, digest: &SecretHash) -> Result<Option<JoinTokenRow>, StoreError> {
    let row: Option<Row> = sqlx::query_as(select_tokens!("WHERE code_digest = ?"))
        .bind(digest.to_stored())
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode).transpose()
}

/// `account_id`'s tokens in creation order, after `after`, at most `limit`.
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    after: Option<TokenCursor>,
    limit: u32,
) -> Result<Vec<JoinTokenRow>, StoreError> {
    let (at, id) = after.map_or((None, None), |c| (Some(c.created_at), Some(c.id.to_string())));
    let rows: Vec<Row> = sqlx::query_as(select_tokens!(
        "WHERE account_id = ?1 AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND id > ?3)) \
         ORDER BY created_at, id LIMIT ?4"
    ))
    .bind(account_id.to_string())
    .bind(at)
    .bind(id)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// Marks the token with `digest` consumed by `node_id`, atomically (SI-11): the single `UPDATE` only matches an
/// unused, unrevoked, unexpired row, judged by the row's own columns. Returns whether it matched. Run it in the
/// transaction that inserts the node.
///
/// A token bound to an agent NodeId (a join request's, H2 §5.4) matches only when `node_id`'s row has that NodeId:
/// any other NodeId gets the invalid-token answer and the token stays unused (the caller's transaction, which
/// inserted the node, is dropped).
pub async fn consume(
    conn: &mut Conn,
    digest: &SecretHash,
    node_id: NodeId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let done = sqlx::query(
        "UPDATE join_tokens SET consumed_at = ?1, consumed_by_node_id = ?2 \
         WHERE code_digest = ?3 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?1 \
           AND (bound_iroh_node_id IS NULL \
                OR bound_iroh_node_id = (SELECT n.iroh_node_id FROM nodes n WHERE n.id = ?2))",
    )
    .bind(ts(now))
    .bind(node_id.to_string())
    .bind(digest.to_stored())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Result of [`revoke`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoke {
    /// The token is now revoked.
    Revoked,
    /// It already was; nothing changed.
    AlreadyRevoked,
    /// A `Join` consumed it: it cannot be revoked (`409 token_consumed`).
    Consumed,
    /// No such token in this account.
    NotFound,
}

/// Revokes an unused token of `account_id`.
pub async fn revoke(
    conn: &mut Conn,
    account_id: AccountId,
    id: JoinTokenId,
    now: OffsetDateTime,
) -> Result<Revoke, StoreError> {
    let done = sqlx::query(
        "UPDATE join_tokens SET revoked_at = ? \
         WHERE account_id = ? AND id = ? AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done == 1 {
        return Ok(Revoke::Revoked);
    }
    Ok(match get(conn, account_id, id).await? {
        None => Revoke::NotFound,
        Some(row) if row.consumed_at.is_some() => Revoke::Consumed,
        Some(_) => Revoke::AlreadyRevoked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        let c = TokenCursor {
            created_at: 1_793_872_800,
            id: JoinTokenId::generate(),
        };
        assert_eq!(TokenCursor::decode(&c.encode()), Some(c));
        for bad in [
            "",
            ".",
            "1.",
            "x.jtk_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "1.node_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        ] {
            assert_eq!(TokenCursor::decode(bad), None, "{bad}");
        }
    }
}
