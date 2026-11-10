// SPDX-License-Identifier: AGPL-3.0-only

//! API keys (spec §5). Only the versioned SHA-256 digest of a secret is ever stored.

use p2pc_proto::api::{ApiKeyInfo, Scope};
use p2pc_proto::auth::SecretHash;
use p2pc_proto::ids::{AccountId, KeyId, ProjectId};
use p2pc_proto::units::Units;
use time::OffsetDateTime;

use super::{Conn, StoreError, decode_digest, from_ts, from_ts_opt, parse_col, ts};

/// `last_used_at` is written at most this often per key.
pub const LAST_USED_GRANULARITY_S: i64 = 60;

/// A stored key. `Debug` is safe: the digest prints as `SecretHash(…)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    /// Public key ID.
    pub key_id: KeyId,
    /// Owning account.
    pub account_id: AccountId,
    /// Project the key acts in.
    pub project_id: ProjectId,
    /// SHA-256 of the secret.
    pub digest: SecretHash,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Daily cap.
    pub daily_unit_cap: Option<Units>,
    /// Image globs; `None` allows every image.
    pub allowed_images: Option<Vec<String>>,
    /// Optional label.
    pub label: Option<String>,
    /// Optional expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last successful authentication (minute granularity).
    pub last_used_at: Option<OffsetDateTime>,
    /// Revocation time.
    pub revoked_at: Option<OffsetDateTime>,
}

impl KeyRow {
    /// Whether the key has expired at `now` (an expiry equal to `now` counts as expired).
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|e| e <= now)
    }

    /// The public view, for `GET /v1/keys`. Never contains the digest.
    #[must_use]
    pub fn info(&self) -> ApiKeyInfo {
        ApiKeyInfo {
            id: self.key_id,
            project_id: self.project_id,
            label: self.label.clone(),
            scopes: self.scopes.clone(),
            daily_unit_cap: self.daily_unit_cap,
            allowed_images: self.allowed_images.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
        }
    }
}

/// A key to insert.
#[derive(Debug, Clone)]
pub struct NewKey {
    /// Public key ID.
    pub key_id: KeyId,
    /// Project the key acts in; it must belong to the account.
    pub project_id: ProjectId,
    /// SHA-256 of the secret.
    pub digest: SecretHash,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Daily cap.
    pub daily_unit_cap: Option<Units>,
    /// Image globs.
    pub allowed_images: Option<Vec<String>>,
    /// Optional label.
    pub label: Option<String>,
    /// Optional expiry.
    pub expires_at: Option<OffsetDateTime>,
}

/// Position after which a key list continues: `(created_at, key_id)` of the last key returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCursor {
    /// `created_at` of the last key, in Unix seconds.
    pub created_at: i64,
    /// Its key ID.
    pub key_id: KeyId,
}

impl KeyCursor {
    /// The cursor after `row`.
    #[must_use]
    pub fn after(row: &KeyRow) -> Self {
        Self {
            created_at: ts(row.created_at),
            key_id: row.key_id,
        }
    }

    /// The opaque text form, `<created_at>.<key_id>`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}.{}", self.created_at, self.key_id)
    }

    /// Parses [`KeyCursor::encode`]'s output.
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let (at, id) = text.split_once('.')?;
        if at.is_empty() || !at.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            created_at: at.parse().ok()?,
            key_id: id.parse().ok()?,
        })
    }
}

type Row = (
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<i64>,
    i64,
    Option<i64>,
    Option<i64>,
);

macro_rules! select_keys {
    ($tail:literal) => {
        concat!(
            "SELECT key_id, account_id, project_id, secret_digest, scopes, daily_unit_cap, allowed_images, label, \
             expires_at, created_at, last_used_at, revoked_at FROM api_keys ",
            $tail
        )
    };
}

fn decode(row: Row) -> Result<KeyRow, StoreError> {
    let (key_id, account_id, project_id, digest, scopes, cap, images, label, expires, created, used, revoked) = row;
    Ok(KeyRow {
        key_id: parse_col(&key_id, "api_keys.key_id")?,
        account_id: parse_col(&account_id, "api_keys.account_id")?,
        project_id: parse_col(&project_id, "api_keys.project_id")?,
        digest: decode_digest(&digest, "api_keys.secret_digest")?,
        scopes: serde_json::from_str(&scopes).map_err(|_| StoreError::Corrupt("api_keys.scopes"))?,
        daily_unit_cap: cap
            .map(|c| u64::try_from(c).map(Units::from_milli))
            .transpose()
            .map_err(|_| StoreError::Corrupt("api_keys.daily_unit_cap"))?,
        allowed_images: images
            .map(|t| serde_json::from_str(&t))
            .transpose()
            .map_err(|_| StoreError::Corrupt("api_keys.allowed_images"))?,
        label,
        expires_at: from_ts_opt(expires, "api_keys.expires_at")?,
        created_at: from_ts(created, "api_keys.created_at")?,
        last_used_at: from_ts_opt(used, "api_keys.last_used_at")?,
        revoked_at: from_ts_opt(revoked, "api_keys.revoked_at")?,
    })
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Corrupt("json"))
}

/// Largest storable `daily_unit_cap`, in milli-units (SQLite integers are signed 64-bit).
pub const MAX_DAILY_UNIT_CAP_MILLI: u64 = i64::MAX as u64;

/// Inserts a key for `account_id` and returns the stored row.
pub async fn insert(
    conn: &mut Conn,
    account_id: AccountId,
    key: &NewKey,
    now: OffsetDateTime,
) -> Result<KeyRow, StoreError> {
    let cap = key
        .daily_unit_cap
        .map(|c| i64::try_from(c.milli()))
        .transpose()
        .map_err(|_| StoreError::Corrupt("api_keys.daily_unit_cap"))?;
    let images = key.allowed_images.as_ref().map(json).transpose()?;
    sqlx::query(
        "INSERT INTO api_keys (key_id, account_id, project_id, secret_digest, scopes, daily_unit_cap, \
         allowed_images, label, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(key.key_id.to_string())
    .bind(account_id.to_string())
    .bind(key.project_id.to_string())
    .bind(key.digest.to_stored())
    .bind(json(&key.scopes)?)
    .bind(cap)
    .bind(images)
    .bind(key.label.clone())
    .bind(key.expires_at.map(ts))
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    get(conn, account_id, key.key_id)
        .await?
        .ok_or(StoreError::Corrupt("api_keys"))
}

/// One key of `account_id`, revoked or not.
pub async fn get(conn: &mut Conn, account_id: AccountId, key_id: KeyId) -> Result<Option<KeyRow>, StoreError> {
    let row: Option<Row> = sqlx::query_as(select_keys!("WHERE account_id = ? AND key_id = ?"))
        .bind(account_id.to_string())
        .bind(key_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode).transpose()
}

/// Looks a key up by ID alone, for authentication.
///
/// This is the only cross-account read in the store (SI-7): it runs before there is a principal, and its result
/// is only used after the secret has been verified against the returned digest.
pub async fn lookup_for_auth(conn: &mut Conn, key_id: KeyId) -> Result<Option<KeyRow>, StoreError> {
    let row: Option<Row> = sqlx::query_as(select_keys!("WHERE key_id = ?"))
        .bind(key_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    row.map(decode).transpose()
}

/// Keys of `account_id` in creation order, starting after `after`, at most `limit` of them.
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    after: Option<KeyCursor>,
    limit: u32,
) -> Result<Vec<KeyRow>, StoreError> {
    let (at, id) = after.map_or((None, None), |c| (Some(c.created_at), Some(c.key_id.to_string())));
    let rows: Vec<Row> = sqlx::query_as(select_keys!(
        "WHERE account_id = ?1 AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND key_id > ?3)) \
         ORDER BY created_at, key_id LIMIT ?4"
    ))
    .bind(account_id.to_string())
    .bind(at)
    .bind(id)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// Records a successful authentication, unless `last_used_at` was written less than a minute ago.
pub async fn touch_last_used(
    conn: &mut Conn,
    account_id: AccountId,
    key_id: KeyId,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE api_keys SET last_used_at = ?1 WHERE account_id = ?2 AND key_id = ?3 \
         AND (last_used_at IS NULL OR last_used_at <= ?1 - ?4)",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(key_id.to_string())
    .bind(LAST_USED_GRANULARITY_S)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether a stored `last_used_at` is old enough to be written again at `now`.
#[must_use]
pub fn last_used_is_stale(last_used_at: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
    last_used_at.is_none_or(|t| ts(now) - ts(t) >= LAST_USED_GRANULARITY_S)
}

/// Result of [`revoke`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoke {
    /// The key is now revoked.
    Revoked,
    /// It already was; nothing changed.
    AlreadyRevoked,
    /// No such key in this account.
    NotFound,
    /// Refused: it is the account's last live unrestricted admin key.
    LastAdmin,
}

impl KeyRow {
    /// A live (not revoked) admin key with no expiry, no cap and no image list: one that can administer the account
    /// forever (§5 "Last admin key").
    #[must_use]
    pub fn is_unrestricted_admin(&self) -> bool {
        self.revoked_at.is_none()
            && self.expires_at.is_none()
            && self.daily_unit_cap.is_none()
            && self.allowed_images.is_none()
            && self.scopes.contains(&Scope::Admin)
    }
}

/// Revokes a key of `account_id` (sets `revoked_at`; the row is never deleted).
///
/// A single `UPDATE` refuses to revoke the account's last live **unrestricted** admin key (see
/// [`KeyRow::is_unrestricted_admin`]) when no unrestricted `admin` device remains either (H2 §5.5: the last live
/// unrestricted `admin` principal, device or key), so no sequence of revocations, concurrent or not, can leave the
/// account with only limited admin principals that may expire or be capped. Who may revoke what (§5 no-escalation) is the caller's
/// check.
pub async fn revoke(
    conn: &mut Conn,
    account_id: AccountId,
    key_id: KeyId,
    now: OffsetDateTime,
) -> Result<Revoke, StoreError> {
    let done = sqlx::query(
        "UPDATE api_keys SET revoked_at = ?1 \
         WHERE account_id = ?2 AND key_id = ?3 AND revoked_at IS NULL \
           AND (NOT (expires_at IS NULL AND daily_unit_cap IS NULL AND allowed_images IS NULL \
                     AND EXISTS (SELECT 1 FROM json_each(api_keys.scopes) WHERE value = 'admin')) \
                OR EXISTS (SELECT 1 FROM api_keys AS other \
                           WHERE other.account_id = ?2 AND other.key_id <> ?3 AND other.revoked_at IS NULL \
                             AND other.expires_at IS NULL AND other.daily_unit_cap IS NULL \
                             AND other.allowed_images IS NULL \
                             AND EXISTS (SELECT 1 FROM json_each(other.scopes) WHERE value = 'admin')) \
                OR EXISTS (SELECT 1 FROM devices AS d \
                           WHERE d.account_id = ?2 AND d.revoked_at IS NULL AND d.expires_at IS NULL \
                             AND d.daily_unit_cap IS NULL AND d.allowed_images IS NULL AND d.blobs_quota_mb IS NULL \
                             AND EXISTS (SELECT 1 FROM json_each(d.scopes) WHERE value = 'admin')))",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(key_id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done == 1 {
        return Ok(Revoke::Revoked);
    }
    Ok(match get(conn, account_id, key_id).await? {
        None => Revoke::NotFound,
        Some(row) if row.revoked_at.is_some() => Revoke::AlreadyRevoked,
        Some(_) => Revoke::LastAdmin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        let c = KeyCursor {
            created_at: 1_793_872_800,
            key_id: KeyId::generate(),
        };
        assert_eq!(KeyCursor::decode(&c.encode()), Some(c));
        for bad in [
            "",
            ".",
            "1.",
            ".abcdefgh2345",
            "-1.abcdefgh2345",
            "x.abcdefgh2345",
            "1.ABCDEFGH2345",
            "1",
        ] {
            assert_eq!(KeyCursor::decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn last_used_staleness() {
        let t = time::macros::datetime!(2026-11-05 10:00:00 UTC);
        assert!(last_used_is_stale(None, t));
        assert!(!last_used_is_stale(Some(t), t + time::Duration::seconds(59)));
        assert!(last_used_is_stale(Some(t), t + time::Duration::seconds(60)));
    }
}
