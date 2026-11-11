// SPDX-License-Identifier: AGPL-3.0-only

//! Paired devices and pairing tickets (H2 spec §5.2, §5.3, §5.5).
//!
//! A device is a principal like an API key, authenticated by its iroh NodeId (iroh's TLS proves it), so the store
//! holds no device secret at all. A pairing ticket is stored only as the SHA-256 of its 16-byte code; the ticket
//! string is returned once by `POST /v1/devices/pairing-tickets` and never again.
//!
//! Every function takes the principal's `account_id` and filters by it (SI-7), except the lookups that run before
//! there is a REST principal: [`by_id_for_auth`] (the device transport attaches a device ID it authenticated),
//! [`live_by_iroh_node_id`] (the device check of `p2pc/device/1`) and [`pair`] (the code is the credential).

use p2pc_proto::api::{DeviceInfo, PairingTicketInfo, Principal, Scope};
use p2pc_proto::auth::SecretHash;
use p2pc_proto::ids::{AccountId, DeviceId, PairingTicketId, ProjectId};
use p2pc_proto::units::Units;
use p2pc_proto::validate::PrincipalLimits;
use time::OffsetDateTime;

use super::jobs::{principal_binds, principal_cols};
use super::{Conn, StoreError, decode_digest, from_ts, from_ts_opt, parse_col, ts};

/// `last_seen_at` is written at most this often per device (§5.5, as H1's `last_used_at`).
pub const LAST_SEEN_GRANULARITY_S: i64 = 60;

/// A stored device. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// Device ID.
    pub device_id: DeviceId,
    /// Owning account.
    pub account_id: AccountId,
    /// Project it acts in (its pairing ticket creator's).
    pub project_id: ProjectId,
    /// The device's iroh NodeId, 64 lowercase hex characters.
    pub iroh_node_id: String,
    /// Label.
    pub label: Option<String>,
    /// Platform hint sent in `Pair`.
    pub platform: String,
    /// Scopes.
    pub scopes: Vec<Scope>,
    /// Daily cap.
    pub daily_unit_cap: Option<Units>,
    /// Image globs; `None` allows every image.
    pub allowed_images: Option<Vec<String>>,
    /// Blob quota in MiB.
    pub blobs_quota_mb: Option<u64>,
    /// Expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// The principal that created its pairing ticket; `None` for a device registered offline.
    pub paired_by: Option<Principal>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last request (minute granularity).
    pub last_seen_at: Option<OffsetDateTime>,
    /// Revocation time.
    pub revoked_at: Option<OffsetDateTime>,
}

impl DeviceRow {
    /// Whether the device is live at `now`: not revoked and not past its `expires_at` (an expiry equal to `now`
    /// counts as expired).
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }

    /// A live `admin` device with no expiry, no cap, no image list and no blob quota (§5.5 "Last admin").
    #[must_use]
    pub fn is_unrestricted_admin(&self) -> bool {
        self.revoked_at.is_none()
            && self.expires_at.is_none()
            && self.daily_unit_cap.is_none()
            && self.allowed_images.is_none()
            && self.blobs_quota_mb.is_none()
            && self.scopes.contains(&Scope::Admin)
    }

    /// Its power, for the no-escalation rule (§5.5: an `admin` revokes only a device it could have created).
    #[must_use]
    pub fn limits(&self) -> PrincipalLimits {
        PrincipalLimits {
            scopes: self.scopes.clone(),
            daily_unit_cap: self.daily_unit_cap,
            allowed_images: self.allowed_images.clone(),
            expires_at: self.expires_at,
            blobs_quota_mb: self.blobs_quota_mb,
        }
    }

    /// The public view (`GET /v1/devices`). A device registered offline has no pairing ticket; it shows itself as
    /// `paired_by`.
    #[must_use]
    pub fn info(&self) -> DeviceInfo {
        // A constructor, then the fields: a field added to the shared type does not break this (CONTRIBUTING rule 7).
        let paired_by = self.paired_by.unwrap_or(Principal::Device(self.device_id));
        let mut info = DeviceInfo::new(
            self.device_id,
            self.platform.clone(),
            self.scopes.clone(),
            self.created_at,
            paired_by,
        );
        info.label.clone_from(&self.label);
        info.daily_unit_cap = self.daily_unit_cap;
        info.allowed_images.clone_from(&self.allowed_images);
        info.blobs_quota_mb = self.blobs_quota_mb;
        info.expires_at = self.expires_at;
        info.last_seen_at = self.last_seen_at;
        info.revoked_at = self.revoked_at;
        info
    }
}

/// A device to insert.
#[derive(Debug, Clone)]
pub struct NewDevice {
    /// Device ID.
    pub device_id: DeviceId,
    /// Project; it must belong to the account.
    pub project_id: ProjectId,
    /// iroh NodeId, 64 lowercase hex characters.
    pub iroh_node_id: String,
    /// Label.
    pub label: Option<String>,
    /// Platform hint.
    pub platform: String,
    /// Scopes.
    pub scopes: Vec<Scope>,
    /// Daily cap.
    pub daily_unit_cap: Option<Units>,
    /// Image globs.
    pub allowed_images: Option<Vec<String>>,
    /// Blob quota in MiB.
    pub blobs_quota_mb: Option<u64>,
    /// Expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// The ticket's creator; `None` offline.
    pub paired_by: Option<Principal>,
}

#[derive(sqlx::FromRow)]
struct Raw {
    device_id: String,
    account_id: String,
    project_id: String,
    iroh_node_id: String,
    label: Option<String>,
    platform: String,
    scopes: String,
    daily_unit_cap: Option<i64>,
    allowed_images: Option<String>,
    blobs_quota_mb: Option<i64>,
    expires_at: Option<i64>,
    paired_by_key_id: Option<String>,
    paired_by_device_id: Option<String>,
    created_at: i64,
    last_seen_at: Option<i64>,
    revoked_at: Option<i64>,
}

macro_rules! select_devices {
    ($tail:literal) => {
        concat!(
            "SELECT device_id, account_id, project_id, iroh_node_id, label, platform, scopes, daily_unit_cap, \
             allowed_images, blobs_quota_mb, expires_at, paired_by_key_id, paired_by_device_id, created_at, \
             last_seen_at, revoked_at FROM devices ",
            $tail
        )
    };
}

fn units_col(v: Option<i64>, column: &'static str) -> Result<Option<Units>, StoreError> {
    v.map(|c| u64::try_from(c).map(Units::from_milli))
        .transpose()
        .map_err(|_| StoreError::Corrupt(column))
}

fn u64_col(v: Option<i64>, column: &'static str) -> Result<Option<u64>, StoreError> {
    v.map(u64::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt(column))
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Corrupt("json"))
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str, column: &'static str) -> Result<T, StoreError> {
    serde_json::from_str(text).map_err(|_| StoreError::Corrupt(column))
}

fn i64_of(v: Option<u64>, column: &'static str) -> Result<Option<i64>, StoreError> {
    v.map(i64::try_from)
        .transpose()
        .map_err(|_| StoreError::Corrupt(column))
}

fn decode(r: Raw) -> Result<DeviceRow, StoreError> {
    Ok(DeviceRow {
        device_id: parse_col(&r.device_id, "devices.device_id")?,
        account_id: parse_col(&r.account_id, "devices.account_id")?,
        project_id: parse_col(&r.project_id, "devices.project_id")?,
        iroh_node_id: r.iroh_node_id,
        label: r.label,
        platform: r.platform,
        scopes: from_json(&r.scopes, "devices.scopes")?,
        daily_unit_cap: units_col(r.daily_unit_cap, "devices.daily_unit_cap")?,
        allowed_images: r
            .allowed_images
            .map(|t| from_json(&t, "devices.allowed_images"))
            .transpose()?,
        blobs_quota_mb: u64_col(r.blobs_quota_mb, "devices.blobs_quota_mb")?,
        expires_at: from_ts_opt(r.expires_at, "devices.expires_at")?,
        paired_by: match (r.paired_by_key_id, r.paired_by_device_id) {
            (None, None) => None,
            (k, d) => Some(principal_cols(k.as_deref(), d.as_deref(), "devices.paired_by")?),
        },
        created_at: from_ts(r.created_at, "devices.created_at")?,
        last_seen_at: from_ts_opt(r.last_seen_at, "devices.last_seen_at")?,
        revoked_at: from_ts_opt(r.revoked_at, "devices.revoked_at")?,
    })
}

/// Why a device cannot be inserted.
#[derive(Debug, thiserror::Error)]
pub enum InsertError {
    /// A live device already has this NodeId.
    #[error("a live device already has this NodeId")]
    NodeIdInUse,
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Inserts a device for `account_id`. A device that is not revoked but has expired, with the same NodeId, is revoked
/// first (it is dead already; only one unrevoked device per NodeId exists, so the device check is one lookup). A live
/// device with that NodeId is refused ([`InsertError::NodeIdInUse`]). Run it in the caller's write transaction.
pub async fn insert(
    conn: &mut Conn,
    account_id: AccountId,
    device: &NewDevice,
    now: OffsetDateTime,
) -> Result<DeviceRow, InsertError> {
    if let Some(existing) = unrevoked_by_iroh_node_id(conn, &device.iroh_node_id).await? {
        if existing.is_live(now) {
            return Err(InsertError::NodeIdInUse);
        }
        sqlx::query("UPDATE devices SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL")
            .bind(ts(now))
            .bind(existing.device_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(StoreError::from)?;
    }
    let cap = i64_of(device.daily_unit_cap.map(Units::milli), "devices.daily_unit_cap")?;
    let images = device.allowed_images.as_ref().map(json).transpose()?;
    let (by_key, by_device) = device.paired_by.map(principal_binds).unwrap_or_default();
    sqlx::query(
        "INSERT INTO devices (device_id, account_id, project_id, iroh_node_id, label, platform, scopes, \
         daily_unit_cap, allowed_images, blobs_quota_mb, expires_at, paired_by_key_id, paired_by_device_id, \
         created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(device.device_id.to_string())
    .bind(account_id.to_string())
    .bind(device.project_id.to_string())
    .bind(&device.iroh_node_id)
    .bind(device.label.clone())
    .bind(&device.platform)
    .bind(json(&device.scopes)?)
    .bind(cap)
    .bind(images)
    .bind(i64_of(device.blobs_quota_mb, "devices.blobs_quota_mb")?)
    .bind(device.expires_at.map(ts))
    .bind(by_key)
    .bind(by_device)
    .bind(ts(now))
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from)?;
    Ok(get(conn, account_id, device.device_id)
        .await?
        .ok_or(StoreError::Corrupt("devices"))?)
}

/// One device of `account_id`, revoked or not.
pub async fn get(conn: &mut Conn, account_id: AccountId, id: DeviceId) -> Result<Option<DeviceRow>, StoreError> {
    let raw: Option<Raw> = sqlx::query_as(select_devices!("WHERE account_id = ? AND device_id = ?"))
        .bind(account_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

/// A device by ID alone, for authentication: the device transport (`p2pc/device/1`, T2-11) attaches the ID of the
/// device whose NodeId iroh authenticated, and every request re-reads the row here (§6.3 "checks the device … on
/// every request"). Like `keys::lookup_for_auth`, it runs before there is a principal.
pub async fn by_id_for_auth(conn: &mut Conn, id: DeviceId) -> Result<Option<DeviceRow>, StoreError> {
    let raw: Option<Raw> = sqlx::query_as(select_devices!("WHERE device_id = ?"))
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

async fn unrevoked_by_iroh_node_id(conn: &mut Conn, iroh_node_id: &str) -> Result<Option<DeviceRow>, StoreError> {
    let raw: Option<Raw> = sqlx::query_as(select_devices!("WHERE iroh_node_id = ? AND revoked_at IS NULL"))
        .bind(iroh_node_id)
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

/// The live device with this iroh NodeId, if any: the one indexed lookup of the `p2pc/device/1` device check (§6.3).
/// A revoked, expired or unknown NodeId gives `None` alike, so the transport answers the same `not_paired` to all.
pub async fn live_by_iroh_node_id(
    conn: &mut Conn,
    iroh_node_id: &str,
    now: OffsetDateTime,
) -> Result<Option<DeviceRow>, StoreError> {
    Ok(unrevoked_by_iroh_node_id(conn, iroh_node_id)
        .await?
        .filter(|d| d.is_live(now)))
}

/// Position after which a device or ticket list continues: `(created_at, id)` of the last item returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// `created_at` of the last item, in Unix seconds.
    pub created_at: i64,
    /// Its ID.
    pub id: String,
}

impl Cursor {
    /// The opaque text form, `<created_at>.<id>`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}.{}", self.created_at, self.id)
    }

    /// Parses [`Cursor::encode`]'s output; the ID must parse as `T`.
    #[must_use]
    pub fn decode<T: std::str::FromStr>(text: &str) -> Option<Self> {
        let (at, id) = text.split_once('.')?;
        if at.is_empty() || !at.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        id.parse::<T>().ok()?;
        Some(Self {
            created_at: at.parse().ok()?,
            id: id.to_string(),
        })
    }
}

/// `account_id`'s devices in creation order, after `after`, at most `limit`.
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    after: Option<&Cursor>,
    limit: u32,
) -> Result<Vec<DeviceRow>, StoreError> {
    let (at, id) = after.map_or((None, None), |c| (Some(c.created_at), Some(c.id.clone())));
    let rows: Vec<Raw> = sqlx::query_as(select_devices!(
        "WHERE account_id = ?1 AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND device_id > ?3)) \
         ORDER BY created_at, device_id LIMIT ?4"
    ))
    .bind(account_id.to_string())
    .bind(at)
    .bind(id)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// Records a request of the device, unless `last_seen_at` was written less than a minute ago.
pub async fn touch_last_seen(
    conn: &mut Conn,
    account_id: AccountId,
    id: DeviceId,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE devices SET last_seen_at = ?1 WHERE account_id = ?2 AND device_id = ?3 \
         AND (last_seen_at IS NULL OR last_seen_at <= ?1 - ?4)",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(id.to_string())
    .bind(LAST_SEEN_GRANULARITY_S)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Whether a stored `last_seen_at` is old enough to be written again at `now`.
#[must_use]
pub fn last_seen_is_stale(last_seen_at: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
    last_seen_at.is_none_or(|t| ts(now) - ts(t) >= LAST_SEEN_GRANULARITY_S)
}

/// Result of [`revoke`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoke {
    /// The device is now revoked.
    Revoked,
    /// It already was; nothing changed.
    AlreadyRevoked,
    /// No such device in this account.
    NotFound,
    /// Refused: it is the account's last live unrestricted `admin` principal (`409 last_admin_device`).
    LastAdmin,
}

/// SQL: whether the account `?2` keeps a live unrestricted `admin` principal other than the device `?3`: a key (H1's
/// definition: no expiry, cap or image list) or a device (also no blob quota).
macro_rules! another_unrestricted_admin {
    () => {
        "(EXISTS (SELECT 1 FROM api_keys k WHERE k.account_id = ?2 AND k.revoked_at IS NULL \
                  AND k.expires_at IS NULL AND k.daily_unit_cap IS NULL AND k.allowed_images IS NULL \
                  AND EXISTS (SELECT 1 FROM json_each(k.scopes) WHERE value = 'admin')) \
          OR EXISTS (SELECT 1 FROM devices o WHERE o.account_id = ?2 AND o.device_id <> ?3 AND o.revoked_at IS NULL \
                  AND o.expires_at IS NULL AND o.daily_unit_cap IS NULL AND o.allowed_images IS NULL \
                  AND o.blobs_quota_mb IS NULL \
                  AND EXISTS (SELECT 1 FROM json_each(o.scopes) WHERE value = 'admin')))"
    };
}

/// Revokes a device of `account_id` (sets `revoked_at`; the row is kept).
///
/// A single `UPDATE` refuses to revoke the account's last live **unrestricted** `admin` principal (§5.5: a device
/// with `admin` and no expiry, cap, image list or blob quota, when no such device or key remains), so no sequence of
/// revocations can leave the account without one. Who may revoke what is the caller's check. Closing the device's
/// live connections is the caller's too ([`crate::devices_api::DeviceSessions`]).
pub async fn revoke(
    conn: &mut Conn,
    account_id: AccountId,
    id: DeviceId,
    now: OffsetDateTime,
) -> Result<Revoke, StoreError> {
    let done = sqlx::query(concat!(
        "UPDATE devices SET revoked_at = ?1 \
         WHERE account_id = ?2 AND device_id = ?3 AND revoked_at IS NULL \
           AND (NOT (expires_at IS NULL AND daily_unit_cap IS NULL AND allowed_images IS NULL \
                     AND blobs_quota_mb IS NULL \
                     AND EXISTS (SELECT 1 FROM json_each(devices.scopes) WHERE value = 'admin')) \
                OR ",
        another_unrestricted_admin!(),
        ")"
    ))
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
        Some(row) if row.revoked_at.is_some() => Revoke::AlreadyRevoked,
        Some(_) => Revoke::LastAdmin,
    })
}

/// Of `ids`, the devices that are no longer live at `now` (revoked, expired, or gone): what the 2 s liveness sweep
/// closes (§5.5). One indexed read per device; the set is the devices that hold live connections.
pub async fn not_live(conn: &mut Conn, ids: &[DeviceId], now: OffsetDateTime) -> Result<Vec<DeviceId>, StoreError> {
    let mut out = Vec::new();
    for id in ids {
        let row: Option<(Option<i64>, Option<i64>)> =
            sqlx::query_as("SELECT revoked_at, expires_at FROM devices WHERE device_id = ?")
                .bind(id.to_string())
                .fetch_optional(&mut *conn)
                .await?;
        let live = row.is_some_and(|(revoked, expires)| revoked.is_none() && expires.is_none_or(|e| e > ts(now)));
        if !live {
            out.push(*id);
        }
    }
    Ok(out)
}

// --- Pairing tickets ----------------------------------------------------------------------------------------------

/// A stored pairing ticket. `Debug` is safe: the digest prints as `SecretHash(…)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRow {
    /// Row ID.
    pub id: PairingTicketId,
    /// Owning account.
    pub account_id: AccountId,
    /// Project the device goes into.
    pub project_id: ProjectId,
    /// SHA-256 of the code.
    pub code_digest: SecretHash,
    /// The device's label.
    pub label: Option<String>,
    /// The device's scopes.
    pub scopes: Vec<Scope>,
    /// The device's daily cap.
    pub daily_unit_cap: Option<Units>,
    /// The device's image globs.
    pub allowed_images: Option<Vec<String>>,
    /// The device's blob quota.
    pub blobs_quota_mb: Option<u64>,
    /// The device's expiry.
    pub device_expires_at: Option<OffsetDateTime>,
    /// The creating principal.
    pub created_by: Principal,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry: the only one that counts.
    pub expires_at: OffsetDateTime,
    /// When a `Pair` consumed it.
    pub consumed_at: Option<OffsetDateTime>,
    /// The device it created.
    pub device_id: Option<DeviceId>,
    /// When it was revoked unused.
    pub revoked_at: Option<OffsetDateTime>,
}

impl TicketRow {
    /// The public view: never the code or its digest.
    #[must_use]
    pub fn info(&self) -> PairingTicketInfo {
        PairingTicketInfo {
            id: self.id,
            label: self.label.clone(),
            scopes: self.scopes.clone(),
            daily_unit_cap: self.daily_unit_cap,
            allowed_images: self.allowed_images.clone(),
            blobs_quota_mb: self.blobs_quota_mb,
            device_expires_at: self.device_expires_at,
            created_by: self.created_by,
            created_at: self.created_at,
            expires_at: self.expires_at,
            consumed_at: self.consumed_at,
            device_id: self.device_id,
            revoked_at: self.revoked_at,
        }
    }

    /// Whether a `Pair` may consume it at `now`: unused, not revoked, not expired (equal counts as expired).
    #[must_use]
    pub fn is_redeemable(&self, now: OffsetDateTime) -> bool {
        self.consumed_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A ticket to insert.
#[derive(Debug, Clone)]
pub struct NewTicket {
    /// Row ID.
    pub id: PairingTicketId,
    /// Project the device goes into (the creator's).
    pub project_id: ProjectId,
    /// SHA-256 of the code.
    pub code_digest: SecretHash,
    /// The device's label.
    pub label: Option<String>,
    /// The device's scopes.
    pub scopes: Vec<Scope>,
    /// The device's daily cap.
    pub daily_unit_cap: Option<Units>,
    /// The device's image globs.
    pub allowed_images: Option<Vec<String>>,
    /// The device's blob quota.
    pub blobs_quota_mb: Option<u64>,
    /// The device's expiry.
    pub device_expires_at: Option<OffsetDateTime>,
    /// The creating principal.
    pub created_by: Principal,
    /// The ticket's expiry.
    pub expires_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct TicketRaw {
    id: String,
    account_id: String,
    project_id: String,
    code_digest: String,
    label: Option<String>,
    scopes: String,
    daily_unit_cap: Option<i64>,
    allowed_images: Option<String>,
    blobs_quota_mb: Option<i64>,
    device_expires_at: Option<i64>,
    created_by_key_id: Option<String>,
    created_by_device_id: Option<String>,
    created_at: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
    device_id: Option<String>,
    revoked_at: Option<i64>,
}

macro_rules! select_tickets {
    ($tail:literal) => {
        concat!(
            "SELECT id, account_id, project_id, code_digest, label, scopes, daily_unit_cap, allowed_images, \
             blobs_quota_mb, device_expires_at, created_by_key_id, created_by_device_id, created_at, expires_at, \
             consumed_at, device_id, revoked_at FROM pairing_tickets ",
            $tail
        )
    };
}

fn decode_ticket(r: TicketRaw) -> Result<TicketRow, StoreError> {
    Ok(TicketRow {
        id: parse_col(&r.id, "pairing_tickets.id")?,
        account_id: parse_col(&r.account_id, "pairing_tickets.account_id")?,
        project_id: parse_col(&r.project_id, "pairing_tickets.project_id")?,
        code_digest: decode_digest(&r.code_digest, "pairing_tickets.code_digest")?,
        label: r.label,
        scopes: from_json(&r.scopes, "pairing_tickets.scopes")?,
        daily_unit_cap: units_col(r.daily_unit_cap, "pairing_tickets.daily_unit_cap")?,
        allowed_images: r
            .allowed_images
            .map(|t| from_json(&t, "pairing_tickets.allowed_images"))
            .transpose()?,
        blobs_quota_mb: u64_col(r.blobs_quota_mb, "pairing_tickets.blobs_quota_mb")?,
        device_expires_at: from_ts_opt(r.device_expires_at, "pairing_tickets.device_expires_at")?,
        created_by: principal_cols(
            r.created_by_key_id.as_deref(),
            r.created_by_device_id.as_deref(),
            "pairing_tickets.created_by",
        )?,
        created_at: from_ts(r.created_at, "pairing_tickets.created_at")?,
        expires_at: from_ts(r.expires_at, "pairing_tickets.expires_at")?,
        consumed_at: from_ts_opt(r.consumed_at, "pairing_tickets.consumed_at")?,
        device_id: r
            .device_id
            .map(|d| parse_col(&d, "pairing_tickets.device_id"))
            .transpose()?,
        revoked_at: from_ts_opt(r.revoked_at, "pairing_tickets.revoked_at")?,
    })
}

/// Inserts a ticket for `account_id` and returns the stored row.
pub async fn insert_ticket(
    conn: &mut Conn,
    account_id: AccountId,
    t: &NewTicket,
    now: OffsetDateTime,
) -> Result<TicketRow, StoreError> {
    let (by_key, by_device) = principal_binds(t.created_by);
    sqlx::query(
        "INSERT INTO pairing_tickets (id, account_id, project_id, code_digest, label, scopes, daily_unit_cap, \
         allowed_images, blobs_quota_mb, device_expires_at, created_by_key_id, created_by_device_id, created_at, \
         expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(t.id.to_string())
    .bind(account_id.to_string())
    .bind(t.project_id.to_string())
    .bind(t.code_digest.to_stored())
    .bind(t.label.clone())
    .bind(json(&t.scopes)?)
    .bind(i64_of(
        t.daily_unit_cap.map(Units::milli),
        "pairing_tickets.daily_unit_cap",
    )?)
    .bind(t.allowed_images.as_ref().map(json).transpose()?)
    .bind(i64_of(t.blobs_quota_mb, "pairing_tickets.blobs_quota_mb")?)
    .bind(t.device_expires_at.map(ts))
    .bind(by_key)
    .bind(by_device)
    .bind(ts(now))
    .bind(ts(t.expires_at))
    .execute(&mut *conn)
    .await?;
    get_ticket(conn, account_id, t.id)
        .await?
        .ok_or(StoreError::Corrupt("pairing_tickets"))
}

/// One ticket of `account_id`.
pub async fn get_ticket(
    conn: &mut Conn,
    account_id: AccountId,
    id: PairingTicketId,
) -> Result<Option<TicketRow>, StoreError> {
    let raw: Option<TicketRaw> = sqlx::query_as(select_tickets!("WHERE account_id = ? AND id = ?"))
        .bind(account_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode_ticket).transpose()
}

/// `account_id`'s tickets in creation order, after `after`, at most `limit`.
pub async fn list_tickets(
    conn: &mut Conn,
    account_id: AccountId,
    after: Option<&Cursor>,
    limit: u32,
) -> Result<Vec<TicketRow>, StoreError> {
    let (at, id) = after.map_or((None, None), |c| (Some(c.created_at), Some(c.id.clone())));
    let rows: Vec<TicketRaw> = sqlx::query_as(select_tickets!(
        "WHERE account_id = ?1 AND (?2 IS NULL OR created_at > ?2 OR (created_at = ?2 AND id > ?3)) \
         ORDER BY created_at, id LIMIT ?4"
    ))
    .bind(account_id.to_string())
    .bind(at)
    .bind(id)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode_ticket).collect()
}

/// Whether any account has a ticket that a `Pair` could consume at `now`: the hub serves `p2pc/pair/1` only then
/// (§5.3, §10.5). Protocol side, before there is a principal: it reads no ticket, only whether one is open.
pub async fn any_open_ticket(conn: &mut Conn, now: OffsetDateTime) -> Result<bool, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pairing_tickets WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(ts(now))
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Result of [`revoke_ticket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeTicket {
    /// The ticket is now revoked.
    Revoked,
    /// It already was, or it was consumed (revoking a consumed ticket changes nothing: revoke the device instead).
    Unchanged,
    /// No such ticket in this account.
    NotFound,
}

/// Revokes an unused ticket of `account_id`. Idempotent; a consumed ticket is left as it is.
pub async fn revoke_ticket(
    conn: &mut Conn,
    account_id: AccountId,
    id: PairingTicketId,
    now: OffsetDateTime,
) -> Result<RevokeTicket, StoreError> {
    let done = sqlx::query(
        "UPDATE pairing_tickets SET revoked_at = ? \
         WHERE account_id = ? AND id = ? AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(id.to_string())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done == 1 {
        return Ok(RevokeTicket::Revoked);
    }
    Ok(match get_ticket(conn, account_id, id).await? {
        None => RevokeTicket::NotFound,
        Some(_) => RevokeTicket::Unchanged,
    })
}

/// What a `Pair` gets (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairOutcome {
    /// A new device, created by this call (audit `device_paired`; the caller commits).
    Paired(Box<DeviceRow>),
    /// The same answer again: the ticket was consumed by this NodeId, whose device is still live (§5.2 "Retry is
    /// idempotent"). Nothing changed.
    Again(Box<DeviceRow>),
    /// `invalid_ticket`: unknown, expired, revoked, used by another NodeId, or used by this NodeId whose device has
    /// since been revoked or has expired; or a NodeId that is already another live device. One answer for all.
    Invalid,
}

/// The pairing transaction (§5.2, §5.3, SI-H2-2), for the `p2pc/pair/1` gateway (T2-11). Run it in a `BEGIN
/// IMMEDIATE` transaction and commit it when the answer is [`PairOutcome::Paired`].
///
/// 1. The ticket is looked up by the digest of the presented code and compared in constant time; a miss compares
///    against `dummy` so the work is the same.
/// 2. A consumed ticket answers again only to the NodeId whose device it created, while that device is live: a
///    consumed ticket never revives a revoked device.
/// 3. Otherwise the row's own expiry and revocation decide, never the ticket's payload.
/// 4. The device is inserted with the ticket's project, scopes and limits, and the one `UPDATE … WHERE consumed_at IS
///    NULL AND expires_at > now AND revoked_at IS NULL` consumes the ticket in the same transaction: of two concurrent
///    `Pair`s for one ticket, exactly one creates a device.
#[allow(clippy::too_many_arguments)]
pub async fn pair(
    conn: &mut Conn,
    code_digest: &SecretHash,
    dummy: &SecretHash,
    iroh_node_id: &str,
    label: Option<String>,
    platform: &str,
    now: OffsetDateTime,
) -> Result<PairOutcome, StoreError> {
    let raw: Option<TicketRaw> = sqlx::query_as(select_tickets!("WHERE code_digest = ?"))
        .bind(code_digest.to_stored())
        .fetch_optional(&mut *conn)
        .await?;
    let ticket = match raw.map(decode_ticket).transpose()? {
        Some(t) if t.code_digest.ct_eq(code_digest) => t,
        _ => {
            std::hint::black_box(code_digest.ct_eq(dummy));
            return Ok(PairOutcome::Invalid);
        }
    };
    if let Some(device_id) = ticket.device_id {
        let device = get(conn, ticket.account_id, device_id).await?;
        return Ok(match device {
            Some(d) if d.iroh_node_id == iroh_node_id && d.is_live(now) => PairOutcome::Again(Box::new(d)),
            _ => PairOutcome::Invalid,
        });
    }
    if !ticket.is_redeemable(now) {
        return Ok(PairOutcome::Invalid);
    }
    let new = NewDevice {
        device_id: DeviceId::generate(),
        project_id: ticket.project_id,
        iroh_node_id: iroh_node_id.to_string(),
        label: label.or_else(|| ticket.label.clone()),
        platform: platform.to_string(),
        scopes: ticket.scopes.clone(),
        daily_unit_cap: ticket.daily_unit_cap,
        allowed_images: ticket.allowed_images.clone(),
        blobs_quota_mb: ticket.blobs_quota_mb,
        expires_at: ticket.device_expires_at,
        paired_by: Some(ticket.created_by),
    };
    let device = match insert(conn, ticket.account_id, &new, now).await {
        Ok(d) => d,
        Err(InsertError::NodeIdInUse) => return Ok(PairOutcome::Invalid),
        Err(InsertError::Store(e)) => return Err(e),
    };
    let done = sqlx::query(
        "UPDATE pairing_tickets SET consumed_at = ?1, device_id = ?2 \
         WHERE code_digest = ?3 AND consumed_at IS NULL AND expires_at > ?1 AND revoked_at IS NULL",
    )
    .bind(ts(now))
    .bind(device.device_id.to_string())
    .bind(code_digest.to_stored())
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done != 1 {
        // Lost a race: the caller drops the transaction, and the device row goes with it.
        return Ok(PairOutcome::Invalid);
    }
    Ok(PairOutcome::Paired(Box::new(device)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        let id = DeviceId::generate().to_string();
        let c = Cursor {
            created_at: 1_793_872_800,
            id: id.clone(),
        };
        assert_eq!(Cursor::decode::<DeviceId>(&c.encode()), Some(c));
        for bad in [
            "",
            ".",
            "1.",
            &format!("x.{id}"),
            "1.dev_nope",
            &format!("1.{}", id.to_lowercase()),
        ] {
            assert_eq!(Cursor::decode::<DeviceId>(bad), None, "{bad}");
        }
        assert_eq!(Cursor::decode::<PairingTicketId>(&format!("1.{id}")), None);
    }

    #[test]
    fn last_seen_staleness() {
        let t = time::macros::datetime!(2026-11-05 10:00:00 UTC);
        assert!(last_seen_is_stale(None, t));
        assert!(!last_seen_is_stale(Some(t), t + time::Duration::seconds(59)));
        assert!(last_seen_is_stale(Some(t), t + time::Duration::seconds(60)));
    }
}
