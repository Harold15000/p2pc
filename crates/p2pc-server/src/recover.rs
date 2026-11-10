// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-server keys recover` (spec §5 "Offline recovery"): the way back for an owner who has lost every admin key.
//!
//! It needs local access to the data dir, which is the proof of ownership, and works while the server runs: the
//! database is in WAL mode and the write is one `BEGIN IMMEDIATE` transaction, which waits behind the server's
//! writers instead of failing. It creates a new **unrestricted** admin key (no expiry, no cap, no image list) in the
//! owner's `default` project and records a `key_recovered` audit event. The key is returned to be printed once; only
//! its digest is stored.

use std::path::Path;

use p2pc_proto::api::{AuditKind, Scope};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{AccountId, ProjectId};

use crate::clock::Clock;
use crate::config::DB_FILE;
use crate::store::accounts::DEFAULT_PROJECT;
use crate::store::audit::NewEvent;
use crate::store::keys::NewKey;
use crate::store::{self, OpenMode, StoreError};

/// What `keys recover` created.
#[derive(Debug)]
pub struct RecoverOutcome {
    /// The new key. Print it once; it cannot be recovered.
    pub admin_key: ApiKey,
    /// The owner account.
    pub account_id: AccountId,
    /// Its `default` project, where the key acts.
    pub project_id: ProjectId,
}

/// Why recovery failed.
#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    /// The data dir has no database, or it cannot be used.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The database has no owner account or no `default` project (it was not made by `p2pc-server init`).
    #[error("the database has no owner account with a `default` project; was it created by `p2pc-server init`?")]
    NoOwner,
}

/// Creates an unrestricted admin key for the owner of the server whose data dir is `data_dir`.
pub async fn recover(data_dir: &Path, clock: &dyn Clock) -> Result<RecoverOutcome, RecoverError> {
    let db = store::open(&data_dir.join(DB_FILE), OpenMode::Existing).await?;
    let result = recover_in(&db, clock).await;
    db.close().await;
    result
}

async fn recover_in(db: &store::Db, clock: &dyn Clock) -> Result<RecoverOutcome, RecoverError> {
    let mut tx = store::begin_immediate(db).await?;
    let account_id = store::accounts::owner(&mut tx).await?.ok_or(RecoverError::NoOwner)?;
    let project_id = store::accounts::project_by_name(&mut tx, account_id, DEFAULT_PROJECT)
        .await?
        .ok_or(RecoverError::NoOwner)?;
    let now = clock.now();
    let admin_key = ApiKey::generate();
    let new = NewKey {
        key_id: admin_key.key_id(),
        project_id,
        digest: admin_key.hash(),
        scopes: vec![Scope::Admin],
        daily_unit_cap: None,
        allowed_images: None,
        label: Some("admin (recovered)".to_string()),
        expires_at: None,
    };
    store::keys::insert(&mut tx, account_id, &new, now).await?;
    let event = NewEvent {
        kind: AuditKind::KeyRecovered,
        actor_key_id: None,
        actor_device_id: None,
        subject_id: Some(admin_key.key_id().to_string()),
        detail: serde_json::Map::from_iter([
            ("scopes".to_string(), serde_json::json!([Scope::Admin])),
            ("project_id".to_string(), serde_json::json!(project_id)),
            ("by".to_string(), serde_json::json!("keys recover")),
        ]),
    };
    store::audit::append(&mut tx, account_id, &event, now).await?;
    tx.commit().await.map_err(StoreError::from)?;
    Ok(RecoverOutcome {
        admin_key,
        account_id,
        project_id,
    })
}

// --- Offline device management (H2 §5.3) -------------------------------------------------------------------------

/// What `p2pc-server devices add` registers: a device known by its public NodeId, in a project of the owner.
#[derive(Debug, Clone)]
pub struct AddDevice {
    /// The device's iroh NodeId (64 lowercase hex of an Ed25519 public key).
    pub node_id: String,
    /// Its scopes: not empty, no duplicates.
    pub scopes: Vec<Scope>,
    /// Its label.
    pub label: Option<String>,
    /// The project; `None` is the owner's `default` project.
    pub project_id: Option<ProjectId>,
}

/// Why an offline device command failed.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCommandError {
    /// The data dir has no database, or it cannot be used.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The database has no owner account, or the project is not one of its projects.
    #[error("the database has no owner account with that project; was it created by `p2pc-server init`?")]
    NoOwner,
    /// The NodeId, scopes or label are not acceptable.
    #[error("{0}")]
    Invalid(&'static str),
    /// A live device already has this NodeId.
    #[error("a live device already has this NodeId; revoke it first")]
    NodeIdInUse,
    /// No such device in the owner account.
    #[error("no such device")]
    NotFound,
    /// It is the account's last live unrestricted `admin` principal (H2 §5.5, as `409 last_admin_device`).
    #[error(
        "this is the account's last live unrestricted admin principal (last_admin_device); add another admin device \
         or recover an admin key first"
    )]
    LastAdmin,
}

/// `p2pc-server devices add` (H2 §5.3): registers a device offline, with local data-dir access as the proof of
/// ownership, audited as `device_added_offline`. Works while the server runs (one `BEGIN IMMEDIATE` transaction).
pub async fn devices_add(
    data_dir: &Path,
    add: &AddDevice,
    clock: &dyn Clock,
) -> Result<store::devices::DeviceRow, DeviceCommandError> {
    if crate::devices_api::ed25519_node_id(&add.node_id).is_none() {
        return Err(DeviceCommandError::Invalid(
            "--node-id must be an iroh NodeId: 64 lowercase hex characters of an Ed25519 public key",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    if add.scopes.is_empty() || !add.scopes.iter().all(|s| seen.insert(*s)) {
        return Err(DeviceCommandError::Invalid(
            "--scopes must list at least one scope, none twice",
        ));
    }
    if !crate::init::valid_device_label(add.label.as_deref()) {
        return Err(DeviceCommandError::Invalid(
            "--label must be 1-256 characters without control characters",
        ));
    }
    let db = store::open(&data_dir.join(DB_FILE), OpenMode::Existing).await?;
    let result = devices_add_in(&db, add, clock).await;
    db.close().await;
    result
}

async fn devices_add_in(
    db: &store::Db,
    add: &AddDevice,
    clock: &dyn Clock,
) -> Result<store::devices::DeviceRow, DeviceCommandError> {
    let mut tx = store::begin_immediate(db).await?;
    let account_id = store::accounts::owner(&mut tx)
        .await?
        .ok_or(DeviceCommandError::NoOwner)?;
    let project_id = match add.project_id {
        Some(p) => store::accounts::project_of(&mut tx, account_id, p)
            .await?
            .ok_or(DeviceCommandError::NoOwner)?,
        None => store::accounts::project_by_name(&mut tx, account_id, DEFAULT_PROJECT)
            .await?
            .ok_or(DeviceCommandError::NoOwner)?,
    };
    let now = clock.now();
    let new = store::devices::NewDevice {
        device_id: p2pc_proto::ids::DeviceId::generate(),
        project_id,
        iroh_node_id: add.node_id.clone(),
        label: add.label.clone(),
        platform: String::new(),
        scopes: add.scopes.clone(),
        daily_unit_cap: None,
        allowed_images: None,
        blobs_quota_mb: None,
        expires_at: None,
        paired_by: None,
    };
    let row = store::devices::insert(&mut tx, account_id, &new, now)
        .await
        .map_err(|e| match e {
            store::devices::InsertError::NodeIdInUse => DeviceCommandError::NodeIdInUse,
            store::devices::InsertError::Store(e) => DeviceCommandError::Store(e),
        })?;
    let event = NewEvent {
        kind: AuditKind::DeviceAddedOffline,
        actor_key_id: None,
        actor_device_id: None,
        subject_id: Some(row.device_id.to_string()),
        detail: serde_json::Map::from_iter([
            ("scopes".to_string(), serde_json::json!(row.scopes)),
            ("project_id".to_string(), serde_json::json!(row.project_id)),
            ("iroh_node_id".to_string(), serde_json::json!(row.iroh_node_id)),
            ("by".to_string(), serde_json::json!("devices add")),
        ]),
    };
    store::audit::append(&mut tx, account_id, &event, now).await?;
    tx.commit().await.map_err(StoreError::from)?;
    Ok(row)
}

/// `p2pc-server devices revoke` (H2 §5.3): revokes a device offline, under the same last-admin rule as `DELETE
/// /v1/devices/{id}`, audited as `device_revoked_offline`. A running hub closes the device's connections within 5 s
/// through its liveness sweep (§5.5). Revoking a revoked device succeeds and changes nothing.
pub async fn devices_revoke(
    data_dir: &Path,
    device_id: p2pc_proto::ids::DeviceId,
    clock: &dyn Clock,
) -> Result<(), DeviceCommandError> {
    let db = store::open(&data_dir.join(DB_FILE), OpenMode::Existing).await?;
    let result = devices_revoke_in(&db, device_id, clock).await;
    db.close().await;
    result
}

async fn devices_revoke_in(
    db: &store::Db,
    device_id: p2pc_proto::ids::DeviceId,
    clock: &dyn Clock,
) -> Result<(), DeviceCommandError> {
    let mut tx = store::begin_immediate(db).await?;
    let account_id = store::accounts::owner(&mut tx)
        .await?
        .ok_or(DeviceCommandError::NoOwner)?;
    let now = clock.now();
    match store::devices::revoke(&mut tx, account_id, device_id, now).await? {
        store::devices::Revoke::Revoked => {
            let event = NewEvent {
                kind: AuditKind::DeviceRevokedOffline,
                actor_key_id: None,
                actor_device_id: None,
                subject_id: Some(device_id.to_string()),
                detail: serde_json::Map::from_iter([("by".to_string(), serde_json::json!("devices revoke"))]),
            };
            store::audit::append(&mut tx, account_id, &event, now).await?;
            tx.commit().await.map_err(StoreError::from)?;
            Ok(())
        }
        store::devices::Revoke::AlreadyRevoked => Ok(()),
        store::devices::Revoke::NotFound => Err(DeviceCommandError::NotFound),
        store::devices::Revoke::LastAdmin => Err(DeviceCommandError::LastAdmin),
    }
}
