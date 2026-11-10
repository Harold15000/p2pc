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
