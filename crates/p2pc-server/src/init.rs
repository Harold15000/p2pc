// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-server init`: creates the data dir (0700), the database, the owner account, the `default` project, the
//! first admin principal and the server's iroh key (`server.key`, 0600), then writes `server.toml` (0600).
//!
//! The first admin principal is an API key (H1, [`init`]), returned to the caller to print once (only its SHA-256
//! digest is stored, and it is never logged), or, with `--owner-device <NodeId>` ([`init_owner_device`], H2 §5.3), an
//! **owner device**: the desktop app's own device key, of which only the public NodeId is given and stored. No API key
//! is created then.

use std::fs::{DirBuilder, OpenOptions, Permissions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use p2pc_proto::api::{AuditKind, OWNER_PROFILE, Scope};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{AccountId, DeviceId, ProjectId};

use crate::clock::Clock;
use crate::config::{CONFIG_FILE, Config, DB_FILE};
use crate::gateway::ServerIdentity;
use crate::store::audit::NewEvent;
use crate::store::keys::NewKey;
use crate::store::{self, OpenMode, StoreError};

/// What `init` created.
#[derive(Debug)]
pub struct InitOutcome {
    /// The absolute data dir.
    pub data_dir: PathBuf,
    /// The config file written.
    pub config_path: PathBuf,
    /// The admin key. Print it once; it cannot be recovered.
    pub admin_key: ApiKey,
    /// The owner account.
    pub account_id: AccountId,
    /// Its `default` project.
    pub project_id: ProjectId,
    /// The server's iroh identity: print its address (§10) with the admin key.
    pub server: ServerIdentity,
}

/// Why `init` failed.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The data dir already holds a config or a database.
    #[error("{0} is already initialised (it has a server.toml or a database); refusing to overwrite it")]
    AlreadyInitialized(PathBuf),
    /// A file system operation failed.
    #[error("{what} {path}: {source}")]
    Io {
        /// What was being done.
        what: &'static str,
        /// On which path.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// The database could not be created.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The config could not be rendered.
    #[error("cannot render server.toml: {0}")]
    Config(#[from] toml::ser::Error),
    /// The iroh key could not be created.
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    /// `--owner-device` is not an iroh NodeId (64 lowercase hex characters of an Ed25519 public key), or the label is
    /// not 1-256 characters without control characters.
    #[error("invalid owner device: {0}")]
    InvalidDevice(&'static str),
}

/// What `init --owner-device` created (H2 §5.3). There is no API key to print.
#[derive(Debug)]
pub struct OwnerDeviceOutcome {
    /// The absolute data dir.
    pub data_dir: PathBuf,
    /// The config file written.
    pub config_path: PathBuf,
    /// The owner device, with the `admin` scope and no limit.
    pub device_id: DeviceId,
    /// The owner account.
    pub account_id: AccountId,
    /// Its `default` project.
    pub project_id: ProjectId,
    /// The server's iroh identity: the desktop app pins its NodeId.
    pub server: ServerIdentity,
}

/// Choices of `init --owner-device` (H2 §5.3).
#[derive(Debug, Clone)]
pub struct OwnerDeviceOptions {
    /// The REST listen address (`bind`). `None` keeps the loopback default.
    pub bind: Option<SocketAddr>,
    /// The owner device's iroh NodeId (the desktop app generated the key and passes its public half).
    pub node_id: String,
    /// The device's label.
    pub label: Option<String>,
}

/// The first admin principal of a new data dir.
enum First {
    /// H1: an unrestricted admin API key.
    Key,
    /// H2 §5.3: an owner device with the `admin` scope.
    Device { node_id: String, label: Option<String> },
}

/// What a new data dir got: the API key, or the device.
enum Created {
    Key(ApiKey),
    Device(DeviceId),
}

/// Checks a device label: 1-256 characters, no control characters (the `devices.label` column's bounds).
pub(crate) fn valid_device_label(label: Option<&str>) -> bool {
    label.is_none_or(|l| (1..=256).contains(&l.chars().count()) && !l.chars().any(char::is_control))
}

fn io<'a>(what: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> InitError + 'a {
    move |source| InitError::Io {
        what,
        path: path.to_path_buf(),
        source,
    }
}

/// Choices made at `init` time and written to `server.toml`.
#[derive(Debug, Clone, Default)]
pub struct InitOptions {
    /// The REST listen address (`bind`). `None` keeps the loopback default (spec §10).
    pub bind: Option<SocketAddr>,
}

/// Initialises `data_dir` with the default options. Refuses to run twice on the same directory.
pub async fn init(data_dir: &Path, clock: &dyn Clock) -> Result<InitOutcome, InitError> {
    init_with(data_dir, &InitOptions::default(), clock).await
}

/// Initialises `data_dir` with `options`. Refuses to run twice on the same directory.
pub async fn init_with(data_dir: &Path, options: &InitOptions, clock: &dyn Clock) -> Result<InitOutcome, InitError> {
    // A fast, friendly refusal. It is not what makes init safe against a concurrent init: `init_unchecked` claims
    // each file with `create_new`, so the loser of a race gets `AlreadyInitialized` and removes nothing of the
    // winner's.
    if data_dir.join(CONFIG_FILE).exists() || data_dir.join(DB_FILE).exists() {
        return Err(InitError::AlreadyInitialized(data_dir.to_path_buf()));
    }
    init_unchecked_with(data_dir, options, clock).await
}

/// [`init`] without the preflight check: what runs when another process creates the files between that check and
/// this call. Public so tests can simulate that race.
///
/// The database file is claimed first with `create_new`. If it already exists the answer is
/// [`InitError::AlreadyInitialized`] and nothing is touched. On any later failure only the files this call created
/// are removed: the database (and its WAL and shared-memory files), never a config another process wrote.
pub async fn init_unchecked(data_dir: &Path, clock: &dyn Clock) -> Result<InitOutcome, InitError> {
    init_unchecked_with(data_dir, &InitOptions::default(), clock).await
}

async fn init_unchecked_with(
    data_dir: &Path,
    options: &InitOptions,
    clock: &dyn Clock,
) -> Result<InitOutcome, InitError> {
    let made = init_first(data_dir, options.bind, First::Key, clock).await?;
    let Created::Key(admin_key) = made.created else {
        return Err(InitError::InvalidDevice("internal: no key"));
    };
    Ok(InitOutcome {
        data_dir: made.data_dir,
        config_path: made.config_path,
        admin_key,
        account_id: made.account_id,
        project_id: made.project_id,
        server: made.server,
    })
}

/// `p2pc-server init --owner-device <NodeId>` (H2 §5.3): like [`init`], but the first admin principal is the owner
/// device whose NodeId is given, and no API key is created or printed. Refuses to run twice on the same directory.
pub async fn init_owner_device(
    data_dir: &Path,
    options: &OwnerDeviceOptions,
    clock: &dyn Clock,
) -> Result<OwnerDeviceOutcome, InitError> {
    if crate::devices_api::ed25519_node_id(&options.node_id).is_none() {
        return Err(InitError::InvalidDevice(
            "--owner-device must be an iroh NodeId: 64 lowercase hex characters of an Ed25519 public key",
        ));
    }
    if !valid_device_label(options.label.as_deref()) {
        return Err(InitError::InvalidDevice(
            "--label must be 1-256 characters without control characters",
        ));
    }
    if data_dir.join(CONFIG_FILE).exists() || data_dir.join(DB_FILE).exists() {
        return Err(InitError::AlreadyInitialized(data_dir.to_path_buf()));
    }
    let first = First::Device {
        node_id: options.node_id.clone(),
        label: options.label.clone(),
    };
    let made = init_first(data_dir, options.bind, first, clock).await?;
    let Created::Device(device_id) = made.created else {
        return Err(InitError::InvalidDevice("internal: no device"));
    };
    Ok(OwnerDeviceOutcome {
        data_dir: made.data_dir,
        config_path: made.config_path,
        device_id,
        account_id: made.account_id,
        project_id: made.project_id,
        server: made.server,
    })
}

struct Made {
    data_dir: PathBuf,
    config_path: PathBuf,
    created: Created,
    account_id: AccountId,
    project_id: ProjectId,
    server: ServerIdentity,
}

async fn init_first(
    data_dir: &Path,
    bind: Option<SocketAddr>,
    first: First,
    clock: &dyn Clock,
) -> Result<Made, InitError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data_dir)
        .map_err(io("cannot create", data_dir))?;
    // The directory may have existed with looser permissions.
    std::fs::set_permissions(data_dir, Permissions::from_mode(0o700)).map_err(io("cannot chmod", data_dir))?;
    let data_dir = data_dir.canonicalize().map_err(io("cannot resolve", data_dir))?;
    let config_path = data_dir.join(CONFIG_FILE);
    let db_path = data_dir.join(DB_FILE);

    // Claim the database file. From here on it is ours, and only ours to clean up.
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&db_path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(InitError::AlreadyInitialized(data_dir));
        }
        Err(e) => return Err(io("cannot create", &db_path)(e)),
    }
    let created = create_database(&db_path, &first, clock).await;
    let (created, account_id, project_id) = match created {
        Ok(v) => v,
        Err(e) => {
            remove_our_database(&db_path);
            return Err(e);
        }
    };
    // The iroh identity. A key left by an earlier, interrupted init is kept: it never belonged to another server.
    let key = match crate::identity::load_or_create(&data_dir) {
        Ok(k) => k,
        Err(e) => {
            remove_our_database(&db_path);
            return Err(e.into());
        }
    };
    let mut config = Config::new(data_dir.clone());
    if let Some(bind) = bind {
        config.bind = bind;
    }
    let server = ServerIdentity::new(key, &config.iroh.relays);
    if let Err(e) = write_config(&config_path, &config) {
        remove_our_database(&db_path);
        return Err(match e {
            // Another process wrote a config meanwhile: leave it alone.
            InitError::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists => {
                InitError::AlreadyInitialized(data_dir)
            }
            other => other,
        });
    }
    Ok(Made {
        data_dir,
        config_path,
        created,
        account_id,
        project_id,
        server,
    })
}

/// Fills the (already claimed, 0600) database file: schema, owner, `default` project and the first admin principal.
async fn create_database(
    db_path: &Path,
    first: &First,
    clock: &dyn Clock,
) -> Result<(Created, AccountId, ProjectId), InitError> {
    let db = store::open(db_path, OpenMode::Create).await?;
    let now = clock.now();
    let mut tx = store::begin_immediate(&db).await?;
    let (account_id, project_id) = store::accounts::create_owner(&mut tx, now).await?;
    if let First::Device { node_id, label } = first {
        let device = store::devices::NewDevice {
            device_id: DeviceId::generate(),
            project_id,
            iroh_node_id: node_id.clone(),
            label: label.clone(),
            platform: String::new(),
            scopes: OWNER_PROFILE.to_vec(),
            daily_unit_cap: None,
            allowed_images: None,
            blobs_quota_mb: None,
            expires_at: None,
            paired_by: None,
        };
        let row = store::devices::insert(&mut tx, account_id, &device, now)
            .await
            .map_err(|e| match e {
                store::devices::InsertError::Store(e) => InitError::Store(e),
                store::devices::InsertError::NodeIdInUse => InitError::InvalidDevice("NodeId already in use"),
            })?;
        let event = NewEvent {
            kind: AuditKind::DeviceAddedOffline,
            actor_key_id: None,
            actor_device_id: None,
            subject_id: Some(row.device_id.to_string()),
            detail: serde_json::Map::from_iter([
                ("scopes".to_string(), serde_json::json!(row.scopes)),
                ("project_id".to_string(), serde_json::json!(project_id)),
                ("iroh_node_id".to_string(), serde_json::json!(row.iroh_node_id)),
                ("by".to_string(), serde_json::json!("init --owner-device")),
            ]),
        };
        store::audit::append(&mut tx, account_id, &event, now).await?;
        tx.commit().await.map_err(StoreError::from)?;
        db.close().await;
        return Ok((Created::Device(row.device_id), account_id, project_id));
    }
    let admin_key = ApiKey::generate();
    let new = NewKey {
        key_id: admin_key.key_id(),
        project_id,
        digest: admin_key.hash(),
        scopes: vec![Scope::Admin],
        daily_unit_cap: None,
        allowed_images: None,
        label: Some("admin (init)".to_string()),
        expires_at: None,
    };
    store::keys::insert(&mut tx, account_id, &new, now).await?;
    let event = NewEvent {
        kind: AuditKind::KeyCreated,
        actor_key_id: None,
        actor_device_id: None,
        subject_id: Some(admin_key.key_id().to_string()),
        detail: serde_json::Map::from_iter([
            ("scopes".to_string(), serde_json::json!([Scope::Admin])),
            ("project_id".to_string(), serde_json::json!(project_id)),
            ("by".to_string(), serde_json::json!("init")),
        ]),
    };
    store::audit::append(&mut tx, account_id, &event, now).await?;
    tx.commit().await.map_err(StoreError::from)?;
    db.close().await;
    Ok((Created::Key(admin_key), account_id, project_id))
}

fn write_config(path: &Path, config: &Config) -> Result<(), InitError> {
    let text = format!(
        "# p2pc-server configuration. Unknown keys are an error.\n# See docs/dev/README.md.\n\n{}",
        config.to_toml()?
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io("cannot create", path))?;
    file.write_all(text.as_bytes()).map_err(io("cannot write", path))?;
    file.sync_all().map_err(io("cannot sync", path))
}

/// Best-effort cleanup after a failed init, so it can be retried. Only called once this process has claimed the
/// database file with `create_new`.
fn remove_our_database(db_path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = db_path.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}
