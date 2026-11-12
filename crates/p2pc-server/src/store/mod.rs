// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite storage (spec §12): connection setup, migrations and the repository functions.
//!
//! Rules for every function in this module tree:
//! - runtime queries (`sqlx::query`/`query_as`/`query_scalar`) with bound parameters only. sqlx only accepts
//!   `&'static str` SQL there, so text built at run time (`format!`) does not even compile;
//! - every function that reads or writes tenant data takes the principal's `account_id` and its SQL filters by it
//!   (SI-7). The exceptions run before there is a REST principal: [`keys::lookup_for_auth`],
//!   [`join_tokens::find_by_digest`], the device lookups of [`devices`] (`by_id_for_auth`, `live_by_iroh_node_id`,
//!   `pair`), and the agent-protocol functions of [`nodes`], where the principal is the node authenticated by iroh;
//! - timestamps are stored as INTEGER Unix seconds (UTC).

pub mod accounts;
pub mod audit;
pub mod devices;
// Crate-private (T04 review): the compiler, not only the `status_writes` tripwire, keeps every status write inside
// this crate.
pub(crate) mod job_state;
pub mod jobs;
pub mod join_requests;
pub mod join_tokens;
pub mod keys;
pub mod leases;
pub mod nodes;
pub mod outputs;
pub mod ports;
pub mod usage;

use std::path::{Path, PathBuf};
use std::time::Duration;

use p2pc_proto::auth::SecretHash;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use time::OffsetDateTime;

/// The connection pool.
pub type Db = sqlx::SqlitePool;
/// One connection, or a transaction (`&mut *tx`).
pub type Conn = sqlx::SqliteConnection;

/// The embedded migrations of `crates/p2pc-server/migrations/` (timestamped, forward-only).
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Connections in the pool. SQLite has a single writer; a few readers are enough for one owner.
const MAX_CONNECTIONS: u32 = 4;
/// How long a statement waits for a lock before failing with `SQLITE_BUSY`.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether [`open`] may create the database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Create it (only `init`).
    Create,
    /// It must already exist (`serve`).
    Existing,
}

/// A storage error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database does not exist yet.
    #[error("database {0} not found: run `p2pc-server init` first")]
    NotInitialized(PathBuf),
    /// SQLite or sqlx failed.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// A migration failed.
    #[error("database migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A file-system step of the store failed (for example the fsync of a directory).
    #[error("file system error: {0}")]
    Io(#[from] std::io::Error),
    /// A stored value cannot be decoded (the database was edited by hand or is corrupt).
    #[error("corrupt value in column {0}")]
    Corrupt(&'static str),
}

/// Opens the database with WAL, `foreign_keys = ON`, a busy timeout and a small pool, then applies pending
/// migrations.
pub async fn open(path: &Path, mode: OpenMode) -> Result<Db, StoreError> {
    if mode == OpenMode::Existing && !path.is_file() {
        return Err(StoreError::NotInitialized(path.to_path_buf()));
    }
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(mode == OpenMode::Create)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(BUSY_TIMEOUT);
    let db = SqlitePoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect_with(options)
        .await?;
    MIGRATOR.run(&db).await?;
    Ok(db)
}

/// Starts a write transaction with `BEGIN IMMEDIATE`. Use it for every transaction that reads, then writes.
///
/// A deferred `BEGIN` takes the write lock only at the first write. In WAL mode, if another connection committed
/// in the meantime, SQLite then answers `SQLITE_BUSY` at once, without waiting for `busy_timeout`. `IMMEDIATE` takes
/// the write lock up front, so concurrent writers queue behind `busy_timeout` instead. This holds across processes
/// too, for example `p2pc-server keys recover` while the server runs.
pub async fn begin_immediate(db: &Db) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, StoreError> {
    Ok(db.begin_with("BEGIN IMMEDIATE").await?)
}

/// Unix seconds of a timestamp, as stored.
#[must_use]
pub fn ts(t: OffsetDateTime) -> i64 {
    t.unix_timestamp()
}

/// Unix milliseconds of a timestamp, for the few columns that need sub-second precision (`*_ms`).
#[must_use]
pub fn ts_ms(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

/// A stored millisecond timestamp.
pub(crate) fn from_ts_ms(ms: i64, column: &'static str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).map_err(|_| StoreError::Corrupt(column))
}

/// A stored timestamp.
pub(crate) fn from_ts(secs: i64, column: &'static str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::from_unix_timestamp(secs).map_err(|_| StoreError::Corrupt(column))
}

pub(crate) fn from_ts_opt(secs: Option<i64>, column: &'static str) -> Result<Option<OffsetDateTime>, StoreError> {
    secs.map(|s| from_ts(s, column)).transpose()
}

/// A stored `secret_digest` (`sha256:<hex>`, the format of [`SecretHash::to_stored`]).
pub(crate) fn decode_digest(text: &str, column: &'static str) -> Result<SecretHash, StoreError> {
    SecretHash::from_stored(text).map_err(|_| StoreError::Corrupt(column))
}

pub(crate) fn parse_col<T: std::str::FromStr>(text: &str, column: &'static str) -> Result<T, StoreError> {
    text.parse().map_err(|_| StoreError::Corrupt(column))
}

#[cfg(test)]
mod tests {
    use p2pc_proto::auth::ApiKey;

    use super::*;

    #[test]
    fn digest_uses_the_proto_stored_form() {
        let h = ApiKey::generate().hash();
        let text = h.to_stored();
        assert_eq!(decode_digest(&text, "c").unwrap(), h);
        for bad in ["", "sha256:", "md5:00", &text.to_uppercase(), &text[..70]] {
            assert!(
                matches!(decode_digest(bad, "c"), Err(StoreError::Corrupt("c"))),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn open_sets_wal_and_foreign_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("t.db");
        assert!(matches!(
            open(&path, OpenMode::Existing).await,
            Err(StoreError::NotInitialized(_))
        ));
        let db = open(&path, OpenMode::Create).await.unwrap();
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(&db).await.unwrap();
        assert_eq!(mode, "wal");
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys").fetch_one(&db).await.unwrap();
        assert_eq!(fk, 1);
        let timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout").fetch_one(&db).await.unwrap();
        assert_eq!(timeout, 5000);
        db.close().await;
        // Reopening applies no migration twice.
        let db = open(&path, OpenMode::Existing).await.unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn the_digest_column_refuses_anything_but_a_versioned_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let db = open(&tmp.path().join("t.db"), OpenMode::Create).await.unwrap();
        let mut conn = db.acquire().await.unwrap();
        let (account, project) = accounts::create_owner(&mut conn, time::OffsetDateTime::UNIX_EPOCH)
            .await
            .unwrap();
        let good = ApiKey::generate().hash().to_stored();
        let insert = |digest: String| {
            let db = db.clone();
            async move {
                sqlx::query(
                    "INSERT INTO api_keys (key_id, account_id, project_id, secret_digest, scopes, created_at) \
                     VALUES (?, ?, ?, ?, '[]', 0)",
                )
                .bind(p2pc_proto::ids::KeyId::generate().to_string())
                .bind(account.to_string())
                .bind(project.to_string())
                .bind(digest)
                .execute(&db)
                .await
            }
        };
        for bad in [
            // A raw secret-looking string, the wrong prefix, wrong length, uppercase hex.
            "p2pc_sk_abcdefgh2345_secret".to_string(),
            good.replacen("sha256:", "sha512:", 1),
            good[..70].to_string(),
            format!("{good}0"),
            good.to_uppercase().replacen("SHA256:", "sha256:", 1),
            format!("sha256:{}", "g".repeat(64)),
        ] {
            assert!(insert(bad.clone()).await.is_err(), "{bad}");
        }
        insert(good).await.unwrap();
    }
}
