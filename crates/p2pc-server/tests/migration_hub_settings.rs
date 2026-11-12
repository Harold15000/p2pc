// SPDX-License-Identifier: AGPL-3.0-only

//! The `hub_settings` migration (T2-18, H2 spec §7.3, §13), run on a database at the schema before it: it is
//! additive (every earlier row is kept, `PRAGMA foreign_key_check` is empty), it starts with no row (no name set),
//! and the table holds one row at most, with a name of 1-64 characters.

// The helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

use p2pc_server::store::{self, MIGRATOR};
use sqlx::{Connection, SqliteConnection};
use time::OffsetDateTime;

/// The migration under test.
const HUB_SETTINGS: i64 = 20_261_112_120_000;

async fn open(dir: &tempfile::TempDir) -> SqliteConnection {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(dir.path().join("t.db"))
        .create_if_missing(true)
        .foreign_keys(true);
    SqliteConnection::connect_with(&options).await.unwrap()
}

/// Applies the migrations matching `which`, each in its own transaction, as sqlx does.
async fn migrate(conn: &mut SqliteConnection, which: impl Fn(i64) -> bool) {
    for m in MIGRATOR.iter().filter(|m| which(m.version)) {
        let mut tx = conn.begin().await.unwrap();
        sqlx::raw_sql(m.sql.clone())
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("migration {}: {e}", m.version));
        tx.commit().await.unwrap();
    }
}

async fn accounts(conn: &mut SqliteConnection) -> String {
    sqlx::query_scalar("SELECT json_group_array(json_array(account_id, is_owner, created_at)) FROM accounts")
        .fetch_one(&mut *conn)
        .await
        .unwrap()
}

#[tokio::test]
async fn hub_settings_is_added_empty_to_the_previous_schema() {
    assert!(
        MIGRATOR.iter().any(|m| m.version == HUB_SETTINGS),
        "the migration is embedded"
    );
    let dir = tempfile::tempdir().unwrap();
    let mut conn = open(&dir).await;
    migrate(&mut conn, |v| v < HUB_SETTINGS).await;
    store::accounts::create_owner(&mut conn, OffsetDateTime::UNIX_EPOCH)
        .await
        .unwrap();
    let before = accounts(&mut conn).await;

    migrate(&mut conn, |v| v == HUB_SETTINGS).await;
    assert_eq!(accounts(&mut conn).await, before, "earlier rows are kept");
    let fk: Vec<(String,)> = sqlx::query_as("SELECT \"table\" FROM pragma_foreign_key_check")
        .fetch_all(&mut conn)
        .await
        .unwrap();
    assert!(fk.is_empty(), "{fk:?}");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hub_settings")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(rows, 0, "no name until an admin sets one");

    // The one row, and the store reads it back.
    store::settings::set_hub_name(&mut conn, "My cloud", OffsetDateTime::UNIX_EPOCH)
        .await
        .unwrap();
    store::settings::set_hub_name(&mut conn, "Home cloud", OffsetDateTime::UNIX_EPOCH)
        .await
        .unwrap();
    assert_eq!(
        store::settings::hub_name(&mut conn).await.unwrap().as_deref(),
        Some("Home cloud")
    );
    for bad in [
        "INSERT INTO hub_settings (id, hub_name, updated_at) VALUES (2, 'x', 0)",
        "UPDATE hub_settings SET hub_name = ''",
        "UPDATE hub_settings SET hub_name = printf('%.65c', 'x')",
    ] {
        assert!(sqlx::query(bad).execute(&mut conn).await.is_err(), "{bad}");
    }
    // 64 characters of two bytes each fit: the limit counts characters.
    sqlx::query("UPDATE hub_settings SET hub_name = ?")
        .bind("é".repeat(64))
        .execute(&mut conn)
        .await
        .unwrap();
}
