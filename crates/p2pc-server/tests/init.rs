// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-server init`: data dir, config, database, owner, default project and the admin key.

use std::os::unix::fs::PermissionsExt;

use p2pc_proto::api::Scope;
use p2pc_server::clock::ManualClock;
use p2pc_server::config::Config;
use p2pc_server::init::{InitError, InitOptions, init, init_unchecked, init_with};
use p2pc_server::store;
use time::macros::datetime;

fn clock() -> ManualClock {
    ManualClock::new(datetime!(2026-11-05 10:00:00 UTC))
}

#[tokio::test]
async fn init_creates_everything_once() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("nested").join("p2pc-server");
    let out = init(&data_dir, &clock()).await.unwrap();

    // Data dir 0700, config 0600, database present.
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&data_dir), 0o700);
    assert_eq!(out.config_path, data_dir.join("server.toml"));
    assert_eq!(mode(&out.config_path), 0o600);
    assert_eq!(mode(&data_dir.join("p2pc.db")), 0o600);
    // §5 "Server identity": the iroh key, 0600, and the address derived from it.
    assert_eq!(mode(&data_dir.join("server.key")), 0o600);
    let key = p2pc_server::identity::load(&data_dir).unwrap();
    assert_eq!(out.server.node_id(), key.public());
    assert_eq!(out.server.address().server, key.public().to_string());

    // The config is valid and points at the data dir.
    let config = Config::load(&out.config_path).unwrap();
    assert_eq!(config.data_dir, data_dir.canonicalize().unwrap());
    assert_eq!(config.bind.to_string(), "127.0.0.1:7477");

    // Owner account, default project and the admin key.
    let db = store::open(&config.db_path(), store::OpenMode::Existing).await.unwrap();
    let owner: (String, i64) = sqlx::query_as("SELECT account_id, is_owner FROM accounts")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(owner, (out.account_id.to_string(), 1));
    let project: (String, String) = sqlx::query_as("SELECT project_id, name FROM projects WHERE account_id = ?")
        .bind(out.account_id.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(project, (out.project_id.to_string(), "default".to_string()));
    let mut conn = db.acquire().await.unwrap();
    let row = store::keys::get(&mut conn, out.account_id, out.admin_key.key_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.scopes, vec![Scope::Admin]);
    assert_eq!(row.project_id, out.project_id);
    assert!(out.admin_key.verify(&row.digest));
    drop(conn);

    // The stored row holds only a hash: no column contains the secret, in any encoding.
    let full = out.admin_key.expose();
    let secret_b32 = &full["p2pc_sk_".len() + 13..];
    let secret_hex = data_encoding::HEXLOWER.encode(out.admin_key.secret().expose_bytes());
    let dump: Vec<(String, String)> =
        sqlx::query_as("SELECT key_id, secret_digest || scopes || coalesce(label, '') FROM api_keys")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(dump.len(), 1);
    let digest: String = sqlx::query_scalar("SELECT secret_digest FROM api_keys")
        .fetch_one(&db)
        .await
        .unwrap();
    // The proto's stored form, `sha256:<hex>`, which reads back to the same hash.
    assert_eq!(digest, out.admin_key.hash().to_stored());
    assert!(digest.starts_with("sha256:"));
    assert_eq!(
        p2pc_proto::auth::SecretHash::from_stored(&digest).unwrap(),
        out.admin_key.hash()
    );
    for (_, text) in &dump {
        assert!(!text.contains(secret_b32) && !text.contains(&secret_hex), "{text}");
    }
    db.close().await;
    // Not in the raw database file either (main file and WAL).
    for name in ["p2pc.db", "p2pc.db-wal"] {
        if let Ok(bytes) = std::fs::read(data_dir.join(name)) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(secret_b32) && !text.contains(&secret_hex), "{name}");
        }
    }
    // Nor in the config file.
    let toml = std::fs::read_to_string(&out.config_path).unwrap();
    assert!(!toml.contains(secret_b32));

    // A second init on the same data dir is refused and changes nothing.
    let err = init(&data_dir, &clock()).await.unwrap_err();
    assert!(matches!(err, InitError::AlreadyInitialized(_)), "{err}");
    assert_eq!(std::fs::read_to_string(&out.config_path).unwrap(), toml);
}

#[tokio::test]
async fn init_refuses_a_dir_that_already_has_a_database() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("p2pc.db"), b"").unwrap();
    let err = init(tmp.path(), &clock()).await.unwrap_err();
    assert!(matches!(err, InitError::AlreadyInitialized(_)), "{err}");
}

/// Review P3-4: another `init` that wins the race after our preflight check. Its files are never removed.
#[tokio::test]
async fn losing_an_init_race_to_another_database_removes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    // Another process created the database between our check and our create.
    let theirs = tmp.path().join("p2pc.db");
    std::fs::write(&theirs, b"their database").unwrap();
    let err = init_unchecked(tmp.path(), &clock()).await.unwrap_err();
    assert!(matches!(err, InitError::AlreadyInitialized(_)), "{err}");
    assert_eq!(std::fs::read(&theirs).unwrap(), b"their database");
    assert!(!tmp.path().join("server.toml").exists());
}

#[tokio::test]
async fn losing_the_race_on_the_config_removes_only_our_own_database() {
    let tmp = tempfile::tempdir().unwrap();
    // Another process wrote the config after our check; we create the database, then find its config.
    let theirs = tmp.path().join("server.toml");
    std::fs::write(&theirs, b"# theirs\n").unwrap();
    let err = init_unchecked(tmp.path(), &clock()).await.unwrap_err();
    assert!(matches!(err, InitError::AlreadyInitialized(_)), "{err}");
    assert_eq!(std::fs::read(&theirs).unwrap(), b"# theirs\n");
    for ours in ["p2pc.db", "p2pc.db-wal", "p2pc.db-shm"] {
        assert!(!tmp.path().join(ours).exists(), "{ours} left behind");
    }
}

#[tokio::test]
async fn two_concurrent_inits_produce_exactly_one_working_server() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("d");
    let (c1, c2) = (clock(), clock());
    let (a, b) = tokio::join!(init(&dir, &c1), init(&dir, &c2));
    let (ok, err) = match (a, b) {
        (Ok(o), Err(e)) | (Err(e), Ok(o)) => (o, e),
        (a, b) => panic!("expected one success and one refusal: {a:?} {b:?}"),
    };
    assert!(matches!(err, InitError::AlreadyInitialized(_)), "{err}");
    let config = Config::load(&ok.config_path).unwrap();
    let db = store::open(&config.db_path(), store::OpenMode::Existing).await.unwrap();
    let mut conn = db.acquire().await.unwrap();
    let row = store::keys::get(&mut conn, ok.account_id, ok.admin_key.key_id())
        .await
        .unwrap()
        .unwrap();
    assert!(ok.admin_key.verify(&row.digest));
}

#[tokio::test]
async fn an_existing_empty_data_dir_is_tightened_to_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("d");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    init(&dir, &clock()).await.unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
}

#[tokio::test]
async fn init_with_a_bind_address_writes_it_to_the_config() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("d");
    let options = InitOptions {
        bind: Some("192.0.2.10:7480".parse().unwrap()),
    };
    let out = init_with(&dir, &options, &clock()).await.unwrap();
    let config = Config::load(&out.config_path).unwrap();
    assert_eq!(config.bind.to_string(), "192.0.2.10:7480");
    // Without the option the default stays loopback (spec §10).
    let other = tmp.path().join("e");
    let out = init_with(&other, &InitOptions::default(), &clock()).await.unwrap();
    assert_eq!(
        Config::load(&out.config_path).unwrap().bind.to_string(),
        "127.0.0.1:7477"
    );
}
