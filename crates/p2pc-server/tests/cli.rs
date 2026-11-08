// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the `p2pc-server` binary.

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;

#[test]
fn version_prints_name_and_version() {
    cargo_bin_cmd!("p2pc-server")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("p2pc-server {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_succeeds() {
    cargo_bin_cmd!("p2pc-server")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("serve"))
        .stdout(contains("init"));
}

#[test]
fn init_prints_the_admin_key_once_and_refuses_to_run_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let out = cargo_bin_cmd!("p2pc-server")
        .args(["init", "--data-dir"])
        .arg(&data)
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|l| l.starts_with("ADMIN API KEY (shown once): "))
        .unwrap_or_else(|| panic!("{stdout}"));
    let key = line.trim_start_matches("ADMIN API KEY (shown once): ");
    assert!(key.parse::<p2pc_proto::auth::ApiKey>().is_ok(), "{line}");
    // Shown once: only on stdout, never on stderr (where logs go).
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&key["p2pc_sk_".len() + 13..]));
    assert!(data.join("server.toml").is_file());
    // The server address is printed next to the key (§10).
    let address = stdout
        .lines()
        .find_map(|l| l.strip_prefix("SERVER ADDRESS: "))
        .unwrap_or_else(|| panic!("{stdout}"));
    assert!(address.parse::<p2pc_proto::auth::ServerAddress>().is_ok(), "{address}");

    cargo_bin_cmd!("p2pc-server")
        .args(["init", "--data-dir"])
        .arg(&data)
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .failure()
        .stderr(contains("already initialised"))
        .stdout(predicates::str::is_empty());
}

#[test]
fn init_bind_sets_the_listen_address_in_the_config() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    cargo_bin_cmd!("p2pc-server")
        .args(["init", "--bind", "[::1]:7480", "--data-dir"])
        .arg(&data)
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .success();
    let config = p2pc_server::config::Config::load(&data.join("server.toml")).unwrap();
    assert_eq!(config.bind.to_string(), "[::1]:7480");
    // A malformed address is refused before anything is created.
    let bad = tmp.path().join("bad");
    cargo_bin_cmd!("p2pc-server")
        .args(["init", "--bind", "localhost:7477", "--data-dir"])
        .arg(&bad)
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .failure()
        .stdout(predicates::str::is_empty());
    assert!(!bad.exists());
}

/// The key line printed by `init` and `keys recover`.
fn printed_key(stdout: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("ADMIN API KEY (shown once): "))
        .unwrap_or_else(|| panic!("{stdout}"));
    line.trim_start_matches("ADMIN API KEY (shown once): ").to_string()
}

#[test]
fn keys_recover_prints_a_new_admin_key_once() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let init = cargo_bin_cmd!("p2pc-server")
        .args(["init", "--data-dir"])
        .arg(&data)
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .success()
        .get_output()
        .clone();
    let first = printed_key(&init.stdout);
    let out = cargo_bin_cmd!("p2pc-server")
        .args(["keys", "recover", "--data-dir"])
        .arg(&data)
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .success()
        .get_output()
        .clone();
    let recovered = printed_key(&out.stdout);
    assert!(recovered.parse::<p2pc_proto::auth::ApiKey>().is_ok(), "{recovered}");
    assert_ne!(recovered, first);
    assert!(!String::from_utf8_lossy(&out.stderr).contains(&recovered["p2pc_sk_".len() + 13..]));
    // Without a database there is nothing to recover.
    cargo_bin_cmd!("p2pc-server")
        .args(["keys", "recover", "--data-dir"])
        .arg(tmp.path().join("nothing"))
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .failure()
        .stderr(contains("p2pc-server init"))
        .stdout(predicates::str::is_empty());
}

#[test]
fn p2pc_data_dir_takes_precedence_over_the_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let from_env = tmp.path().join("env");
    let from_flag = tmp.path().join("flag");
    cargo_bin_cmd!("p2pc-server")
        .args(["init", "--data-dir"])
        .arg(&from_flag)
        .env("P2PC_DATA_DIR", &from_env)
        .assert()
        .success();
    assert!(from_env.join("server.toml").is_file());
    assert!(!from_flag.exists());
}

#[test]
fn serve_rejects_a_config_with_an_unknown_field() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("server.toml");
    std::fs::write(&config, "data_dir = \"/srv/p2pc\"\nbindd = \"127.0.0.1:7477\"\n").unwrap();
    cargo_bin_cmd!("p2pc-server")
        .args(["serve", "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stderr(contains("unknown field `bindd`"));
}

#[test]
fn info_prints_the_node_id_and_the_address() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let init = cargo_bin_cmd!("p2pc-server")
        .args(["init", "--data-dir"])
        .arg(&data)
        .env_remove("P2PC_DATA_DIR")
        .assert()
        .success()
        .get_output()
        .clone();
    let init_out = String::from_utf8(init.stdout).unwrap();
    let out = cargo_bin_cmd!("p2pc-server")
        .args(["info", "--config"])
        .arg(data.join("server.toml"))
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let node_id = stdout
        .lines()
        .find_map(|l| l.strip_prefix("NODE ID: "))
        .unwrap_or_else(|| panic!("{stdout}"));
    let address: p2pc_proto::auth::ServerAddress = stdout
        .lines()
        .find_map(|l| l.strip_prefix("SERVER ADDRESS: "))
        .unwrap_or_else(|| panic!("{stdout}"))
        .parse()
        .unwrap();
    assert_eq!(address.server, node_id);
    assert!(
        init_out.contains(&address.to_string()),
        "init and info print the same address"
    );
    // Never the secret key or the admin key.
    let key = std::fs::read(data.join("server.key")).unwrap();
    assert!(!stdout.contains(&data_encoding::HEXLOWER.encode(&key)));
    assert!(!stdout.contains("p2pc_sk_"));
    // A key readable by others is refused.
    std::fs::set_permissions(
        data.join("server.key"),
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    cargo_bin_cmd!("p2pc-server")
        .args(["info", "--config"])
        .arg(data.join("server.toml"))
        .assert()
        .failure()
        .stderr(contains("chmod 600"));
}

/// §10 "Tunnel budget": the server refuses to start when tunnelled streams could take every REST connection.
#[test]
fn serve_refuses_a_tunnel_budget_that_reaches_the_rest_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("server.toml");
    std::fs::write(
        &config,
        "data_dir = \"/srv/p2pc\"\n[iroh]\ntunnel_max_streams = 256\n[http]\nmax_connections = 256\n",
    )
    .unwrap();
    cargo_bin_cmd!("p2pc-server")
        .args(["serve", "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stderr(contains(
            "iroh.tunnel_max_streams = 256 must be at least 1 and below http.max_connections = 256",
        ));
}
