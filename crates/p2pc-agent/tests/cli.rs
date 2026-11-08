// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the `p2pc-agent` binary.
//!
//! Mostly the commands that run no external tool are exercised here (`config show`, `identity`). `inventory` and
//! `doctor` run `nvidia-smi` and `podman`, so they are tested in the library with a fake runner; see
//! `real_machine_smoke` below for the manual run.
//!
//! One exception (T10i): `join_on_a_fresh_data_dir_under_a_0755_parent_…` has to get past the data dir to be worth
//! anything, so the real binary reaches `inventory::detect`, which runs `podman` and `nvidia-smi` **on the host** when
//! they exist (a missing one is only reported), and then dials the server it names; it ends on the connection error.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::str::contains;

#[test]
fn version_prints_name_and_version() {
    cargo_bin_cmd!("p2pc-agent")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("p2pc-agent {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_succeeds() {
    cargo_bin_cmd!("p2pc-agent")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("run"))
        .stdout(contains("join"))
        .stdout(contains("status"))
        .stdout(contains("inventory"))
        .stdout(contains("doctor"))
        .stdout(contains("identity"));
}

const SERVER_ID: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// A join token for a server nobody runs, valid or long expired. Encoded only to be passed to the binary.
fn token(expired: bool) -> String {
    let now = time::OffsetDateTime::now_utc();
    let issued = if expired { now - time::Duration::hours(2) } else { now };
    p2pc_proto::auth::JoinToken::generate(SERVER_ID.into(), vec![], time::Duration::minutes(15), issued)
        .unwrap()
        .encode()
        .unwrap()
}

/// `status` and `run` before any `join`; `status` needs no network.
#[test]
fn status_and_run_before_joining() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    agent(dir.path())
        .args(["status", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("Enrolled:      no"))
        .stdout(contains("Connection:    not enrolled"));
    agent(dir.path())
        .args(["run", "--config"])
        .arg(&config)
        .assert()
        .code(8)
        .stderr(contains("not enrolled yet"));
}

#[test]
fn join_exit_codes_that_need_no_server() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    // Malformed: 4.
    agent(dir.path())
        .args(["join", "p2pc_join_not-a-token", "--config"])
        .arg(&config)
        .assert()
        .code(4)
        .stderr(contains("not a valid join token"));
    // Expired: 5, before anything is dialled or created. A token in argv also gets the warning (T14b2 review), and
    // is never echoed.
    let expired = token(true);
    agent(dir.path())
        .args(["join", &expired, "--config"])
        .arg(&config)
        .assert()
        .code(5)
        .stderr(contains("expired"))
        .stderr(contains(
            "warning: the token was visible to other users in the process list; next time, paste it when asked or \
             pipe it on stdin",
        ))
        .stderr(predicates::str::contains(&expired["p2pc_join_".len()..]).not());
    assert!(
        !dir.path().join("data").exists(),
        "no identity was created for an expired token"
    );
    // Already enrolled, without --force: 3, and the token is not even read.
    let enrolled = write_config(
        dir.path(),
        &format!(
            "[server]\nnode_id = \"{SERVER_ID}\"\naccount_id = \"acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n\
             agent_node_id = \"node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n"
        ),
    );
    agent(dir.path())
        .args(["join", &token(false), "--config"])
        .arg(&enrolled)
        .assert()
        .code(3)
        .stderr(contains("already enrolled"))
        .stderr(contains("--force"));
    // With --force the enrollment check is passed: the token is read and judged (here: expired, 5).
    agent(dir.path())
        .args(["join", &token(true), "--force", "--config"])
        .arg(&enrolled)
        .assert()
        .code(5)
        .stderr(contains("expired"));
    // `status` shows the enrollment.
    agent(dir.path())
        .args(["status", "--config"])
        .arg(&enrolled)
        .assert()
        .success()
        .stdout(contains("Enrolled:      yes (node node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4"))
        .stdout(contains(format!("Server NodeId: {SERVER_ID}")))
        .stdout(contains("Running leases: unknown"));
}

/// T10c: `join` (also with `--force`) takes the data dir's `agent.lock` like `run` does, and refuses while a running
/// agent holds it: it must not replace the identity or the config under a live agent.
#[test]
fn join_refuses_while_an_agent_holds_the_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let enrolled = write_config(
        dir.path(),
        &format!(
            "[server]\nnode_id = \"{SERVER_ID}\"\naccount_id = \"acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n\
             agent_node_id = \"node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n"
        ),
    );
    // The "running agent": this process holds the lock (flock conflicts across open file descriptions).
    let running = p2pc_agent::node::lock_data_dir(&dir.path().join("data")).unwrap();
    agent(dir.path())
        .args(["join", &token(false), "--force", "--config"])
        .arg(&enrolled)
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .code(1)
        .stderr(contains("already running"))
        .stderr(contains("stop it first"));
    assert!(
        !dir.path().join("data/identity.key").exists(),
        "no identity was created or replaced under a running agent"
    );
    drop(running);
}

/// The agent binary run under `umask 022`, as on a real node, whatever the umask of the test runner is. Without it
/// the test could not show the bug of ACC-1: under umask 077 the old `create_dir_all` made a 0700 dir by itself.
///
/// Hermetic (T10i review P3 5): the shell is started by absolute path and the child's `PATH` is an empty directory, so
/// the host's real `podman`, `systemctl` and `nvidia-smi` are never run. To the agent they are missing, which it only
/// reports.
fn agent_under_umask_022(home: &Path) -> Command {
    let empty_path = home.join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "umask 022; exec \"$0\" \"$@\""])
        .arg(env!("CARGO_BIN_EXE_p2pc-agent"))
        .env("HOME", home)
        .env("PATH", &empty_path)
        .env_remove("P2PC_AGENT_CONFIG");
    cmd
}

/// T10i (ACC-1): the first `join` on a fresh node, with a data dir that does not exist under a 0755 parent, under
/// umask 022. It must get past the directory (created 0700, `agent.lock` and `identity.key` in it) and fail only
/// later, on the server nobody runs here: the token is well formed, so it is not refused before the lock; the dial
/// ends with exit 1 and a connection error (never the exit codes of a token or of the directory).
#[test]
fn join_on_a_fresh_data_dir_under_a_0755_parent_is_not_refused_for_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let data = dir.path().join(".local/share/p2pc-agent");
    let config = dir.path().join("agent.toml");
    fs::write(&config, format!("data_dir = \"{}\"\n", data.display())).unwrap();
    agent_under_umask_022(dir.path())
        .args(["join", "-", "--config"])
        .arg(&config)
        .write_stdin(token(false))
        .timeout(std::time::Duration::from_secs(90))
        .assert()
        .code(1)
        .stderr(
            contains("cannot reach the server")
                .or(contains("did not answer within"))
                .and(contains("refusing to use").not())
                .and(contains("agent.lock").not()),
        );
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(data.parent().unwrap()), 0o700);
    assert!(data.join("agent.lock").exists());
    assert!(data.join("identity.key").exists());
}

/// `status` lists the running leases `run` recorded: lease, epoch, job name, phase, time, log bytes. Never the job's
/// content (the file holds none).
#[test]
fn status_lists_the_running_leases() {
    let dir = tempfile::tempdir().unwrap();
    let enrolled = write_config(
        dir.path(),
        &format!(
            "[server]\nnode_id = \"{SERVER_ID}\"\naccount_id = \"acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n\
             agent_node_id = \"node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n"
        ),
    );
    let data = dir.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(
        data.join("agent-leases.json"),
        r#"{"updated_at":"2027-01-15T08:00:00Z","leases":[{"lease_id":"lse_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4","epoch":2,
            "job_name":"train","phase":"uploading","accepted_at":"2027-01-15T07:00:00Z",
            "started_at":"2027-01-15T07:00:05Z","log_bytes_sent":2048}]}"#,
    )
    .unwrap();
    agent(dir.path())
        .args(["status", "--config"])
        .arg(&enrolled)
        .assert()
        .success()
        .stdout(contains("Running leases: 1 (as of 2027-01-15T08:00:00Z)"))
        .stdout(contains(
            "lse_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4 epoch 2  job \"train\"  uploading outputs  running for",
        ))
        .stdout(contains("logs sent 2.0 KiB"));
}

/// §7 / SI-6: with `-` or no argument the token comes from stdin, so no `ps`-visible argv ever holds it. The
/// expired token makes the run end with exit code 5, which proves the binary read it from stdin.
#[test]
fn join_reads_the_token_from_stdin_never_from_argv() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let secret = token(true);
    for args in [vec!["join"], vec!["join", "-"]] {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_p2pc-agent"))
            .args(&args)
            .arg("--config")
            .arg(&config)
            .env("HOME", dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // While it waits for stdin: its argv (what `ps` shows) and its environment hold no token.
        let pid = child.id();
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
        let environ = fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        for seen in [&cmdline, &environ] {
            let seen = String::from_utf8_lossy(seen);
            assert!(!seen.contains("p2pc_join_"), "{seen}");
        }
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{secret}").unwrap();
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(5), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains("process list"),
            "no warning when the token comes on stdin"
        );
        // Nor does anything it prints.
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!printed.contains(&secret[10..]), "{printed}");
    }
}

/// The binary, isolated from the developer's own config and home.
fn agent(home: &Path) -> Command {
    let mut cmd = cargo_bin_cmd!("p2pc-agent");
    cmd.env("HOME", home).env_remove("P2PC_AGENT_CONFIG");
    cmd
}

fn write_config(dir: &Path, extra: &str) -> std::path::PathBuf {
    let path = dir.join("agent.toml");
    let data_dir = dir.join("data");
    fs::write(&path, format!("data_dir = \"{}\"\n{extra}", data_dir.display())).unwrap();
    path
}

#[test]
fn config_show_prints_the_effective_config() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "[share]\ncpu_cores = 1.5\n[labels]\nzone = \"home\"\n");
    agent(dir.path())
        .args(["config", "show", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("# source: "))
        .stdout(contains("(from --config)"))
        .stdout(contains(format!(
            "data_dir = \"{}\"",
            dir.path().join("data").display()
        )))
        .stdout(contains("agent_lease_ttl_s = 45"))
        .stdout(contains("runtime = \"crun\""))
        .stdout(contains("cpu_cores = 1.5"))
        .stdout(contains("memory_mb = "))
        .stdout(contains("disk_mb = "))
        .stdout(contains("gpus = \"all\""))
        .stdout(contains("zone = \"home\""));
}

#[test]
fn config_from_the_environment_and_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "agent_lease_ttl_s = 30\n");
    agent(dir.path())
        .env("P2PC_AGENT_CONFIG", &config)
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains("(from $P2PC_AGENT_CONFIG)"))
        .stdout(contains("agent_lease_ttl_s = 30"));
    // No file at the default path: built-in defaults under $HOME.
    agent(dir.path())
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(contains("not found: built-in defaults"))
        .stdout(contains(".local/share/p2pc-agent"));
}

#[test]
fn bad_configs_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let typo = write_config(dir.path(), "[share]\ncpu_core = 2\n");
    agent(dir.path())
        .args(["config", "show", "--config"])
        .arg(&typo)
        .assert()
        .code(1)
        .stderr(contains("cpu_core"));
    let too_short = write_config(dir.path(), "agent_lease_ttl_s = 5\n");
    agent(dir.path())
        .args(["config", "show", "--config"])
        .arg(&too_short)
        .assert()
        .code(1)
        .stderr(contains("agent_lease_ttl_s"));
    let greedy = write_config(dir.path(), "[share]\ncpu_cores = 100000\n");
    agent(dir.path())
        .args(["config", "show", "--config"])
        .arg(&greedy)
        .assert()
        .code(1)
        .stderr(contains("logical cores"));
    agent(dir.path())
        .args(["config", "show", "--config"])
        .arg(dir.path().join("missing.toml"))
        .assert()
        .code(1)
        .stderr(contains("not found"));
}

#[test]
fn identity_is_created_once_and_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let run = || {
        let out = agent(dir.path())
            .args(["identity", "--config"])
            .arg(&config)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).unwrap()
    };
    let first = run();
    let node_id = first.trim();
    assert_eq!(node_id.len(), 64, "{first}");
    assert!(
        node_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(run(), first, "same NodeId across restarts");
    let key = dir.path().join("data/identity.key");
    assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(dir.path().join("data")).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // The output is the public key only: the 32 secret bytes appear nowhere.
    let secret = fs::read(&key).unwrap();
    assert!(!first.contains(&data_encoding::HEXLOWER.encode(&secret)));

    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    agent(dir.path())
        .args(["identity", "--config"])
        .arg(&config)
        .assert()
        .code(1)
        .stdout("")
        .stderr(contains("wider than 0600"));
}

/// Manual smoke test on a real node: runs the real `nvidia-smi`, `podman` and friends.
///
/// Run it on a test node with `cargo test -p p2pc-agent --test cli -- --ignored real_machine_smoke`. It only checks
/// that both commands produce a report; whether the node is ready depends on the machine.
#[test]
#[ignore = "runs the real nvidia-smi and podman; run manually on a test node"]
fn real_machine_smoke() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    agent(dir.path())
        .args(["inventory", "--json", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("\"inventory\""));
    agent(dir.path())
        .args(["doctor", "--config"])
        .arg(&config)
        .assert()
        .stdout(contains("Result: "));
}
