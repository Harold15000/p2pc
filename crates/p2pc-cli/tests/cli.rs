// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The real `p2pc` binary: `--help` of every command, the absence of `--key`, and one run against a mock server.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use clap::CommandFactory;
use p2pc_cli::cli::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::JobStatus;
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::JobId;
use predicates::str::contains;

/// The binary with an empty, private configuration directory and no inherited `P2PC_*` variables.
fn p2pc(config_dir: &std::path::Path) -> Command {
    let mut cmd = cargo_bin_cmd!("p2pc");
    cmd.env_clear()
        .env("P2PC_CONFIG_DIR", config_dir)
        .env("HOME", config_dir)
        .env("RUST_BACKTRACE", "0");
    cmd
}

/// Every command and subcommand, as the path of names that reaches it (the root is the empty path).
fn command_paths() -> Vec<Vec<String>> {
    fn walk(cmd: &clap::Command, prefix: &[String], out: &mut Vec<Vec<String>>) {
        for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
            let mut path = prefix.to_vec();
            path.push(sub.get_name().to_string());
            out.push(path.clone());
            walk(sub, &path, out);
        }
    }
    let mut paths = vec![Vec::new()];
    walk(&Cli::command(), &[], &mut paths);
    paths
}

#[test]
fn version_prints_name_and_version() {
    let dir = tempfile::tempdir().unwrap();
    p2pc(dir.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("p2pc {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn every_command_and_subcommand_has_a_working_help() {
    let dir = tempfile::tempdir().unwrap();
    let paths = command_paths();
    assert!(paths.len() >= 29, "the walk found the whole tree: {}", paths.len());
    for path in paths {
        p2pc(dir.path())
            .args(&path)
            .arg("--help")
            .assert()
            .success()
            .stdout(contains("Usage:"));
    }
}

#[test]
fn the_help_lists_every_documented_command() {
    let dir = tempfile::tempdir().unwrap();
    let mut assert = p2pc(dir.path()).arg("--help").assert().success();
    for name in [
        "login",
        "logout",
        "whoami",
        "run",
        "estimate",
        "jobs",
        "status",
        "cancel",
        "machines",
        "join-token",
        "keys",
        "audit",
        "completion",
    ] {
        assert = assert.stdout(contains(name));
    }
}

#[test]
fn no_command_accepts_a_key_flag() {
    let dir = tempfile::tempdir().unwrap();
    for path in command_paths() {
        let secret = ApiKey::generate().expose();
        let assert = p2pc(dir.path())
            .args(&path)
            .args(["--key", &secret])
            .assert()
            .failure()
            .code(125)
            .stderr(contains("unexpected argument"));
        // The rejected value is not echoed back by the usage error.
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
        assert!(!stderr.contains(&secret), "{path:?} echoed the key");
    }
}

#[test]
fn run_detach_against_a_mock_server_prints_only_the_job_id() {
    let id = JobId::generate();
    let created = serde_json::to_value(fixtures::job(id, JobStatus::Queued, None)).unwrap();
    let server = MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &created),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    });
    let dir = tempfile::tempdir().unwrap();
    let key = ApiKey::generate();
    p2pc(dir.path())
        .env("P2PC_SERVER", server.url())
        .env("P2PC_API_KEY", key.expose())
        .args([
            "run",
            "-d",
            "--image",
            "python:3.12-slim",
            "--",
            "python",
            "-c",
            "print(6*7)",
        ])
        .assert()
        .success()
        .stdout(format!("{id}\n"))
        .stderr("");
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn run_following_returns_the_jobs_exit_code() {
    let id = JobId::generate();
    let created = serde_json::to_value(fixtures::job(id, JobStatus::Queued, None)).unwrap();
    let done = serde_json::to_value(fixtures::job(id, JobStatus::Failed, Some(3))).unwrap();
    let server = MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &created),
        // The job wrote nothing: its live log is empty and ends at once.
        r if r.ends_with("/logs") => MockResponse::text(200, ""),
        r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &done),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    });
    let dir = tempfile::tempdir().unwrap();
    p2pc(dir.path())
        .env("P2PC_SERVER", server.url())
        .env("P2PC_API_KEY", ApiKey::generate().expose())
        .args(["run", "--image", "python:3.12-slim", "--", "false"])
        .assert()
        .code(3)
        .stdout("")
        .stderr(contains(id.to_string()))
        .stderr(contains("job failed with exit code 3"));
}

#[test]
fn rm_without_yes_and_without_a_terminal_is_refused() {
    let server = MockServer::start(|_| MockResponse::problem(500, "unexpected", "must not be called"));
    let dir = tempfile::tempdir().unwrap();
    p2pc(dir.path())
        .env("P2PC_SERVER", server.url())
        .env("P2PC_API_KEY", ApiKey::generate().expose())
        .args(["machines", "rm", "laptop"])
        .write_stdin("y\n")
        .assert()
        .code(125)
        .stderr(contains("--yes"));
    assert!(server.requests().is_empty());
}

/// The real binary: its stdout and stderr are pipes here, so a job's output is written as stored (on a terminal it is
/// escaped; that is tested in process, where a terminal can be simulated).
#[test]
fn the_binary_writes_a_jobs_log_as_stored_when_piped() {
    let id = JobId::generate();
    let data = "\u{1b}[31mred\u{1b}[0m\n";
    let line = |seq: u64, stream: &str| {
        let mut body = serde_json::to_string(&serde_json::json!({
            "seq": seq, "stream": stream, "ts": "2023-11-14T22:13:20Z", "data": data,
        }))
        .unwrap();
        body.push('\n');
        body
    };
    let body = format!("{}{}", line(0, "stdout"), line(1, "stderr"));
    let server = MockServer::start(move |_| MockResponse::text(200, &body));
    let dir = tempfile::tempdir().unwrap();
    p2pc(dir.path())
        .env("P2PC_SERVER", server.url())
        .env("P2PC_API_KEY", ApiKey::generate().expose())
        .args(["logs", &id.to_string()])
        .assert()
        .success()
        .stdout(data)
        .stderr(data);
}

#[test]
fn logs_results_and_usage_need_what_they_work_on() {
    let dir = tempfile::tempdir().unwrap();
    for sub in ["logs", "results"] {
        p2pc(dir.path()).arg(sub).assert().code(125).stderr(contains("JOB_ID"));
    }
    // `usage` needs a server and a key, like every command that asks the server.
    p2pc(dir.path()).arg("usage").assert().code(125);
}

#[cfg(unix)]
#[test]
fn a_credentials_file_that_others_can_read_is_refused_by_the_binary() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.toml");
    std::fs::write(
        &path,
        format!("[profiles.default]\napi_key = \"{}\"\n", ApiKey::generate().expose()),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    p2pc(dir.path())
        .env("P2PC_SERVER", "https://p2pc.example.invalid")
        .arg("whoami")
        .assert()
        .code(125)
        .stderr(contains("chmod 600"));
}
