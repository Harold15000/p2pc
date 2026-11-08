// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The commands, in process, against a mock HTTP server on `127.0.0.1:0`. No real network and no `p2pc-server`.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::{ApiKeyInfo, JoinTokenInfo, JoinTokenResponse, NewApiKey, Node, Page, Scope};
use p2pc_proto::api::{Job, JobStatus};
use p2pc_proto::auth::{ApiKey, JoinToken};
use p2pc_proto::ids::{JobId, JoinTokenId, KeyId, NodeId};
use p2pc_proto::units::Units;
use serde_json::{Value, json};

fn json_of<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serializable")
}

fn secret_part(key: &ApiKey) -> String {
    key.expose().rsplit('_').next().expect("secret").to_string()
}

// ---------------------------------------------------------------------------------------------------------------
// login, whoami, logout
// ---------------------------------------------------------------------------------------------------------------

fn whoami_server(key: &ApiKey, scopes: Vec<Scope>) -> (MockServer, p2pc_proto::api::WhoAmI) {
    let who = fixtures::whoami(key.key_id(), scopes);
    let body = json_of(&who);
    let server = MockServer::start(move |req| match req.route().as_str() {
        "GET /v1/whoami" => MockResponse::json(200, &body),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    });
    (server, who)
}

#[test]
fn login_checks_the_key_stores_it_and_whoami_then_uses_it() {
    let cli = Cli::new();
    let (server, who) = whoami_server(&cli.key, vec![Scope::Admin, Scope::JobsWrite]);
    let key_line = format!("{}\n", cli.key.expose());
    let cli = cli.with_stdin(&key_line);

    let login = cli.run(&["login", "--server", &server.url(), "--key-stdin"]);
    assert_eq!(login.code, 0, "{login:?}");
    // It prints the account, project, key ID and scopes.
    for expected in [
        who.account_id.to_string(),
        who.project_id.to_string(),
        who.key_id.to_string(),
        "admin, jobs:write".to_string(),
    ] {
        assert!(login.stdout.contains(&expected), "{expected} in {}", login.stdout);
    }
    // The server saw the key as a bearer token, once.
    let calls = server.requests_to("GET /v1/whoami");
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].header("authorization"),
        Some(format!("Bearer {}", cli.key.expose()).as_str())
    );
    // The key is never echoed.
    assert!(!login.stdout.contains(&secret_part(&cli.key)) && !login.stderr.contains(&secret_part(&cli.key)));

    // Stored, with the server in config.toml.
    let creds = std::fs::read_to_string(cli.config_dir().join("credentials.toml")).unwrap();
    assert!(creds.contains(&cli.key.expose()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(cli.config_dir().join("credentials.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let config = std::fs::read_to_string(cli.config_dir().join("config.toml")).unwrap();
    assert!(config.contains(&server.url()), "{config}");

    // `whoami` now works from the files alone: no server and no key in the environment.
    let again = Cli {
        env: [("P2PC_CONFIG_DIR".to_string(), cli.config_dir().display().to_string())].into(),
        ..Cli::new()
    };
    let whoami = again.run(&["whoami"]);
    assert_eq!(whoami.code, 0, "{whoami:?}");
    assert!(whoami.stdout.contains(&who.key_id.to_string()));
    assert_eq!(server.requests_to("GET /v1/whoami").len(), 2);

    // `--json` is the API's JSON.
    let json_out = again.run(&["whoami", "--json"]);
    assert_eq!(serde_json::from_str::<Value>(&json_out.stdout).unwrap(), json_of(&who));

    // And logout removes the key again.
    let logout = again.run(&["logout"]);
    assert_eq!(logout.code, 0, "{logout:?}");
    let after = again.run(&["whoami"]);
    assert_eq!(after.code, 125);
    assert!(after.stderr.contains("p2pc login"), "{}", after.stderr);
}

#[test]
fn login_refuses_a_malformed_key_without_calling_the_server_or_echoing_it() {
    let cli = Cli::new();
    let (server, _) = whoami_server(&cli.key, vec![Scope::Admin]);
    let bad = format!("{}x", cli.key.expose());
    let cli = cli.with_stdin(&format!("{bad}\n"));
    let out = cli.run(&["login", "--server", &server.url(), "--key-stdin"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("not a valid API key"), "{}", out.stderr);
    assert!(
        !out.stderr.contains(&secret_part(&cli.key)),
        "the key was echoed: {}",
        out.stderr
    );
    assert!(server.requests().is_empty());
    assert!(!cli.config_dir().join("credentials.toml").exists());
}

#[test]
fn login_stores_nothing_when_the_server_rejects_the_key() {
    let cli = Cli::new();
    let server = MockServer::start(|_| MockResponse::problem(401, "unauthorized", "invalid credentials"));
    let key_line = format!("{}\n", cli.key.expose());
    let cli = cli.with_stdin(&key_line);
    let out = cli.run(&["login", "--server", &server.url(), "--key-stdin"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("unauthorized"), "{}", out.stderr);
    assert!(!out.stderr.contains(&secret_part(&cli.key)));
    assert!(!cli.config_dir().join("credentials.toml").exists());
}

#[test]
fn login_without_a_terminal_needs_key_stdin() {
    let cli = Cli::new();
    let out = cli.run(&["login", "--server", "https://p2pc.example.invalid"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("--key-stdin"), "{}", out.stderr);
}

#[test]
fn login_refuses_a_malformed_server_address() {
    let cli = Cli::new().with_stdin(&format!("{}\n", ApiKey::generate().expose()));
    let out = cli.run(&["login", "--server", "p2pc_srv_MFRGGZDFMZTWQ2LK", "--key-stdin"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("not a valid server address"), "{}", out.stderr);
    assert!(!cli.config_dir().join("credentials.toml").exists());
}

#[test]
fn a_command_without_login_says_how_to_log_in() {
    let out = Cli::new()
        .with_env("P2PC_SERVER", "https://p2pc.example.invalid")
        .run(&["jobs"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("p2pc login"), "{}", out.stderr);
}

#[test]
fn whoami_shows_the_keys_limits_only_as_the_server_reports_them() {
    // A capped agent key: the limits are shown, and the JSON has them too.
    let cli = Cli::new();
    let who = fixtures::whoami_capped(
        cli.key.key_id(),
        vec![Scope::JobsRead, Scope::JobsWrite],
        Units::from_units(5),
    );
    let body = json_of(&who);
    let server = MockServer::start(move |req| match req.route().as_str() {
        "GET /v1/whoami" => MockResponse::json(200, &body),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    });
    let cli = cli.with_server(&server);
    let out = cli.run(&["whoami"]);
    assert_eq!(out.code, 0, "{out:?}");
    for line in [
        "label:",
        "agent",
        "daily cap:",
        "5.000 units",
        "images:",
        "docker.io/library/python:*",
        "expires:",
        "never",
    ] {
        assert!(out.stdout.contains(line), "{line:?} not in {}", out.stdout);
    }
    let json_out = cli.run(&["whoami", "--json"]);
    let v: Value = serde_json::from_str(&json_out.stdout).unwrap();
    assert_eq!(v["daily_unit_cap"], 5000);

    // An unrestricted key says so, and has no label row.
    let cli = Cli::new();
    let (server, _) = whoami_server(&cli.key, vec![Scope::Admin]);
    let out = cli.with_server(&server).run(&["whoami"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stdout.contains("daily cap: none"), "{}", out.stdout);
    assert!(
        out.stdout.contains("images:") && out.stdout.contains("any"),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("label:"), "{}", out.stdout);
}

#[test]
fn the_server_flag_beats_the_environment() {
    let cli = Cli::new();
    let (server, _) = whoami_server(&cli.key, vec![Scope::Admin]);
    let cli = cli
        .with_server(&server)
        .with_env("P2PC_SERVER", "https://unused.example.invalid");
    // The flag points at the mock; the environment points nowhere. If the flag lost, this would fail on the network.
    let out = cli.run(&["--server", &server.url(), "whoami"]);
    assert_eq!(out.code, 0, "{out:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------------------------------------------

/// A server that accepts a job and then reports `final_job` for every poll.
fn job_server(created: Job, polled: Job) -> MockServer {
    let (created, polled) = (json_of(&created), json_of(&polled));
    MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &created),
        // The job wrote nothing: its live log is empty and ends at once.
        r if r.ends_with("/logs") => no_log_lines(),
        r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &polled),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

/// A log stream with no lines that the server ends at once.
fn no_log_lines() -> MockResponse {
    MockResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/x-ndjson".into())],
        body: Vec::new(),
    }
}

const RUN: [&str; 7] = ["run", "--image", "python:3.12-slim", "--cpu", "2", "--mem", "4G"];

fn run_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut args: Vec<&str> = RUN.to_vec();
    args.extend_from_slice(extra);
    args.extend(["--", "python", "-c", "print(6*7)"]);
    args
}

#[test]
fn run_detach_prints_only_the_job_id_on_stdout() {
    let id = JobId::generate();
    let server = job_server(
        fixtures::job(id, JobStatus::Queued, None),
        fixtures::job(id, JobStatus::Queued, None),
    );
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&run_args(&["-d"]));
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, format!("{id}\n"));
    assert_eq!(out.stderr, "");
    // It did not follow: one POST and no polling.
    assert_eq!(server.requests().len(), 1);
    let body = server.requests()[0].json();
    assert_eq!(body["image"], "python:3.12-slim");
    assert_eq!(body["command"], json!(["python", "-c", "print(6*7)"]));
    assert_eq!(body["resources"]["cpu"], 2.0);
    assert_eq!(body["resources"]["memory_mb"], 4096);
    assert_eq!(body["resources"]["gpu"], 0);
    assert_eq!(body["timeout_s"], 3600);
    assert_eq!(body["retry"]["max_attempts"], 2);
    assert_eq!(body["egress"]["allow"], json!([]));
}

#[test]
fn run_detach_with_json_prints_the_job() {
    let id = JobId::generate();
    let job = fixtures::job(id, JobStatus::Queued, None);
    let server = job_server(job.clone(), job.clone());
    let out = Cli::new().with_server(&server).run(&run_args(&["-d", "--json"]));
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(serde_json::from_str::<Value>(&out.stdout).unwrap(), json_of(&job));
}

/// (final state, the job's exit code, its error, the exit code of p2pc, text on stderr)
type Case = (JobStatus, Option<i32>, Option<&'static str>, u8, &'static str);

#[test]
fn run_follows_the_job_and_exits_with_its_outcome() {
    // (final state, exit code of the job, expected exit code of p2pc, text on stderr)
    let cases: [Case; 7] = [
        (JobStatus::Succeeded, Some(0), None, 0, "job succeeded"),
        (JobStatus::Failed, Some(3), None, 3, "job failed with exit code 3"),
        (
            JobStatus::Failed,
            None,
            Some("disk_limit"),
            125,
            "the job wrote more than its disk limit (",
        ),
        (
            JobStatus::Failed,
            None,
            Some("image_pull_failed"),
            125,
            "job failed before it started: image_pull_failed",
        ),
        (JobStatus::TimedOut, None, None, 124, "timed out"),
        (JobStatus::Lost, None, None, 75, "lost"),
        (JobStatus::Cancelled, None, None, 130, "cancelled"),
    ];
    for (status, exit_code, error, expected, text) in cases {
        let id = JobId::generate();
        let mut finished = fixtures::job(id, status, exit_code);
        finished.error = error.map(str::to_string);
        let server = job_server(fixtures::job(id, JobStatus::Queued, None), finished);
        let out = Cli::new().with_server(&server).run(&run_args(&[]));
        assert_eq!(out.code, expected, "{status}: {out:?}");
        // The job ID and the state changes go to stderr; stdout stays empty (this job wrote nothing).
        assert!(out.stderr.starts_with(&id.to_string()), "{status}: {}", out.stderr);
        assert!(
            out.stderr.contains(&format!("{id}: queued")),
            "{status}: {}",
            out.stderr
        );
        assert!(
            out.stderr.contains(&format!("{id}: {status}")),
            "{status}: {}",
            out.stderr
        );
        assert!(out.stderr.contains(text), "{status}: {}", out.stderr);
        assert_eq!(out.stdout, "", "{status}");
    }
}

#[test]
fn run_follow_with_json_prints_the_final_job_on_stdout() {
    let id = JobId::generate();
    let finished = fixtures::job(id, JobStatus::Failed, Some(3));
    let server = job_server(fixtures::job(id, JobStatus::Queued, None), finished.clone());
    let out = Cli::new().with_server(&server).run(&run_args(&["--json"]));
    assert_eq!(out.code, 3);
    assert_eq!(serde_json::from_str::<Value>(&out.stdout).unwrap(), json_of(&finished));
}

#[test]
fn ctrl_c_detaches_without_cancelling_and_exits_130() {
    let id = JobId::generate();
    let running = json_of(&fixtures::job(id, JobStatus::Running, None));
    // Ctrl-C arrives while the job is being followed: when the first poll reaches the server.
    let ctrl_c = Arc::new(tokio::sync::Notify::new());
    let server = {
        let ctrl_c = Arc::clone(&ctrl_c);
        MockServer::start(move |req| match req.route().as_str() {
            "POST /v1/jobs" => MockResponse::json(201, &running),
            r if r.ends_with("/logs") => {
                ctrl_c.notify_one();
                no_log_lines()
            }
            r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &running),
            _ => MockResponse::problem(404, "not_found", "no such route"),
        })
    };
    let out = Cli::new()
        .with_server(&server)
        .interrupted_on(ctrl_c)
        .run(&run_args(&[]));
    assert_eq!(out.code, 130, "{out:?}");
    assert!(
        out.stderr.contains(&format!("p2pc logs --follow {id}")),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains(&format!("p2pc cancel {id}")), "{}", out.stderr);
    assert!(
        server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty(),
        "Ctrl-C must not cancel"
    );
}

/// T11a review: Ctrl-C during the submission (here, while the server keeps answering 503 and the client retries) no
/// longer kills the process: it says what happened and how to get the job without a duplicate, and exits 130.
#[test]
fn ctrl_c_during_submission_prints_the_idempotency_key_and_exits_130() {
    let ctrl_c = Arc::new(tokio::sync::Notify::new());
    let server = {
        let ctrl_c = Arc::clone(&ctrl_c);
        MockServer::start(move |req| match req.route().as_str() {
            "POST /v1/jobs" => {
                ctrl_c.notify_one();
                MockResponse::problem(503, "unavailable", "try again")
            }
            _ => MockResponse::problem(404, "not_found", "no such route"),
        })
    };
    let out = Cli::new()
        .with_server(&server)
        .interrupted_on(ctrl_c)
        .run(&run_args(&["--idempotency-key", "my-key-1"]));
    assert_eq!(out.code, 130, "{out:?}");
    assert!(out.stderr.contains("interrupted while submitting"), "{}", out.stderr);
    assert!(out.stderr.contains("--idempotency-key my-key-1"), "{}", out.stderr);
    assert_eq!(server.requests_to("POST /v1/jobs").len(), 1, "no retry after Ctrl-C");
    // Without a key of the user's, the generated one is printed, and it is the one that was sent.
    let ctrl_c = Arc::new(tokio::sync::Notify::new());
    let server = {
        let ctrl_c = Arc::clone(&ctrl_c);
        MockServer::start(move |_| {
            ctrl_c.notify_one();
            MockResponse::problem(503, "unavailable", "try again")
        })
    };
    let out = Cli::new()
        .with_server(&server)
        .interrupted_on(ctrl_c)
        .run(&run_args(&[]));
    assert_eq!(out.code, 130, "{out:?}");
    let sent = server.requests()[0].header("idempotency-key").unwrap().to_string();
    assert!(
        out.stderr.contains(&format!("--idempotency-key {sent}")),
        "{}",
        out.stderr
    );
}

/// T11a review: a short outage while following no longer ends `p2pc run` with 125: it says "reconnecting…" once and
/// carries on to the job's own exit code.
#[test]
fn run_keeps_following_through_a_transient_failure() {
    let id = JobId::generate();
    let created = json_of(&fixtures::job(id, JobStatus::Running, None));
    let done = json_of(&fixtures::job(id, JobStatus::Succeeded, Some(0)));
    let polls = Arc::new(AtomicUsize::new(0));
    let server = {
        let polls = Arc::clone(&polls);
        MockServer::start(move |req| match req.route().as_str() {
            "POST /v1/jobs" => MockResponse::json(201, &created),
            r if r.ends_with("/logs") => no_log_lines(),
            // Four failures in a row: more than the client's own three retries.
            r if r.starts_with("GET /v1/jobs/") && polls.fetch_add(1, Ordering::SeqCst) < 4 => {
                MockResponse::text(502, "bad gateway")
            }
            r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &done),
            _ => MockResponse::problem(404, "not_found", "no such route"),
        })
    };
    let out = Cli::new().with_server(&server).run(&run_args(&[]));
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stderr.matches("reconnecting…").count(), 1, "{}", out.stderr);
}

#[test]
fn run_retries_a_503_with_the_same_idempotency_key() {
    let id = JobId::generate();
    let created = json_of(&fixtures::job(id, JobStatus::Queued, None));
    let calls = Arc::new(AtomicUsize::new(0));
    let server = {
        let calls = Arc::clone(&calls);
        MockServer::start(move |req| match req.route().as_str() {
            "POST /v1/jobs" if calls.fetch_add(1, Ordering::SeqCst) == 0 => {
                MockResponse::problem(503, "unavailable", "try again")
            }
            "POST /v1/jobs" => MockResponse::json(201, &created),
            _ => MockResponse::problem(404, "not_found", "no such route"),
        })
    };
    let out = Cli::new().with_server(&server).run(&run_args(&["-d"]));
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, format!("{id}\n"));
    let posts = server.requests_to("POST /v1/jobs");
    assert_eq!(posts.len(), 2);
    let key = posts[0].header("idempotency-key").expect("a key is always sent");
    assert_eq!(posts[1].header("idempotency-key"), Some(key));
    assert_eq!(posts[0].json()["idempotency_key"], key);
    assert_eq!(posts[1].json()["idempotency_key"], key);
}

#[test]
fn run_uses_the_idempotency_key_the_user_gave() {
    let id = JobId::generate();
    let job = fixtures::job(id, JobStatus::Queued, None);
    let server = job_server(job.clone(), job);
    Cli::new()
        .with_server(&server)
        .run(&run_args(&["-d", "--idempotency-key", "nightly-2026-11-05"])); // gitleaks:allow
    assert_eq!(
        server.requests()[0].header("idempotency-key"),
        Some("nightly-2026-11-05")
    );
}

#[test]
fn a_problem_json_error_exits_125_and_shows_the_code_and_the_field_paths() {
    let server = MockServer::start(|_| {
        MockResponse::problem_with(
            422,
            "validation_failed",
            "The request is invalid",
            &json!([
                {"field": "resources.memory_mb", "code": "out_of_range", "message": "must be 128-1048576"},
                {"field": "egress.allow[0]", "code": "invalid_format", "message": "not a domain"},
            ]),
        )
    });
    let out = Cli::new().with_server(&server).run(&run_args(&["-d"]));
    assert_eq!(out.code, 125);
    for expected in [
        "validation_failed",
        "The request is invalid",
        "resources.memory_mb",
        "egress.allow[0]",
    ] {
        assert!(out.stderr.contains(expected), "{expected} in {}", out.stderr);
    }
    assert_eq!(out.stdout, "");
    // With --json the error is one JSON object on stderr.
    let json_out = Cli::new().with_server(&server).run(&run_args(&["-d", "--json"]));
    assert_eq!(json_out.code, 125);
    let v: Value = serde_json::from_str(json_out.stderr.trim()).unwrap();
    assert_eq!(v["error"]["code"], "validation_failed");
    assert_eq!(v["error"]["errors"][1]["field"], "egress.allow[0]");
}

#[test]
fn an_unauthorized_answer_hints_at_login_and_never_echoes_the_key() {
    let server = MockServer::start(|_| MockResponse::problem(401, "unauthorized", "invalid credentials"));
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&["jobs"]);
    assert_eq!(out.code, 125);
    assert!(
        out.stderr.contains("unauthorized") && out.stderr.contains("p2pc login"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains(&secret_part(&cli.key)) && !out.stdout.contains(&secret_part(&cli.key)));
}

#[test]
fn an_unreachable_server_is_a_network_error_with_exit_125() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cli = Cli::new()
        .with_env("P2PC_SERVER", &format!("http://127.0.0.1:{port}"))
        .with_env("P2PC_API_KEY", &ApiKey::generate().expose());
    let out = cli.run(&["jobs"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("network error"), "{}", out.stderr);
}

#[test]
fn local_validation_fails_before_any_request() {
    let server = MockServer::start(|_| MockResponse::problem(500, "unexpected", "must not be called"));
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&[
        "run",
        "-d",
        "--image",
        "python:3.12",
        "--cpu",
        "1000",
        "--mem",
        "64M",
        "--",
        "true",
    ]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("resources.cpu"), "{}", out.stderr);
    assert!(out.stderr.contains("resources.memory_mb"), "{}", out.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn run_sends_env_files_labels_egress_and_placement() {
    let id = JobId::generate();
    let job = fixtures::job(id, JobStatus::Queued, None);
    let server = job_server(job.clone(), job);
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data.csv");
    std::fs::write(&data, b"a,b\n1,2\n").unwrap();
    let env_file = dir.path().join("vars.env");
    std::fs::write(&env_file, "# comment\nFROM_FILE=file\nOVERRIDDEN=file\n").unwrap();
    let node = NodeId::generate();
    let cli = Cli::new().with_server(&server).with_env("FROM_ENV", "from-env");
    let out = cli.run(&[
        "run",
        "-d",
        "--image",
        "python:3.12",
        "--env-file",
        env_file.to_str().unwrap(),
        "--env",
        "OVERRIDDEN=flag",
        "--env",
        "FROM_ENV",
        "--env",
        "EMPTY=",
        "--file",
        data.to_str().unwrap(),
        "--file",
        &format!("{}:/inputs/in/renamed.csv", data.display()),
        "--egress",
        "pypi.org,Files.PythonHosted.org",
        "--timeout",
        "90s",
        "--name",
        "etl",
        "--node",
        &node.to_string(),
        "--label",
        "gpu=rtx",
        "--retries",
        "0",
        "--disk",
        "20G",
        "--gpu",
        "1",
        "--",
        "python",
        "main.py",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    let body = server.requests()[0].json();
    assert_eq!(
        body["env"],
        json!({"FROM_FILE": "file", "OVERRIDDEN": "flag", "FROM_ENV": "from-env", "EMPTY": ""})
    );
    assert_eq!(body["files"][0]["path"], "/inputs/data.csv");
    assert_eq!(body["files"][0]["content_b64"], "YSxiCjEsMgo=");
    assert_eq!(body["files"][1]["path"], "/inputs/in/renamed.csv");
    assert_eq!(body["egress"]["allow"], json!(["pypi.org", "files.pythonhosted.org"]));
    assert_eq!(body["timeout_s"], 90);
    assert_eq!(body["name"], "etl");
    assert_eq!(body["placement"]["node_id"], node.to_string());
    assert_eq!(body["placement"]["labels"], json!({"gpu": "rtx"}));
    assert_eq!(body["retry"]["max_attempts"], 1);
    assert_eq!(body["resources"]["disk_mb"], 20_480);
    assert_eq!(body["resources"]["gpu"], 1);
}

#[test]
fn an_env_name_that_is_not_set_is_an_error_before_any_request() {
    let server = MockServer::start(|_| MockResponse::problem(500, "unexpected", "must not be called"));
    let out = Cli::new().with_server(&server).run(&[
        "run",
        "-d",
        "--image",
        "python:3.12",
        "--env",
        "NOT_SET_ANYWHERE",
        "--",
        "true",
    ]);
    assert_eq!(out.code, 125);
    assert!(
        out.stderr.contains("NOT_SET_ANYWHERE") && out.stderr.contains("not set"),
        "{}",
        out.stderr
    );
    assert!(server.requests().is_empty());
}

#[test]
fn env_values_never_appear_in_output_or_errors() {
    let server = MockServer::start(|_| MockResponse::problem(500, "unexpected", "must not be called"));
    // An invalid name with a secret value: the message names the field, never the value.
    let out = Cli::new().with_server(&server).run(&[
        "run",
        "-d",
        "--image",
        "python:3.12",
        "--env",
        "bad-name=SUPERSECRETVALUE",
        "--",
        "true",
    ]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("env"), "{}", out.stderr);
    assert!(!out.stderr.contains("SUPERSECRETVALUE") && !out.stdout.contains("SUPERSECRETVALUE"));
}

#[test]
fn a_file_over_the_inline_limit_is_refused_before_it_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.bin");
    std::fs::write(&big, vec![0u8; 600 * 1024]).unwrap();
    let server = MockServer::start(|_| MockResponse::problem(500, "unexpected", "must not be called"));
    let out = Cli::new().with_server(&server).run(&[
        "run",
        "-d",
        "--image",
        "python:3.12",
        "--file",
        big.to_str().unwrap(),
        "--",
        "true",
    ]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("512 KiB"), "{}", out.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn estimate_prints_the_answer() {
    let server = MockServer::start(|req| match req.route().as_str() {
        "POST /v1/estimate" => MockResponse::json(
            200,
            &json!({"feasible": true, "matching_nodes": 2, "would_queue": false, "units_per_hour": 2000}),
        ),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    });
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&["estimate", "--image", "python:3.12", "--cpu", "2", "--", "true"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stdout.contains("feasible") && out.stdout.contains("yes"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("2.000"), "{}", out.stdout);
    let body = server.requests()[0].json();
    assert_eq!(body["resources"]["cpu"], 2.0);
    let json_out = cli.run(&["estimate", "--image", "python:3.12", "--json", "--", "true"]);
    assert_eq!(
        serde_json::from_str::<Value>(&json_out.stdout).unwrap()["matching_nodes"],
        2
    );
}

// ---------------------------------------------------------------------------------------------------------------
// jobs, status, cancel
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn jobs_all_walks_three_pages_and_prints_one_json_array() {
    let ids: Vec<JobId> = (0..5).map(|_| JobId::generate()).collect();
    let page = |range: std::ops::Range<usize>, next: Option<&str>| json!({"items": ids[range].iter().map(|id| json_of(&fixtures::job(*id, JobStatus::Running, None))).collect::<Vec<_>>(), "next_cursor": next});
    let pages = [page(0..2, Some("c1")), page(2..4, Some("c2")), page(4..5, None)];
    let server = MockServer::start(move |req| {
        let q = req.query.clone().unwrap_or_default();
        let index = if q.contains("cursor=c2") {
            2
        } else if q.contains("cursor=c1") {
            1
        } else {
            0
        };
        MockResponse::json(200, &pages[index])
    });
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&["jobs", "--all", "--json"]);
    assert_eq!(out.code, 0, "{out:?}");
    let jobs: Vec<Value> = serde_json::from_str(&out.stdout).unwrap();
    let got: Vec<&str> = jobs.iter().map(|j| j["id"].as_str().unwrap()).collect();
    assert_eq!(got, ids.iter().map(|i| i.to_string()).collect::<Vec<_>>());
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(
        requests
            .iter()
            .all(|r| r.query.as_deref().unwrap_or("").contains("limit=100"))
    );
}

#[test]
fn jobs_without_all_fetches_one_page_and_says_there_is_more() {
    let id = JobId::generate();
    let body = json!({"items": [json_of(&fixtures::job(id, JobStatus::Running, None))], "next_cursor": "more"});
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let out = Cli::new()
        .with_server(&server)
        .run(&["jobs", "--status", "running", "--limit", "5"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(server.requests().len(), 1);
    let q = server.requests()[0].query.clone().unwrap();
    assert!(q.contains("status=running") && q.contains("limit=5"), "{q}");
    assert!(
        out.stdout.contains(&id.to_string()) && out.stdout.contains("running"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.starts_with("ID"), "{}", out.stdout);
    assert!(out.stderr.contains("--all"), "{}", out.stderr);
}

#[test]
fn status_shows_the_job_and_exits_zero_whatever_its_state() {
    let id = JobId::generate();
    let failed = fixtures::job(id, JobStatus::Failed, Some(3));
    let body = json_of(&failed);
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&["status", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stdout.contains("failed") && out.stdout.contains("exit code:") && out.stdout.contains('3'),
        "{}",
        out.stdout
    );
    // Redacted env values never show.
    assert!(!out.stdout.contains("never-shown"));
    let json_out = cli.run(&["status", &id.to_string(), "--json"]);
    assert_eq!(
        serde_json::from_str::<Value>(&json_out.stdout).unwrap(),
        json_of(&failed)
    );
}

#[test]
fn status_of_a_job_that_hit_its_disk_limit_says_how_to_fix_it() {
    let id = JobId::generate();
    let mut job = fixtures::job(id, JobStatus::Failed, None);
    job.error = Some("disk_limit".into());
    let body = json_of(&job);
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let out = Cli::new().with_server(&server).run(&["status", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stdout.contains("the job wrote more than its disk limit (")
            && out.stdout.contains("run it again with `--disk <MiB>`"),
        "{}",
        out.stdout
    );
}

#[test]
fn cancel_posts_and_reports_the_state() {
    let id = JobId::generate();
    let body = json_of(&fixtures::job(id, JobStatus::Cancelled, None));
    let server = MockServer::start(move |req| {
        if req.route().ends_with("/cancel") {
            MockResponse::json(200, &body)
        } else {
            MockResponse::problem(404, "not_found", "x")
        }
    });
    let out = Cli::new().with_server(&server).run(&["cancel", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, format!("{id}: cancelled\n"));
    assert_eq!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).len(), 1);
}

#[test]
fn a_malformed_job_id_is_a_usage_error() {
    let out = Cli::new()
        .with_env("P2PC_SERVER", "https://p2pc.example.invalid")
        .run(&["status", "not-a-job"]);
    assert_eq!(out.code, 125);
}

// ---------------------------------------------------------------------------------------------------------------
// machines
// ---------------------------------------------------------------------------------------------------------------

fn machines_server(nodes: Vec<Node>) -> MockServer {
    MockServer::start(move |req| {
        let route = req.route();
        match route.as_str() {
            "GET /v1/nodes" => MockResponse::json(
                200,
                &json!({"items": nodes.iter().map(json_of).collect::<Vec<_>>(), "next_cursor": null}),
            ),
            r if r.starts_with("GET /v1/nodes/") => {
                let id = r.trim_start_matches("GET /v1/nodes/");
                nodes.iter().find(|n| n.id.to_string() == id).map_or_else(
                    || MockResponse::problem(404, "not_found", "no such node"),
                    |n| MockResponse::json(200, &json_of(n)),
                )
            }
            r if r.starts_with("POST /v1/nodes/") => {
                let id = r.split('/').nth(3).unwrap_or_default();
                let mut node = nodes
                    .iter()
                    .find(|n| n.id.to_string() == id)
                    .cloned()
                    .expect("known node");
                node.draining = r.ends_with("/drain");
                MockResponse::json(200, &json_of(&node))
            }
            r if r.starts_with("DELETE /v1/nodes/") => MockResponse::empty(204),
            _ => MockResponse::problem(404, "not_found", "no such route"),
        }
    })
}

#[test]
fn machines_lists_name_state_platform_and_capacity() {
    let (a, b) = (NodeId::generate(), NodeId::generate());
    let mut gpu_box = fixtures::node(b, "gpu-box");
    gpu_box.state = p2pc_proto::api::NodeState::Offline;
    gpu_box.draining = true;
    gpu_box.last_seen = None;
    let server = machines_server(vec![fixtures::node(a, "laptop"), gpu_box]);
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&["machines"]);
    assert_eq!(out.code, 0, "{out:?}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(
        lines[0].starts_with("NAME") && lines[0].contains("CPU FREE/OFFERED") && lines[0].contains("LAST SEEN"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains("laptop") && lines[1].contains("online") && lines[1].contains("linux"),
        "{}",
        lines[1]
    );
    assert!(
        lines[1].contains("3.5/4") && lines[1].contains("6 GiB/8 GiB") && lines[1].contains("0/0"),
        "{}",
        lines[1]
    );
    assert!(lines[1].contains("1m ago") || lines[1].contains("ago"), "{}", lines[1]);
    assert!(
        lines[2].contains("offline (draining)") && lines[2].contains("never"),
        "{}",
        lines[2]
    );
    let json_out = cli.run(&["machines", "--json"]);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&json_out.stdout).unwrap().len(), 2);
}

#[test]
fn machines_resolve_names_by_listing_and_ids_directly() {
    let (a, b) = (NodeId::generate(), NodeId::generate());
    let server = machines_server(vec![fixtures::node(a, "laptop"), fixtures::node(b, "gpu-box")]);
    let cli = Cli::new().with_server(&server);

    let by_name = cli.run(&["machines", "show", "GPU-Box"]);
    assert_eq!(by_name.code, 0, "{by_name:?}");
    assert!(
        by_name.stdout.contains(&b.to_string()) && by_name.stdout.contains("gpu-box"),
        "{}",
        by_name.stdout
    );
    assert_eq!(server.requests_to("GET /v1/nodes").len(), 1);

    let by_id = cli.run(&["machines", "show", &a.to_string()]);
    assert_eq!(by_id.code, 0, "{by_id:?}");
    assert!(by_id.stdout.contains("laptop"));
    assert_eq!(server.requests_to("GET /v1/nodes").len(), 1, "an ID needs no listing");
    assert_eq!(server.requests_to(&format!("GET /v1/nodes/{a}")).len(), 1);

    let missing = cli.run(&["machines", "show", "nope"]);
    assert_eq!(missing.code, 125);
    assert!(
        missing.stderr.contains("no machine is named \"nope\""),
        "{}",
        missing.stderr
    );
}

#[test]
fn an_ambiguous_machine_name_lists_the_candidates() {
    let (a, b) = (NodeId::generate(), NodeId::generate());
    let server = machines_server(vec![
        fixtures::node(a, "twin"),
        fixtures::node(b, "twin"),
        fixtures::node(NodeId::generate(), "other"),
    ]);
    let out = Cli::new().with_server(&server).run(&["machines", "drain", "twin"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("more than one machine"), "{}", out.stderr);
    assert!(
        out.stderr.contains(&a.to_string()) && out.stderr.contains(&b.to_string()),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("other"), "{}", out.stderr);
    assert!(
        server.requests_to(&format!("POST /v1/nodes/{a}/drain")).is_empty(),
        "nothing is drained"
    );
}

#[test]
fn drain_and_resume_call_the_endpoints() {
    let a = NodeId::generate();
    let server = machines_server(vec![fixtures::node(a, "laptop")]);
    let cli = Cli::new().with_server(&server);
    let drained = cli.run(&["machines", "drain", "laptop"]);
    assert_eq!(drained.code, 0, "{drained:?}");
    assert!(drained.stdout.contains("draining"));
    let resumed = cli.run(&["machines", "resume", &a.to_string(), "--json"]);
    assert_eq!(resumed.code, 0, "{resumed:?}");
    assert_eq!(
        serde_json::from_str::<Value>(&resumed.stdout).unwrap()["id"],
        a.to_string()
    );
    assert_eq!(server.requests_to(&format!("POST /v1/nodes/{a}/drain")).len(), 1);
    assert_eq!(server.requests_to(&format!("POST /v1/nodes/{a}/resume")).len(), 1);
}

#[test]
fn rm_without_yes_and_without_a_terminal_is_refused_before_any_request() {
    let a = NodeId::generate();
    let server = machines_server(vec![fixtures::node(a, "laptop")]);
    let out = Cli::new().with_server(&server).run(&["machines", "rm", "laptop"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("--yes"), "{}", out.stderr);
    assert!(server.requests().is_empty(), "no request, not even the listing");
}

#[test]
fn rm_with_yes_deletes() {
    let a = NodeId::generate();
    let server = machines_server(vec![fixtures::node(a, "laptop")]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["machines", "rm", "laptop", "--yes"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(server.requests_to(&format!("DELETE /v1/nodes/{a}")).len(), 1);
    assert!(out.stdout.contains("removed"), "{}", out.stdout);
}

#[test]
fn rm_asks_on_a_terminal_and_only_a_yes_deletes() {
    let a = NodeId::generate();
    let server = machines_server(vec![fixtures::node(a, "laptop")]);
    let no = Cli::new()
        .with_server(&server)
        .with_tty()
        .with_stdin("n\n")
        .run(&["machines", "rm", "laptop"]);
    assert_eq!(no.code, 130, "{no:?}");
    assert!(
        no.stderr.contains("[y/N]") && no.stderr.contains("Not removed"),
        "{}",
        no.stderr
    );
    assert!(server.requests_to(&format!("DELETE /v1/nodes/{a}")).is_empty());
    let yes = Cli::new()
        .with_server(&server)
        .with_tty()
        .with_stdin("y\n")
        .run(&["machines", "rm", "laptop"]);
    assert_eq!(yes.code, 0, "{yes:?}");
    assert_eq!(server.requests_to(&format!("DELETE /v1/nodes/{a}")).len(), 1);
}

// ---------------------------------------------------------------------------------------------------------------
// join tokens, keys, audit
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn join_token_create_prints_the_token_once_and_never_inside_a_command() {
    let token = JoinToken::generate("a".repeat(52), vec![], time::Duration::minutes(15), fixtures::t0()).unwrap();
    let encoded = token.encode().unwrap();
    let response = JoinTokenResponse::new(p2pc_proto::ids::JoinTokenId::generate(), token);
    assert_eq!(response.expires_at, fixtures::t0() + time::Duration::minutes(15));
    let body = json_of(&response);
    let server = MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/nodes/join-tokens" => MockResponse::json(201, &body),
        _ => MockResponse::problem(404, "not_found", "x"),
    });
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&["join-token", "create", "--expires", "15m", "--label", "spare-laptop"]);
    assert_eq!(out.code, 0, "{out:?}");
    // The token is printed once, on a line of its own; no command line carries it (it would end up in argv and in the
    // shell history of the new machine).
    assert_eq!(out.stdout.matches(encoded.as_str()).count(), 1, "{}", out.stdout);
    assert!(out.stdout.lines().any(|l| l.trim() == encoded), "{}", out.stdout);
    for line in out.stdout.lines().filter(|l| l.contains(encoded.as_str())) {
        assert!(!line.contains("p2pc-agent") && !line.contains("install"), "{line}");
    }
    for hint in [
        "sudo sh install-node.sh --from <dist dir>",
        r".\install.ps1 -Join",
        "p2pc-agent join",
    ] {
        assert!(out.stdout.contains(hint), "missing {hint:?} in {}", out.stdout);
    }
    assert!(!out.stdout.contains(&format!("p2pc-agent join {encoded}")));
    let sent = server.requests()[0].json();
    assert_eq!(sent, json!({"label": "spare-laptop", "ttl_s": 900}));
    // Too long is refused locally.
    let too_long = cli.run(&["join-token", "create", "--expires", "48h"]);
    assert_eq!(too_long.code, 125);
    assert!(too_long.stderr.contains("ttl_s"), "{}", too_long.stderr);
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn join_token_create_token_only_prints_just_the_token() {
    let token = JoinToken::generate("a".repeat(52), vec![], time::Duration::minutes(15), fixtures::t0()).unwrap();
    let encoded = token.encode().unwrap();
    let response = JoinTokenResponse::new(p2pc_proto::ids::JoinTokenId::generate(), token);
    let body = json_of(&response);
    let server = MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/nodes/join-tokens" => MockResponse::json(201, &body),
        _ => MockResponse::problem(404, "not_found", "x"),
    });
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&["join-token", "create", "--token-only"]);
    assert_eq!(out.code, 0, "{out:?}");
    // Exactly the token and a newline: it can be redirected into a file for `install-node.sh < token.txt`.
    assert_eq!(out.stdout, format!("{encoded}\n"));
    // It cannot be combined with --json (two different output formats).
    let both = cli.run(&["join-token", "create", "--token-only", "--json"]);
    assert_eq!(both.code, 125, "{both:?}");
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn join_token_list_and_revoke() {
    let (unused, used) = (JoinTokenId::generate(), JoinTokenId::generate());
    let info = |id: JoinTokenId, consumed: Option<NodeId>| JoinTokenInfo {
        id,
        label: Some("l".into()),
        created_by_key_id: KeyId::generate(),
        created_at: fixtures::t0(),
        expires_at: fixtures::t0() + time::Duration::hours(1),
        consumed_at: consumed.map(|_| fixtures::t0()),
        consumed_by_node_id: consumed,
        revoked_at: None,
    };
    let node = NodeId::generate();
    let page = Page {
        items: vec![info(unused, None), info(used, Some(node))],
        next_cursor: None,
    };
    let body = json_of(&page);
    let server = MockServer::start(move |req| match req.method.as_str() {
        "GET" => MockResponse::json(200, &body),
        "DELETE" => MockResponse::empty(204),
        _ => MockResponse::problem(404, "not_found", "x"),
    });
    let cli = Cli::new().with_server(&server);
    let list = cli.run(&["join-token", "list"]);
    assert_eq!(list.code, 0, "{list:?}");
    assert!(
        list.stdout.contains("unused") && list.stdout.contains("used") && list.stdout.contains(&node.to_string()),
        "{}",
        list.stdout
    );
    let revoke = cli.run(&["join-token", "revoke", &unused.to_string()]);
    assert_eq!(revoke.code, 0, "{revoke:?}");
    assert_eq!(
        server
            .requests_to(&format!("DELETE /v1/nodes/join-tokens/{unused}"))
            .len(),
        1
    );
}

fn new_key_response(request: &Value) -> (NewApiKey, ApiKey) {
    let key = ApiKey::generate();
    let info = ApiKeyInfo {
        id: key.key_id(),
        project_id: p2pc_proto::ids::ProjectId::generate(),
        label: request["label"].as_str().map(str::to_string),
        scopes: serde_json::from_value(request["scopes"].clone()).unwrap(),
        daily_unit_cap: serde_json::from_value(request["daily_unit_cap"].clone()).unwrap(),
        allowed_images: serde_json::from_value(request["allowed_images"].clone()).unwrap(),
        created_at: fixtures::t0(),
        expires_at: None,
        last_used_at: None,
        revoked_at: None,
    };
    (NewApiKey { key: key.clone(), info }, key)
}

#[test]
fn keys_create_prints_the_key_exactly_once_on_stdout_with_a_warning_on_stderr() {
    let issued = Arc::new(Mutex::new(None));
    let server = {
        let issued = Arc::clone(&issued);
        MockServer::start(move |req| match req.route().as_str() {
            "POST /v1/keys" => {
                let (resp, key) = new_key_response(&req.json());
                *issued.lock().unwrap() = Some(key);
                MockResponse::json(201, &json_of(&resp))
            }
            _ => MockResponse::problem(404, "not_found", "x"),
        })
    };
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&[
        "keys",
        "create",
        "--label",
        "ci",
        "--scope",
        "jobs:write",
        "--scope",
        "jobs:read",
        "--cap",
        "2.5",
        "--image",
        "docker.io/library/python:*",
        "--image",
        "ghcr.io/me/*",
        "--expires",
        "30d",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    let key = issued.lock().unwrap().clone().expect("a key was issued");
    let text = key.expose();
    assert_eq!(out.stdout, format!("{text}\n"), "stdout is the key and nothing else");
    assert_eq!(out.stdout.matches(&text).count(), 1);
    assert!(
        !out.stderr.contains(&text) && !out.stderr.contains(&secret_part(&key)),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("only this once") && out.stderr.contains("Store"),
        "{}",
        out.stderr
    );
    // What was asked for.
    let sent = server.requests()[0].json();
    assert_eq!(sent["label"], "ci");
    assert_eq!(sent["scopes"], json!(["jobs:write", "jobs:read"]));
    assert_eq!(sent["daily_unit_cap"], 2500);
    assert_eq!(
        sent["allowed_images"],
        json!(["docker.io/library/python:*", "ghcr.io/me/*"])
    );
    assert_eq!(
        sent["expires_at"], "2023-12-14T22:15:00Z",
        "30 days after the clock of the run"
    );
    // --json includes the `key` field.
    let json_out = cli.run(&["keys", "create", "--label", "ci", "--scope", "jobs:read", "--json"]);
    let v: Value = serde_json::from_str(&json_out.stdout).unwrap();
    let key2 = issued.lock().unwrap().clone().unwrap().expose();
    assert_eq!(v["key"], key2.as_str());
    assert_eq!(json_out.stdout.matches(&key2).count(), 1);
    assert!(!json_out.stderr.contains(&key2));
}

#[test]
fn keys_create_validates_locally() {
    let server = MockServer::start(|_| MockResponse::problem(500, "unexpected", "must not be called"));
    let cli = Cli::new().with_server(&server);
    let out = cli.run(&[
        "keys",
        "create",
        "--label",
        "ci",
        "--scope",
        "jobs:read",
        "--image",
        "bad[pattern",
    ]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("allowed_images"), "{}", out.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn an_escalation_denied_answer_shows_its_code() {
    let server =
        MockServer::start(|_| MockResponse::problem(403, "escalation_denied", "the new key would have more power"));
    let out = Cli::new()
        .with_server(&server)
        .run(&["keys", "create", "--label", "x", "--scope", "admin"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("escalation_denied"), "{}", out.stderr);
}

#[test]
fn keys_list_and_revoke() {
    let (live, dead) = (KeyId::generate(), KeyId::generate());
    let mut revoked = fixtures::key_info(dead);
    revoked.revoked_at = Some(fixtures::t0());
    let page = Page {
        items: vec![fixtures::key_info(live), revoked],
        next_cursor: None,
    };
    let body = json_of(&page);
    let server = MockServer::start(move |req| match req.method.as_str() {
        "GET" => MockResponse::json(200, &body),
        "DELETE" => MockResponse::empty(204),
        _ => MockResponse::problem(404, "not_found", "x"),
    });
    let cli = Cli::new().with_server(&server);
    let list = cli.run(&["keys", "list"]);
    assert_eq!(list.code, 0, "{list:?}");
    assert!(
        list.stdout.contains(&live.to_string()) && list.stdout.contains("active") && list.stdout.contains("revoked"),
        "{}",
        list.stdout
    );
    let revoke = cli.run(&["keys", "revoke", &live.to_string()]);
    assert_eq!(revoke.code, 0, "{revoke:?}");
    assert_eq!(server.requests_to(&format!("DELETE /v1/keys/{live}")).len(), 1);
    let last_admin = MockServer::start(|_| MockResponse::problem(409, "last_admin_key", "the last admin key"));
    let out = Cli::new()
        .with_server(&last_admin)
        .run(&["keys", "revoke", &live.to_string()]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("last_admin_key"), "{}", out.stderr);
}

#[test]
fn audit_lists_events_and_walks_pages_with_all() {
    let pages = [
        json!({"items": [json_of(&fixtures::audit_event())], "next_cursor": "c1"}),
        json!({"items": [json_of(&fixtures::audit_event())], "next_cursor": null}),
    ];
    let server = MockServer::start(move |req| {
        let second = req.query.clone().unwrap_or_default().contains("cursor=c1");
        MockResponse::json(200, &pages[usize::from(second)])
    });
    let cli = Cli::new().with_server(&server);
    let one = cli.run(&["audit"]);
    assert_eq!(one.code, 0, "{one:?}");
    assert!(
        one.stdout.contains("key_created") && one.stdout.starts_with("TIME"),
        "{}",
        one.stdout
    );
    assert!(one.stderr.contains("--all"));
    let all = cli.run(&["audit", "--all", "--json"]);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&all.stdout).unwrap().len(), 2);
}

// ---------------------------------------------------------------------------------------------------------------
// completion and the commands that are not here yet
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn completion_prints_a_script_for_each_shell() {
    let cli = Cli::new();
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let out = cli.run(&["completion", shell]);
        assert_eq!(out.code, 0, "{shell}: {out:?}");
        assert!(out.stdout.contains("p2pc") && out.stdout.len() > 200, "{shell}");
    }
    assert_eq!(cli.run(&["completion", "tcsh"]).code, 125);
}

#[test]
fn usage_errors_exit_125_and_help_exits_zero() {
    let bad = Cli::new().run(&["run"]);
    assert_eq!(bad.code, 125);
    assert!(bad.stderr.contains("--image"), "{}", bad.stderr);
    let help = Cli::new().run(&["run", "--help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("--detach") && help.stdout.contains("--idempotency-key"));
    let version = Cli::new().run(&["--version"]);
    assert_eq!(version.code, 0);
    assert_eq!(version.stdout, format!("p2pc {}\n", env!("CARGO_PKG_VERSION")));
}

/// T11a review: `login` fixes a credentials file that others can read, as `docs/cli.md` says: it is replaced by a
/// private one holding the new key, with a warning, and its old content is not carried over.
#[cfg(unix)]
#[test]
fn login_replaces_a_credentials_file_that_others_can_read() {
    use std::os::unix::fs::PermissionsExt;
    let cli = Cli::new();
    let (server, _) = whoami_server(&cli.key, vec![Scope::JobsRead]);
    let path = cli.config_dir().join("credentials.toml");
    let old = ApiKey::generate();
    std::fs::write(&path, format!("[profiles.old]\napi_key = \"{}\"\n", old.expose())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    // Without login, the file is refused.
    let refused = Cli::new()
        .with_env("P2PC_CONFIG_DIR", &cli.config_dir().display().to_string())
        .with_env("P2PC_SERVER", &server.url())
        .run(&["whoami"]);
    assert_eq!(refused.code, 125);
    assert!(refused.stderr.contains("chmod 600"), "{}", refused.stderr);

    let key_line = format!("{}\n", cli.key.expose());
    let cli = cli.with_stdin(&key_line);
    let out = cli.run(&["login", "--server", &server.url(), "--key-stdin"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stderr.contains("warning:"), "{}", out.stderr);
    assert!(out.stderr.contains("readable by other users"), "{}", out.stderr);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains(&secret_part(&old)), "the old keys are not carried over");
    assert!(!text.contains("[profiles.old]"));
    assert!(!out.stderr.contains(&secret_part(&old)));
}
