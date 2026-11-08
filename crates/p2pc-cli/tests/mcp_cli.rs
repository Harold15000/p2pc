// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc mcp` as a command: the start-up refusals (in process) and the real binary over stdio (a child process, with
//! its stdin and stdout piped). The REST server is a mock on `127.0.0.1:0`.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::{Page, Scope};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::NodeId;
use serde_json::{Value, json};

/// What `GET /v1/whoami` answers for a key with these scopes and this cap. `cap` of `Some(None)` is a `null` cap
/// (uncapped), `Some(Some(n))` a cap of `n` milli-units, and `None` **removes the four limit members** (`label`,
/// `daily_unit_cap`, `allowed_images`, `expires_at`): a server older than the cap fields. `p2pc mcp` tells "absent"
/// from `null` in the raw JSON, and the proto struct always serializes `null`, so the legacy case is built as JSON.
fn whoami_body(key: &ApiKey, scopes: Vec<Scope>, cap: Option<Option<u64>>) -> Value {
    match cap {
        None => fixtures::whoami_legacy(key.key_id(), scopes),
        Some(cap) => {
            let mut body = serde_json::to_value(fixtures::whoami(key.key_id(), scopes)).unwrap();
            body["daily_unit_cap"] = json!(cap);
            body["allowed_images"] = Value::Null;
            body
        }
    }
}

fn whoami_server(body: Value) -> MockServer {
    MockServer::start(move |req| match req.route().as_str() {
        "GET /v1/whoami" => MockResponse::json(200, &body),
        "GET /v1/nodes" => MockResponse::json(
            200,
            &serde_json::to_value(Page {
                items: vec![fixtures::node(NodeId::generate(), "workstation")],
                next_cursor: None,
            })
            .unwrap(),
        ),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

// ---------------------------------------------------------------------------------------------------------------
// The start-up refusals, in process: they happen before anything touches stdio
// ---------------------------------------------------------------------------------------------------------------

fn refused(scopes: Vec<Scope>, cap: Option<Option<u64>>, extra: &[&str]) -> (common::Out, MockServer) {
    let cli = Cli::new();
    let server = whoami_server(whoami_body(&cli.key, scopes, cap));
    let cli = cli.with_server(&server);
    let mut args = vec!["mcp"];
    args.extend_from_slice(extra);
    (cli.run(&args), server)
}

#[test]
fn an_admin_key_is_refused_with_a_clear_message_on_stderr_and_a_non_zero_exit() {
    let (out, server) = refused(vec![Scope::Admin, Scope::JobsWrite], Some(Some(5000)), &[]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stdout.is_empty(), "stdout carries the protocol only: {out:?}");
    for needle in [
        "refusing to start",
        "`admin`",
        "--allow-admin",
        "p2pc keys create --label agent",
    ] {
        assert!(out.stderr.contains(needle), "{needle} in {}", out.stderr);
    }
    assert_eq!(server.requests_to("GET /v1/whoami").len(), 1);
    assert_eq!(server.requests().len(), 1, "nothing but the whoami check");
}

#[test]
fn an_uncapped_key_is_refused() {
    let (out, _) = refused(vec![Scope::JobsWrite, Scope::JobsRead], Some(None), &[]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stdout.is_empty());
    assert!(out.stderr.contains("no daily unit cap"), "{}", out.stderr);
    assert!(out.stderr.contains("--allow-uncapped"), "{}", out.stderr);
}

#[test]
fn a_whoami_without_the_cap_fields_is_treated_as_an_unknown_cap_and_refused() {
    let (out, _) = refused(vec![Scope::JobsWrite, Scope::JobsRead], None, &[]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stdout.is_empty());
    assert!(out.stderr.contains("did not report"), "{}", out.stderr);
    assert!(out.stderr.contains("--allow-uncapped"), "{}", out.stderr);
}

#[test]
fn allow_admin_does_not_excuse_a_missing_cap_and_allow_uncapped_does_not_excuse_admin() {
    let (out, _) = refused(vec![Scope::Admin], Some(None), &["--allow-admin"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("no daily unit cap") && !out.stderr.contains("An agent must not hold admin"));
    let (out, _) = refused(vec![Scope::Admin], Some(None), &["--allow-uncapped"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("An agent must not hold admin"));
}

#[test]
fn a_key_the_server_rejects_stops_the_start_with_the_problem() {
    let cli = Cli::new();
    let server = MockServer::start(|_| MockResponse::problem(401, "unauthorized", "the key was rejected"));
    let out = cli.with_server(&server).run(&["mcp"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("unauthorized"), "{}", out.stderr);
    assert!(out.stdout.is_empty());
}

#[test]
fn without_a_key_or_a_server_it_does_not_start() {
    let out = Cli::new().run(&["mcp"]);
    assert_eq!(out.code, 125);
    assert!(out.stdout.is_empty());
}

#[test]
fn the_secret_never_appears_in_a_refusal() {
    let cli = Cli::new();
    let server = whoami_server(whoami_body(&cli.key, vec![Scope::Admin], Some(None)));
    let key = cli.key.expose();
    let secret = key.rsplit('_').next().unwrap().to_string();
    let out = cli.with_server(&server).run(&["mcp"]);
    assert!(
        !out.stderr.contains(&secret) && !out.stdout.contains(&secret),
        "{out:?}"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// The real binary over stdio
// ---------------------------------------------------------------------------------------------------------------

/// A running `p2pc mcp` with its pipes. Lines of stdout arrive on a channel, so that a hung server fails the test with
/// a timeout instead of hanging it.
struct Process {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
}

const GUARD: Duration = Duration::from_secs(20);

fn lines_of(reader: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

impl Process {
    fn spawn(server: &MockServer, key: &ApiKey, config_dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_p2pc"));
        command
            .arg("mcp")
            .args(args)
            .env_clear()
            .env("P2PC_CONFIG_DIR", config_dir)
            .env("HOME", config_dir)
            .env("P2PC_SERVER", server.url())
            .env("P2PC_API_KEY", key.expose())
            .env("RUST_BACKTRACE", "0")
            .current_dir(config_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            command.env(k, v);
        }
        let mut child = command.spawn().expect("spawn p2pc mcp");
        let stdin = child.stdin.take();
        let stdout = lines_of(child.stdout.take().unwrap());
        let stderr = lines_of(child.stderr.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{value}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next response with this ID. Every line read must be a JSON-RPC message: that is the point.
    fn response(&mut self, id: &Value) -> Value {
        loop {
            let line = self
                .stdout
                .recv_timeout(GUARD)
                .expect("a line on stdout (or the server hung or exited)");
            let message: Value =
                serde_json::from_str(&line).unwrap_or_else(|e| panic!("stdout must be protocol only: {e}: {line}"));
            assert_eq!(message["jsonrpc"], "2.0", "{line}");
            if message.get("id") == Some(id) && message.get("method").is_none() {
                return message;
            }
        }
    }

    fn handshake(&mut self) {
        self.send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": serde_json::to_value(rmcp::model::ProtocolVersion::default()).unwrap(),
            "capabilities": {}, "clientInfo": {"name": "binary-test", "version": "0"}}}));
        let reply = self.response(&json!(1));
        assert_eq!(reply["result"]["serverInfo"]["name"], "p2pc", "{reply}");
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    }

    /// Closes stdin (the client went away), waits for the exit and returns the code, all of stdout and all of stderr.
    fn finish(mut self) -> (Option<i32>, Vec<String>, String) {
        drop(self.stdin.take());
        let (tx, rx) = mpsc::channel();
        let mut child = self.child;
        std::thread::spawn(move || {
            let _ = tx.send(child.wait());
        });
        let status = rx
            .recv_timeout(GUARD)
            .expect("the server exits when stdin closes")
            .unwrap();
        let rest: Vec<String> = self.stdout.try_iter().collect();
        let stderr: Vec<String> =
            std::iter::from_fn(|| self.stderr.recv_timeout(Duration::from_secs(5)).ok()).collect();
        (status.code(), rest, stderr.join("\n"))
    }
}

#[test]
fn the_binary_serves_mcp_on_stdout_only_and_exits_cleanly_when_stdin_closes() {
    let dir = tempfile::tempdir().unwrap();
    let key = ApiKey::generate();
    let server = whoami_server(whoami_body(
        &key,
        vec![Scope::JobsWrite, Scope::JobsRead, Scope::NodesRead],
        Some(Some(5000)),
    ));
    let mut p = Process::spawn(&server, &key, dir.path(), &[], &[]);
    p.handshake();

    p.send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let tools = p.response(&json!(2));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 7, "{names:?}");
    assert!(names.contains(&"p2pc_run") && names.contains(&"p2pc_machines"));

    // A real tool call, through the binary, to the mock REST server.
    p.send(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "p2pc_machines", "arguments": {}}}));
    let machines = p.response(&json!(3));
    assert_eq!(machines["result"]["isError"], false, "{machines}");
    assert_eq!(
        machines["result"]["structuredContent"]["machines"][0]["name"],
        "workstation"
    );

    let (code, rest, stderr) = p.finish();
    assert_eq!(code, Some(0), "stderr: {stderr}");
    for line in rest {
        assert!(
            serde_json::from_str::<Value>(&line).is_ok(),
            "stdout must be protocol only: {line}"
        );
    }
    // The key authenticated the check and the call, and it is nowhere in what the process printed.
    let calls = server.requests_to("GET /v1/whoami");
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].header("authorization"),
        Some(format!("Bearer {}", key.expose()).as_str())
    );
    assert!(!stderr.contains(&key.expose()), "{stderr}");
    assert!(!stderr.to_lowercase().contains("secret"), "{stderr}");
}

#[test]
fn the_binary_refuses_an_admin_key_and_prints_nothing_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let key = ApiKey::generate();
    let server = whoami_server(whoami_body(&key, vec![Scope::Admin], Some(Some(5000))));
    let p = Process::spawn(&server, &key, dir.path(), &[], &[]);
    let (code, stdout, stderr) = p.finish();
    assert_eq!(code, Some(125), "{stderr}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(
        stderr.contains("refusing to start") && stderr.contains("--allow-admin"),
        "{stderr}"
    );
    assert!(!stderr.contains(&key.expose()));
}

#[test]
fn allow_uncapped_serves_an_uncapped_key_with_a_warning_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let key = ApiKey::generate();
    let server = whoami_server(whoami_body(&key, vec![Scope::JobsWrite, Scope::JobsRead], Some(None)));
    let mut p = Process::spawn(&server, &key, dir.path(), &["--allow-uncapped"], &[]);
    p.handshake();
    let (code, _, stderr) = p.finish();
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("warning: --allow-uncapped"), "{stderr}");
}

#[test]
fn allow_admin_serves_an_admin_key_with_a_warning_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let key = ApiKey::generate();
    let server = whoami_server(whoami_body(&key, vec![Scope::Admin], Some(Some(5000))));
    let mut p = Process::spawn(&server, &key, dir.path(), &["--allow-admin"], &[]);
    p.handshake();
    let (code, _, stderr) = p.finish();
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("warning: --allow-admin"), "{stderr}");
}

#[test]
fn logs_go_to_stderr_and_never_hold_the_key_or_the_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let key = ApiKey::generate();
    let server = whoami_server(whoami_body(
        &key,
        vec![Scope::JobsWrite, Scope::JobsRead],
        Some(Some(5000)),
    ));
    let mut p = Process::spawn(&server, &key, dir.path(), &[], &[("P2PC_LOG", "trace")]);
    p.handshake();
    // A call whose arguments hold a recognisable env value (it fails local validation: no request is made).
    p.send(
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "p2pc_run",
        "arguments": {"image": "x", "command": ["true"], "cpu": 0.01, "env": {"API_TOKEN": "hunter2-canary"}}}}),
    );
    let reply = p.response(&json!(5));
    assert_eq!(reply["result"]["isError"], true);
    let (code, _, stderr) = p.finish();
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains("serving MCP over stdio"),
        "the log is on stderr: {stderr}"
    );
    assert!(stderr.contains("tool call"), "{stderr}");
    assert!(
        !stderr.contains("hunter2-canary"),
        "arguments are never logged: {stderr}"
    );
    assert!(!stderr.contains(&key.expose()) && !stderr.contains(key.expose().rsplit('_').next().unwrap()));
}
