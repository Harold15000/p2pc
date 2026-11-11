// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc service` (H2 §7.4, §7.8), in process against the mock server.

mod common;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::{Job, JobStatus, ServiceHealth};
use p2pc_proto::ids::JobId;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IMAGE: &str = "docker.io/library/python:3.12-slim";

fn to_json(job: &Job) -> Value {
    serde_json::to_value(job).unwrap()
}

fn created(server: &MockServer) -> Value {
    server.requests_to("POST /v1/jobs")[0].json()
}

/// A hub that creates every job as a queued service and, for `GET /v1/jobs/{id}`, answers with `states` in order (the
/// last one forever).
fn run_server(states: Vec<Job>) -> MockServer {
    let next = AtomicUsize::new(0);
    MockServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/v1/jobs") => MockResponse::json(
            201,
            &to_json(&fixtures::service_job(states[0].id, JobStatus::Queued, None)),
        ),
        ("GET", p) if p.starts_with("/v1/jobs/") => {
            let i = next.fetch_add(1, Ordering::SeqCst).min(states.len() - 1);
            MockResponse::json(200, &to_json(&states[i]))
        }
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

fn svc(args: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = ["service", "run", "--image", IMAGE]
        .iter()
        .map(|s| s.to_string())
        .collect();
    argv.extend(args.iter().map(|s| s.to_string()));
    argv
}

fn run_service(server: &MockServer, args: &[&str]) -> common::Out {
    let argv = svc(args);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    Cli::new().with_server(server).run(&argv)
}

// ---------------------------------------------------------------------------------------------------------------
// service run
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn run_builds_a_service_spec_and_prints_only_the_job_id() {
    let job = fixtures::service_job(JobId::generate(), JobStatus::Queued, None);
    let server = run_server(vec![job.clone()]);
    let out = run_service(
        &server,
        &[
            "--port",
            "8080:web",
            "--port",
            "9090",
            "--health-http",
            "/healthz",
            "--idle",
            "30m",
            "--restart",
            "never",
            "--volume",
            "data:/volumes/data:2G",
            "--cpu",
            "2",
            "--mem",
            "4G",
            "--env",
            "MODE=prod",
            "--",
            "/bin/server",
            "--flag",
        ],
    );
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, format!("{}\n", job.id));
    let spec = created(&server);
    assert_eq!(spec["kind"], "service");
    assert_eq!(spec["image"], IMAGE);
    assert_eq!(spec["command"], json!(["/bin/server", "--flag"]));
    assert_eq!(spec["resources"]["cpu"], 2.0);
    assert_eq!(spec["resources"]["memory_mb"], 4096);
    assert_eq!(spec["env"]["MODE"], "prod");
    // A service has a finite limit like any job: the maximum, 30 days, unless asked otherwise (§7.1, §7.8).
    assert_eq!(spec["timeout_s"], 2_592_000);
    assert_eq!(spec["retry"]["max_attempts"], 3);
    let service = &spec["service"];
    assert_eq!(
        service["ports"],
        json!([{"port": 8080, "name": "web"}, {"port": 9090, "name": "port-9090"}])
    );
    assert_eq!(service["health"]["http_get"], "/healthz");
    // The check goes to the first port; the rest of the check takes the spec's own defaults.
    assert_eq!(service["health"]["port"], 8080);
    assert_eq!(service["health"]["interval_s"], 10);
    assert_eq!(service["idle_timeout_s"], 1800);
    assert_eq!(service["restart"], "never");
    assert_eq!(
        spec["volumes"],
        json!([{"name": "data", "mount": "/volumes/data", "max_mb": 2048}])
    );
    // Always an idempotency key, so a retried submission never starts a second service.
    assert!(
        server.requests_to("POST /v1/jobs")[0]
            .header("idempotency-key")
            .is_some()
    );
}

#[test]
fn run_with_only_a_port_takes_the_defaults_of_the_spec() {
    let server = run_server(vec![fixtures::service_job(JobId::generate(), JobStatus::Queued, None)]);
    let out = run_service(&server, &["--port", "8080", "--", "serve"]);
    assert_eq!(out.code, 0, "{out:?}");
    let spec = created(&server);
    assert_eq!(spec["service"]["idle_timeout_s"], 3600);
    assert_eq!(spec["service"]["restart"], "on_node_loss");
    assert!(spec["service"].get("health").is_none());
    assert!(spec.get("volumes").is_none());
}

#[test]
fn run_health_tcp_and_no_idle() {
    let server = run_server(vec![fixtures::service_job(JobId::generate(), JobStatus::Queued, None)]);
    let out = run_service(&server, &["--port", "80", "--health-tcp", "--no-idle", "--", "serve"]);
    assert_eq!(out.code, 0, "{out:?}");
    let service = &created(&server)["service"];
    assert_eq!(service["health"]["tcp"], true);
    assert_eq!(service["health"]["port"], 80);
    assert!(service["health"].get("http_get").is_none());
    assert_eq!(service["idle_timeout_s"], Value::Null);
}

#[test]
fn run_timeout_and_retries_override_the_defaults() {
    let server = run_server(vec![fixtures::service_job(JobId::generate(), JobStatus::Queued, None)]);
    let out = run_service(
        &server,
        &[
            "--port",
            "80",
            "--timeout",
            "2h",
            "--retries",
            "0",
            "--restart",
            "on-node-loss",
            "--",
            "serve",
        ],
    );
    assert_eq!(out.code, 0, "{out:?}");
    let spec = created(&server);
    assert_eq!(spec["timeout_s"], 7200);
    assert_eq!(spec["retry"]["max_attempts"], 1);
    assert_eq!(spec["service"]["restart"], "on_node_loss");
}

#[test]
fn run_a_volume_without_a_size_gets_one_gib() {
    let server = run_server(vec![fixtures::service_job(JobId::generate(), JobStatus::Queued, None)]);
    let out = run_service(
        &server,
        &["--port", "80", "--volume", "cache:/volumes/cache", "--", "serve"],
    );
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(created(&server)["volumes"][0]["max_mb"], 1024);
}

#[test]
fn run_refuses_what_the_spec_refuses_before_any_request() {
    let cases: [(&[&str], &str); 11] = [
        (&["--port", "0"], "port"),
        (&["--port", "70000"], "port"),
        (&["--port", "80:UPPER"], "name"),
        (&["--port", "80", "--port", "80"], "port"),
        (&["--port", "80", "--timeout", "10s"], "timeout_s"),
        (&["--port", "80", "--idle", "10s"], "idle_timeout_s"),
        (&["--port", "80", "--health-http", "relative"], "http_get"),
        (&["--port", "80", "--volume", "UPPER:/volumes/x"], "volumes"),
        (&["--port", "80", "--volume", "x:/etc/x"], "mount"),
        (&["--port", "80", "--volume", "x:/volumes/x:1K"], "max_mb"),
        (&["--port", "80", "--volume", "x"], "--volume"),
    ];
    for (args, needle) in cases {
        let server = run_server(vec![fixtures::service_job(JobId::generate(), JobStatus::Queued, None)]);
        let mut all: Vec<&str> = args.to_vec();
        all.extend(["--", "serve"]);
        let out = run_service(&server, &all);
        assert_eq!(out.code, 125, "{args:?}: {out:?}");
        assert!(out.stderr.contains(needle), "{args:?}: {}", out.stderr);
        assert!(server.requests().is_empty(), "{args:?}");
    }
}

#[test]
fn run_needs_a_port_and_refuses_contradictory_flags() {
    for args in [
        &["--", "serve"][..],
        &["--port", "80", "--health-http", "/h", "--health-tcp", "--", "serve"],
        &["--port", "80", "--idle", "1h", "--no-idle", "--", "serve"],
        &["--port", "80", "--restart", "sometimes", "--", "serve"],
    ] {
        let server = run_server(vec![fixtures::service_job(JobId::generate(), JobStatus::Queued, None)]);
        let out = run_service(&server, args);
        assert_eq!(out.code, 125, "{args:?}: {out:?}");
        assert!(server.requests().is_empty(), "{args:?}");
    }
}

#[test]
fn run_json_prints_the_job() {
    let server = run_server(vec![fixtures::service_job(JobId::generate(), JobStatus::Queued, None)]);
    let out = run_service(&server, &["--port", "80", "--json", "--", "serve"]);
    let v: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["spec"]["kind"], "service");
}

#[test]
fn run_wait_ready_waits_for_healthy_and_keeps_the_id_alone_on_stdout() {
    let id = JobId::generate();
    let server = run_server(vec![
        fixtures::service_job(id, JobStatus::Queued, None),
        fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Starting)),
        fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy)),
    ]);
    let out = run_service(&server, &["--port", "8080", "--wait-ready", "--", "serve"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, format!("{id}\n"));
    assert!(out.stderr.contains("healthy"), "{}", out.stderr);
    assert_eq!(server.requests_to(&format!("GET /v1/jobs/{id}")).len(), 3);
}

#[test]
fn run_wait_ready_reports_a_service_that_ended_first() {
    for (state, code) in [
        (
            fixtures::service_job(JobId::generate(), JobStatus::Cancelled, None),
            130,
        ),
        (fixtures::service_job(JobId::generate(), JobStatus::TimedOut, None), 124),
        (fixtures::service_job(JobId::generate(), JobStatus::Lost, None), 75),
        // Exited by itself before it was ever healthy: it did not become ready.
        (
            fixtures::service_job(JobId::generate(), JobStatus::Succeeded, None),
            125,
        ),
    ] {
        let server = run_server(vec![state.clone()]);
        let out = run_service(&server, &["--port", "8080", "--wait-ready", "--", "serve"]);
        assert_eq!(out.code, code, "{:?}: {out:?}", state.status);
        // The id was printed before waiting, so the user can still stop or inspect it.
        assert_eq!(out.stdout, format!("{}\n", state.id));
    }
    let mut failed = fixtures::service_job(JobId::generate(), JobStatus::Failed, None);
    failed.error = Some("health_check_failed".into());
    let server = run_server(vec![failed]);
    let out = run_service(&server, &["--port", "8080", "--wait-ready", "--", "serve"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("health_check_failed"), "{}", out.stderr);
}

#[test]
fn run_wait_ready_stops_waiting_on_ctrl_c_and_leaves_the_service_running() {
    let id = JobId::generate();
    let server = run_server(vec![fixtures::service_job(
        id,
        JobStatus::Running,
        Some(ServiceHealth::Starting),
    )]);
    let argv = svc(&["--port", "8080", "--wait-ready", "--", "serve"]);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (out, ()) = Cli::new()
        .with_server(&server)
        .run_alongside(&argv, async |mut lines, stop| {
            // Ctrl-C arrives once the command is waiting, not while it submits.
            loop {
                if lines.recv().await.unwrap().contains("waiting for") {
                    break;
                }
            }
            let _ = stop.ctrl_c.send(());
        });
    assert_eq!(out.code, 130, "{out:?}");
    assert!(
        out.stderr.contains(&id.to_string()) && out.stderr.contains("p2pc service stop"),
        "{}",
        out.stderr
    );
    assert!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// service list and stop
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn list_asks_for_services_only_and_shows_their_health_and_ports() {
    let healthy = fixtures::service_job(JobId::generate(), JobStatus::Running, Some(ServiceHealth::Healthy));
    let queued = fixtures::service_job(JobId::generate(), JobStatus::Queued, None);
    let items = json!({"items": [to_json(&healthy), to_json(&queued)], "next_cursor": null});
    let server = MockServer::start(move |_| MockResponse::json(200, &items));
    let out = Cli::new().with_server(&server).run(&["service", "list"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(server.requests()[0].query.as_deref().unwrap().contains("kind=service"));
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(
        lines[0].starts_with("ID") && lines[0].contains("HEALTH") && lines[0].contains("PORTS"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains(&healthy.id.to_string())
            && lines[1].contains("running")
            && lines[1].contains("healthy")
            && lines[1].contains("8080"),
        "{}",
        lines[1]
    );
    assert!(lines[2].contains("queued") && lines[2].contains(" - "), "{}", lines[2]);
    let json_out = Cli::new().with_server(&server).run(&["service", "list", "--json"]);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&json_out.stdout).unwrap().len(), 2);
}

#[test]
fn stop_is_cancel() {
    let id = JobId::generate();
    let job = fixtures::service_job(id, JobStatus::Cancelled, None);
    let server = MockServer::start(move |_| MockResponse::json(200, &to_json(&job)));
    let out = Cli::new()
        .with_server(&server)
        .run(&["service", "stop", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(server.requests()[0].route(), format!("POST /v1/jobs/{id}/cancel"));
    assert!(
        out.stdout.contains(&id.to_string()) && out.stdout.contains("cancelled"),
        "{}",
        out.stdout
    );
}

#[test]
fn status_shows_the_service_view() {
    let id = JobId::generate();
    let mut job = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    job.service.as_mut().unwrap().open_connections = 2;
    let server = MockServer::start(move |_| MockResponse::json(200, &to_json(&job)));
    let out = Cli::new().with_server(&server).run(&["status", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stdout.contains("service")
            && out.stdout.contains("healthy")
            && out.stdout.contains("8080")
            && out.stdout.contains("web"),
        "{}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------------------------------------------
// service connect
// ---------------------------------------------------------------------------------------------------------------

/// A hub whose job is `first` until `flip` is set, then `then`; every port connection is an echo.
fn connect_server(first: Job, then: Job, flip: std::sync::Arc<AtomicBool>) -> MockServer {
    MockServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", p) if p.starts_with("/v1/jobs/") => {
            let job = if flip.load(Ordering::SeqCst) { &then } else { &first };
            MockResponse::json(200, &to_json(job))
        }
        ("POST", p) if p.contains("/ports/") => MockResponse::upgrade_echo(),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

/// The address of the "listening on" line.
async fn listening(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
    loop {
        let line = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("the command said where it listens")
            .expect("the command is running");
        if let Some(rest) = line.split("listening on ").nth(1) {
            return rest.split_whitespace().next().unwrap().to_string();
        }
    }
}

#[test]
fn connect_forwards_each_local_connection_through_an_upgraded_port_connection() {
    let id = JobId::generate();
    let running = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    let ended = fixtures::service_job(id, JobStatus::Cancelled, None);
    let flip = std::sync::Arc::new(AtomicBool::new(false));
    let server = connect_server(running, ended, flip.clone());
    let cli = Cli::new().with_server(&server);
    let (out, ()) = cli.run_alongside(
        &[
            "service",
            "connect",
            &id.to_string(),
            "--port",
            "8080",
            "--listen",
            "127.0.0.1:0",
        ],
        async |mut lines, _stop| {
            let addr = listening(&mut lines).await;
            // Two connections, each its own upgraded connection to the hub, each echoing its own bytes.
            for message in [&b"first"[..], &b"second connection"[..]] {
                let mut tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
                tcp.write_all(message).await.unwrap();
                let mut back = vec![0u8; message.len()];
                tokio::time::timeout(std::time::Duration::from_secs(10), tcp.read_exact(&mut back))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(back, message);
            }
            // The service ends: the command exits by itself.
            flip.store(true, Ordering::SeqCst);
        },
    );
    // `cancelled` is how a stop ends a service: the command's work is done, not failed (§7.8).
    assert_eq!(out.code, 0, "{out:?}");
    let connects = server.requests_to(&format!("POST /v1/jobs/{id}/ports/8080/connect"));
    assert_eq!(connects.len(), 2);
    for c in &connects {
        assert_eq!(c.header("upgrade"), Some("p2pc-port/1"));
        assert!(c.header("authorization").is_some_and(|a| a.starts_with("Bearer ")));
        // A connection made as soon as the user's tool asks for it waits for a service that is still starting.
        assert_eq!(c.query.as_deref(), Some("wait_ready=true"));
    }
}

#[test]
fn connect_exits_with_the_code_of_how_the_service_ended() {
    let mut failed_with_code = fixtures::service_job(JobId::generate(), JobStatus::Failed, None);
    failed_with_code.exit_code = Some(3);
    let cases = [
        (fixtures::service_job(JobId::generate(), JobStatus::Cancelled, None), 0),
        (fixtures::service_job(JobId::generate(), JobStatus::Succeeded, None), 0),
        (fixtures::service_job(JobId::generate(), JobStatus::Lost, None), 75),
        (fixtures::service_job(JobId::generate(), JobStatus::TimedOut, None), 124),
        (failed_with_code, 3),
        (fixtures::service_job(JobId::generate(), JobStatus::Failed, None), 125),
    ];
    for (job, code) in cases {
        let (id, status) = (job.id, job.status);
        let server = MockServer::start(move |_| MockResponse::json(200, &to_json(&job)));
        let out = Cli::new().with_server(&server).run(&[
            "service",
            "connect",
            &id.to_string(),
            "--port",
            "8080",
            "--listen",
            "127.0.0.1:0",
        ]);
        assert_eq!(out.code, code, "{status:?}: {out:?}");
        // Already over: nothing was listened on and no connection was tried.
        assert!(
            server
                .requests_to(&format!("POST /v1/jobs/{id}/ports/8080/connect"))
                .is_empty()
        );
    }
}

#[test]
fn connect_exits_when_the_service_becomes_terminal_while_it_runs() {
    let id = JobId::generate();
    let running = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    let lost = fixtures::service_job(id, JobStatus::Lost, None);
    let flip = std::sync::Arc::new(AtomicBool::new(false));
    let server = connect_server(running, lost, flip.clone());
    let (out, ()) = Cli::new().with_server(&server).run_alongside(
        &[
            "service",
            "connect",
            &id.to_string(),
            "--port",
            "8080",
            "--listen",
            "127.0.0.1:0",
        ],
        async |mut lines, _stop| {
            let _ = listening(&mut lines).await;
            flip.store(true, Ordering::SeqCst);
        },
    );
    assert_eq!(out.code, 75, "{out:?}");
}

#[test]
fn connect_stops_with_130_on_ctrl_c_and_0_on_sigterm() {
    let id = JobId::generate();
    let running = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    for (code, term) in [(130, false), (0, true)] {
        let server = connect_server(
            running.clone(),
            running.clone(),
            std::sync::Arc::new(AtomicBool::new(false)),
        );
        let (out, ()) = Cli::new().with_server(&server).run_alongside(
            &[
                "service",
                "connect",
                &id.to_string(),
                "--port",
                "8080",
                "--listen",
                "127.0.0.1:0",
            ],
            async |mut lines, stop| {
                let _ = listening(&mut lines).await;
                let _ = if term {
                    stop.sigterm.send(())
                } else {
                    stop.ctrl_c.send(())
                };
            },
        );
        assert_eq!(out.code, code, "{out:?}");
    }
}

#[test]
fn connect_says_why_the_hub_refused_a_connection_and_keeps_running() {
    let id = JobId::generate();
    let running = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    let server = MockServer::start(move |req| {
        if req.method == "GET" {
            MockResponse::json(200, &to_json(&running))
        } else {
            MockResponse::problem(502, "node_unreachable", "the node did not answer")
        }
    });
    let (out, refused) = Cli::new().with_server(&server).run_alongside(
        &[
            "service",
            "connect",
            &id.to_string(),
            "--port",
            "8080",
            "--listen",
            "127.0.0.1:0",
        ],
        async |mut lines, stop| {
            let addr = listening(&mut lines).await;
            let mut tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
            // The local connection is closed: there is nothing behind it.
            let mut buf = Vec::new();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), tcp.read_to_end(&mut buf)).await;
            // The reason arrives as a line on stderr.
            let note = loop {
                let line = lines.recv().await.unwrap();
                if line.contains("node did not answer") {
                    break line;
                }
            };
            let _ = stop.ctrl_c.send(());
            note
        },
    );
    assert_eq!(out.code, 130, "{out:?}");
    assert!(
        refused.contains("node_unreachable") || refused.contains("did not answer"),
        "{refused}"
    );
}

#[test]
fn connect_refuses_a_job_that_is_not_a_service_or_a_port_it_does_not_expose() {
    let id = JobId::generate();
    let batch = fixtures::job(id, JobStatus::Running, None);
    let server = MockServer::start(move |_| MockResponse::json(200, &to_json(&batch)));
    let out = Cli::new().with_server(&server).run(&[
        "service",
        "connect",
        &id.to_string(),
        "--port",
        "8080",
        "--listen",
        "127.0.0.1:0",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("not a service"), "{}", out.stderr);

    let running = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    let server = MockServer::start(move |_| MockResponse::json(200, &to_json(&running)));
    let out = Cli::new().with_server(&server).run(&[
        "service",
        "connect",
        &id.to_string(),
        "--port",
        "9999",
        "--listen",
        "127.0.0.1:0",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(
        out.stderr.contains("9999") && out.stderr.contains("8080"),
        "{}",
        out.stderr
    );
}

#[test]
fn connect_listens_on_loopback_unless_told_otherwise() {
    let id = JobId::generate();
    let running = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    let server = MockServer::start(move |_| MockResponse::json(200, &to_json(&running)));
    let out = Cli::new().with_server(&server).run(&[
        "service",
        "connect",
        &id.to_string(),
        "--port",
        "8080",
        "--listen",
        "0.0.0.0:0",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("--allow-non-loopback"), "{}", out.stderr);
}

#[test]
fn connect_with_an_unknown_job_is_the_hubs_404() {
    let server = MockServer::start(|_| MockResponse::problem(404, "not_found", "no such job"));
    let out = Cli::new().with_server(&server).run(&[
        "service",
        "connect",
        &JobId::generate().to_string(),
        "--port",
        "8080",
        "--listen",
        "127.0.0.1:0",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("no such job"), "{}", out.stderr);
}

#[test]
fn connect_through_the_tunnel_reaches_the_same_service() {
    use p2pc_client::testing::MockTunnelServer;
    let id = JobId::generate();
    let running = fixtures::service_job(id, JobStatus::Running, Some(ServiceHealth::Healthy));
    let ended = fixtures::service_job(id, JobStatus::Cancelled, None);
    let flip = std::sync::Arc::new(AtomicBool::new(false));
    let seen = std::sync::Arc::new(Mutex::new(0usize));
    let (flip2, seen2) = (flip.clone(), seen.clone());
    let server = MockTunnelServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", p) if p.starts_with("/v1/jobs/") => MockResponse::json(
            200,
            &to_json(if flip2.load(Ordering::SeqCst) { &ended } else { &running }),
        ),
        ("POST", p) if p.contains("/ports/") => {
            *seen2.lock().unwrap() += 1;
            MockResponse::upgrade_echo()
        }
        _ => MockResponse::problem(404, "not_found", "no such route"),
    });
    let cli = Cli::new().with_tunnel_server(&server);
    let (out, ()) = cli.run_alongside(
        &[
            "service",
            "connect",
            &id.to_string(),
            "--port",
            "8080",
            "--listen",
            "127.0.0.1:0",
        ],
        async |mut lines, _stop| {
            let addr = listening(&mut lines).await;
            let mut tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
            tcp.write_all(b"through the tunnel").await.unwrap();
            let mut back = vec![0u8; 18];
            tokio::time::timeout(std::time::Duration::from_secs(10), tcp.read_exact(&mut back))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(back, b"through the tunnel");
            flip.store(true, Ordering::SeqCst);
        },
    );
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(*seen.lock().unwrap(), 1);
}
