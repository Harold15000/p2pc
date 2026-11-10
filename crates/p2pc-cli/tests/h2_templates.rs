// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc templates` (H2 §7.6, §7.8), in process against the mock server.

mod common;

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::JobStatus;
use p2pc_proto::ids::JobId;
use serde_json::{Value, json};

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn bundle() -> Value {
    json!({
        "bundle_version": 7,
        "templates": [
            {
                "id": "private-chat", "version": 2, "title": "Private AI chat",
                "description": "Chat with a model that runs on your PC", "kind": "service", "ui": "chat",
                "singleton": true, "requirements": {"gpu": "preferred"},
                "params": [
                    {"name": "model", "type": "enum", "values": ["small", "tiny"], "default": "small", "target": "pull"},
                    {"name": "idle_timeout_s", "type": "int", "min": 900, "max": 86400, "default": 3600,
                     "target": "field:service.idle_timeout_s"}
                ],
                "licenses": ["MIT"], "download_mb": 2500
            },
            {
                "id": "transcribe", "version": 1, "title": "Transcribe audio", "kind": "batch", "ui": "transcribe",
                "requirements": {"gpu": "preferred"},
                "params": [
                    {"name": "audio", "type": "blob", "target": "input:/inputs/audio"},
                    {"name": "diarize", "type": "bool", "default": false, "target": "env:DIARIZE"}
                ],
                "download_mb": 800
            }
        ],
        "bundle_error": null
    })
}

fn server(status: u16) -> MockServer {
    let bundle = bundle();
    MockServer::start(move |req| match req.route().as_str() {
        "GET /v1/templates" => MockResponse::json(200, &bundle),
        r if r.starts_with("POST /v1/templates/") => {
            let job = fixtures::job(JobId::generate(), JobStatus::Queued, None);
            MockResponse::json(status, &serde_json::to_value(job).unwrap())
        }
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

fn launches(server: &MockServer) -> Vec<Value> {
    server
        .requests()
        .iter()
        .filter(|r| r.method == "POST")
        .map(|r| r.json())
        .collect()
}

#[test]
fn templates_ls_shows_what_a_template_is_and_needs() {
    let out = Cli::new().with_server(&server(201)).run(&["templates", "ls"]);
    assert_eq!(out.code, 0, "{out:?}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(
        lines[0].starts_with("ID") && lines[0].contains("TITLE") && lines[0].contains("KIND"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains("private-chat")
            && lines[1].contains("Private AI chat")
            && lines[1].contains("service")
            && lines[1].contains("2.4 GiB"),
        "{}",
        lines[1]
    );
    assert!(
        lines[2].contains("transcribe") && lines[2].contains("batch"),
        "{}",
        lines[2]
    );
    assert!(out.stderr.is_empty(), "{}", out.stderr);
}

#[test]
fn templates_ls_json_is_what_the_hub_said() {
    let out = Cli::new().with_server(&server(201)).run(&["templates", "ls", "--json"]);
    let v: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["bundle_version"], 7);
    assert_eq!(v["templates"].as_array().unwrap().len(), 2);
}

#[test]
fn templates_ls_explains_a_hub_that_cannot_load_its_bundle() {
    let server = MockServer::start(|_| {
        MockResponse::json(
            200,
            &json!({"bundle_version": null, "templates": [], "bundle_error": "the bundle is below the high-water mark"}),
        )
    });
    let out = Cli::new().with_server(&server).run(&["templates", "ls"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stderr.contains("high-water mark"), "{}", out.stderr);
}

#[test]
fn launch_types_the_parameters_by_what_the_template_declares() {
    let server = server(201);
    let out = Cli::new().with_server(&server).run(&[
        "templates",
        "launch",
        "private-chat",
        "--param",
        "model=tiny",
        "--param",
        "idle_timeout_s=1800",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    let sent = launches(&server);
    assert_eq!(sent.len(), 1);
    // The int is a JSON number, the enum a string: the hub checks the types.
    assert_eq!(sent[0]["params"], json!({"model": "tiny", "idle_timeout_s": 1800}));
    assert!(server.requests()[1].route() == "POST /v1/templates/private-chat/launch");
    // The job's id, alone on stdout.
    assert!(
        out.stdout.trim().starts_with("job_") && out.stdout.trim().lines().count() == 1,
        "{}",
        out.stdout
    );
    assert!(out.stderr.contains("started"), "{}", out.stderr);
}

#[test]
fn launch_without_params_sends_none_and_lets_the_defaults_apply() {
    let server = server(201);
    let out = Cli::new()
        .with_server(&server)
        .run(&["templates", "launch", "private-chat"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(launches(&server)[0]["params"], json!({}));
}

#[test]
fn launch_takes_booleans_and_blob_digests() {
    let server = server(201);
    let out = Cli::new().with_server(&server).run(&[
        "templates",
        "launch",
        "transcribe",
        "--param",
        "diarize=true",
        "--param",
        &format!("audio={DIGEST}"),
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(
        launches(&server)[0]["params"],
        json!({"diarize": true, "audio": DIGEST})
    );
    // A bare digest is written the way a job spec writes it.
    let server = self::server(201);
    let bare = &DIGEST["sha256:".len()..];
    let out = Cli::new().with_server(&server).run(&[
        "templates",
        "launch",
        "transcribe",
        "--param",
        &format!("audio={bare}"),
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(launches(&server)[0]["params"]["audio"], DIGEST);
}

#[test]
fn launch_says_when_a_singleton_was_already_running() {
    let out = Cli::new()
        .with_server(&server(200))
        .run(&["templates", "launch", "private-chat"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stderr.contains("already running"), "{}", out.stderr);
    assert!(out.stdout.trim().starts_with("job_"));
}

#[test]
fn launch_json_prints_the_job() {
    let out = Cli::new()
        .with_server(&server(201))
        .run(&["templates", "launch", "private-chat", "--json"]);
    let v: Value = serde_json::from_str(&out.stdout).unwrap();
    assert!(v["id"].as_str().unwrap().starts_with("job_"));
}

#[test]
fn launch_refuses_what_the_template_does_not_declare_before_launching() {
    let cases: [(&[&str], &str); 7] = [
        (&["nope"], "no template"),
        (&["private-chat", "--param", "color=red"], "color"),
        (&["private-chat", "--param", "idle_timeout_s=soon"], "idle_timeout_s"),
        (&["private-chat", "--param", "model"], "k=v"),
        (&["private-chat", "--param", "=x"], "k=v"),
        (&["private-chat", "--param", "model=a", "--param", "model=b"], "twice"),
        (&["transcribe", "--param", "diarize=maybe"], "diarize"),
    ];
    for (args, needle) in cases {
        let server = server(201);
        let mut argv = vec!["templates", "launch"];
        argv.extend_from_slice(args);
        let out = Cli::new().with_server(&server).run(&argv);
        assert_eq!(out.code, 125, "{args:?}: {out:?}");
        assert!(out.stderr.contains(needle), "{args:?}: {}", out.stderr);
        assert!(launches(&server).is_empty(), "{args:?}: nothing was launched");
    }
}

#[test]
fn launch_leaves_values_the_template_may_bound_to_the_hub() {
    // Bounds and enum membership belong to the hub (422 invalid_params); the CLI only types the value.
    let server = MockServer::start(|req| {
        if req.method == "GET" {
            MockResponse::json(200, &bundle())
        } else {
            MockResponse::problem(422, "invalid_params", "idle_timeout_s must be between 900 and 86400")
        }
    });
    let out = Cli::new().with_server(&server).run(&[
        "templates",
        "launch",
        "private-chat",
        "--param",
        "idle_timeout_s=5",
        "--param",
        "model=huge",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("between 900 and 86400"), "{}", out.stderr);
}

#[test]
fn launch_shows_the_running_instance_a_singleton_conflict_names() {
    let server = MockServer::start(|req| {
        if req.method == "GET" {
            MockResponse::json(200, &bundle())
        } else {
            MockResponse::problem(409, "singleton_running", "job_x is running with the model small")
        }
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["templates", "launch", "private-chat", "--param", "model=tiny"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(
        out.stderr.contains("job_x is running with the model small"),
        "{}",
        out.stderr
    );
}

#[test]
fn launch_by_a_capped_principal_shows_the_cap_message() {
    let server = MockServer::start(|req| {
        if req.method == "GET" {
            MockResponse::json(200, &bundle())
        } else {
            MockResponse::problem(402, "cap_exceeded", "Your daily limit does not allow private-chat")
        }
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["templates", "launch", "private-chat"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("daily limit"), "{}", out.stderr);
}

#[test]
fn a_hub_without_a_bundle_cannot_launch() {
    let server = MockServer::start(|_| MockResponse::json(200, &json!({"templates": [], "bundle_error": "no bundle"})));
    let out = Cli::new()
        .with_server(&server)
        .run(&["templates", "launch", "private-chat"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("no bundle"), "{}", out.stderr);
    assert_eq!(server.requests().len(), 1);
}
