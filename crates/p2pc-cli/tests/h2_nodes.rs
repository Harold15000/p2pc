// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc nodes` (H2 §7.8, §5.5): the approval column and `nodes approve`, in process against the mock server.

mod common;

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::{Node, NodeApproval};
use p2pc_proto::ids::NodeId;
use serde_json::{Value, json};

const PHRASE: &str = "amber bridge candle dune ember falcon";

fn pending(id: NodeId, name: &str) -> Node {
    let mut node = fixtures::node(id, name);
    node.approval = NodeApproval::PendingApproval;
    node.node_phrase = Some(PHRASE.into());
    node
}

fn server(nodes: Vec<Node>) -> MockServer {
    MockServer::start(move |req| {
        let route = req.route();
        match route.as_str() {
            "GET /v1/nodes" => MockResponse::json(
                200,
                &json!({"items": nodes.iter().map(|n| serde_json::to_value(n).unwrap()).collect::<Vec<_>>(), "next_cursor": null}),
            ),
            r if r.starts_with("GET /v1/nodes/") => {
                let id = r.trim_start_matches("GET /v1/nodes/");
                nodes.iter().find(|n| n.id.to_string() == id).map_or_else(
                    || MockResponse::problem(404, "not_found", "no such node"),
                    |n| MockResponse::json(200, &serde_json::to_value(n).unwrap()),
                )
            }
            r if r.starts_with("POST /v1/nodes/") && r.ends_with("/approve") => MockResponse::empty(204),
            _ => MockResponse::problem(404, "not_found", "no such route"),
        }
    })
}

fn approvals(server: &MockServer) -> usize {
    server
        .requests()
        .iter()
        .filter(|r| r.method == "POST" && r.path.ends_with("/approve"))
        .count()
}

#[test]
fn nodes_ls_shows_the_approval_of_each_node_and_machines_is_the_same_command() {
    let (a, b) = (NodeId::generate(), NodeId::generate());
    let server = server(vec![fixtures::node(a, "laptop"), pending(b, "new-pc")]);
    let cli = Cli::new().with_server(&server);
    for args in [&["nodes", "ls"][..], &["nodes"], &["machines"], &["machines", "ls"]] {
        let out = cli.run(args);
        assert_eq!(out.code, 0, "{args:?}: {out:?}");
        let lines: Vec<&str> = out.stdout.lines().collect();
        assert!(lines[0].contains("APPROVAL"), "{args:?}: {}", lines[0]);
        assert!(
            lines[1].contains("laptop") && lines[1].contains("approved") && !lines[1].contains("pending"),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].contains("new-pc") && lines[2].contains("pending_approval"),
            "{}",
            lines[2]
        );
    }
}

#[test]
fn nodes_show_tells_the_approval_and_the_phrase() {
    let id = NodeId::generate();
    let server = server(vec![pending(id, "new-pc")]);
    let out = Cli::new().with_server(&server).run(&["nodes", "show", "new-pc"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stdout.contains("pending_approval") && out.stdout.contains(PHRASE),
        "{}",
        out.stdout
    );
}

#[test]
fn approve_prints_the_phrase_asks_and_approves_on_yes() {
    let id = NodeId::generate();
    let server = server(vec![pending(id, "new-pc")]);
    let out = Cli::new()
        .with_server(&server)
        .with_tty()
        .with_stdin("y\n")
        .run(&["nodes", "approve", "new-pc"]);
    assert_eq!(out.code, 0, "{out:?}");
    // The phrase is what the owner compares with the joined PC's screen, so it is on the screen before the question.
    assert!(out.stderr.contains(PHRASE), "{}", out.stderr);
    assert!(
        out.stderr.contains("new-pc") && out.stderr.contains("[y/N]"),
        "{}",
        out.stderr
    );
    assert!(
        out.stdout.contains("approved") && out.stdout.contains(&id.to_string()),
        "{}",
        out.stdout
    );
    assert_eq!(approvals(&server), 1);
    assert_eq!(server.requests_to(&format!("POST /v1/nodes/{id}/approve")).len(), 1);
}

#[test]
fn approve_does_nothing_on_no_or_on_an_empty_answer() {
    let id = NodeId::generate();
    for answer in ["n\n", "\n", "yes please\n", ""] {
        let server = server(vec![pending(id, "new-pc")]);
        let out =
            Cli::new()
                .with_server(&server)
                .with_tty()
                .with_stdin(answer)
                .run(&["nodes", "approve", &id.to_string()]);
        assert_eq!(out.code, 130, "{answer:?}: {out:?}");
        assert!(out.stderr.contains("Not approved"), "{}", out.stderr);
        assert_eq!(approvals(&server), 0, "{answer:?}");
    }
}

#[test]
fn approve_yes_skips_the_question_but_still_prints_the_phrase() {
    let id = NodeId::generate();
    let server = server(vec![pending(id, "new-pc")]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["nodes", "approve", "new-pc", "--yes"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stderr.contains(PHRASE) && !out.stderr.contains("[y/N]"),
        "{}",
        out.stderr
    );
    assert_eq!(approvals(&server), 1);
}

#[test]
fn approve_without_a_terminal_or_yes_refuses_before_any_request() {
    let id = NodeId::generate();
    let server = server(vec![pending(id, "new-pc")]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["nodes", "approve", &id.to_string()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("--yes"), "{}", out.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn approving_an_approved_node_is_a_no_op() {
    let id = NodeId::generate();
    let server = server(vec![fixtures::node(id, "laptop")]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["nodes", "approve", &id.to_string(), "--yes"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stderr.contains("already approved"), "{}", out.stderr);
    assert_eq!(approvals(&server), 0);
}

#[test]
fn approve_refuses_a_pending_node_that_has_no_phrase_to_compare() {
    let id = NodeId::generate();
    let mut node = pending(id, "new-pc");
    node.node_phrase = None;
    let server = server(vec![node]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["nodes", "approve", &id.to_string(), "--yes"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("phrase"), "{}", out.stderr);
    assert_eq!(approvals(&server), 0);
}

#[test]
fn approve_shows_the_hubs_refusal_for_a_principal_that_is_not_admin() {
    let id = NodeId::generate();
    let node = serde_json::to_value(pending(id, "new-pc")).unwrap();
    let server = MockServer::start(move |req| {
        if req.method == "POST" {
            MockResponse::problem(403, "forbidden", "only an admin principal may approve a node")
        } else {
            MockResponse::json(200, &node)
        }
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["nodes", "approve", &id.to_string(), "--yes"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("only an admin principal"), "{}", out.stderr);
    assert!(!out.stdout.contains("approved"));
}

#[test]
fn a_node_name_from_the_server_cannot_inject_escape_sequences() {
    let id = NodeId::generate();
    let server = server(vec![pending(id, "evil\u{1b}[2Jpc")]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["nodes", "approve", &id.to_string(), "--yes"]);
    assert!(
        !out.stderr.contains('\u{1b}') && !out.stdout.contains('\u{1b}'),
        "{out:?}"
    );
}

#[test]
fn approve_with_json_prints_the_approved_id() {
    let id = NodeId::generate();
    let server = server(vec![pending(id, "new-pc")]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["nodes", "approve", &id.to_string(), "--yes", "--json"]);
    assert_eq!(out.code, 0, "{out:?}");
    let v: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["approved"], id.to_string());
}
