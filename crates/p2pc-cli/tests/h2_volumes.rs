// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc volumes` (H2 §7.3, §7.8), in process against the mock server.

mod common;

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::VolumeInfo;
use p2pc_proto::ids::{JobId, NodeId};
use serde_json::{Value, json};

fn volume(node: NodeId, name: &str, in_use_by: Option<JobId>) -> VolumeInfo {
    VolumeInfo {
        name: name.into(),
        node_id: node,
        size_mb: 2_500,
        max_mb: 20_480,
        last_used_at: Some(fixtures::t0()),
        in_use_by,
    }
}

fn server(node: NodeId, volumes: Vec<VolumeInfo>) -> MockServer {
    let nodes = json!({"items": [serde_json::to_value(fixtures::node(node, "laptop")).unwrap()], "next_cursor": null});
    let volumes = json!({"items": volumes, "next_cursor": null});
    MockServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/volumes") => MockResponse::json(200, &volumes),
        ("GET", "/v1/nodes") => MockResponse::json(200, &nodes),
        ("DELETE", p) if p.starts_with("/v1/volumes/") => MockResponse::empty(204),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

fn deletes(server: &MockServer) -> Vec<String> {
    server
        .requests()
        .iter()
        .filter(|r| r.method == "DELETE")
        .map(|r| r.path.clone())
        .collect()
}

#[test]
fn volumes_ls_shows_name_node_size_and_holder() {
    let node = NodeId::generate();
    let job = JobId::generate();
    let server = server(
        node,
        vec![
            volume(node, "tpl:private-chat/models", Some(job)),
            volume(node, "scratch", None),
        ],
    );
    let out = Cli::new().with_server(&server).run(&["volumes", "ls"]);
    assert_eq!(out.code, 0, "{out:?}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(
        lines[0].starts_with("NAME") && lines[0].contains("NODE") && lines[0].contains("IN USE BY"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains("tpl:private-chat/models")
            && lines[1].contains(&node.to_string())
            && lines[1].contains(&job.to_string())
            && lines[1].contains("2.4 GiB")
            && lines[1].contains("20 GiB"),
        "{}",
        lines[1]
    );
    assert!(
        lines[2].contains("scratch") && lines[2].trim_end().ends_with('-'),
        "{}",
        lines[2]
    );
}

#[test]
fn volumes_ls_json_is_an_array_and_an_empty_list_says_so() {
    let node = NodeId::generate();
    let out = Cli::new()
        .with_server(&server(node, vec![volume(node, "scratch", None)]))
        .run(&["volumes", "ls", "--json"]);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&out.stdout).unwrap().len(), 1);
    let empty = Cli::new().with_server(&server(node, vec![])).run(&["volumes", "ls"]);
    assert_eq!(empty.code, 0);
    assert!(
        empty.stdout.is_empty() && empty.stderr.contains("No volumes"),
        "{empty:?}"
    );
}

#[test]
fn volumes_rm_sends_a_template_name_as_one_percent_encoded_segment() {
    let node = NodeId::generate();
    let server = server(node, vec![]);
    let out =
        Cli::new()
            .with_server(&server)
            .run(&["volumes", "rm", &node.to_string(), "tpl:private-chat/models", "--yes"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(
        deletes(&server),
        [format!("/v1/volumes/{node}/tpl%3Aprivate-chat%2Fmodels")]
    );
    assert!(out.stdout.contains("tpl:private-chat/models"), "{}", out.stdout);
}

#[test]
fn volumes_rm_finds_the_node_by_name_and_sends_a_plain_name_as_it_is() {
    let node = NodeId::generate();
    let server = server(node, vec![]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["volumes", "rm", "LAPTOP", "scratch.v1", "--yes"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(deletes(&server), [format!("/v1/volumes/{node}/scratch.v1")]);
}

#[test]
fn volumes_rm_asks_first_and_does_nothing_on_no() {
    let node = NodeId::generate();
    for (stdin, deleted) in [("y\n", 1), ("n\n", 0), ("", 0)] {
        let server = server(node, vec![]);
        let out = Cli::new().with_server(&server).with_tty().with_stdin(stdin).run(&[
            "volumes",
            "rm",
            &node.to_string(),
            "scratch",
        ]);
        assert!(
            out.stderr.contains("scratch") && out.stderr.contains("[y/N]"),
            "{}",
            out.stderr
        );
        assert_eq!(deletes(&server).len(), deleted, "{stdin:?}: {out:?}");
        assert_eq!(out.code, if deleted == 1 { 0 } else { 130 }, "{stdin:?}");
    }
}

#[test]
fn volumes_rm_without_a_terminal_or_yes_refuses_before_any_request() {
    let node = NodeId::generate();
    let server = server(node, vec![]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["volumes", "rm", &node.to_string(), "scratch"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("--yes"));
    assert!(server.requests().is_empty());
}

#[test]
fn volumes_rm_refuses_a_name_that_is_not_a_volume_name_before_any_request() {
    let node = NodeId::generate();
    for name in ["../keys", "UPPER", "tpl:x", "tpl:../a/b", "a b", ""] {
        let server = server(node, vec![]);
        let out = Cli::new()
            .with_server(&server)
            .run(&["volumes", "rm", &node.to_string(), name, "--yes"]);
        assert_eq!(out.code, 125, "{name:?}: {out:?}");
        assert!(out.stderr.contains("volume name"), "{name:?}: {}", out.stderr);
        assert!(server.requests().is_empty(), "{name:?}");
    }
}

#[test]
fn volumes_rm_shows_the_hubs_reason_for_a_busy_volume_and_an_offline_node() {
    let node = NodeId::generate();
    for (status, code, detail) in [
        (409, "volume_in_use", "the volume is in use by job_x"),
        (503, "node_offline", "the node is offline; nothing was queued"),
        (404, "not_found", "no such volume"),
    ] {
        let server = MockServer::start(move |_| MockResponse::problem(status, code, detail));
        let out = Cli::new()
            .with_server(&server)
            .run(&["volumes", "rm", &node.to_string(), "scratch", "--yes"]);
        assert_eq!(out.code, 125, "{status}: {out:?}");
        assert!(out.stderr.contains(detail), "{status}: {}", out.stderr);
        assert!(!out.stdout.contains("removed"));
    }
}

#[test]
fn volumes_rm_json_names_what_was_removed() {
    let node = NodeId::generate();
    let out = Cli::new().with_server(&server(node, vec![])).run(&[
        "volumes",
        "rm",
        &node.to_string(),
        "tpl:private-chat/models",
        "--yes",
        "--json",
    ]);
    let v: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["removed"], "tpl:private-chat/models");
    assert_eq!(v["node_id"], node.to_string());
}
