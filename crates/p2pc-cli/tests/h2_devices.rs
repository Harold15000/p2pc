// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc devices` (H2 §5.2, §7.3, §7.8), in process against the mock server.

mod common;

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::{DeviceInfo, Principal, Scope};
use p2pc_proto::ids::{DeviceId, KeyId, PairingTicketId};
use serde_json::{Value, json};

const TICKET: &str = "p2pc_pair_FAKEFAKEFAKEFAKE"; // gitleaks:allow
const URL: &str = "https://app.example.invalid/pair#p2pc_pair_FAKEFAKEFAKEFAKE"; // gitleaks:allow

fn device(label: &str, scopes: Vec<Scope>) -> DeviceInfo {
    let mut d = DeviceInfo::new(
        DeviceId::generate(),
        "iOS Safari",
        scopes,
        fixtures::t0(),
        Principal::Key(KeyId::generate()),
    );
    d.label = Some(label.into());
    d
}

fn server(devices: Vec<DeviceInfo>) -> MockServer {
    let list = json!({"items": devices, "next_cursor": null});
    MockServer::start(move |req| match req.route().as_str() {
        "GET /v1/devices" => MockResponse::json(200, &list),
        "POST /v1/devices/pairing-tickets" => MockResponse::json(
            201,
            &json!({
                "id": PairingTicketId::generate(), "ticket": TICKET, "url": URL,
                "expires_at": "2023-11-14T22:23:20Z",
            }),
        ),
        r if r.starts_with("DELETE /v1/devices/") => MockResponse::empty(204),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

// ---------------------------------------------------------------------------------------------------------------
// ls and revoke
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn ls_shows_each_device_with_its_scopes_limits_and_state() {
    let mut phone = device("iPhone", vec![Scope::TemplatesLaunch, Scope::BlobsWrite]);
    phone.daily_unit_cap = Some(p2pc_proto::units::Units::from_milli(2_500));
    phone.last_seen_at = Some(fixtures::t0());
    let mut old = device("old tablet", vec![Scope::Admin]);
    old.revoked_at = Some(fixtures::t0());
    let mut lapsed = device("loaner", vec![Scope::JobsRead]);
    lapsed.expires_at = Some(fixtures::t0());
    let server = server(vec![phone.clone(), old, lapsed]);
    let out = Cli::new().with_server(&server).run(&["devices", "ls"]);
    assert_eq!(out.code, 0, "{out:?}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(
        lines[0].starts_with("ID")
            && lines[0].contains("LABEL")
            && lines[0].contains("SCOPES")
            && lines[0].contains("STATUS"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains(&phone.id.to_string())
            && lines[1].contains("iPhone")
            && lines[1].contains("iOS Safari")
            && lines[1].contains("templates:launch,blobs:write")
            && lines[1].contains("2.5")
            && lines[1].trim_end().ends_with("live"),
        "{}",
        lines[1]
    );
    assert!(
        lines[2].contains("old tablet") && lines[2].trim_end().ends_with("revoked"),
        "{}",
        lines[2]
    );
    assert!(
        lines[3].contains("loaner") && lines[3].trim_end().ends_with("expired"),
        "{}",
        lines[3]
    );
}

#[test]
fn ls_json_is_an_array() {
    let out = Cli::new()
        .with_server(&server(vec![device("a", vec![Scope::Admin])]))
        .run(&["devices", "ls", "--json"]);
    assert_eq!(serde_json::from_str::<Vec<Value>>(&out.stdout).unwrap().len(), 1);
}

#[test]
fn ls_with_no_devices_says_so() {
    let out = Cli::new().with_server(&server(vec![])).run(&["devices", "ls"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.is_empty() && out.stderr.contains("No devices"), "{out:?}");
}

#[test]
fn revoke_sends_the_delete_and_says_so() {
    let id = DeviceId::generate();
    let server = server(vec![]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["devices", "revoke", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(server.requests_to(&format!("DELETE /v1/devices/{id}")).len(), 1);
    assert!(out.stdout.contains(&id.to_string()));
    let json = Cli::new()
        .with_server(&server)
        .run(&["devices", "revoke", &id.to_string(), "--json"]);
    assert_eq!(
        serde_json::from_str::<Value>(&json.stdout).unwrap()["revoked"],
        id.to_string()
    );
}

#[test]
fn revoke_refuses_what_is_not_a_device_id() {
    let server = server(vec![]);
    for text in ["", "key_abc", "../keys", "dev_nope"] {
        let out = Cli::new().with_server(&server).run(&["devices", "revoke", text]);
        assert_eq!(out.code, 125, "{text:?}: {out:?}");
    }
    assert!(server.requests().is_empty());
}

#[test]
fn revoke_shows_the_hubs_refusals() {
    for (status, code, detail) in [
        (409, "last_admin_device", "this is the last admin device"),
        (403, "escalation_denied", "you could not have created this device"),
        (404, "not_found", "no such device"),
    ] {
        let server = MockServer::start(move |_| MockResponse::problem(status, code, detail));
        let out = Cli::new()
            .with_server(&server)
            .run(&["devices", "revoke", &DeviceId::generate().to_string()]);
        assert_eq!(out.code, 125, "{status}: {out:?}");
        assert!(out.stderr.contains(detail), "{status}: {}", out.stderr);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// pair
// ---------------------------------------------------------------------------------------------------------------

fn posted(server: &MockServer) -> Value {
    server.requests_to("POST /v1/devices/pairing-tickets")[0].json()
}

#[test]
fn pair_prints_the_url_once_as_the_only_thing_on_stdout() {
    let server = server(vec![]);
    let out = Cli::new().with_server(&server).run(&["devices", "pair"]);
    assert_eq!(out.code, 0, "{out:?}");
    // The secret is on stdout, alone, so that `url=$(p2pc devices pair)` works, and nowhere else.
    assert_eq!(out.stdout, format!("{URL}\n"));
    assert!(
        !out.stderr.contains("FAKEFAKE") && !out.stderr.contains(TICKET),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("once") && out.stderr.contains("2023-11-14"),
        "{}",
        out.stderr
    );
    // No flags: the body is empty, so the hub applies the phone profile.
    assert_eq!(posted(&server), json!({}));
}

#[test]
fn pair_passes_scopes_cap_and_images_on() {
    let server = server(vec![]);
    let out = Cli::new().with_server(&server).run(&[
        "devices",
        "pair",
        "--scopes",
        "templates:launch,jobs:read",
        "--scopes",
        "services:connect",
        "--cap",
        "2.5",
        "--image",
        "docker.io/library/python:*",
        "--image",
        "ghcr.io/example/*",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(
        posted(&server),
        json!({
            "scopes": ["templates:launch", "jobs:read", "services:connect"],
            "daily_unit_cap": 2500,
            "allowed_images": ["docker.io/library/python:*", "ghcr.io/example/*"],
        })
    );
}

#[test]
fn pair_accepts_every_scope_the_hub_knows_and_nothing_else() {
    for scope in ["admin", "nodes:invite", "nodes:join", "blobs:write", "templates:launch"] {
        let server = server(vec![]);
        let out = Cli::new()
            .with_server(&server)
            .run(&["devices", "pair", "--scopes", scope]);
        assert_eq!(out.code, 0, "{scope}: {out:?}");
    }
    let server = server(vec![]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["devices", "pair", "--scopes", "root"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(
        out.stderr.contains("templates:launch"),
        "the message lists the real scopes: {}",
        out.stderr
    );
    assert!(server.requests().is_empty());
}

#[test]
fn pair_refuses_what_the_hub_would_refuse_before_asking() {
    for args in [&["--image", ""][..], &["--scopes", "jobs:read,jobs:read"]] {
        let server = server(vec![]);
        let mut argv = vec!["devices", "pair"];
        argv.extend_from_slice(args);
        let out = Cli::new().with_server(&server).run(&argv);
        assert_eq!(out.code, 125, "{args:?}: {out:?}");
        assert!(server.requests().is_empty(), "{args:?}");
    }
}

#[test]
fn pair_on_a_terminal_draws_a_qr_code_of_the_url() {
    let server = server(vec![]);
    let out = Cli::new()
        .with_server(&server)
        .with_terminal_output()
        .run(&["devices", "pair"]);
    assert_eq!(out.code, 0, "{out:?}");
    let expected = qrcode::QrCode::new(URL.as_bytes())
        .unwrap()
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .build();
    let (url_line, qr) = out.stdout.split_once('\n').unwrap();
    assert_eq!(url_line, URL);
    assert_eq!(qr.trim_end(), expected.trim_end());
    assert!(qr.lines().count() > 10);
}

#[test]
fn pair_with_a_pipe_or_json_draws_no_qr_code() {
    let piped = Cli::new().with_server(&server(vec![])).run(&["devices", "pair"]);
    assert_eq!(piped.stdout.lines().count(), 1);
    let json = Cli::new()
        .with_server(&server(vec![]))
        .with_terminal_output()
        .run(&["devices", "pair", "--json"]);
    let v: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(v["url"], URL);
    assert_eq!(v["ticket"], TICKET);
}

#[test]
fn a_url_from_the_server_cannot_inject_escape_sequences_or_a_qr_of_something_else() {
    let server = MockServer::start(|_| {
        MockResponse::json(
            201,
            &json!({
                "id": PairingTicketId::generate(), "ticket": TICKET,
                "url": "https://app.example.invalid/pair#x\u{1b}[2J", "expires_at": "2023-11-14T22:23:20Z",
            }),
        )
    });
    let out = Cli::new()
        .with_server(&server)
        .with_terminal_output()
        .run(&["devices", "pair"]);
    assert!(
        !out.stdout.contains('\u{1b}') && !out.stderr.contains('\u{1b}'),
        "{out:?}"
    );
}

#[test]
fn pair_shows_the_hubs_refusals() {
    for (status, code, detail) in [
        (403, "escalation_denied", "the ticket asks for more than you may give"),
        (403, "forbidden", "only an admin may create a pairing ticket"),
        (422, "out_of_range", "expires_in_s is out of range"),
    ] {
        let server = MockServer::start(move |_| MockResponse::problem(status, code, detail));
        let out = Cli::new().with_server(&server).run(&["devices", "pair"]);
        assert_eq!(out.code, 125, "{status}: {out:?}");
        assert!(out.stderr.contains(detail), "{status}: {}", out.stderr);
        assert!(out.stdout.is_empty());
    }
}
