// SPDX-License-Identifier: AGPL-3.0-only

//! Service ports (H2 spec §5.5, §6.1, §6.3, §7.4, §12; SI-H2-4, SI-H2-5, SI-H2-6, SI-H2-18): the upgrade endpoint on
//! every transport, who reaches which service, the `allowed_routes` filter of template services, the hub-opened
//! `PortOpen` streams and their fencing, the connection limits, the idle limit, the idle accounting on the injected
//! clock and the traffic counters.
//!
//! The server runs as `serve` wires it; the node is a fake agent whose service records every byte that reaches it
//! (`common::ports`).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::ports::{Act, CHAT_PORT, Wire, World, eventually, plain_service, template_service};
use common::{DeviceLimits, Resp, assert_problem, second_account};
use iroh::SecretKey;
use p2pc_proto::api::{DEVELOPER_DEVICE_PROFILE, PHONE_PROFILE, Principal, Scope};
use p2pc_proto::ids::{DeviceId, JobId};
use p2pc_proto::protocol::ServerMsg;
use p2pc_server::auth::DeviceConnection;
use p2pc_server::clock::Clock;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;

/// A timestamp as the API writes it.
fn ts(t: OffsetDateTime) -> Value {
    json!(t.format(&Rfc3339).unwrap())
}

/// Who asks, in the in-process requests of the first test.
#[derive(Clone, Copy)]
enum As<'a> {
    Key(&'a str),
    Device(DeviceId),
}

/// One connect request served in-process: by the TCP router with an API key, or by the device router with the
/// device its transport attached. It never upgrades, which is all a refusal needs.
async fn ask(w: &World, who: As<'_>, job: &str, port: &str, query: &str, upgrade: bool) -> Resp {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/jobs/{job}/ports/{port}/connect{query}"));
    if upgrade {
        request = request.header("connection", "Upgrade").header("upgrade", "p2pc-port/1");
    }
    let app = w.app();
    match who {
        As::Key(key) => {
            let request = request.header("authorization", format!("Bearer {key}"));
            app.send(request.body(Body::empty()).unwrap()).await
        }
        As::Device(device_id) => {
            let mut request = request.body(Body::empty()).unwrap();
            request.extensions_mut().insert(DeviceConnection { device_id });
            app.send_on(p2pc_server::app::device_router(app.state.clone()), request)
                .await
        }
    }
}

/// SI-H2-5: opening a service port requires `services:connect` (or `templates:launch` for a template service of the
/// caller's template view), the job's account and project, a `running` service and a listed port. A job outside
/// the caller's view answers `404`, exactly as an unknown id, before anything about the job is said.
#[tokio::test]
async fn only_a_visible_running_service_with_a_listed_port_is_reachable() {
    let mut w = World::start().await;
    let owner = w.owner();
    let phone = w.app().add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let other = w.app().add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let developer = w
        .app()
        .add_device(&DEVELOPER_DEVICE_PROFILE, DeviceLimits::default())
        .await;
    let (chat, ..) = w.running(owner, template_service("private-chat")).await;
    let (dev_service, ..) = w.running(owner, plain_service()).await;
    let (others_notes, ..) = w.running(Principal::Device(other), template_service("notes")).await;
    let (own_notes, ..) = w.running(Principal::Device(phone), template_service("notes")).await;
    let starting = w.store_job(owner, plain_service()).await;
    w.node.start_next_unready(&w.fleet).await;
    // Stored after the last scheduler pass: they stay queued.
    let queued = w.store_job(owner, plain_service()).await;
    let batch = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256}});
    let batch = w.store_job(owner, batch).await;
    let admin = w.app().admin.clone();
    let port = CHAT_PORT.to_string();
    let unknown = JobId::generate().to_string();

    // A caller with neither scope gets `403`, whatever it asks for.
    let reader = w.app().key_with(&[Scope::JobsRead, Scope::NodesRead]).await;
    let r = ask(&w, As::Key(&reader), &chat.to_string(), &port, "", true).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = ask(&w, As::Key(&reader), &unknown, &port, "", true).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");

    // The phone profile: `404` on a `p2pc service run` service, on another device's non-singleton template service,
    // on a batch job and on an unknown id, with one and the same body; also when the port is not listed or the
    // request is no upgrade, so nothing about the job leaks.
    let not_found = ask(&w, As::Device(phone), &unknown, &port, "", true).await;
    assert_problem(&not_found, StatusCode::NOT_FOUND, "not_found");
    for hidden in [dev_service, others_notes, batch, queued] {
        for (port, upgrade) in [(port.as_str(), true), ("81", true), (port.as_str(), false)] {
            let r = ask(&w, As::Device(phone), &hidden.to_string(), port, "", upgrade).await;
            assert_eq!((r.status, &r.body), (not_found.status, &not_found.body), "{hidden}");
        }
    }
    // Another account's admin key: `404` too.
    let (stranger, _) = second_account(w.app()).await;
    let r = ask(&w, As::Key(&stranger), &chat.to_string(), &port, "", true).await;
    assert_eq!((r.status, &r.body), (not_found.status, &not_found.body));
    let r = ask(&w, As::Key(&admin), "not-a-job-id", &port, "", true).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");

    // A listed port: anything else is `422 port_not_exposed`, for a visible job.
    for (who, job) in [
        (As::Key(&admin), chat),
        (As::Device(phone), chat),
        (As::Key(&admin), dev_service),
    ] {
        for bad in ["81", "0", "65536", "+11434", "http", "11434x"] {
            let r = ask(&w, who, &job.to_string(), bad, "", true).await;
            assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "port_not_exposed");
        }
    }
    // A batch job exposes no port.
    let r = ask(&w, As::Key(&admin), &batch.to_string(), &port, "", true).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "port_not_exposed");

    // An upgrade to `p2pc-port/1`, and nothing else.
    for who in [As::Key(&admin), As::Device(phone)] {
        let r = ask(&w, who, &chat.to_string(), &port, "", false).await;
        assert_problem(&r, StatusCode::BAD_REQUEST, "upgrade_required");
    }
    let r = ask(&w, As::Key(&admin), &chat.to_string(), &port, "?wait=1", true).await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "invalid_query");

    // A running service: a queued one is `409 service_not_running`, a starting one `409 service_not_ready`.
    let r = ask(&w, As::Key(&admin), &queued.to_string(), &port, "", true).await;
    assert_problem(&r, StatusCode::CONFLICT, "service_not_running");
    let r = ask(&w, As::Key(&admin), &starting.to_string(), &port, "", true).await;
    assert_problem(&r, StatusCode::CONFLICT, "service_not_ready");

    // A template service is closed to a caller that is not `admin` wherever its template allows no route: a
    // template without `allowed_routes`, and a listed port no route names. `services:connect` does not change that.
    for (who, job, port) in [
        (As::Device(phone), own_notes, CHAT_PORT),
        (As::Device(phone), chat, 8080),
        (As::Device(developer), own_notes, CHAT_PORT),
        (As::Device(developer), others_notes, CHAT_PORT),
        (As::Device(developer), chat, 8080),
    ] {
        let r = ask(&w, who, &job.to_string(), &port.to_string(), "", true).await;
        assert_problem(&r, StatusCode::FORBIDDEN, "route_not_allowed");
    }
    // None of this opened anything on the node.
    assert!(w.node.service.opens().is_empty());
    assert_eq!(w.job(chat).await["service"]["open_connections"], 0);
}

/// H2 §7.4: `409 service_not_ready` while the health is `starting`; `?wait_ready=true` waits instead, and gives up
/// with the same `409` when the wait is over.
#[tokio::test]
async fn wait_ready_waits_for_a_starting_service() {
    let mut w = World::start().await;
    let admin = w.app().admin.clone();
    let job = w.store_job(w.owner(), plain_service()).await;
    let (lease, epoch) = w.node.start_next_unready(&w.fleet).await;
    let mut wire = Wire::tcp(w.rest).await;
    let r = wire.connect(job, CHAT_PORT, Some(&admin), "").await;
    assert_eq!((r.status, r.code().as_str()), (409, "service_not_ready"));
    let r = wire.connect(job, CHAT_PORT, Some(&admin), "?wait_ready=false").await;
    assert_eq!((r.status, r.code().as_str()), (409, "service_not_ready"));
    // The wait, shortened to one second: the answer comes when it is over, not before.
    let ports = &w.app().state.ports;
    let spec = ports.limits();
    ports.set_limits(p2pc_server::gateway::ports::PortLimits {
        ready_wait: Duration::seconds(1),
        ready_poll: StdDuration::from_millis(50),
        ..spec
    });
    let asked = Instant::now();
    let r = wire.connect(job, CHAT_PORT, Some(&admin), "?wait_ready=true").await;
    assert_eq!((r.status, r.code().as_str()), (409, "service_not_ready"));
    assert!(
        asked.elapsed() >= StdDuration::from_millis(900),
        "{:?}",
        asked.elapsed()
    );
    // With the spec's 30 s: the service becomes healthy while a connect waits, and the connect goes through.
    ports.set_limits(p2pc_server::gateway::ports::PortLimits {
        ready_poll: StdDuration::from_millis(50),
        ..spec
    });
    let request = format!(
        "POST /v1/jobs/{job}/ports/{CHAT_PORT}/connect?wait_ready=true HTTP/1.1\r\nHost: hub\r\n\
         Connection: Upgrade\r\nUpgrade: p2pc-port/1\r\nAuthorization: Bearer {admin}\r\n\r\n"
    );
    assert!(wire.send(request.as_bytes()).await);
    w.node
        .health(&w.fleet, lease, epoch, p2pc_proto::protocol::HealthState::Healthy)
        .await;
    let r = wire.answer().await.unwrap();
    assert_eq!(r.status, 101, "{}", r.head);
    assert!(wire.send(b"ready").await);
    assert_eq!(wire.exactly(5).await.unwrap(), b"ready");
}

/// H2 §7.4 "The same endpoint serves every client": an `admin` principal gets a raw, bidirectional byte stream, to
/// a template service too, over TCP, over `p2pc/http/1` and over `p2pc/device/1`. SI-H2-6: each `PortOpen` names the
/// job's current lease and epoch, and the port.
#[tokio::test]
async fn an_admin_gets_raw_bytes_on_every_transport() {
    let mut w = World::start().await;
    let admin = w.app().admin.clone();
    let (chat, lease, epoch) = w.running(w.owner(), template_service("private-chat")).await;
    let key = SecretKey::generate();
    w.add_device(&key, &[Scope::Admin], DeviceLimits::default()).await;
    let (device, tunnel) = (w.device(&key).await, w.tunnel().await);
    let wires = [
        (Wire::tcp(w.rest).await, Some(admin.as_str()), &b"over tcp"[..], true),
        (
            Wire::stream(&device).await,
            None,
            b"POST /api/pull HTTP/1.1\r\n\r\n",
            true,
        ),
        (
            Wire::stream(&tunnel).await,
            Some(admin.as_str()),
            b"over the tunnel",
            false,
        ),
    ];
    for (mut wire, auth, bytes, half_close) in wires {
        wire.upgraded(chat, CHAT_PORT, auth).await;
        // Both ways, in pieces: nothing is parsed, not even what looks like a request the filter would refuse.
        let (first, second) = bytes.split_at(3);
        assert!(wire.send(first).await);
        assert_eq!(wire.exactly(3).await.unwrap(), first);
        assert_eq!(w.job(chat).await["service"]["open_connections"], 1);
        assert!(wire.send(second).await);
        assert_eq!(wire.exactly(second.len()).await.unwrap(), second);
        if half_close {
            // A clean end travels on: the client ends its side, the service sees the end and ends its own.
            wire.finish().await;
            assert_eq!(wire.rest().await, (Vec::new(), true));
        } else {
            // H1's tunnel does not pass the end of a client's side on to the REST listener (`gateway::tunnel`): a
            // tunnel client ends its port connection by closing.
            drop(wire);
            tunnel.conn.close(0u32.into(), b"done");
        }
        let seen = w.node.seen().await;
        assert_eq!(seen.bytes, bytes);
        if half_close {
            assert!(seen.clean, "a clean end stays a clean end");
        }
        assert_eq!(
            (seen.open.lease_id, seen.open.epoch, seen.open.port),
            (lease, epoch, CHAT_PORT)
        );
    }
    let opens = w.node.service.opens();
    assert_eq!(opens.len(), 3);
    let mut ids: Vec<u64> = opens.iter().map(|open| open.conn_id).collect();
    ids.dedup();
    assert_eq!(ids.len(), 3, "each connection has its own conn_id");
    eventually("the connections are counted closed", || async {
        (w.job(chat).await["service"]["open_connections"] == 0).then_some(())
    })
    .await;
}

fn problem_of(answer: &common::ports::Answer) -> (u16, String) {
    assert!(
        answer
            .head
            .to_ascii_lowercase()
            .contains("content-type: application/problem+json"),
        "{}",
        answer.head
    );
    (answer.status, answer.code())
}

/// One request on a new, upgraded connection of `peer` to the chat port: the hub's own answer to it.
async fn refused(w: &World, peer: &common::h2::Peer, job: JobId, request: &[u8]) -> (u16, String) {
    let mut wire = Wire::stream(peer).await;
    wire.upgraded(job, CHAT_PORT, None).await;
    // The hub may answer, and stop reading, before it has taken all of an oversized request.
    let _ = wire.send(request).await;
    let answer = wire.answer().await.expect("the hub answers a refused request itself");
    let (rest, _) = wire.rest().await;
    assert!(rest.is_empty(), "the hub closes after its answer");
    assert!(
        w.node.service.opens().len() <= 2,
        "a refused request opens nothing on the node"
    );
    problem_of(&answer)
}

/// SI-H2-18: **the private chat's port is filtered by its `allowed_routes`**. Through a phone-profile device,
/// `POST /api/chat` (streamed) and `GET /api/tags` work, and the service receives the re-serialized request without
/// hop-by-hop headers and nothing after its body. Every other route, an allowed path with a query string or the wrong
/// method get `403 route_not_allowed`; oversized headers `431`, an oversized body `413`; ambiguous framing and the
/// smuggling attempt `400`. A refused request reaches nothing in the container: the hub does not even open a stream
/// to the node for it.
#[tokio::test]
async fn the_private_chat_port_is_filtered_by_its_allowed_routes() {
    let mut w = World::start().await;
    let (chat, lease, epoch) = w.running(w.owner(), template_service("private-chat")).await;
    let key = SecretKey::generate();
    w.add_device(&key, &PHONE_PROFILE, DeviceLimits::default()).await;
    let phone = w.device(&key).await;

    // `GET /api/tags`: forwarded, answered, and then the hub closes the connection.
    let tags =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"models\":[]}".to_vec();
    w.node.service.set(Act::Http {
        first: tags.clone(),
        second: Vec::new(),
        gate: None,
    });
    let mut wire = Wire::stream(&phone).await;
    wire.upgraded(chat, CHAT_PORT, None).await;
    assert!(wire.send(b"GET /api/tags HTTP/1.1\r\n\r\n").await);
    assert_eq!(wire.rest().await, (tags.clone(), true));
    let seen = w.node.seen().await;
    let forwarded_tags = b"GET /api/tags HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    assert_eq!(
        String::from_utf8_lossy(&seen.bytes),
        String::from_utf8_lossy(forwarded_tags)
    );
    assert!(seen.clean);
    assert_eq!(
        (seen.open.lease_id, seen.open.epoch, seen.open.port),
        (lease, epoch, CHAT_PORT)
    );

    // `POST /api/chat`, streamed: the first part of the answer reaches the phone while the service is still
    // answering. The request carries hop-by-hop headers, and a second request right behind its body.
    let body = r#"{"model":"m","stream":true}"#;
    let pipelined = "POST /api/pull HTTP/1.1\r\nHost: hub\r\nContent-Length: 2\r\n\r\n{}";
    let request = format!(
        "POST /api/chat HTTP/1.1\r\nhost: hub.example.invalid\r\nContent-Type: application/json\r\n\
         Connection: keep-alive, te\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\nProxy-Connection: keep-alive\r\n\
         X-Request-Id: 7\r\ncontent-length: {}\r\n\r\n{body}{pipelined}",
        body.len()
    );
    let forwarded_chat = format!(
        "POST /api/chat HTTP/1.1\r\nHost: hub.example.invalid\r\nContent-Type: application/json\r\n\
         X-Request-Id: 7\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let first = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n{\"message\":\"Hel\"}\n".to_vec();
    let second = b"{\"message\":\"lo\",\"done\":true}\n".to_vec();
    let gate = Arc::new(Semaphore::new(0));
    w.node.service.set(Act::Http {
        first: first.clone(),
        second: second.clone(),
        gate: Some(gate.clone()),
    });
    let mut wire = Wire::stream(&phone).await;
    wire.upgraded(chat, CHAT_PORT, None).await;
    assert!(wire.send(request.as_bytes()).await);
    assert_eq!(wire.exactly(first.len()).await.unwrap(), first);
    gate.add_permits(1);
    assert_eq!(wire.rest().await, (second.clone(), true));
    let seen = w.node.seen().await;
    // Exactly the request, written by the hub from its parsed form: no hop-by-hop field, `Content-Length` and
    // `Host` in the hub's own spelling, `Connection: close`, the body, and not one byte of what came after it.
    assert_eq!(String::from_utf8_lossy(&seen.bytes), forwarded_chat);
    assert!(seen.clean);

    // Everything else is refused by the hub itself.
    let digest = format!("sha256:{}", "0".repeat(64));
    let with_body = |line: &str| format!("{line} HTTP/1.1\r\nHost: hub\r\nContent-Length: 2\r\n\r\n{{}}");
    for line in [
        "POST /api/pull".to_string(),
        "POST /api/create".to_string(),
        format!("POST /api/blobs/{digest}"),
        format!("HEAD /api/blobs/{digest}"),
        "POST /api/copy".to_string(),
        "DELETE /api/delete".to_string(),
        "POST /api/push".to_string(),
        "GET /api/version".to_string(),
        "POST /api/chat?stream=1".to_string(),
        "GET /api/tags?x".to_string(),
        "GET /api/chat".to_string(),
        "POST /api/tags".to_string(),
        "POST /api/pull/../chat".to_string(),
        "POST /API/CHAT".to_string(),
    ] {
        let answer = refused(&w, &phone, chat, with_body(&line).as_bytes()).await;
        assert_eq!(answer, (403, "route_not_allowed".to_string()), "{line}");
    }
    let headers = |extra: &str| format!("POST /api/chat HTTP/1.1\r\nHost: hub\r\n{extra}\r\n{{}}");
    // Headers over 8 KiB, and more than 64 of them.
    let padded = headers(&format!("X-Pad: {}\r\nContent-Length: 2\r\n", "a".repeat(9000)));
    assert_eq!(
        refused(&w, &phone, chat, padded.as_bytes()).await,
        (431, "headers_too_large".to_string())
    );
    let many: String = (0..65).map(|i| format!("X-{i}: v\r\n")).collect();
    assert_eq!(
        refused(&w, &phone, chat, headers(&many).as_bytes()).await,
        (431, "headers_too_large".to_string())
    );
    // A body over 1 MiB: refused on its `Content-Length`, before any of it is read.
    assert_eq!(
        refused(&w, &phone, chat, headers("Content-Length: 1048577\r\n").as_bytes()).await,
        (413, "too_large".to_string())
    );
    // Ambiguous framing, malformed lines, and what the filter never forwards.
    let smuggled = "POST /api/pull HTTP/1.1\r\nHost: hub\r\nContent-Length: 2\r\n\r\n{}";
    for extra in [
        "Transfer-Encoding: chunked\r\n".to_string(),
        "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n".to_string(),
        "Content-Length: 2\r\nContent-Length: 2\r\n".to_string(),
        "Content-Length: two\r\n".to_string(),
        "Content-Length: 2, 2\r\n".to_string(),
        "X-A: 1\r\n folded\r\nContent-Length: 2\r\n".to_string(),
        "X-A : 1\r\nContent-Length: 2\r\n".to_string(),
        "NoColon\r\nContent-Length: 2\r\n".to_string(),
        "Upgrade: websocket\r\nContent-Length: 2\r\n".to_string(),
        "Expect: 100-continue\r\nContent-Length: 2\r\n".to_string(),
        // `Connection: content-length` on a `POST /api/chat` whose body holds a smuggled `POST /api/pull`.
        format!(
            "Connection: content-length\r\nContent-Length: {}\r\n\r\n{smuggled}",
            smuggled.len()
        ),
        "Connection: close, host\r\nContent-Length: 2\r\n".to_string(),
    ] {
        let answer = refused(&w, &phone, chat, headers(&extra).as_bytes()).await;
        assert_eq!(answer, (400, "invalid_request".to_string()), "{extra:?}");
    }
    for raw in [
        &b"POST /api/chat HTTP/1.1\nHost: hub\n\n"[..],
        b"POST /api/chat HTTP/1.1\r\nX-A: a\rb\r\n\r\n",
        b"CONNECT /api/chat HTTP/1.1\r\n\r\n",
        b"POST /api/chat HTTP/1.0\r\n\r\n",
    ] {
        let answer = refused(&w, &phone, chat, raw).await;
        assert_eq!(answer, (400, "invalid_request".to_string()), "{raw:?}");
    }
    // A body shorter than its `Content-Length`: the phone ends its side early, and nothing is forwarded.
    let mut wire = Wire::stream(&phone).await;
    wire.upgraded(chat, CHAT_PORT, None).await;
    assert!(wire.send(headers("Content-Length: 5\r\n").as_bytes()).await);
    wire.finish().await;
    assert_eq!(
        problem_of(&wire.answer().await.unwrap()),
        (400, "invalid_request".to_string())
    );

    // The fake service saw the two allowed requests and nothing else: no other stream was ever opened to it.
    assert_eq!(w.node.service.opens().len(), 2);
    // And the day's traffic counts exactly what was forwarded and relayed (H2 §12).
    let traffic = json!({
        "day": ts(common::T0.replace_time(time::Time::MIDNIGHT)),
        "bytes_in": forwarded_tags.len() + forwarded_chat.len(),
        "bytes_out": tags.len() + first.len() + second.len(),
        "connections": 2,
    });
    eventually("the traffic is recorded", || async {
        (w.job(chat).await["service"]["traffic"] == traffic).then_some(())
    })
    .await;
}

/// SI-H2-18: a developer-profile device (`services:connect`) on the chat's port is filtered too, and so is an API
/// key that is not `admin`, while both still get a raw connection to a `p2pc service run` service. SI-H2-5: over
/// its real transport, a phone-profile device gets `404` on that service.
#[tokio::test]
async fn services_connect_is_filtered_on_a_template_service_and_raw_elsewhere() {
    let mut w = World::start().await;
    let (chat, ..) = w.running(w.owner(), template_service("private-chat")).await;
    let (dev_service, dev_lease, dev_epoch) = w.running(w.owner(), plain_service()).await;
    let (dev_key, phone_key) = (SecretKey::generate(), SecretKey::generate());
    w.add_device(&dev_key, &DEVELOPER_DEVICE_PROFILE, DeviceLimits::default())
        .await;
    w.add_device(&phone_key, &PHONE_PROFILE, DeviceLimits::default()).await;
    let (developer, phone) = (w.device(&dev_key).await, w.device(&phone_key).await);
    let connector = w
        .app()
        .key_with(&[Scope::ServicesConnect, Scope::JobsRead, Scope::JobsWrite])
        .await;
    let pull = b"POST /api/pull HTTP/1.1\r\nHost: hub\r\nContent-Length: 2\r\n\r\n{}";

    // The developer device on the chat's port: `POST /api/pull` is refused, and nothing is opened.
    let mut wire = Wire::stream(&developer).await;
    wire.upgraded(chat, CHAT_PORT, None).await;
    assert!(wire.send(pull).await);
    assert_eq!(
        problem_of(&wire.answer().await.unwrap()),
        (403, "route_not_allowed".to_string())
    );
    // The API key with `services:connect`, over TCP and over the tunnel: the same.
    let tunnel = w.tunnel().await;
    for mut wire in [Wire::tcp(w.rest).await, Wire::stream(&tunnel).await] {
        wire.upgraded(chat, CHAT_PORT, Some(&connector)).await;
        assert!(wire.send(pull).await);
        assert_eq!(
            problem_of(&wire.answer().await.unwrap()),
            (403, "route_not_allowed".to_string())
        );
        assert_eq!(wire.rest().await.0, Vec::<u8>::new());
    }
    assert!(w.node.service.opens().is_empty());
    // An allowed request of the same callers goes through, filtered.
    let tags = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec();
    w.node.service.set(Act::Http {
        first: tags.clone(),
        second: Vec::new(),
        gate: None,
    });
    for (mut wire, auth) in [
        (Wire::stream(&developer).await, None),
        (Wire::tcp(w.rest).await, Some(connector.as_str())),
    ] {
        wire.upgraded(chat, CHAT_PORT, auth).await;
        assert!(
            wire.send(b"GET /api/tags HTTP/1.1\r\nHost: hub\r\nCookie: a=b\r\n\r\n")
                .await
        );
        assert_eq!(wire.rest().await.0, tags);
        let seen = w.node.seen().await;
        assert_eq!(
            String::from_utf8_lossy(&seen.bytes),
            "GET /api/tags HTTP/1.1\r\nHost: hub\r\nCookie: a=b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    // The `p2pc service run` service: raw bytes for both, whatever they look like.
    w.node.service.set(Act::Echo);
    for (mut wire, auth) in [
        (Wire::stream(&developer).await, None),
        (Wire::tcp(w.rest).await, Some(connector.as_str())),
    ] {
        wire.upgraded(dev_service, CHAT_PORT, auth).await;
        assert!(wire.send(pull).await);
        assert_eq!(wire.exactly(pull.len()).await.unwrap(), pull);
        wire.finish().await;
        assert_eq!(wire.rest().await, (Vec::new(), true));
        let seen = w.node.seen().await;
        assert_eq!(seen.bytes, pull);
        assert_eq!((seen.open.lease_id, seen.open.epoch), (dev_lease, dev_epoch));
    }
    // The phone: that service does not exist for it.
    let mut wire = Wire::stream(&phone).await;
    let r = wire.connect(dev_service, CHAT_PORT, None, "").await;
    assert_eq!((r.status, r.code().as_str()), (404, "not_found"));
}

/// H2 §7.4 "Limits": at most 64 open connections per service and 16 per principal per service (lowered here), and
/// API-key clients together hold at most `port_conn_budget`, which a device never takes from. A slot is given back
/// when its connection ends.
#[tokio::test]
async fn connections_are_capped_per_service_per_principal_and_for_api_keys() {
    let mut w = World::start_with(|c| c.services.port_conn_budget = Some(3)).await;
    let ports = w.app().state.ports.clone();
    assert_eq!(
        (ports.limits().per_service, ports.limits().per_principal),
        (64, 16),
        "the spec's limits by default"
    );
    ports.set_limits(p2pc_server::gateway::ports::PortLimits {
        per_service: 3,
        per_principal: 2,
        ..ports.limits()
    });
    let (job, ..) = w.running(w.owner(), plain_service()).await;
    let (other, ..) = w.running(w.owner(), plain_service()).await;
    let admin = w.app().admin.clone();
    let second = w.app().key_with(&[Scope::Admin]).await;
    let key = SecretKey::generate();
    w.add_device(&key, &[Scope::Admin], DeviceLimits::default()).await;
    let device = w.device(&key).await;
    w.node.service.set(Act::Silent);

    let too_many = |r: &common::ports::Answer, what: &str| {
        assert_eq!((r.status, r.code().as_str()), (429, "too_many_connections"));
        let detail = r.json()["detail"].as_str().unwrap().to_string();
        assert!(detail.contains(what), "{detail}");
    };
    // Two per principal per service.
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut wire = Wire::tcp(w.rest).await;
        wire.upgraded(job, CHAT_PORT, Some(&admin)).await;
        held.push(wire);
    }
    let mut wire = Wire::tcp(w.rest).await;
    too_many(&wire.connect(job, CHAT_PORT, Some(&admin), "").await, "principal");
    // Three per service, whoever holds them.
    let mut third = Wire::tcp(w.rest).await;
    third.upgraded(job, CHAT_PORT, Some(&second)).await;
    too_many(&wire.connect(job, CHAT_PORT, Some(&second), "").await, "service");
    let mut stream = Wire::stream(&device).await;
    too_many(&stream.connect(job, CHAT_PORT, None, "").await, "service");
    assert_eq!(w.job(job).await["service"]["open_connections"], 3);
    // The three API-key connections are the whole `port_conn_budget`: a key gets no connection to another service,
    // a device does.
    assert_eq!(ports.key_budget_free(), 0);
    too_many(&wire.connect(other, CHAT_PORT, Some(&admin), "").await, "budget");
    stream.upgraded(other, CHAT_PORT, None).await;
    assert_eq!(w.job(other).await["service"]["open_connections"], 1);
    // A connection that ends gives its places back: the principal's, the service's and the budget's.
    drop(held.pop());
    // The service sees the end of the client that went away, and ends its side.
    w.node.seen().await;
    eventually("the slot is given back", || async {
        (ports.key_budget_free() == 1).then_some(())
    })
    .await;
    wire.upgraded(job, CHAT_PORT, Some(&admin)).await;
    assert_eq!(w.job(job).await["service"]["open_connections"], 3);
    assert_eq!(
        w.node.service.opens().len(),
        5,
        "a refused connect opened nothing on the node"
    );
}

/// H2 §7.4 "Limits": an upgraded port connection keeps its slot of the REST connection cap (`http.max_connections`)
/// for its whole life, so the cap still bounds the listener's open connections.
#[tokio::test]
async fn an_upgraded_tcp_connection_keeps_its_slot_of_the_rest_cap() {
    let mut w = World::start_with(|c| c.http.max_connections = 2).await;
    let admin = w.app().admin.clone();
    let (job, ..) = w.running(w.owner(), plain_service()).await;
    let whoami = format!("GET /v1/whoami HTTP/1.1\r\nHost: hub\r\nAuthorization: Bearer {admin}\r\n\r\n");
    let mut port = Wire::tcp(w.rest).await;
    port.upgraded(job, CHAT_PORT, Some(&admin)).await;
    assert!(port.send(b"one").await);
    assert_eq!(port.exactly(3).await.unwrap(), b"one");
    // The second slot: a keep-alive connection.
    let mut keep = Wire::tcp(w.rest).await;
    assert!(keep.send(whoami.as_bytes()).await);
    assert_eq!(keep.answer().await.unwrap().status, 200);
    // A third connection waits in the backlog: both slots are held, one of them by the port connection.
    let mut waiting = Wire::tcp(w.rest).await;
    assert!(waiting.send(whoami.as_bytes()).await);
    let early = tokio::time::timeout(StdDuration::from_millis(300), waiting.answer()).await;
    assert!(early.is_err(), "served although the cap is in use: {early:?}");
    drop(keep);
    assert_eq!(waiting.answer().await.unwrap().status, 200);
    // The port connection was never in the way of its own traffic.
    assert!(port.send(b"two").await);
    assert_eq!(port.exactly(3).await.unwrap(), b"two");
}

/// H2 §7.4 "Limits", §6.3: on every transport an upgraded connection closes after `port_idle_s` with no byte in
/// either direction, and not before while bytes flow; the REST listener's header and keep-alive limits do not apply
/// to it. The relay keeps the time itself: a connection whose client ended its side, and that nobody reads, closes
/// too.
#[tokio::test]
async fn an_idle_port_connection_closes_after_port_idle_on_every_transport() {
    let mut w = World::start_with(|c| {
        c.services.port_idle_s = 1;
        c.http.header_read_timeout_ms = 200;
        c.http.keepalive_idle_ms = 200;
    })
    .await;
    let admin = w.app().admin.clone();
    let ports = w.app().state.ports.clone();
    let free = ports.key_budget_free();
    let (chat, ..) = w.running(w.owner(), template_service("private-chat")).await;
    // TCP, raw: traffic for longer than `port_idle_s` and than the listener's limits keeps the connection.
    let mut wire = Wire::tcp(w.rest).await;
    wire.upgraded(chat, CHAT_PORT, Some(&admin)).await;
    let start = Instant::now();
    while start.elapsed() < StdDuration::from_millis(1500) {
        assert!(wire.send(b"ping").await);
        assert_eq!(wire.exactly(4).await.unwrap(), b"ping");
    }
    // Then silence: the hub closes it one `port_idle_s` after the last byte, and resets the stream to the node.
    let last = Instant::now();
    wire.rest().await;
    assert!(last.elapsed() >= StdDuration::from_millis(900), "{:?}", last.elapsed());
    assert!(!w.node.seen().await.clean);
    eventually("the slots are given back", || async {
        (ports.key_budget_free() == free && w.job(chat).await["service"]["open_connections"] == 0).then_some(())
    })
    .await;

    // A device, filtered: the request is forwarded, the service never answers, and the phone has ended its side,
    // so nothing reads its stream any more. The relay still closes the connection.
    let key = SecretKey::generate();
    w.add_device(&key, &PHONE_PROFILE, DeviceLimits::default()).await;
    let phone = w.device(&key).await;
    w.node.service.set(Act::Silent);
    let mut wire = Wire::stream(&phone).await;
    wire.upgraded(chat, CHAT_PORT, None).await;
    assert!(wire.send(b"GET /api/tags HTTP/1.1\r\n\r\n").await);
    wire.finish().await;
    let last = Instant::now();
    assert_eq!(wire.rest().await.0, Vec::<u8>::new());
    assert!(last.elapsed() >= StdDuration::from_millis(900), "{:?}", last.elapsed());
    let seen = w.node.seen().await;
    assert!(!seen.clean);
    assert!(seen.bytes.starts_with(b"GET /api/tags HTTP/1.1\r\n"));
    eventually("the connection is counted closed", || async {
        (w.job(chat).await["service"]["open_connections"] == 0).then_some(())
    })
    .await;
    assert!(phone.is_open(), "only the stream ended");
}

/// H2 §7.4 "Idle accounting", §12, with the injected clock: the hub moves `last_activity_at` when it relays a byte,
/// at most once every 10 s per service; a service with an open connection is never idle; after the last connection
/// closed, `Cancel{reason: "idle_timeout"}` goes out once `idle_timeout_s` has passed with no connection and no
/// traffic. The bytes and the connection are in the day's `service_traffic`.
#[tokio::test]
async fn activity_is_recorded_every_ten_seconds_and_an_idle_service_is_cancelled() {
    let mut w = World::start().await;
    let admin = w.app().admin.clone();
    let mut spec = plain_service();
    spec["service"]["idle_timeout_s"] = json!(300);
    let (job, lease, _) = w.running(w.owner(), spec).await;
    let t0 = w.app().clock.now();
    let clock = w.app().clock.clone();
    let advance = move |seconds: i64| clock.advance(Duration::seconds(seconds));
    // The first `healthy` starts the idle timeout.
    assert_eq!(w.last_activity(job).await, Some(t0.unix_timestamp()));
    assert_eq!(w.job(job).await["service"]["traffic"], Value::Null);

    advance(100);
    let mut wire = Wire::tcp(w.rest).await;
    wire.upgraded(job, CHAT_PORT, Some(&admin)).await;
    let ping = async |wire: &mut Wire| {
        assert!(wire.send(b"ping").await);
        assert_eq!(wire.exactly(4).await.unwrap(), b"ping");
    };
    // The first byte moves the activity.
    ping(&mut wire).await;
    eventually("the first byte moves the activity", || async {
        (w.last_activity(job).await == Some(t0.unix_timestamp() + 100)).then_some(())
    })
    .await;
    // 5 s later: bytes flow, the activity stays. Two exchanges: when the second one is back, the hub has accounted
    // for the first one's bytes, so the row would show a write if there had been one.
    advance(5);
    ping(&mut wire).await;
    ping(&mut wire).await;
    assert_eq!(w.last_activity(job).await, Some(t0.unix_timestamp() + 100));
    // 10 s after the last write: it moves again.
    advance(5);
    ping(&mut wire).await;
    eventually("the activity moves again after 10 s", || async {
        (w.last_activity(job).await == Some(t0.unix_timestamp() + 110)).then_some(())
    })
    .await;
    let service = w.job(job).await["service"].clone();
    assert_eq!(service["open_connections"], 1);
    assert_eq!(service["last_activity_at"], ts(t0 + Duration::seconds(110)));
    assert_eq!(
        service["idle_deadline"],
        Value::Null,
        "no deadline while a connection is open"
    );

    // An open connection: never idle, however long ago the last byte was.
    advance(1000);
    assert_eq!(w.fleet.scheduler.tick().await.errors, 0);
    assert!(w.node.agent.sync().await.is_empty(), "nothing is cancelled");
    // The connection closes: from here the service has no connection and no traffic.
    wire.finish().await;
    assert_eq!(wire.rest().await, (Vec::new(), true));
    assert!(w.node.seen().await.clean);
    let closed = t0 + Duration::seconds(1110);
    let service = eventually("the connection is counted closed", || async {
        let service = w.job(job).await["service"].clone();
        (service["open_connections"] == 0).then_some(service)
    })
    .await;
    assert_eq!(service["last_activity_at"], ts(closed));
    assert_eq!(service["idle_deadline"], ts(closed + Duration::seconds(300)));
    assert_eq!(
        service["traffic"],
        json!({"day": ts(t0.replace_time(time::Time::MIDNIGHT)), "bytes_in": 16, "bytes_out": 16,
            "connections": 1})
    );

    // `idle_timeout_s` later, and not a second before, the hub asks the service to stop.
    advance(299);
    assert_eq!(w.fleet.scheduler.tick().await.errors, 0);
    assert!(w.node.agent.sync().await.is_empty());
    advance(1);
    assert_eq!(w.fleet.scheduler.tick().await.errors, 0);
    let cancels: Vec<_> = w
        .node
        .agent
        .sync()
        .await
        .into_iter()
        .filter_map(|m| match m {
            ServerMsg::Cancel { lease_id, reason, .. } => Some((lease_id, reason)),
            _ => None,
        })
        .collect();
    assert_eq!(cancels, vec![(lease, "idle_timeout".to_string())]);
}

/// SI-H2-6 on the hub: a `PortOpen` names the job's current lease, and a stream whose lease was replaced while the
/// agent answered is dropped, not handed to the client. After a restart on a new lease, connections go to the new
/// lease and epoch only.
#[tokio::test]
async fn a_port_stream_is_fenced_by_the_current_lease() {
    let mut w = World::start().await;
    let admin = w.app().admin.clone();
    let (job, lease, epoch) = w.running(w.owner(), plain_service()).await;
    // The agent holds its answer; meanwhile the lease ends.
    let gate = Arc::new(Semaphore::new(0));
    w.node.service.set(Act::AckLate(gate.clone()));
    let mut wire = Wire::tcp(w.rest).await;
    let request = format!(
        "POST /v1/jobs/{job}/ports/{CHAT_PORT}/connect HTTP/1.1\r\nHost: hub\r\nConnection: Upgrade\r\n\
         Upgrade: p2pc-port/1\r\nAuthorization: Bearer {admin}\r\n\r\n"
    );
    assert!(wire.send(request.as_bytes()).await);
    w.node.asked().await;
    w.node.agent.finished(lease, epoch, 0, vec![]).await;
    assert_eq!(w.job(job).await["status"], "succeeded");
    gate.add_permits(1);
    let r = wire.answer().await.unwrap();
    assert_eq!((r.status, r.code().as_str()), (409, "service_not_running"));
    let seen = w.node.seen().await;
    assert_eq!((seen.open.lease_id, seen.open.epoch), (lease, epoch));
    assert!(
        seen.bytes.is_empty() && !seen.clean,
        "the stale stream is reset, unused"
    );

    // A service whose node comes back without its lease is restarted on a new lease.
    w.node.service.set(Act::Echo);
    let (job, first_lease, first_epoch) = w.running(w.owner(), plain_service()).await;
    let mut old = Wire::tcp(w.rest).await;
    old.upgraded(job, CHAT_PORT, Some(&admin)).await;
    assert!(old.send(b"old").await);
    assert_eq!(old.exactly(3).await.unwrap(), b"old");
    w.node = w.node.restart(&w.fleet).await;
    // The connection of the lost attempt ends with it.
    old.rest().await;
    let (lease, epoch) = w.node.start_next(&w.fleet).await;
    assert_ne!((lease, epoch), (first_lease, first_epoch));
    let mut wire = Wire::tcp(w.rest).await;
    wire.upgraded(job, CHAT_PORT, Some(&admin)).await;
    assert!(wire.send(b"new").await);
    assert_eq!(wire.exactly(3).await.unwrap(), b"new");
    let last = w.node.service.opens().pop().unwrap();
    assert_eq!((last.lease_id, last.epoch, last.port), (lease, epoch, CHAT_PORT));
}

/// H2 §7.4: `502 node_unreachable` when the agent answers `PortOpenAck{ok: false}` (its reason is in `detail`) or the
/// hub cannot open the stream. For a filtered connection the stream is opened after the request passed the filter,
/// so the `502` is the hub's answer inside the upgraded connection.
#[tokio::test]
async fn a_node_that_refuses_or_is_gone_is_node_unreachable() {
    let mut w = World::start().await;
    let admin = w.app().admin.clone();
    let (chat, ..) = w.running(w.owner(), template_service("private-chat")).await;
    let key = SecretKey::generate();
    w.add_device(&key, &PHONE_PROFILE, DeviceLimits::default()).await;
    let phone = w.device(&key).await;

    w.node.service.set(Act::Refuse("not_ready"));
    let mut wire = Wire::tcp(w.rest).await;
    let r = wire.connect(chat, CHAT_PORT, Some(&admin), "").await;
    assert_eq!((r.status, r.code().as_str()), (502, "node_unreachable"));
    assert!(
        r.json()["detail"].as_str().unwrap().contains("not_ready"),
        "{:?}",
        r.json()
    );
    // An agent's reason is repeated only when it is one of the spec's codes.
    w.node.service.set(Act::Refuse("<b>look here</b>"));
    let r = wire.connect(chat, CHAT_PORT, Some(&admin), "").await;
    assert_eq!((r.status, r.code().as_str()), (502, "node_unreachable"));
    assert!(!String::from_utf8_lossy(&r.body).contains("look here"));
    // Filtered: upgraded first, then the hub's `502` to the allowed request.
    w.node.service.set(Act::Refuse("connect_failed"));
    let mut stream = Wire::stream(&phone).await;
    stream.upgraded(chat, CHAT_PORT, None).await;
    assert!(stream.send(b"GET /api/tags HTTP/1.1\r\n\r\n").await);
    let r = stream.answer().await.unwrap();
    assert_eq!(problem_of(&r), (502, "node_unreachable".to_string()));
    assert!(r.json()["detail"].as_str().unwrap().contains("connect_failed"));
    assert_eq!(
        w.job(chat).await["service"]["traffic"],
        Value::Null,
        "nothing was relayed"
    );

    // The node's connection is gone, and the job still `running` (its lease has not expired).
    w.node.agent.conn.close(0u32.into(), b"gone");
    let r = eventually("the hub sees the node gone", || async {
        let mut wire = Wire::tcp(w.rest).await;
        let r = wire.connect(chat, CHAT_PORT, Some(&admin), "").await;
        r.json()["detail"]
            .as_str()
            .is_some_and(|d| d.contains("not connected"))
            .then_some(r)
    })
    .await;
    assert_eq!((r.status, r.code().as_str()), (502, "node_unreachable"));
    assert_eq!(w.job(chat).await["status"], "running");
}

/// SI-H2-4: revoking a device closes the service streams it opened, also one that carries no traffic and that the
/// phone no longer writes to.
#[tokio::test]
async fn revoking_a_device_closes_its_port_connections() {
    let mut w = World::start().await;
    let (chat, ..) = w.running(w.owner(), template_service("private-chat")).await;
    let key = SecretKey::generate();
    let device = w.add_device(&key, &PHONE_PROFILE, DeviceLimits::default()).await;
    let phone = w.device(&key).await;
    w.node.service.set(Act::Silent);
    let mut wire = Wire::stream(&phone).await;
    wire.upgraded(chat, CHAT_PORT, None).await;
    assert!(wire.send(b"GET /api/tags HTTP/1.1\r\n\r\n").await);
    wire.finish().await;
    eventually("the request is forwarded", || async {
        (w.node.service.opens().len() == 1).then_some(())
    })
    .await;
    assert_eq!(w.job(chat).await["service"]["open_connections"], 1);
    let app = w.app();
    let r = app
        .call(Method::DELETE, &format!("/v1/devices/{device}"), Some(&app.admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // The stream to the node is reset, the phone's connection closed, the slot given back.
    let seen = w.node.seen().await;
    assert!(!seen.clean);
    wire.rest().await;
    phone.closed_not_paired().await;
    eventually("the connection is counted closed", || async {
        (w.job(chat).await["service"]["open_connections"] == 0).then_some(())
    })
    .await;
    // A device that is revoked gets nothing more.
    let again = w.device(&key).await;
    again.closed_not_paired().await;
}
