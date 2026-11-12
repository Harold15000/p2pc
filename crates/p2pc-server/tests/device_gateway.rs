// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc/device/1` through the real gateway, on loopback with relays disabled (H2 spec §5.5, §6.3, §10.5; SI-H2-3,
//! SI-H2-4, SI-H2-11, SI-H2-17).
//!
//! - Each stream is one HTTP/1.1 connection served **in-process** with the device principal: the REST listener these
//!   hubs would relay to is unreachable, and the requests are answered all the same.
//! - A NodeId that is not a live device gets `not_paired`, under the limits that run before the device check.
//! - The device stream budget: a cap per device, a share reserved for `admin` devices, apart from the TCP connection
//!   cap.
//! - A revocation (online or offline) and an expiry close the device's connections and its streams, upgraded ones
//!   with traffic included.
//!
//! The clock is injected. The slow-client and idle limits are real timers, as on the TCP listener: those tests set
//! them short and wait for the hub to close the stream.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration as StdDuration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use axum::routing::get;
use common::DeviceLimits;
use common::h2::{HttpStream, Hub, Peer, WAIT, limits, tcp_request};
use iroh::SecretKey;
use p2pc_proto::api::{PHONE_PROFILE, Scope};
use p2pc_proto::ids::DeviceId;
use p2pc_proto::{PROTOCOL_ALPN_AGENT, PROTOCOL_ALPN_HTTP, PROTOCOL_ALPN_INVITE, PROTOCOL_ALPN_PAIR};
use p2pc_server::app::AppState;
use p2pc_server::clock::Clock;
use p2pc_server::devices_api::sweep_once;
use p2pc_server::gateway::GatewayLimits;
use serde_json::json;
use time::Duration;
use tokio::io::AsyncWriteExt;

/// The API's device router plus `GET /echo`: an HTTP upgrade whose connection echoes every byte, standing in for the
/// port connections of T2-13 (H2 §7.4). It is behind the same device authentication as every other route.
fn with_echo(state: &AppState) -> Option<Router> {
    async fn echo(req: axum::extract::Request) -> Response {
        let upgrade = hyper::upgrade::on(req);
        tokio::spawn(async move {
            if let Ok(io) = upgrade.await {
                let (mut read, mut write) = tokio::io::split(hyper_util::rt::TokioIo::new(io));
                let _ = tokio::io::copy(&mut read, &mut write).await;
            }
        });
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "p2pc-echo")
            .body(Body::empty())
            .unwrap()
    }
    let echo = Router::new()
        .route("/echo", get(echo))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            p2pc_server::auth::require_device,
        ));
    Some(p2pc_server::app::device_router(state.clone()).merge(echo))
}

async fn hub_with_echo(edit: impl FnOnce(&mut p2pc_server::config::Config)) -> Hub {
    Hub::start_full(edit, limits(), with_echo, "127.0.0.1:9".parse().unwrap()).await
}

/// Upgrades a new stream of `peer` to the echo connection.
async fn upgraded(peer: &Peer) -> HttpStream {
    let mut s = peer.stream().await;
    s.send_request("GET", "/echo", "Connection: Upgrade\r\nUpgrade: p2pc-echo\r\n", "")
        .await
        .unwrap();
    let r = s.response().await.unwrap();
    assert_eq!(r.status, 101, "{}", r.head);
    s.echo(b"ready").await.unwrap();
    s
}

async fn phone(hub: &Hub, key: &SecretKey) -> DeviceId {
    hub.add_device(key, &PHONE_PROFILE, DeviceLimits::default()).await
}

async fn admin(hub: &Hub, key: &SecretKey) -> DeviceId {
    hub.add_device(key, &[Scope::Admin], DeviceLimits::default()).await
}

/// Retries `attempt` until it gives a value. For what the hub does after a peer can observe it (a slot given back
/// when a handler ends): the peer retries, as a real client does, and nothing sleeps.
async fn eventually<T, F: Future<Output = Option<T>>>(what: &str, mut attempt: impl FnMut() -> F) -> T {
    let retry = async {
        loop {
            if let Some(value) = attempt().await {
                return value;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(WAIT, retry)
        .await
        .unwrap_or_else(|_| panic!("never: {what}"))
}

/// SI-H2-3, H2 §6.3: a device stream is an HTTP/1.1 connection to the API, served in-process with
/// `Principal::Device` (the REST listener of this hub is unreachable). Keep-alive works. A request that carries an
/// `Authorization` header gets `400 unexpected_authorization`, so nothing can run as an API key over a device
/// connection, and a device header on the key-authenticated router is just an unauthenticated request.
#[tokio::test]
async fn a_device_stream_is_served_in_process_with_the_device_principal() {
    let hub = Hub::start().await;
    let key = SecretKey::generate();
    let device = phone(&hub, &key).await;
    let peer = hub.device(&key).await;

    let who = peer.get("/v1/whoami").await.unwrap();
    assert_eq!(who.status, 200, "{}", who.head);
    let v = who.json();
    assert_eq!(v["principal"], json!({"kind": "device", "id": device.to_string()}));
    assert_eq!(v["key_id"], json!(null));
    assert_eq!(v["scopes"], json!(PHONE_PROFILE));

    // Several requests on one stream, then a second stream beside it.
    let mut stream = peer.stream().await;
    for _ in 0..3 {
        let r = stream.roundtrip("GET", "/v1/whoami", "").await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["principal"]["id"], device.to_string());
    }
    let r = peer.get("/v1/nodes").await.unwrap();
    assert_eq!(r.status, 200, "the phone profile has nodes:read");
    // The scopes are the device's own: the phone profile cannot list keys.
    let r = peer.get("/v1/keys").await.unwrap();
    assert_eq!((r.status, r.json()["code"].as_str()), (403, Some("forbidden")));
    // Unknown routes and public routes behave as on the TCP listener.
    assert_eq!(peer.get("/healthz").await.unwrap().status, 200);
    assert_eq!(peer.get("/v1/nope").await.unwrap().status, 404);

    // Mixing two principals is refused, with a valid API key too.
    let with_key = format!("Authorization: Bearer {}\r\n", hub.app.admin);
    let r = peer.request("GET", "/v1/whoami", &with_key, "").await.unwrap();
    assert_eq!(
        (r.status, r.json()["code"].as_str()),
        (400, Some("unexpected_authorization"))
    );
    // No header makes a device request on the key-authenticated router (the TCP listener and `p2pc/http/1`).
    let req = axum::http::Request::builder()
        .uri("/v1/whoami")
        .header("x-p2pc-device", device.to_string())
        .header("x-device-id", device.to_string())
        .body(Body::empty())
        .unwrap();
    assert_eq!(hub.app.send(req).await.status, StatusCode::UNAUTHORIZED);
    let r = hub
        .app
        .get(&format!("/v1/whoami?device_id={device}"), "p2pc_sk_nope") // gitleaks:allow
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

/// H2 §5.5, §6.3, SI-H2-4: a NodeId that is not a live device gets the same close, `not_paired`, whether it was never
/// paired, was revoked or has expired, right after the handshake: no stream of it is ever served.
#[tokio::test]
async fn a_node_id_that_is_not_a_live_device_gets_not_paired() {
    let hub = Hub::start().await;
    let (revoked_key, expired_key) = (SecretKey::generate(), SecretKey::generate());
    let revoked = phone(&hub, &revoked_key).await;
    let expiring = DeviceLimits {
        expires_at: Some(hub.app.clock.now() + Duration::hours(1)),
        ..DeviceLimits::default()
    };
    hub.add_device(&expired_key, &PHONE_PROFILE, expiring).await;
    let path = format!("/v1/devices/{revoked}");
    let r = hub.app.call(Method::DELETE, &path, Some(&hub.app.admin), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // One second before its expiry the device is live; at its expiry it is not.
    hub.app.clock.advance(Duration::seconds(3599));
    let live = hub.device(&expired_key).await;
    assert_eq!(live.get("/v1/whoami").await.unwrap().status, 200);
    live.close().await;
    hub.app.clock.advance(Duration::seconds(1));

    for key in [SecretKey::generate(), revoked_key, expired_key] {
        let peer = hub.device(&key).await;
        peer.closed_not_paired().await;
        assert!(peer.get("/v1/whoami").await.is_err(), "no stream is served");
        assert!(peer.get("/healthz").await.is_err(), "not even a public route");
    }
    assert_eq!(hub.failures_audited("device").await, 3);
    assert_eq!(hub.gw.device_streams_in_use(), 0);
}

/// H2 §6.3 "Before the device check": `not_paired` closes are counted per NodeId. A NodeId over its limit is closed
/// at connect with no detail and **without the lookup**: even once it is a live device it stays refused until the
/// minute ends (only its own failures count). Other NodeIds are not affected.
#[tokio::test]
async fn not_paired_closes_are_limited_per_node_id_without_the_lookup() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            device_not_paired_per_node_per_minute: 2,
            ..limits()
        },
    )
    .await;
    let noisy = SecretKey::generate();
    for _ in 0..2 {
        hub.device(&noisy).await.closed_not_paired().await;
    }
    hub.device(&noisy).await.closed_with_no_detail().await;
    // It becomes a live device: a lookup would now pass, and none is made.
    let device = phone(&hub, &noisy).await;
    hub.device(&noisy).await.closed_with_no_detail().await;
    // Others get their own answer, and a device that never failed connects.
    hub.device(&SecretKey::generate()).await.closed_not_paired().await;
    let other = SecretKey::generate();
    phone(&hub, &other).await;
    assert_eq!(hub.device(&other).await.get("/v1/whoami").await.unwrap().status, 200);
    // Closes without the lookup are not `not_paired` closes: three were.
    assert_eq!(hub.failures_audited("device").await, 3);
    // The next minute starts empty.
    hub.app.clock.advance(Duration::seconds(60));
    let peer = hub.device(&noisy).await;
    assert_eq!(
        peer.get("/v1/whoami").await.unwrap().json()["principal"]["id"],
        device.to_string()
    );
}

/// SI-H2-17, H2 §5.3 "aggregate failure cap" on the device check: with `not_paired` closes spread over fresh NodeIds,
/// beyond the cap a NodeId that is not a device is closed with no detail and nothing is audited one by one (one
/// aggregated row counts them all), while a live device that gets a slot still connects.
#[tokio::test]
async fn beyond_the_aggregate_cap_not_paired_gets_no_detail_and_a_live_device_still_connects() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            aggregate_failures_per_minute: 3,
            ..limits()
        },
    )
    .await;
    let key = SecretKey::generate();
    let device = phone(&hub, &key).await;
    for _ in 0..3 {
        hub.device(&SecretKey::generate()).await.closed_not_paired().await;
    }
    for _ in 0..4 {
        hub.device(&SecretKey::generate()).await.closed_with_no_detail().await;
    }
    assert_eq!(hub.failures_audited("device").await, 7);
    // The cap limits answers and logging, never the lookup.
    let peer = hub.device(&key).await;
    let who = peer.get("/v1/whoami").await.unwrap();
    assert_eq!(who.json()["principal"]["id"], device.to_string());
    assert_eq!(hub.failures_audited("device").await, 7, "a live device is no failure");
    // The next minute the close has its detail again.
    hub.app.clock.advance(Duration::seconds(60));
    hub.device(&SecretKey::generate()).await.closed_not_paired().await;
}

/// H2 §6.3 "Before the device check": at most `device_max_unchecked_connections` connections at once have not
/// passed the check, each checked within the deadline; one beyond the cap is closed with no detail.
///
/// The check is one indexed lookup, so to hold connections in it the test takes every connection of the database
/// pool: a lookup then waits for one. Nothing depends on timing.
#[tokio::test]
async fn unchecked_connections_are_capped_and_checked_within_the_deadline() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            device_max_unchecked_connections: 2,
            device_check_deadline: StdDuration::from_secs(1),
            ..limits()
        },
    )
    .await;
    let key = SecretKey::generate();
    let device = phone(&hub, &key).await;
    let mut pool = Vec::new();
    for _ in 0..4 {
        pool.push(hub.app.db.acquire().await.unwrap());
    }
    // Three connections for two slots, the device's among them: exactly one is closed at once, with no detail.
    let peers = [
        hub.device(&SecretKey::generate()).await,
        hub.device(&key).await,
        hub.device(&SecretKey::generate()).await,
    ];
    let refused = tokio::select! {
        c = peers[0].closed() => (0, c),
        c = peers[1].closed() => (1, c),
        c = peers[2].closed() => (2, c),
    };
    assert_eq!(refused.1, (common::h2::CLOSE_BY_SERVER, String::new()));
    // The other two hold their slots until the deadline, then are closed with no detail too: the hub could not
    // tell whether they are devices, so it never says `not_paired`.
    for (i, peer) in peers.iter().enumerate() {
        if i != refused.0 {
            peer.closed_with_no_detail().await;
        }
    }
    // A check that timed out is not a `not_paired` close.
    drop(pool);
    assert_eq!(hub.failures_audited("device").await, 0);
    // The slots are free again: the device connects, and a stranger gets its `not_paired`.
    let peer = eventually("the device connects", || async {
        hub.device(&key).await.get("/v1/whoami").await.ok()
    })
    .await;
    assert_eq!(peer.json()["principal"]["id"], device.to_string());
    hub.device(&SecretKey::generate()).await.closed_not_paired().await;
}

/// H2 §6.3 "Per device": at most 2 connections per device. A third is closed with no detail, and a closed one makes
/// room again.
#[tokio::test]
async fn a_device_holds_at_most_two_connections() {
    let hub = Hub::start().await;
    let key = SecretKey::generate();
    phone(&hub, &key).await;
    let (first, second) = (hub.device(&key).await, hub.device(&key).await);
    // Both passed the check: each serves a request.
    assert_eq!(first.get("/v1/whoami").await.unwrap().status, 200);
    assert_eq!(second.get("/v1/whoami").await.unwrap().status, 200);
    let third = hub.device(&key).await;
    third.closed_with_no_detail().await;
    assert!(first.is_open() && second.is_open());
    // Another device is not affected.
    let other = SecretKey::generate();
    phone(&hub, &other).await;
    assert_eq!(hub.device(&other).await.get("/v1/whoami").await.unwrap().status, 200);
    first.close().await;
    eventually("a new connection after one closed", || async {
        hub.device(&key).await.get("/v1/whoami").await.ok()
    })
    .await;
}

/// SI-H2-4, H2 §6.3: with every non-`admin` device at its per-device stream cap and the non-`admin` share of the
/// device budget full, an `admin` device still opens streams from its reserve and revokes a phone; the revocation
/// closes that phone's connection and its streams, a later connection gets `not_paired`, and its slots go back to
/// the phones.
#[tokio::test]
async fn an_admin_device_revokes_from_its_reserve_when_phones_fill_their_share() {
    let hub = Hub::start_with(
        |c| {
            c.devices.device_streams_per_device = 2;
            c.devices.device_stream_budget = 5;
            c.devices.device_stream_admin_reserve = 2;
        },
        limits(),
    )
    .await;
    let (key_a, key_b, key_c, key_app) = (
        SecretKey::generate(),
        SecretKey::generate(),
        SecretKey::generate(),
        SecretKey::generate(),
    );
    let phone_a = phone(&hub, &key_a).await;
    phone(&hub, &key_b).await;
    phone(&hub, &key_c).await;
    admin(&hub, &key_app).await;
    let (a, b, c) = (
        hub.device(&key_a).await,
        hub.device(&key_b).await,
        hub.device(&key_c).await,
    );
    // Phone A holds its two streams, on two connections: the per-device cap counts across them.
    let a2 = hub.device(&key_a).await;
    let (mut a_first, mut a_second) = (a.stream().await, a2.stream().await);
    a_first.hold().await;
    a_second.hold().await;
    assert!(a.stream().await.is_refused().await, "a third stream of one device");
    assert!(a2.stream().await.is_refused().await);
    // Phone B takes the last stream of the non-admin share (5 - 2).
    let mut b_first = b.stream().await;
    b_first.hold().await;
    assert_eq!(hub.gw.device_streams_in_use(), 3);
    assert!(b.stream().await.is_refused().await, "the non-admin share is full");
    assert!(c.stream().await.is_refused().await);
    // A refused stream costs the connection nothing.
    assert!(a.is_open() && b.is_open() && c.is_open());

    // The owner's app still gets its whole share: one stream held, the other one revokes phone A.
    let app = hub.device(&key_app).await;
    let mut app_held = app.stream().await;
    app_held.hold().await;
    let r = app
        .request("DELETE", &format!("/v1/devices/{phone_a}"), "", "")
        .await
        .unwrap();
    assert_eq!(r.status, 204, "{}", r.head);
    // The phone's connections are closed and its streams end.
    a.closed_not_paired().await;
    a2.closed_not_paired().await;
    a_first.ended().await;
    a_second.ended().await;
    hub.device(&key_a).await.closed_not_paired().await;
    // Its slots are free for the other phones.
    eventually("phone C gets a stream", || async {
        let mut s = c.stream().await;
        s.roundtrip("GET", "/v1/whoami", "").await.ok().map(|_| s)
    })
    .await;
    assert!(b.is_open() && app.is_open());
    let r = app_held.roundtrip("GET", "/v1/whoami", "").await.unwrap();
    assert_eq!(r.status, 200);
}

/// SI-H2-4: a device reaching its `expires_at` is closed by the liveness sweep, **with an open upgraded connection
/// that carries traffic**; an online revocation and an offline one (`p2pc-server devices revoke`, another process's
/// write) do the same. In each case the next sweep pass, or the `DELETE` itself, closes the connection, so the
/// 5 s of SI-H2-4 hold with the sweep's 2 s interval.
#[tokio::test]
async fn an_expiry_and_a_revocation_close_an_upgraded_connection_with_traffic() {
    let hub = hub_with_echo(|_| {}).await;
    let (expiring_key, online_key, offline_key) = (SecretKey::generate(), SecretKey::generate(), SecretKey::generate());
    let limits = DeviceLimits {
        expires_at: Some(hub.app.clock.now() + Duration::hours(1)),
        ..DeviceLimits::default()
    };
    let expiring = hub.add_device(&expiring_key, &PHONE_PROFILE, limits).await;
    let online = phone(&hub, &online_key).await;
    let offline = phone(&hub, &offline_key).await;

    // Each device: an upgraded connection with traffic flowing until the hub ends it.
    let mut traffic = Vec::new();
    let mut peers = Vec::new();
    for key in [&expiring_key, &online_key, &offline_key] {
        let peer = hub.device(key).await;
        let mut stream = upgraded(&peer).await;
        let (started, flowing) = tokio::sync::oneshot::channel();
        traffic.push(tokio::spawn(async move {
            let mut started = Some(started);
            let mut rounds = 0u64;
            while stream.echo(b"ping").await.is_ok() {
                rounds += 1;
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
            }
            rounds
        }));
        flowing.await.unwrap();
        peers.push(peer);
    }
    assert_eq!(hub.gw.device_streams_in_use(), 3);
    // Nothing is due: a sweep closes nobody.
    assert_eq!(sweep_once(&hub.app.state).await.unwrap(), vec![]);
    assert!(peers.iter().all(Peer::is_open));

    // The online revocation closes at once, without any sweep.
    let path = format!("/v1/devices/{online}");
    let r = hub.app.call(Method::DELETE, &path, Some(&hub.app.admin), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    peers[1].closed_not_paired().await;

    // The offline revocation is another process's write: the next sweep sees it.
    p2pc_server::recover::devices_revoke(&hub.app.data_dir(), offline, hub.app.clock.as_ref())
        .await
        .unwrap();
    assert!(peers[2].is_open(), "the hub has not looked yet");
    assert_eq!(sweep_once(&hub.app.state).await.unwrap(), vec![offline]);
    peers[2].closed_not_paired().await;

    // The expiry: at `expires_at` the next sweep closes the connection, traffic or not.
    hub.app.clock.advance(Duration::seconds(3599));
    assert_eq!(sweep_once(&hub.app.state).await.unwrap(), vec![]);
    assert!(peers[0].is_open());
    hub.app.clock.advance(Duration::seconds(1));
    assert_eq!(sweep_once(&hub.app.state).await.unwrap(), vec![expiring]);
    peers[0].closed_not_paired().await;

    // Every upgraded connection ended, after carrying traffic, and gave its slot back.
    for task in traffic {
        let rounds = tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
        assert!(rounds > 0);
    }
    eventually("the slots are given back", || async {
        (hub.gw.device_streams_in_use() == 0).then_some(())
    })
    .await;
    // Later connections of all three get the same `not_paired` as a NodeId never paired.
    for key in [&expiring_key, &online_key, &offline_key, &SecretKey::generate()] {
        hub.device(key).await.closed_not_paired().await;
    }
}

/// H2 §6.3: the hub checks the device on every request. An expiry is seen at the next request of an open stream even
/// before the sweep runs.
#[tokio::test]
async fn an_expiry_is_seen_at_the_next_request_before_any_sweep() {
    let hub = Hub::start().await;
    let key = SecretKey::generate();
    let limits = DeviceLimits {
        expires_at: Some(hub.app.clock.now() + Duration::minutes(5)),
        ..DeviceLimits::default()
    };
    hub.add_device(&key, &PHONE_PROFILE, limits).await;
    let peer = hub.device(&key).await;
    let mut stream = peer.stream().await;
    stream.hold().await;
    hub.app.clock.advance(Duration::minutes(5));
    let r = stream.roundtrip("GET", "/v1/whoami", "").await.unwrap();
    assert_eq!((r.status, r.json()["code"].as_str()), (401, Some("unauthenticated")));
}

/// SI-H2-4, H2 §6.3 "Idle limits": an upgraded port connection closes after `port_idle_s` with no byte in either
/// direction, and not before while bytes flow. The REST listener's idle limits do not apply to it.
#[tokio::test]
async fn an_idle_upgraded_connection_closes_after_port_idle() {
    let hub = hub_with_echo(|c| {
        c.services.port_idle_s = 1;
        c.http.header_read_timeout_ms = 200;
        c.http.keepalive_idle_ms = 200;
    })
    .await;
    let key = SecretKey::generate();
    phone(&hub, &key).await;
    let peer = hub.device(&key).await;
    let mut stream = upgraded(&peer).await;
    // Traffic for longer than `port_idle_s` (and than the keep-alive limit): the connection stays.
    let start = Instant::now();
    while start.elapsed() < StdDuration::from_millis(1500) {
        stream.echo(b"ping").await.unwrap();
    }
    // Then silence: the hub ends the stream one `port_idle_s` after the last byte, and only the stream.
    let last = Instant::now();
    stream.ended().await;
    assert!(
        last.elapsed() >= StdDuration::from_millis(900),
        "closed {:?} after the last byte",
        last.elapsed()
    );
    assert!(peer.is_open());
    eventually("the slot is given back", || async {
        (hub.gw.device_streams_in_use() == 0).then_some(())
    })
    .await;
    assert_eq!(peer.get("/v1/whoami").await.unwrap().status, 200);
}

/// H2 §6.3 "Same limits as the REST listener": a device stream whose request head does not arrive in time, or that
/// stays idle between two requests for the keep-alive limit, is closed, and gives its slot back. The connection
/// stays.
#[tokio::test]
async fn device_streams_get_the_rest_listeners_slow_client_limits() {
    let hub = Hub::start_with(
        |c| {
            c.http.header_read_timeout_ms = 300;
            c.http.keepalive_idle_ms = 600;
        },
        limits(),
    )
    .await;
    let key = SecretKey::generate();
    phone(&hub, &key).await;
    let peer = hub.device(&key).await;
    // Half a request head.
    let mut slow = peer.stream().await;
    slow.send.write_all(b"GET /v1/whoami HTTP/1.1\r\nHost:").await.unwrap();
    let start = Instant::now();
    slow.ended().await;
    assert!(
        start.elapsed() >= StdDuration::from_millis(250),
        "{:?}",
        start.elapsed()
    );
    // A request, then nothing.
    let mut idle = peer.stream().await;
    idle.hold().await;
    let start = Instant::now();
    idle.ended().await;
    assert!(
        start.elapsed() >= StdDuration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert!(peer.is_open());
    eventually("the slots are given back", || async {
        (hub.gw.device_streams_in_use() == 0).then_some(())
    })
    .await;
    assert_eq!(peer.get("/v1/whoami").await.unwrap().status, 200);
}

/// A hub whose REST listener really listens (on loopback), as `serve` wires it: the `p2pc/http/1` tunnel relays to
/// it, and its connection cap is `http.max_connections`.
async fn hub_with_rest(edit: impl FnOnce(&mut p2pc_server::config::Config)) -> (Hub, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Hub::start_full(edit, limits(), |_| None, addr).await;
    tokio::spawn(p2pc_server::serve::serve_on(
        listener,
        hub.app.state.clone(),
        std::future::pending(),
    ));
    (hub, addr)
}

/// SI-H2-4, H2 §6.3 "Total": device streams and the TCP REST listener have separate budgets. With the TCP
/// listener's connection cap held full by unauthenticated loopback connections, an `admin` device still opens
/// streams and revokes; with the whole device budget in use, a TCP client with an API key still gets a connection,
/// and so does a `p2pc/http/1` stream.
#[tokio::test]
async fn device_streams_and_tcp_connections_have_separate_budgets() {
    let (hub, rest) = hub_with_rest(|c| {
        c.http.max_connections = 2;
        c.iroh.tunnel_max_streams = 1;
        c.devices.device_streams_per_device = 1;
        c.devices.device_stream_budget = 3;
        c.devices.device_stream_admin_reserve = 1;
    })
    .await;
    let (key_app, key_a, key_b) = (SecretKey::generate(), SecretKey::generate(), SecretKey::generate());
    admin(&hub, &key_app).await;
    let phone_a = phone(&hub, &key_a).await;
    phone(&hub, &key_b).await;

    // Two unauthenticated TCP connections take the whole TCP cap: each got an answer, so each holds its slot.
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut tcp = tokio::net::TcpStream::connect(rest).await.unwrap();
        tcp.write_all(b"GET /v1/whoami HTTP/1.1\r\nHost: hub\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 12];
        tokio::io::AsyncReadExt::read_exact(&mut tcp, &mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 401");
        held.push(tcp);
    }
    // The owner's app is not affected: it opens a stream and revokes a phone.
    let app = hub.device(&key_app).await;
    let r = app
        .request("DELETE", &format!("/v1/devices/{phone_a}"), "", "")
        .await
        .unwrap();
    assert_eq!(r.status, 204, "{}", r.head);
    hub.device(&key_a).await.closed_not_paired().await;
    drop(held);

    // Now the whole device budget is in use: the app's stream and two phones'.
    let key_c = SecretKey::generate();
    phone(&hub, &key_c).await;
    let (b, c) = (hub.device(&key_b).await, hub.device(&key_c).await);
    let (mut s_app, mut s_b, mut s_c) = (app.stream().await, b.stream().await, c.stream().await);
    s_app.hold().await;
    s_b.hold().await;
    s_c.hold().await;
    assert_eq!(hub.gw.device_streams_in_use(), 3);
    // A TCP client with an API key gets its connection and its answer.
    let request = format!(
        "GET /v1/whoami HTTP/1.1\r\nHost: hub\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        hub.app.admin
    );
    let r = eventually("a TCP connection once the held ones are gone", || async {
        Some(tcp_request(rest, request.clone()).await)
    })
    .await;
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(r.json()["principal"]["kind"], "key");
    // And so does a `p2pc/http/1` stream, which is relayed to that listener.
    let tunnel = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_HTTP).await.unwrap();
    let with_key = format!("Authorization: Bearer {}\r\n", hub.app.admin);
    let r = tunnel.request("GET", "/v1/whoami", &with_key, "").await.unwrap();
    assert_eq!(r.status, 200, "{}", r.head);
    // The held device streams were never in the way, and are still served.
    assert_eq!(s_app.roundtrip("GET", "/v1/whoami", "").await.unwrap().status, 200);
}

/// SI-H2-11 (the probes of the hub's endpoint, here on loopback instead of through a relay), hard rule 4, H2 §10.5:
/// from an unknown NodeId, `p2pc/pair/1` with no ticket open fails at the handshake, `p2pc/device/1` gets
/// `not_paired`, `p2pc/http/1` without a key gets `401`, `p2pc/agent/1` without a valid `Join` is closed, and no
/// other ALPN is accepted at all.
#[tokio::test]
async fn the_hubs_endpoint_accepts_only_what_the_spec_lists() {
    let (hub, _rest) = hub_with_rest(|_| {}).await;
    let stranger = SecretKey::generate();

    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err());
    // The invite ALPN is a joining PC's, never the hub's; anything else is unknown.
    for alpn in [PROTOCOL_ALPN_INVITE, b"p2pc/admin/1", b"h3", b""] {
        assert!(
            hub.connect(&stranger, alpn).await.is_err(),
            "{:?} must not be accepted",
            String::from_utf8_lossy(alpn)
        );
    }

    hub.device(&stranger).await.closed_not_paired().await;

    let tunnel = hub.connect(&stranger, PROTOCOL_ALPN_HTTP).await.unwrap();
    let r = tunnel.get("/v1/whoami").await.unwrap();
    assert_eq!((r.status, r.json()["code"].as_str()), (401, Some("unauthenticated")));
    let r = tunnel.get("/v1/devices").await.unwrap();
    assert_eq!(r.status, 401);

    // `p2pc/agent/1`: a `Hello` from a NodeId that is not enrolled gets `not_enrolled`, a `Join` with a token the
    // hub never issued `invalid_token`; then the connection is closed.
    let agent = hub.connect(&stranger, PROTOCOL_ALPN_AGENT).await.unwrap();
    let (mut send, mut recv) = agent.conn.open_bi().await.unwrap();
    let hello = p2pc_proto::protocol::AgentMsg::Hello {
        agent_version: "0.1.0".into(),
        inventory: common::inventory("probe"),
        running: vec![],
        features: vec![],
    };
    p2pc_proto::protocol::write_frame(&mut send, &hello).await.unwrap();
    let answer: Option<p2pc_proto::protocol::ServerMsg> = tokio::time::timeout(
        WAIT,
        p2pc_proto::protocol::read_frame(&mut recv, p2pc_proto::protocol::MAX_FRAME_LEN),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(&answer, Some(p2pc_proto::protocol::ServerMsg::Error { code, .. }) if code == "not_enrolled"),
        "{answer:?}"
    );
    agent.closed_with_no_detail().await;

    // Nothing was created by any of it.
    let (devices, nodes): (i64, i64) =
        sqlx::query_as("SELECT (SELECT COUNT(*) FROM devices), (SELECT COUNT(*) FROM nodes)")
            .fetch_one(&hub.app.db)
            .await
            .unwrap();
    assert_eq!((devices, nodes), (0, 0));
}

/// SI-H2-4: with the pre-check slots of `p2pc/device/1` held full by unknown NodeIds, the owner still revokes a
/// phone through the offline `p2pc-server devices revoke` while the hub runs, and the hub's next sweep closes that
/// phone's connection and streams.
///
/// The slots are held as in [`unchecked_connections_are_capped_and_checked_within_the_deadline`]: the test takes the
/// hub's database pool, so the checks of the unknown NodeIds wait. The offline command opens the database itself, as
/// the other process it is.
#[tokio::test]
async fn an_offline_revocation_works_with_the_pre_check_slots_full() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            device_max_unchecked_connections: 1,
            device_check_deadline: WAIT,
            ..limits()
        },
    )
    .await;
    let (key_phone, key_app) = (SecretKey::generate(), SecretKey::generate());
    let device = phone(&hub, &key_phone).await;
    admin(&hub, &key_app).await;
    let peer = hub.device(&key_phone).await;
    let mut stream = peer.stream().await;
    stream.hold().await;

    let mut pool = Vec::new();
    for _ in 0..4 {
        pool.push(hub.app.db.acquire().await.unwrap());
    }
    // An unknown NodeId and the owner's app contend for the only pre-check slot: one of them is turned away, and
    // the other waits in its check. Either way the app has no device connection to revoke with.
    let (stranger, app) = (hub.device(&SecretKey::generate()).await, hub.device(&key_app).await);
    let turned_away = tokio::select! {
        c = stranger.closed() => c,
        c = app.closed() => c,
    };
    assert_eq!(turned_away, (common::h2::CLOSE_BY_SERVER, String::new()));

    // The offline revocation needs no slot.
    p2pc_server::recover::devices_revoke(&hub.app.data_dir(), device, hub.app.clock.as_ref())
        .await
        .unwrap();
    assert!(peer.is_open());
    drop(pool);
    assert_eq!(sweep_once(&hub.app.state).await.unwrap(), vec![device]);
    peer.closed_not_paired().await;
    stream.ended().await;
    hub.device(&key_phone).await.closed_not_paired().await;
}
