// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The client over the `p2pc/http/1` tunnel (spec §10, option B), against an in-process fake tunnel server: iroh on
//! loopback with relays disabled, hyper on every stream. No real network, no public relay, no `p2pc-server`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use p2pc_client::testing::{MockResponse, MockTunnelServer, fixtures};
use p2pc_client::tunnel::{Tunnel, TunnelOptions, endpoint_plan};
use p2pc_client::{Client, Error, JobListParams, NetworkKind, RetryPolicy};
use p2pc_proto::api::{JobSpec, JobStatus, Resources, Scope};
use p2pc_proto::auth::{ApiKey, ServerAddress};
use p2pc_proto::ids::{JobId, KeyId};
use p2pc_proto::net::{DirectAddresses, IfAddr, Interface};
use serde_json::json;
use url::Url;

/// The client endpoint binds loopback only and gets the server's loopback sockets as hints.
fn options_for(server: &MockTunnelServer) -> TunnelOptions {
    TunnelOptions {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        server_addrs: server.addrs(),
        ..TunnelOptions::new(server.address())
    }
}

fn tunnel_client(server: &MockTunnelServer, key: &ApiKey) -> (Client, Tunnel) {
    let tunnel = Tunnel::new(options_for(server)).unwrap();
    let client = Client::builder_tunnel(tunnel.clone(), key.clone())
        .retry(RetryPolicy::immediate(3))
        .build()
        .unwrap();
    (client, tunnel)
}

fn spec() -> JobSpec {
    JobSpec {
        name: None,
        image: "docker.io/library/python:3.12-slim".into(),
        command: vec!["true".into()],
        env: Default::default(),
        files: vec![],
        resources: Resources {
            cpu: 1.0,
            memory_mb: 512,
            gpu: 0,
            disk_mb: 10_240,
        },
        timeout_s: 60,
        egress: Default::default(),
        outputs: Default::default(),
        placement: Default::default(),
        retry: Default::default(),
        idempotency_key: None,
    }
}

fn api(key_id: KeyId) -> MockTunnelServer {
    let who = serde_json::to_value(fixtures::whoami(key_id, vec![Scope::JobsRead])).unwrap();
    let job = fixtures::job(JobId::generate(), JobStatus::Running, None);
    let job_value = serde_json::to_value(&job).unwrap();
    MockTunnelServer::start(move |r| match r.route().as_str() {
        "GET /v1/whoami" => MockResponse::json(200, &who),
        "GET /v1/jobs" => MockResponse::json(200, &json!({"items": [job_value], "next_cursor": null})),
        _ if r.path.starts_with("/v1/jobs/") => MockResponse::json(200, &job_value),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

#[tokio::test]
async fn requests_go_through_one_connection_with_one_stream_each() {
    let key = ApiKey::generate();
    let server = api(key.key_id());
    let (client, tunnel) = tunnel_client(&server, &key);
    let who = client.whoami().await.unwrap();
    assert_eq!(who.key_id, key.key_id());
    let page = client.list_jobs(&JobListParams::default()).await.unwrap();
    assert_eq!(page.items.len(), 1);
    client.get_job(&page.items[0].id).await.unwrap();

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(server.connections(), 1, "one connection per process");
    for r in &requests {
        assert_eq!(
            r.header("authorization"),
            Some(format!("Bearer {}", key.expose()).as_str())
        );
        // Each request asks the server to end its stream once answered: no idle stream holds a server slot.
        assert_eq!(r.header("connection"), Some("close"));
        assert_eq!(r.header("host"), Some("p2pc-tunnel.invalid"));
        assert!(r.header("user-agent").is_some_and(|ua| ua.starts_with("p2pc/")));
    }
    assert_eq!(requests[1].route(), "GET /v1/jobs");
    tunnel.close().await;
}

#[tokio::test]
async fn api_errors_and_retries_behave_as_over_tcp() {
    let calls = Arc::new(AtomicUsize::new(0));
    let job = fixtures::job(JobId::generate(), JobStatus::Queued, None);
    let body = serde_json::to_value(&job).unwrap();
    let server = {
        let calls = Arc::clone(&calls);
        MockTunnelServer::start(move |r| match r.route().as_str() {
            "POST /v1/jobs" if calls.fetch_add(1, Ordering::SeqCst) == 0 => {
                MockResponse::problem(503, "unavailable", "try again")
            }
            "POST /v1/jobs" => MockResponse::json(201, &body),
            _ => MockResponse::problem(404, "job_not_found", "no such job"),
        })
    };
    let key = ApiKey::generate();
    let (client, tunnel) = tunnel_client(&server, &key);
    // A 503 is retried with the same idempotency key.
    let got = client.create_job(&spec()).await.unwrap();
    assert_eq!(got.id, job.id);
    let posts = server.requests_to("POST /v1/jobs");
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].header("idempotency-key"), posts[1].header("idempotency-key"));
    // problem+json is an API error, not retried.
    let err = client.get_job(&JobId::generate()).await.unwrap_err();
    assert_eq!(err.api_code(), Some("job_not_found"));
    assert_eq!(server.requests().len(), 3);
    // A request that cannot be built is a local error, sent zero times.
    let mut bad = spec();
    bad.idempotency_key = Some("bad\nkey".into());
    let err = client.create_job(&bad).await.unwrap_err();
    assert!(matches!(err, Error::Local(_)), "{err:?}");
    assert_eq!(server.requests().len(), 3);
    tunnel.close().await;
}

#[tokio::test]
async fn a_lost_connection_is_reestablished_on_the_next_request() {
    let key = ApiKey::generate();
    let server = api(key.key_id());
    let (client, tunnel) = tunnel_client(&server, &key);
    client.whoami().await.unwrap();
    server.close_connections();
    // The client notices the closed connection when it needs a stream, reconnects once, and the request works.
    client.whoami().await.unwrap();
    assert_eq!(server.connections(), 2);
    assert_eq!(server.peers().len(), 1, "the same endpoint (NodeId) reconnects");
    tunnel.close().await;
}

#[tokio::test]
async fn downloads_and_log_pages_stream_through_the_tunnel() {
    use p2pc_proto::api::{LogLine, LogStream, OutputFile, Sha256Digest};
    use sha2::{Digest, Sha256};

    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let digest = Sha256Digest(Sha256::digest(&content).into());
    let lines: Vec<LogLine> = (1..=3)
        .map(|seq| LogLine {
            seq,
            stream: LogStream::Stdout,
            ts: fixtures::t0(),
            data: format!("line {seq}"),
        })
        .collect();
    let ndjson: Vec<u8> = lines
        .iter()
        .flat_map(|l| {
            let mut v = serde_json::to_vec(l).unwrap();
            v.push(b'\n');
            v
        })
        .collect();
    let server = {
        let content = content.clone();
        MockTunnelServer::start(move |r| {
            if r.path.ends_with("/logs") {
                MockResponse {
                    status: 200,
                    headers: vec![("Content-Type".into(), "application/x-ndjson".into())],
                    body: ndjson.clone(),
                }
            } else {
                MockResponse {
                    status: 200,
                    headers: vec![],
                    body: content.clone(),
                }
            }
        })
    };
    let (client, tunnel) = tunnel_client(&server, &ApiKey::generate());
    let id = JobId::generate();
    let page = client.log_page(&id, 2, None, 1 << 20).await.unwrap();
    assert_eq!(page.lines, lines[1..]);
    let file = OutputFile {
        path: "out/data.bin".into(),
        size: content.len() as u64,
        sha256: digest,
    };
    let mut sink = Vec::new();
    client.download_output(&id, None, &file, &mut sink).await.unwrap();
    assert_eq!(sink, content);
    tunnel.close().await;
}

#[tokio::test]
async fn an_unreachable_server_is_a_network_error_that_never_shows_the_key() {
    // A real NodeId nobody serves, a hint to a loopback port nobody listens on, no relay.
    let nobody = MockTunnelServer::start(|_| MockResponse::empty(200));
    let (address, hints) = (nobody.address(), nobody.addrs());
    drop(nobody);
    let tunnel = Tunnel::new(TunnelOptions {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        server_addrs: hints,
        connect_timeout: Duration::from_millis(500),
        ..TunnelOptions::new(address)
    })
    .unwrap();
    let key = ApiKey::generate();
    let client = Client::builder_tunnel(tunnel.clone(), key.clone())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();
    let err = client.whoami().await.unwrap_err();
    match &err {
        Error::Network(n) => assert!(matches!(n.kind(), NetworkKind::Timeout | NetworkKind::Connect), "{n:?}"),
        other => panic!("{other:?}"),
    }
    let secret = key.expose();
    let secret_part = secret.rsplit('_').next().unwrap();
    for text in [err.to_string(), format!("{err:?}"), format!("{client:?}")] {
        assert!(!text.contains(secret_part), "{text}");
    }
    tunnel.close().await;
}

/// §10 address hygiene, on a host like E4's: only the default-route interface's addresses are bound (so
/// advertised), never Tailscale, a bridge, link-local or loopback; the relays are the address's own.
#[test]
fn the_endpoint_plan_applies_the_address_hygiene() {
    let ifc = |name: &str, addrs: &[(&str, u8)]| {
        Interface::new(
            name,
            true,
            addrs
                .iter()
                .map(|(ip, p)| IfAddr::new(ip.parse().unwrap(), *p))
                .collect(),
        )
    };
    let host = vec![
        ifc("lo", &[("127.0.0.1", 8), ("::1", 128)]),
        ifc(
            "eth0",
            &[
                ("192.0.2.10", 24),
                ("169.254.3.4", 16),
                ("fe80::1", 64),
                ("100.64.1.2", 10),
                ("2001:db8::10", 64),
            ],
        ),
        ifc("tailscale0", &[("100.100.1.1", 32)]),
        ifc("docker0", &[("198.51.100.1", 24)]),
        ifc("vEthernet (WSL)", &[("198.18.0.1", 24)]),
        ifc("wlan0", &[("198.51.100.200", 24)]),
    ];
    let relay = Url::parse("https://relay.example.invalid/").unwrap();
    let address = ServerAddress::new("a".repeat(64), vec![relay.clone()]);
    let plan = endpoint_plan(&TunnelOptions::new(address.clone()), &host, Some("eth0"));
    let ips: Vec<String> = plan.bind.iter().map(|s| s.addr.ip.to_string()).collect();
    assert_eq!(ips, ["192.0.2.10", "2001:db8::10"]);
    assert_eq!(plan.relays, vec![relay.clone()]);
    // What `p2pc_net::bind_endpoint` gets: those relays only (never the public defaults), those sockets on port 0,
    // and no ALPN (a client accepts no connection). Port mapping and address lookup are fixed off in `p2pc_net`; the
    // bound endpoint is checked below, and the `portmapper` feature by `iroh_is_built_without_portmapper`.
    let spec = plan.bind_spec();
    assert_eq!(
        spec.relay_mode.relay_map().urls::<Vec<_>>(),
        vec![iroh::RelayUrl::from(relay)]
    );
    assert_eq!(spec.addrs, plan.bind);
    assert_eq!(spec.port, 0);
    assert!(spec.alpns.is_empty());
    // No default route known: relay only, never "every interface".
    assert!(
        endpoint_plan(&TunnelOptions::new(address.clone()), &host, None)
            .bind
            .is_empty()
    );
    // `none`: relay only.
    let relay_only = TunnelOptions {
        bind: DirectAddresses::None,
        ..TunnelOptions::new(address)
    };
    assert!(endpoint_plan(&relay_only, &host, Some("eth0")).bind.is_empty());
}

/// The endpoint `p2pc_net` binds for a plan, as the tunnel does: no address-lookup service at all (nothing publishes
/// or resolves addresses), and only the planned sockets.
#[tokio::test]
async fn the_bound_endpoint_has_no_address_lookup_and_only_the_planned_sockets() {
    let host = vec![Interface::new(
        "lo",
        true,
        vec![IfAddr::new("127.0.0.1".parse().unwrap(), 8)],
    )];
    let options = TunnelOptions {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        ..TunnelOptions::new(ServerAddress::new("a".repeat(64), vec![]))
    };
    let plan = endpoint_plan(&options, &host, None);
    let ep = p2pc_net::bind_endpoint(iroh::SecretKey::generate(), &plan.bind_spec())
        .await
        .unwrap();
    let lookup = ep.address_lookup().expect("the endpoint is open");
    assert!(lookup.is_empty(), "{} address-lookup services", lookup.len());
    assert!(ep.bound_sockets().iter().all(|a| a.ip().is_loopback()));
    ep.close().await;
}

/// The `portmapper` feature of iroh would ask the owner's router to open a port (§10). With it on, the `portmapper`
/// crate would be in the lock file; `scripts/check-iroh-features.sh` checks the feature itself in CI.
#[test]
fn iroh_is_built_without_portmapper() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
    assert!(lock.contains("name = \"iroh\""), "this is the workspace lock file");
    assert!(
        !lock.contains("name = \"portmapper\""),
        "iroh's portmapper must stay off"
    );
}

/// The endpoint that is really bound has exactly the planned sockets: here loopback only.
#[tokio::test]
async fn the_bound_endpoint_has_only_the_selected_sockets() {
    let key = ApiKey::generate();
    let server = api(key.key_id());
    let (client, tunnel) = tunnel_client(&server, &key);
    assert!(
        tunnel.bound_sockets().await.is_empty(),
        "nothing is bound before a request"
    );
    client.whoami().await.unwrap();
    let bound = tunnel.bound_sockets().await;
    assert!(!bound.is_empty());
    assert!(bound.iter().all(|a| a.ip().is_loopback()), "{bound:?}");
    tunnel.close().await;
}

#[test]
fn an_invalid_address_is_refused() {
    let bad = ServerAddress::new("not-a-node-id", vec![]);
    assert!(Tunnel::new(TunnelOptions::new(bad)).is_err());
}

/// A server address whose NodeId nobody serves, with a hint to a loopback port nobody listens on, and no relay.
fn dead_server_options(connect_timeout: Duration, reconnect_base: Duration) -> TunnelOptions {
    let nobody = MockTunnelServer::start(|_| MockResponse::empty(200));
    let (address, hints) = (nobody.address(), nobody.addrs());
    drop(nobody);
    TunnelOptions {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        server_addrs: hints,
        connect_timeout,
        reconnect_base,
        ..TunnelOptions::new(address)
    }
}

/// T11b1 review: while the server is unreachable, requests that wait for the tunnel do not each make a full
/// connection attempt in turn. One attempt fails; the others, inside its backoff window, fail at once with its error.
#[tokio::test]
async fn waiting_requests_fail_fast_inside_the_backoff_window() {
    let tunnel = Tunnel::new(dead_server_options(Duration::from_millis(300), Duration::from_secs(60))).unwrap();
    let waiters: Vec<_> = (0..8)
        .map(|_| {
            let t = tunnel.clone();
            tokio::spawn(async move { t.open_stream().await.map(|_| ()) })
        })
        .collect();
    let mut errors = Vec::new();
    for w in waiters {
        errors.push(w.await.unwrap().unwrap_err());
    }
    let (attempts, binds) = tunnel.counters().await;
    assert_eq!(attempts, 1, "one full attempt for eight waiting requests");
    assert_eq!(binds, 1);
    // They all carry the attempt's error.
    let first = errors[0].to_string();
    assert!(errors.iter().all(|e| e.to_string() == first), "{errors:?}");
    assert!(matches!(errors[0].kind(), NetworkKind::Timeout | NetworkKind::Connect));
    tunnel.close().await;
}

/// T11b1 review: after two failed reconnects in a row the endpoint is bound again, so a laptop whose network changed
/// uses its new default-route addresses.
#[tokio::test]
async fn the_endpoint_is_bound_again_after_two_failures_in_a_row() {
    // No backoff window, so every call makes an attempt.
    let tunnel = Tunnel::new(dead_server_options(Duration::from_millis(200), Duration::ZERO)).unwrap();
    for _ in 0..3 {
        assert!(tunnel.open_stream().await.is_err());
    }
    let (attempts, binds) = tunnel.counters().await;
    // Attempts 1 and 2 share the first endpoint; the second failure drops it, so attempt 3 binds a new one.
    assert_eq!((attempts, binds), (3, 2));
    tunnel.close().await;
}

/// T11b1 review: a caller that gives up in the middle of a connection attempt (a timeout, a cancelled MCP call) does
/// not cancel the attempt. Its failure is recorded, and the next caller fails fast inside the backoff window.
#[tokio::test]
async fn a_cancelled_connect_still_counts_as_a_failure() {
    let tunnel = Tunnel::new(dead_server_options(Duration::from_millis(500), Duration::from_secs(60))).unwrap();
    // Give up well before the 500 ms connect timeout.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), tunnel.open_stream())
            .await
            .is_err()
    );
    // The next request waits for that attempt's outcome, then fails at once with it: no second attempt.
    let err = tunnel.open_stream().await.map(|_| ()).unwrap_err();
    assert!(
        matches!(err.kind(), NetworkKind::Timeout | NetworkKind::Connect),
        "{err}"
    );
    assert_eq!(tunnel.counters().await.0, 1, "one attempt in all");
    tunnel.close().await;
}

/// T11b1 review: `close()` stops the tunnel for good. A connection task that a caller started and abandoned (a
/// timeout) must not bind or connect after it, and `close()` must not wait out the attempt that is in flight.
#[tokio::test]
async fn close_stops_the_tunnel_even_with_a_connect_in_flight() {
    // No backoff window and a long connect timeout: without the fix, every queued call makes a full attempt.
    let tunnel = Tunnel::new(dead_server_options(Duration::from_secs(20), Duration::ZERO)).unwrap();
    // Caller 1 gives up while its connection attempt runs in the task it started.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), tunnel.open_stream())
            .await
            .is_err()
    );
    // Caller 2 queues behind that attempt.
    let queued = {
        let t = tunnel.clone();
        tokio::spawn(async move { t.open_stream().await.map(|_| ()) })
    };
    tokio::task::yield_now().await;
    // `close()` returns promptly, and does not wait for the 20 s attempt.
    tokio::time::timeout(Duration::from_secs(5), tunnel.close())
        .await
        .expect("close() must not wait for the connection attempt in flight");
    // The queued call fails because the tunnel is closed; it does not start an attempt of its own.
    let err = tokio::time::timeout(Duration::from_secs(5), queued)
        .await
        .expect("the queued call ends")
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("tunnel closed"), "{err}");
    assert_eq!(tunnel.counters().await.0, 1, "no attempt after close()");
    // And any later call fails at once too.
    let err = tunnel.open_stream().await.map(|_| ()).unwrap_err();
    assert!(err.to_string().contains("tunnel closed"), "{err}");
    assert_eq!(
        tunnel.counters().await,
        (1, 1),
        "nothing was bound or connected after close()"
    );
}

/// A `p2pc/http/1` server that accepts every connection and closes it at once. Counts the handshakes.
async fn accept_and_close_server() -> (iroh::Endpoint, Arc<AtomicUsize>) {
    let spec = p2pc_net::BindSpec {
        relay_mode: iroh::RelayMode::Disabled,
        addrs: vec![p2pc_proto::net::SelectedAddr::new(
            IfAddr::new("127.0.0.1".parse().unwrap(), 8),
            "lo",
        )],
        port: 0,
        alpns: vec![p2pc_proto::PROTOCOL_ALPN_HTTP.to_vec()],
    };
    let ep = p2pc_net::bind_endpoint(iroh::SecretKey::generate(), &spec)
        .await
        .unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let (accepting, count) = (ep.clone(), Arc::clone(&handshakes));
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            if let Ok(conn) = incoming.await {
                count.fetch_add(1, Ordering::SeqCst);
                conn.close(0u32.into(), b"go away");
            }
        }
    });
    (ep, handshakes)
}

/// T11b1 review: a server that accepts and closes at once does not reset the backoff (only a stream that worked
/// does). One request costs at most two handshakes, and the requests after it fail fast.
#[tokio::test]
async fn a_server_that_accepts_and_closes_does_not_reset_the_backoff() {
    let (server, handshakes) = accept_and_close_server().await;
    let tunnel = Tunnel::new(TunnelOptions {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        server_addrs: server.bound_sockets(),
        reconnect_base: Duration::from_secs(60),
        ..TunnelOptions::new(ServerAddress::new(server.id().to_string(), vec![]))
    })
    .unwrap();
    let client = Client::builder_tunnel(tunnel.clone(), ApiKey::generate())
        .retry(RetryPolicy::immediate(3))
        .build()
        .unwrap();
    assert!(client.whoami().await.is_err());
    let after_first = handshakes.load(Ordering::SeqCst);
    assert!(
        (1..=2).contains(&after_first),
        "{after_first} handshakes for one request"
    );
    for _ in 0..5 {
        let err = client.whoami().await.unwrap_err();
        assert!(matches!(err, Error::Network(_)), "{err:?}");
    }
    assert_eq!(
        handshakes.load(Ordering::SeqCst),
        after_first,
        "later requests fail fast"
    );
    tunnel.close().await;
    server.close().await;
}

/// T11b1 review: a network change (here, `rebind` as the watcher calls it) drops the endpoint; the next request binds
/// a new one and reconnects.
#[tokio::test]
async fn rebind_binds_a_new_endpoint_and_the_next_request_reconnects() {
    let key = ApiKey::generate();
    let server = api(key.key_id());
    let (client, tunnel) = tunnel_client(&server, &key);
    client.whoami().await.unwrap();
    assert_eq!(tunnel.counters().await, (1, 1));
    tunnel.rebind().await;
    assert!(tunnel.bound_sockets().await.is_empty(), "the old endpoint is gone");
    client.whoami().await.unwrap();
    assert_eq!(tunnel.counters().await, (2, 2));
    assert_eq!(server.connections(), 2);
    assert_eq!(server.peers().len(), 2, "a new endpoint is a new (ephemeral) NodeId");
    tunnel.close().await;
}

/// The network watch of long-running commands starts and stops with its handle, and the tunnel keeps working. (The
/// re-selection itself is `p2pc_net::watch_network`'s, shared with the server and the agent; what it triggers here is
/// `Tunnel::rebind`, tested above.)
#[tokio::test]
async fn the_network_watch_runs_beside_the_tunnel_and_stops_with_its_handle() {
    let key = ApiKey::generate();
    let server = api(key.key_id());
    let (client, tunnel) = tunnel_client(&server, &key);
    let watch = tunnel.watch_network().await;
    client.whoami().await.unwrap();
    drop(watch);
    client.whoami().await.unwrap();
    assert_eq!(
        tunnel.counters().await,
        (1, 1),
        "no spurious re-bind: the addresses did not change"
    );
    tunnel.close().await;
}
