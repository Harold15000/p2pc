// SPDX-License-Identifier: AGPL-3.0-only

//! The node gateway over real iroh connections: two in-process endpoints bound to loopback with relays disabled,
//! and the injectable clock for every expiry (spec §5, §6, §10; SI-10, SI-11, SI-13 server half).
//!
//! Nothing here sleeps to synchronise: the tests wait on protocol replies, connection closes and hub events, each
//! under a timeout that only fires when something is broken. The one short real timeout (the first-message
//! deadline, set to 300 ms) is the behaviour under test.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::http::{Method, StatusCode};
use common::{T0, TestApp, inventory};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, SecretKey};

use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{LeaseId, NodeId};
use p2pc_proto::protocol::{
    AgentMsg, Load, MAX_FRAME_LEN, RunningLease, ServerMsg, decode_frame, read_frame_bytes, write_frame,
};
use p2pc_proto::{PROTOCOL_ALPN_AGENT, PROTOCOL_ALPN_HTTP};
use p2pc_server::app::AppState;
use p2pc_server::clock::Clock as _;
use p2pc_server::config::Config;
use p2pc_server::gateway::endpoint::bind;
use p2pc_server::gateway::{
    BoxFuture, EndpointOptions, Gateway, GatewayConfig, GatewayLimits, HubEvent, NodeEvents, OfflineReason,
};
use p2pc_server::store::nodes;
use serde::Serialize;
use serde_json::{Value, json};
use time::Duration;
use tokio::sync::{broadcast, mpsc};

/// A tick in a test must not have failed any step.
trait Clean {
    fn clean(self) -> Self;
}

impl Clean for p2pc_server::scheduler::TickReport {
    fn clean(self) -> Self {
        assert_eq!(self.errors, 0, "a scheduling step failed: see the log");
        self
    }
}

/// The bound for anything that should happen promptly. Only reached when something is broken.
const WAIT: StdDuration = StdDuration::from_secs(10);

/// Records what the gateway routes to [`NodeEvents`].
#[derive(Debug)]
struct Recorder {
    tx: mpsc::UnboundedSender<(NodeId, String)>,
}

impl NodeEvents for Recorder {
    fn on_message(&self, node_id: NodeId, msg: AgentMsg) -> BoxFuture<'_, ()> {
        let _ = self.tx.send((node_id, msg.kind().to_string()));
        Box::pin(async {})
    }

    fn on_node_offline(&self, node_id: NodeId, reason: OfflineReason) -> BoxFuture<'_, ()> {
        let what = match reason {
            OfflineReason::Lost => "offline:lost",
            OfflineReason::Deleted => "offline:deleted",
        };
        let _ = self.tx.send((node_id, what.to_string()));
        Box::pin(async {})
    }
}

struct Harness {
    app: TestApp,
    gw: Gateway,
    events: mpsc::UnboundedReceiver<(NodeId, String)>,
    hub_events: broadcast::Receiver<HubEvent>,
    /// Hub events received while waiting for another one, kept for the next wait (review P2: a wait must never
    /// throw away an event another wait needs).
    seen: Vec<HubEvent>,
}

fn test_limits() -> GatewayLimits {
    GatewayLimits {
        // The background sweep never runs during a test: the tests sweep after moving the clock.
        sweep_interval: StdDuration::from_secs(3600),
        ..GatewayLimits::default()
    }
}

async fn start_with(app: TestApp, state: AppState, limits: GatewayLimits, rest: std::net::SocketAddr) -> Harness {
    let (tx, events) = mpsc::unbounded_channel();
    let hub_events = state.hub.subscribe();
    let mut config = GatewayConfig::new(EndpointOptions::loopback_without_relays(), rest);
    config.limits = limits;
    config.events = Arc::new(Recorder { tx });
    let gw = Gateway::start(state, config).await.unwrap();
    Harness {
        app,
        gw,
        events,
        hub_events,
        seen: Vec::new(),
    }
}

async fn start(limits: GatewayLimits) -> Harness {
    let app = TestApp::new().await;
    let state = app.state.clone();
    start_with(app, state, limits, "127.0.0.1:9".parse().unwrap()).await
}

impl Harness {
    fn addr(&self) -> EndpointAddr {
        let ep = self.gw.endpoint();
        EndpointAddr::new(ep.id()).with_ip_addr(ep.bound_sockets()[0])
    }

    async fn token(&self, body: Value) -> JoinToken {
        let r = self
            .app
            .call(Method::POST, "/v1/nodes/join-tokens", Some(&self.app.admin), Some(body))
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap()
    }

    async fn agent(&self, key: &SecretKey) -> Agent {
        Agent::connect(self.addr(), key, PROTOCOL_ALPN_AGENT).await
    }

    /// Waits for the first hub event that `wanted` matches, taking it from the events already seen if one is there.
    /// Events that do not match are kept, in order, for later waits.
    async fn hub_event(&mut self, what: &str, wanted: impl Fn(&HubEvent) -> bool) {
        if let Some(i) = self.seen.iter().position(&wanted) {
            self.seen.remove(i);
            return;
        }
        let rx = &mut self.hub_events;
        let seen = &mut self.seen;
        tokio::time::timeout(WAIT, async {
            loop {
                let e = rx.recv().await.unwrap();
                if wanted(&e) {
                    return;
                }
                seen.push(e);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {what} event"));
    }

    /// Waits for the hub to report `node_id` connected.
    async fn connected(&mut self, node_id: NodeId) {
        self.hub_event("Connected", |e| matches!(e, HubEvent::Connected(id) if *id == node_id))
            .await;
    }

    async fn disconnected(&mut self, node_id: NodeId) {
        self.hub_event(
            "Disconnected",
            |e| matches!(e, HubEvent::Disconnected(id) if *id == node_id),
        )
        .await;
    }

    async fn event(&mut self) -> (NodeId, String) {
        tokio::time::timeout(WAIT, self.events.recv()).await.unwrap().unwrap()
    }

    async fn node_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(&self.app.db)
            .await
            .unwrap()
    }

    async fn node(&self, id: NodeId) -> nodes::NodeRow {
        let mut c = self.app.db.acquire().await.unwrap();
        nodes::by_id(&mut c, id).await.unwrap().unwrap()
    }

    /// Joins a new agent and returns it, connected, with its node ID.
    async fn joined(&mut self, key: &SecretKey, hostname: &str) -> (Agent, NodeId) {
        let token = self.token(json!({})).await;
        let mut agent = self.agent(key).await;
        agent.join(&token, hostname).await;
        let node_id = agent.welcome().await;
        self.connected(node_id).await;
        (agent, node_id)
    }
}

struct Agent {
    _ep: Endpoint,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl Agent {
    async fn connect(addr: EndpointAddr, key: &SecretKey, alpn: &[u8]) -> Agent {
        let ep = bind(key.clone(), &EndpointOptions::loopback_without_relays())
            .await
            .unwrap();
        let conn = tokio::time::timeout(WAIT, ep.connect(addr, alpn))
            .await
            .unwrap()
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        Agent {
            _ep: ep,
            conn,
            send,
            recv,
        }
    }

    async fn send(&mut self, msg: &impl Serialize) {
        write_frame(&mut self.send, msg).await.unwrap();
    }

    async fn join(&mut self, token: &JoinToken, hostname: &str) {
        self.send(&AgentMsg::Join {
            token: token.clone(),
            inventory: inventory(hostname),
        })
        .await;
    }

    async fn hello(&mut self, version: &str, running: Vec<RunningLease>) {
        self.send(&AgentMsg::Hello {
            agent_version: version.into(),
            inventory: inventory("node-1"),
            running,
            features: vec!["lease_restrictions_v1".into()],
        })
        .await;
    }

    async fn heartbeat(&mut self, seq: u64) {
        self.send(&AgentMsg::Heartbeat {
            seq,
            load: Load {
                cpu_pct: 3,
                mem_used_mb: 100,
                gpu_util_pct: None,
            },
            running: vec![],
        })
        .await;
    }

    /// The next frame's raw bytes, or `None` when the stream or the connection ended.
    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(WAIT, read_frame_bytes(&mut self.recv, MAX_FRAME_LEN))
            .await
            .expect("no frame and no close")
            .ok()
            .flatten()
    }

    async fn recv(&mut self) -> Option<ServerMsg> {
        self.recv_raw().await.map(|b| decode_frame(&b).unwrap())
    }

    async fn welcome(&mut self) -> NodeId {
        match self.recv().await {
            Some(ServerMsg::Welcome { node_id, .. }) => node_id,
            other => panic!("expected Welcome, got {other:?}"),
        }
    }

    async fn expect_error(&mut self, code: &str) {
        match self.recv().await {
            Some(ServerMsg::Error { code: got, .. }) => assert_eq!(got, code),
            other => panic!("expected Error{{{code}}}, got {other:?}"),
        }
    }

    /// Closes the connection and the endpoint, as an agent that exits does.
    async fn close(self) {
        self.conn.close(0u32.into(), b"bye");
        self._ep.close().await;
    }

    /// Asserts the server closes the connection, with no further message.
    async fn expect_closed(&mut self) {
        assert_eq!(self.recv().await, None, "expected a close with no detail");
        tokio::time::timeout(WAIT, self.conn.closed())
            .await
            .expect("connection still open");
    }
}

#[tokio::test]
async fn join_enrolls_a_node_in_the_tokens_account() {
    let mut h = start(test_limits()).await;
    let token = h.token(json!({"label": "box"})).await;
    let key = SecretKey::generate();
    let mut agent = h.agent(&key).await;
    agent.join(&token, "node-1.example.invalid").await;
    let Some(ServerMsg::Welcome {
        node_id,
        account_id,
        heartbeat_interval_s,
        lease_ttl_s,
        server_version,
        pending_approval,
    }) = agent.recv().await
    else {
        panic!("no Welcome");
    };
    // H1 behaviour until node approval lands (H2 §5.5).
    assert!(!pending_approval);
    assert_eq!(account_id, h.app.account_id);
    assert_eq!((heartbeat_interval_s, lease_ttl_s), (5, 60));
    assert_eq!(server_version, env!("CARGO_PKG_VERSION"));
    h.connected(node_id).await;
    assert!(h.gw.hub().is_connected(node_id));
    let row = h.node(node_id).await;
    assert_eq!(row.iroh_node_id, key.public().to_string());
    assert_eq!(row.account_id, h.app.account_id);
    assert_eq!(row.project_id, h.app.project_id);
    assert_eq!(row.name, "node-1");
    assert_eq!(row.state, nodes::DbState::Online);
    let api = h.app.get(&format!("/v1/nodes/{node_id}"), &h.app.admin).await.json();
    assert_eq!(api["state"], "online");
    // The token is consumed by this node, and both events are audited.
    let tokens = h.app.get("/v1/nodes/join-tokens", &h.app.admin).await.json();
    assert_eq!(tokens["items"][0]["consumed_by_node_id"], node_id.to_string());
    for kind in ["join_token_consumed", "node_enrolled"] {
        let a = h.app.get(&format!("/v1/audit?kind={kind}"), &h.app.admin).await.json();
        assert_eq!(a["items"].as_array().unwrap().len(), 1, "{kind}");
    }
    // The connection carries on: every heartbeat gets its ack.
    for seq in 1..=5 {
        agent.heartbeat(seq).await;
        assert_eq!(agent.recv().await, Some(ServerMsg::HeartbeatAck { seq }));
    }
    // A second Join on the same connection closes it.
    agent.join(&token, "node-1").await;
    agent.expect_closed().await;
}

/// SI-11: the row's expiry decides, never the payload's.
#[tokio::test]
async fn an_expired_token_is_refused_even_with_a_forged_later_expiry() {
    let h = start(test_limits()).await;
    let token = h.token(json!({"ttl_s": 60})).await;
    h.app.clock.advance(Duration::seconds(60));
    let forged = JoinToken {
        expires_at: T0 + Duration::days(365),
        ..token.clone()
    };
    assert!(!forged.is_expired(h.app.clock.now()), "the payload alone says valid");
    let mut agent = h.agent(&SecretKey::generate()).await;
    agent.join(&forged, "late").await;
    agent.expect_error("invalid_token").await;
    agent.expect_closed().await;
    assert_eq!(h.node_count().await, 0);
}

#[tokio::test]
async fn revoked_and_wrong_code_tokens_are_refused() {
    let h = start(test_limits()).await;
    let revoked = h.token(json!({})).await;
    let id: String = sqlx::query_scalar("SELECT id FROM join_tokens")
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    let r = h
        .app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/join-tokens/{id}"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let valid = h.token(json!({})).await;
    let mut wrong = valid.clone();
    wrong.code[0] ^= 1;
    for token in [revoked, wrong] {
        let mut agent = h.agent(&SecretKey::generate()).await;
        agent.join(&token, "x").await;
        agent.expect_error("invalid_token").await;
        agent.expect_closed().await;
    }
    assert_eq!(h.node_count().await, 0);
    // Failed joins are audited, aggregated per minute.
    h.app.flush_audit().await;
    let a = h.app.get("/v1/audit?kind=auth_failed", &h.app.admin).await.json();
    assert_eq!(a["items"][0]["subject_id"], "join");
    assert_eq!(a["items"][0]["detail"]["count"], 2);
}

/// SI-11: a retry by the same NodeId gets the same `Welcome`; a consumed token refuses everyone else.
#[tokio::test]
async fn a_retry_by_the_same_node_id_is_idempotent_and_others_are_refused() {
    let mut h = start(test_limits()).await;
    let token = h.token(json!({})).await;
    let key = SecretKey::generate();
    let mut first = h.agent(&key).await;
    first.join(&token, "a").await;
    let node_id = first.welcome().await;
    h.connected(node_id).await;
    // The agent lost the Welcome and retries on a new connection, with the same token.
    let mut retry = h.agent(&key).await;
    retry.join(&token, "a").await;
    assert_eq!(retry.welcome().await, node_id);
    // Even after the row's expiry: the NodeId, not the token, now proves who it is.
    h.app.clock.advance(Duration::hours(1));
    let mut late = h.agent(&key).await;
    late.join(&token, "a").await;
    assert_eq!(late.welcome().await, node_id);
    let mut other = h.agent(&SecretKey::generate()).await;
    other.join(&token, "b").await;
    other.expect_error("invalid_token").await;
    assert_eq!(h.node_count().await, 1);
}

/// SI-11: two concurrent `Join`s with one token create exactly one node.
#[tokio::test]
async fn two_concurrent_joins_with_one_token_create_exactly_one_node() {
    let h = start(test_limits()).await;
    let token = h.token(json!({})).await;
    let mut a = h.agent(&SecretKey::generate()).await;
    let mut b = h.agent(&SecretKey::generate()).await;
    let (ra, rb) = tokio::join!(
        async {
            a.join(&token, "a").await;
            a.recv().await
        },
        async {
            b.join(&token, "b").await;
            b.recv().await
        }
    );
    let welcomes = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Some(ServerMsg::Welcome { .. })))
        .count();
    let refusals = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Some(ServerMsg::Error { code, .. }) if code == "invalid_token"))
        .count();
    assert_eq!((welcomes, refusals), (1, 1), "{ra:?} {rb:?}");
    assert_eq!(h.node_count().await, 1);
}

/// A join token of `key`'s account (any admin key).
async fn token_with(h: &Harness, key: &str) -> JoinToken {
    let r = h
        .app
        .call(Method::POST, "/v1/nodes/join-tokens", Some(key), Some(json!({})))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap()
}

async fn audit_count(h: &Harness, kind: &str) -> usize {
    let a = h.app.get(&format!("/v1/audit?kind={kind}"), &h.app.admin).await.json();
    a["items"].as_array().unwrap().len()
}

/// §5 "Re-enrolling the same machine" (T14b2 real run): `join --force` with a new token from a NodeId that is still a
/// live node of the token's account re-enrolls it: the same node id, a refreshed inventory, the project of the
/// token, the token consumed, and `node_reenrolled` audited.
#[tokio::test]
async fn a_join_from_a_live_node_of_the_same_account_re_enrolls_it() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "old-name").await;
    agent.close().await;
    h.disconnected(node_id).await;
    let token = h.token(json!({"label": "again"})).await;
    let mut again = h.agent(&key).await;
    again.join(&token, "new-host").await;
    assert_eq!(again.welcome().await, node_id, "the same node id");
    h.connected(node_id).await;
    assert_eq!(h.node_count().await, 1);
    let row = h.node(node_id).await;
    assert_eq!(row.inventory.hostname, "new-host", "the inventory is refreshed");
    assert_eq!(row.name, "old-name", "the name is kept");
    assert_eq!((row.account_id, row.project_id), (h.app.account_id, h.app.project_id));
    assert_eq!(row.state, nodes::DbState::Online);
    let tokens = h.app.get("/v1/nodes/join-tokens", &h.app.admin).await.json();
    let used = tokens["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["label"] == "again")
        .unwrap()
        .clone();
    assert_eq!(used["consumed_by_node_id"], node_id.to_string());
    assert_eq!(audit_count(&h, "node_reenrolled").await, 1);
    assert_eq!(
        audit_count(&h, "node_enrolled").await,
        1,
        "enrolled once, re-enrolled once"
    );
    assert_eq!(audit_count(&h, "join_token_consumed").await, 2);
    let a = h.app.get("/v1/audit?kind=node_reenrolled", &h.app.admin).await.json();
    assert_eq!(a["items"][0]["subject_id"], node_id.to_string());
    // The connection is a normal session.
    sync(&mut again, 1).await;
    // A retry of that same join (a lost `Welcome`) is idempotent, as for a first enrolment.
    let mut retry = h.agent(&key).await;
    retry.join(&token, "new-host").await;
    assert_eq!(retry.welcome().await, node_id);
    assert_eq!(audit_count(&h, "node_reenrolled").await, 1);
}

/// §5: a live node of another account is refused like an invalid token, and nothing changes.
#[tokio::test]
async fn a_join_from_a_live_node_of_another_account_is_refused() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "mine").await;
    agent.close().await;
    h.disconnected(node_id).await;
    let (other_admin, _) = common::second_account(&h.app).await;
    let theirs = token_with(&h, &other_admin).await;
    let mut again = h.agent(&key).await;
    again.join(&theirs, "stolen").await;
    again.expect_error("invalid_token").await;
    again.expect_closed().await;
    let row = h.node(node_id).await;
    assert_eq!(
        (row.account_id, row.inventory.hostname.as_str()),
        (h.app.account_id, "mine")
    );
    let unused: Option<String> =
        sqlx::query_scalar("SELECT consumed_by_node_id FROM join_tokens WHERE account_id != ?")
            .bind(h.app.account_id.to_string())
            .fetch_one(&h.app.db)
            .await
            .unwrap();
    assert_eq!(unused, None, "the other account's token is not consumed");
    assert_eq!(audit_count(&h, "node_reenrolled").await, 0);
}

/// A deleted node is not live: its NodeId joins as a new node, as before the re-enrolment rule.
#[tokio::test]
async fn a_deleted_node_joins_again_as_a_new_node() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "box").await;
    let r = h
        .app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/{node_id}"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    drop(agent);
    let token = h.token(json!({})).await;
    let mut again = h.agent(&key).await;
    again.join(&token, "box").await;
    let new_id = again.welcome().await;
    assert_ne!(new_id, node_id);
    assert_eq!(h.node_count().await, 2);
    assert_eq!(audit_count(&h, "node_enrolled").await, 2);
    assert_eq!(audit_count(&h, "node_reenrolled").await, 0);
}

/// Review P2 (the harness): waiting for one node's event keeps the events of others for their own waits, in any
/// order. `b` disconnects first, but the test waits for `a` first.
#[tokio::test]
async fn the_harness_keeps_hub_events_that_another_wait_needs() {
    let mut h = start(test_limits()).await;
    let (a, na) = h.joined(&SecretKey::generate(), "a").await;
    let (b, nb) = h.joined(&SecretKey::generate(), "b").await;
    b.close().await;
    tokio::time::timeout(WAIT, async {
        while h.gw.hub().is_connected(nb) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("b never left the hub");
    a.close().await;
    h.disconnected(na).await;
    h.disconnected(nb).await;
}

/// SI-11 for re-enrolment: two live nodes re-join at once with one token: exactly one succeeds.
#[tokio::test]
async fn two_concurrent_re_joins_with_one_token_re_enroll_exactly_one_node() {
    let mut h = start(test_limits()).await;
    let (ka, kb) = (SecretKey::generate(), SecretKey::generate());
    let (a0, na) = h.joined(&ka, "a").await;
    let (b0, nb) = h.joined(&kb, "b").await;
    a0.close().await;
    b0.close().await;
    h.disconnected(na).await;
    h.disconnected(nb).await;
    let token = h.token(json!({})).await;
    let mut a = h.agent(&ka).await;
    let mut b = h.agent(&kb).await;
    let (ra, rb) = tokio::join!(
        async {
            a.join(&token, "a2").await;
            a.recv().await
        },
        async {
            b.join(&token, "b2").await;
            b.recv().await
        }
    );
    let welcomed: Vec<NodeId> = [&ra, &rb]
        .iter()
        .filter_map(|r| match r {
            Some(ServerMsg::Welcome { node_id, .. }) => Some(*node_id),
            _ => None,
        })
        .collect();
    let refusals = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Some(ServerMsg::Error { code, .. }) if code == "invalid_token"))
        .count();
    assert_eq!((welcomed.len(), refusals), (1, 1), "{ra:?} {rb:?}");
    assert!(welcomed[0] == na || welcomed[0] == nb);
    assert_eq!(h.node_count().await, 2);
    assert_eq!(audit_count(&h, "node_reenrolled").await, 1);
}

/// §5 "Ownership": the account comes from the token row, never from the message or the inventory.
#[tokio::test]
async fn a_join_claiming_another_account_still_gets_the_tokens_account() {
    let h = start(test_limits()).await;
    let token = h.token(json!({})).await;
    let other = "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let mut inv = serde_json::to_value(inventory("claims")).unwrap();
    inv["account_id"] = json!(other);
    inv["project_id"] = json!("prj_01ARZ3NDEKTSV4RRFFQ69G5FAV");
    let msg = json!({"type": "join", "token": token.encode().unwrap(), "inventory": inv, "account_id": other});
    let mut agent = h.agent(&SecretKey::generate()).await;
    agent.send(&msg).await;
    let Some(ServerMsg::Welcome {
        node_id, account_id, ..
    }) = agent.recv().await
    else {
        panic!("no Welcome");
    };
    assert_eq!(account_id, h.app.account_id);
    assert_eq!(h.node(node_id).await.account_id, h.app.account_id);
}

#[tokio::test]
async fn a_connection_that_sends_nothing_is_closed_at_the_deadline() {
    let h = start(GatewayLimits {
        first_message_timeout: StdDuration::from_millis(300),
        ..test_limits()
    })
    .await;
    let mut agent = h.agent(&SecretKey::generate()).await;
    // The stream exists only once it carries data: send a partial frame prefix, then nothing.
    agent.send.write_all(&[0, 0]).await.unwrap();
    agent.expect_closed().await;
    // A connection that opens no stream at all is closed too.
    let silent = Agent::connect(h.addr(), &SecretKey::generate(), PROTOCOL_ALPN_AGENT).await;
    tokio::time::timeout(WAIT, silent.conn.closed())
        .await
        .expect("still open");
}

/// §6 "Before Join": failed `Join`s are limited per NodeId and in total; beyond that, close with no detail.
#[tokio::test]
async fn failed_joins_are_rate_limited_per_node_id() {
    let h = start(test_limits()).await;
    let valid = h.token(json!({})).await;
    let mut bad = valid.clone();
    bad.code[3] ^= 0xff;
    let key = SecretKey::generate();
    for _ in 0..10 {
        let mut a = h.agent(&key).await;
        a.join(&bad, "x").await;
        a.expect_error("invalid_token").await;
    }
    // The 11th attempt in the minute is closed with no detail, even with a valid token.
    let mut a = h.agent(&key).await;
    a.join(&valid, "x").await;
    a.expect_closed().await;
    assert_eq!(h.node_count().await, 0);
    // Another NodeId is not affected.
    let mut b = h.agent(&SecretKey::generate()).await;
    b.join(&bad, "y").await;
    b.expect_error("invalid_token").await;
    // The next minute, the first NodeId may try again.
    h.app.clock.advance(Duration::seconds(60));
    let mut a = h.agent(&key).await;
    a.join(&valid, "x").await;
    a.welcome().await;
}

/// Beyond the total of failed `Join`s, a bad `Join` gets no detailed answer (a valid one still enrolls: H2 §6.1, see
/// the next test).
#[tokio::test]
async fn failed_joins_are_rate_limited_in_total() {
    let h = start(GatewayLimits {
        join_failures_per_minute: 3,
        ..test_limits()
    })
    .await;
    let mut bad = h.token(json!({})).await;
    bad.code[0] ^= 1;
    for _ in 0..3 {
        let mut a = h.agent(&SecretKey::generate()).await;
        a.join(&bad, "x").await;
        a.expect_error("invalid_token").await;
    }
    let mut a = h.agent(&SecretKey::generate()).await;
    a.join(&bad, "x").await;
    a.expect_closed().await;
}

/// H2 §6.1, SI-H2-17 (T2-17): with the total of failed `Join`s reached by other NodeIds, a `Join` with a valid token
/// from a fresh NodeId that gets a slot still enrolls. The total limits failure answers only, never the lookup.
#[tokio::test]
async fn a_valid_join_enrolls_after_other_node_ids_exhaust_the_failure_total() {
    let mut h = start(GatewayLimits {
        join_failures_per_minute: 3,
        ..test_limits()
    })
    .await;
    let valid = h.token(json!({})).await;
    let mut bad = valid.clone();
    bad.code[0] ^= 1;
    for _ in 0..3 {
        let mut a = h.agent(&SecretKey::generate()).await;
        a.join(&bad, "x").await;
        a.expect_error("invalid_token").await;
    }
    // The total is reached: a further bad `Join` gets no detail.
    let mut over = h.agent(&SecretKey::generate()).await;
    over.join(&bad, "x").await;
    over.expect_closed().await;
    // A valid token still enrolls, in the same minute.
    let mut good = h.agent(&SecretKey::generate()).await;
    good.join(&valid, "good").await;
    let node_id = good.welcome().await;
    h.connected(node_id).await;
    assert_eq!(h.node_count().await, 1);
    assert_eq!(audit_count(&h, "node_enrolled").await, 1);
}

/// H2 §6.1, §5.3 (T2-17): bad `Join`s beyond the total are still refused, with no detail, and counted into the one
/// aggregated `auth_failed` row; they still count against their own NodeId, whose limit refuses it without the
/// lookup, even with a valid token.
#[tokio::test]
async fn bad_joins_beyond_the_total_are_refused_audited_and_count_per_node_id() {
    let h = start(GatewayLimits {
        join_failures_per_node_per_minute: 2,
        join_failures_per_minute: 1,
        ..test_limits()
    })
    .await;
    let valid = h.token(json!({})).await;
    let mut bad = valid.clone();
    bad.code[5] ^= 0x10;
    let key = SecretKey::generate();
    // The first failure gets its detailed answer; it reaches the total.
    let mut a = h.agent(&key).await;
    a.join(&bad, "x").await;
    a.expect_error("invalid_token").await;
    // Beyond the total, the token is looked up, found invalid, and refused with no detail.
    let mut a = h.agent(&key).await;
    a.join(&bad, "x").await;
    a.expect_closed().await;
    let mut other = h.agent(&SecretKey::generate()).await;
    other.join(&bad, "y").await;
    other.expect_closed().await;
    // `key` is now over its own limit (2): refused without the lookup, even with the valid token.
    let mut a = h.agent(&key).await;
    a.join(&valid, "x").await;
    a.expect_closed().await;
    assert_eq!(h.node_count().await, 0);
    // The three failures are audited in the one aggregated row; the refusal without lookup is not a failure.
    h.app.flush_audit().await;
    let audit = h.app.get("/v1/audit?kind=auth_failed", &h.app.admin).await.json();
    let items = audit["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{audit}");
    assert_eq!(items[0]["subject_id"], "join");
    assert_eq!(items[0]["detail"]["count"], 3);
    // The valid token was never consumed: a fresh NodeId still enrolls with it.
    let mut b = h.agent(&SecretKey::generate()).await;
    b.join(&valid, "b").await;
    b.welcome().await;
}

/// H2 §6.1 (T2-17): a `Join` with a valid token never consumes the failure budget, per NodeId or in total, and
/// neither does the idempotent retry of an enrolled NodeId.
#[tokio::test]
async fn valid_joins_never_consume_the_failure_budget() {
    let h = start(GatewayLimits {
        join_failures_per_node_per_minute: 1,
        join_failures_per_minute: 1,
        ..test_limits()
    })
    .await;
    for i in 0..3 {
        let token = h.token(json!({})).await;
        let key = SecretKey::generate();
        let mut a = h.agent(&key).await;
        a.join(&token, &format!("n{i}")).await;
        let node_id = a.welcome().await;
        // The same NodeId retries with the same token, more often than its failure limit.
        for _ in 0..2 {
            let mut retry = h.agent(&key).await;
            retry.join(&token, &format!("n{i}")).await;
            assert_eq!(retry.welcome().await, node_id);
        }
    }
    assert_eq!(h.node_count().await, 3);
    // The budget is untouched: the first failure of the minute still gets its detailed answer.
    let mut bad = h.token(json!({})).await;
    bad.code[1] ^= 1;
    let mut a = h.agent(&SecretKey::generate()).await;
    a.join(&bad, "x").await;
    a.expect_error("invalid_token").await;
    h.app.flush_audit().await;
    let audit = h.app.get("/v1/audit?kind=auth_failed", &h.app.admin).await.json();
    assert_eq!(audit["items"][0]["detail"]["count"], 1, "{audit}");
}

/// T05 review, carry-over 6: when the network changes, the gateway binds a new endpoint on the newly selected
/// addresses and closes the old one. Agents connected before are dropped and reconnect to the new one.
#[tokio::test]
async fn a_network_change_rebinds_the_endpoint_and_agents_reconnect() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "roamer").await;
    let old = h.gw.endpoint();
    let old_addr = h.addr();
    let loopback = p2pc_proto::net::SelectedAddr::new(
        p2pc_proto::net::IfAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8),
        "lo",
    );
    h.gw.rebind_to(vec![loopback]).await;
    assert!(old.is_closed(), "the old endpoint is closed");
    assert_ne!(h.addr(), old_addr, "a new socket");
    assert_eq!(h.gw.endpoint().id(), old.id(), "same identity");
    agent.expect_closed().await;
    h.disconnected(node_id).await;
    // The new endpoint serves: the node reconnects with Hello.
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    assert_eq!(again.welcome().await, node_id);
    h.connected(node_id).await;
}

/// §6 "Before Join": connections from NodeIds that are not enrolled are capped; enrolled nodes are not.
#[tokio::test]
async fn connections_from_unknown_node_ids_are_capped() {
    let mut h = start(GatewayLimits {
        max_unknown_connections: 1,
        ..test_limits()
    })
    .await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "n").await;
    agent.close().await;
    h.disconnected(node_id).await;
    // Two unknown NodeIds contend for the only slot. The first one sends the start of a frame and then waits;
    // the second sends a Hello. Whichever handler runs first holds the slot: the other is closed with no detail.
    let mut waiting = h.agent(&SecretKey::generate()).await;
    waiting.send.write_all(&[0]).await.unwrap();
    let mut second = h.agent(&SecretKey::generate()).await;
    second.hello("0.1.0", vec![]).await;
    match second.recv().await {
        // The second won the slot: it gets its answer, and the waiting one was refused.
        Some(ServerMsg::Error { code, .. }) => {
            assert_eq!(code, "not_enrolled");
            waiting.expect_closed().await;
        }
        // The waiting one holds the slot: the second was closed with no detail, and the waiting one is open.
        None => assert!(waiting.conn.close_reason().is_none(), "both were closed"),
        other => panic!("{other:?}"),
    }
    // The enrolled node is never capped.
    let mut enrolled = h.agent(&key).await;
    enrolled.hello("0.1.0", vec![]).await;
    assert_eq!(enrolled.welcome().await, node_id);
}

/// §6 "Before Join": at most `max_pending_joins` `Join`s are processed at once; one beyond the cap is closed with no
/// detail. The test holds SQLite's write lock, so a `Join` that got a slot waits inside its transaction (with the
/// slot) until the lock is released; nothing depends on timing.
#[tokio::test]
async fn pending_joins_are_capped() {
    let h = start(GatewayLimits {
        max_pending_joins: 1,
        ..test_limits()
    })
    .await;
    let token = h.token(json!({})).await;
    let lock = p2pc_server::store::begin_immediate(&h.app.db).await.unwrap();
    let mut a = h.agent(&SecretKey::generate()).await;
    let mut b = h.agent(&SecretKey::generate()).await;
    a.join(&token, "a").await;
    b.join(&token, "b").await;
    // Whichever `Join` reached the cap first is stuck on the lock; the other is refused at once, with no detail.
    let (mut waiting, refused_first) = tokio::select! {
        r = a.recv() => (b, r),
        r = b.recv() => (a, r),
    };
    assert_eq!(
        refused_first, None,
        "the Join over the cap must be closed with no detail"
    );
    // Release the lock: the waiting `Join` completes and enrolls the node.
    drop(lock);
    waiting.welcome().await;
    assert_eq!(h.node_count().await, 1);
    // The slot is free again: the next `Join` is processed (and refused, the token being consumed).
    let mut c = h.agent(&SecretKey::generate()).await;
    c.join(&token, "c").await;
    c.expect_error("invalid_token").await;
}

/// The bytes of a `Hello` frame, to send in two parts: the start now (so the server reads its stream), the rest
/// later.
async fn hello_frame() -> Vec<u8> {
    let mut buf = Vec::new();
    write_frame(
        &mut buf,
        &AgentMsg::Hello {
            agent_version: "0.1.0".into(),
            inventory: inventory("node-1"),
            running: vec![],
            features: vec![],
        },
    )
    .await
    .unwrap();
    buf
}

/// Waits until exactly one of `agents` is closed by the server, and returns its index. The others are still open.
async fn exactly_one_closed(agents: &[Agent]) -> usize {
    let mut set = tokio::task::JoinSet::new();
    for (i, a) in agents.iter().enumerate() {
        let conn = a.conn.clone();
        set.spawn(async move {
            conn.closed().await;
            i
        });
    }
    let closed = tokio::time::timeout(WAIT, set.join_next())
        .await
        .expect("none was closed")
        .unwrap()
        .unwrap();
    for (i, a) in agents.iter().enumerate() {
        if i != closed {
            assert!(a.conn.close_reason().is_none(), "connection {i} was closed too");
        }
    }
    closed
}

/// P1 (review of PR #14): a connection opened **before** `DELETE` must not survive it. The server has already looked
/// the NodeId up as enrolled when the node is deleted; its `Hello` then gets `not_enrolled` and the connection
/// closes.
#[tokio::test]
async fn a_connection_opened_before_delete_gets_not_enrolled() {
    let mut h = start(GatewayLimits {
        max_connections_per_node: 1,
        ..test_limits()
    })
    .await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "gone").await;
    agent.close().await;
    h.disconnected(node_id).await;
    // Two connections from the enrolled NodeId, each with the start of a `Hello`. With one slot per node, exactly
    // one is refused: the other's handler has looked the NodeId up as enrolled and holds the slot.
    let frame = hello_frame().await;
    let mut agents = Vec::new();
    for _ in 0..2 {
        let mut a = h.agent(&key).await;
        a.send.write_all(&frame[..10]).await.unwrap();
        agents.push(a);
    }
    let refused = exactly_one_closed(&agents).await;
    let mut survivor = agents.swap_remove(1 - refused);
    // Now the owner deletes the node, and only then does the `Hello` arrive.
    let r = h
        .app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/{node_id}"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    survivor.send.write_all(&frame[10..]).await.unwrap();
    survivor.expect_error("not_enrolled").await;
    survivor.expect_closed().await;
    assert!(!h.gw.hub().is_connected(node_id));
    assert!(!h.gw.hub().has_session(node_id));
}

/// The reverse order: the session is registered (welcomed), then `DELETE` closes it, tells `NodeEvents`
/// (`OfflineReason::Deleted`), and a reconnect gets `not_enrolled`.
#[tokio::test]
async fn delete_after_register_closes_the_session_and_tells_node_events() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "gone").await;
    assert!(h.gw.hub().is_connected(node_id));
    let r = h
        .app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/{node_id}"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    tokio::time::timeout(WAIT, agent.conn.closed())
        .await
        .expect("still connected");
    assert!(!h.gw.hub().is_connected(node_id));
    assert_eq!(h.event().await, (node_id, "offline:deleted".to_string()));
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    again.expect_error("not_enrolled").await;
    again.expect_closed().await;
    assert!(!h.gw.hub().is_connected(node_id));
}

/// At most `max_connections_per_node` (4) agent connections at once per enrolled node: a fifth is closed with no
/// detail, and a slot frees when a connection ends.
#[tokio::test]
async fn agent_connections_per_node_are_capped() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "n").await;
    agent.close().await;
    h.disconnected(node_id).await;
    let frame = hello_frame().await;
    let mut agents = Vec::new();
    for _ in 0..5 {
        let mut a = h.agent(&key).await;
        a.send.write_all(&frame[..10]).await.unwrap();
        agents.push(a);
    }
    let refused = exactly_one_closed(&agents).await;
    let refused = agents.remove(refused);
    assert!(refused.conn.close_reason().is_some());
    // The four that hold a slot still work: finish one Hello.
    let mut first = agents.remove(0);
    first.send.write_all(&frame[10..]).await.unwrap();
    assert_eq!(first.welcome().await, node_id);
    // Closing the other three frees their slots once the server sees the closes: a new connection is then accepted.
    for a in agents {
        a.close().await;
    }
    for attempt in 0.. {
        assert!(attempt < 100, "the slots were never released");
        let mut next = h.agent(&key).await;
        next.hello("0.1.0", vec![]).await;
        match next.recv().await {
            Some(ServerMsg::Welcome { node_id: id, .. }) => {
                assert_eq!(id, node_id);
                break;
            }
            // Refused while the closes were still in flight: try again.
            None => {}
            other => panic!("{other:?}"),
        }
    }
}

/// §5 "Deletion": `DELETE /v1/nodes/{id}` closes the live connection, and a reconnect gets `not_enrolled`,
/// byte-identical to the answer for a NodeId that never enrolled.
#[tokio::test]
async fn deletion_closes_the_connection_and_not_enrolled_is_identical_for_deleted_and_unknown() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "gone").await;
    let r = h
        .app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/{node_id}"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    tokio::time::timeout(WAIT, agent.conn.closed())
        .await
        .expect("still connected");
    assert!(!h.gw.hub().is_connected(node_id));

    let mut deleted = h.agent(&key).await;
    deleted.hello("0.1.0", vec![]).await;
    let deleted_bytes = deleted.recv_raw().await.unwrap();
    deleted.expect_closed().await;
    let mut unknown = h.agent(&SecretKey::generate()).await;
    unknown.hello("0.1.0", vec![]).await;
    let unknown_bytes = unknown.recv_raw().await.unwrap();
    assert_eq!(deleted_bytes, unknown_bytes);
    match decode_frame::<ServerMsg>(&deleted_bytes).unwrap() {
        ServerMsg::Error { code, .. } => assert_eq!(code, "not_enrolled"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn hello_from_an_enrolled_node_gets_welcome_and_its_leases_are_cancelled() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "node-1").await;
    agent.close().await;
    h.disconnected(node_id).await;
    let lease: LeaseId = "lse_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![RunningLease::new(lease, 2)]).await;
    assert_eq!(again.welcome().await, node_id);
    // No lease exists before T06: the default reconciler cancels it.
    assert_eq!(
        again.recv().await,
        Some(ServerMsg::Cancel {
            lease_id: lease,
            epoch: 2,
            reason: "unknown_lease".into()
        })
    );
    h.connected(node_id).await;
    let row = h.node(node_id).await;
    assert_eq!(row.state, nodes::DbState::Online);
    assert_eq!(row.features, ["lease_restrictions_v1"]);
    // The disconnection was resolved as recovered. The session resolves it after the reconciliation's `Cancel`s and
    // before it reads the next message, so a heartbeat's ack orders this read after it.
    sync(&mut again, 1).await;
    let mut c = h.app.db.acquire().await.unwrap();
    let log = nodes::disconnections(&mut c, node_id).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome.as_deref(), Some("recovered"));
}

#[tokio::test]
async fn an_agent_older_than_min_agent_version_is_refused() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "old").await;
    agent.close().await;
    h.disconnected(node_id).await;
    for version in ["0.0.9", "0.1.0-rc.1", "not-semver"] {
        let mut a = h.agent(&key).await;
        a.hello(version, vec![]).await;
        a.expect_error("agent_too_old").await;
        a.expect_closed().await;
    }
}

/// H2 §6.1 before the hub serves them: the new agent messages are answered as an unknown type (H1 §6), the connection
/// stays, and a `Leave` removes nothing.
#[tokio::test]
async fn h2_agent_messages_are_answered_as_unknown_types_for_now() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (mut agent, _node_id) = h.joined(&key, "n").await;
    let lease = LeaseId::generate();
    for (n, msg) in [
        json!({"type": "service_health", "lease_id": lease, "epoch": 1, "state": "healthy",
               "since": "2026-11-10T10:00:00Z"}),
        json!({"type": "volume_report", "volumes": []}),
        json!({"type": "leave", "reason": "uninstall"}),
    ]
    .iter()
    .enumerate()
    {
        agent.send(msg).await;
        agent.expect_error("unsupported_message").await;
        let seq = n as u64 + 1;
        agent.heartbeat(seq).await;
        assert_eq!(agent.recv().await, Some(ServerMsg::HeartbeatAck { seq }));
    }
}

/// SI-10 and §6 "Compatibility".
#[tokio::test]
async fn unknown_messages_keep_the_connection_and_malformed_frames_close_it() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "n").await;
    agent.send(&json!({"type": "gpu_report", "temps": [70]})).await;
    agent.expect_error("unsupported_message").await;
    agent.heartbeat(1).await;
    assert_eq!(agent.recv().await, Some(ServerMsg::HeartbeatAck { seq: 1 }));
    // An oversize frame: the prefix alone is enough to close the connection, with nothing allocated.
    agent.send.write_all(&(MAX_FRAME_LEN + 1).to_be_bytes()).await.unwrap();
    agent.expect_closed().await;
    h.disconnected(node_id).await;
    // Malformed JSON closes too, and a message that fails validation (a CPU load over 100 %).
    let mut a = h.agent(&key).await;
    a.hello("0.1.0", vec![]).await;
    a.welcome().await;
    a.send.write_all(&[0, 0, 0, 3, b'{', b'x', b'}']).await.unwrap();
    a.expect_closed().await;
    h.disconnected(node_id).await;
    let mut b = h.agent(&key).await;
    b.hello("0.1.0", vec![]).await;
    b.welcome().await;
    b.send(&json!({"type": "heartbeat", "seq": 1, "load": {"cpu_pct": 101, "mem_used_mb": 1}, "running": []}))
        .await;
    b.expect_closed().await;
    // Before Join, frames over 64 KiB are refused.
    let mut unknown = h.agent(&SecretKey::generate()).await;
    let body = vec![b' '; 64 * 1024 + 1];
    unknown
        .send
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    unknown.send.write_all(&body).await.unwrap();
    unknown.expect_closed().await;
    // The server is still fine.
    let mut c = h.agent(&key).await;
    c.hello("0.1.0", vec![]).await;
    c.welcome().await;
}

#[tokio::test]
async fn lease_and_job_messages_are_routed_to_node_events() {
    let mut h = start(test_limits()).await;
    let (mut agent, node_id) = h.joined(&SecretKey::generate(), "n").await;
    let lease: LeaseId = "lse_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
    agent
        .send(&AgentMsg::LeaseAccepted {
            lease_id: lease,
            epoch: 1,
        })
        .await;
    agent
        .send(&json!({"type": "log_chunk", "lease_id": lease, "epoch": 1, "stream": "stdout", "seq": 0, "data_b64": "aGk="}))
        .await;
    assert_eq!(h.event().await, (node_id, "lease_accepted".to_string()));
    assert_eq!(h.event().await, (node_id, "log_chunk".to_string()));
}

#[tokio::test]
async fn inventory_updates_are_validated_and_stored() {
    let mut h = start(test_limits()).await;
    let (mut agent, node_id) = h.joined(&SecretKey::generate(), "n").await;
    let mut inv = inventory("n");
    inv.offered.cpu = 7.5;
    agent.send(&AgentMsg::InventoryUpdate { inventory: inv }).await;
    agent.heartbeat(9).await;
    assert_eq!(agent.recv().await, Some(ServerMsg::HeartbeatAck { seq: 9 }));
    assert_eq!(h.node(node_id).await.inventory.offered.cpu, 7.5);
    // `offered` above the hardware fails validation and closes the connection.
    let mut inv = inventory("n");
    inv.offered.cpu = 64.0;
    agent.send(&AgentMsg::InventoryUpdate { inventory: inv }).await;
    agent.expect_closed().await;
    assert_eq!(h.node(node_id).await.inventory.offered.cpu, 7.5);
}

#[tokio::test]
async fn drain_and_resume_reach_a_connected_node_and_drain_survives_reconnects() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "n").await;
    let r = h
        .app
        .call(
            Method::POST,
            &format!("/v1/nodes/{node_id}/drain"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(agent.recv().await, Some(ServerMsg::Drain {}));
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Draining);
    agent.close().await;
    h.disconnected(node_id).await;
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    again.welcome().await;
    assert_eq!(again.recv().await, Some(ServerMsg::Drain {}));
    h.connected(node_id).await;
    let r = h
        .app
        .call(
            Method::POST,
            &format!("/v1/nodes/{node_id}/resume"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.json()["draining"], false);
    assert_eq!(again.recv().await, Some(ServerMsg::Resume {}));
}

#[tokio::test]
async fn a_new_connection_replaces_the_old_one() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (mut first, node_id) = h.joined(&key, "n").await;
    let mut second = h.agent(&key).await;
    second.hello("0.1.0", vec![]).await;
    second.welcome().await;
    tokio::time::timeout(WAIT, first.conn.closed())
        .await
        .expect("old connection still open");
    assert_eq!(first.recv().await, None);
    second.heartbeat(1).await;
    assert_eq!(second.recv().await, Some(ServerMsg::HeartbeatAck { seq: 1 }));
    assert!(h.gw.hub().is_connected(node_id));
    // NodeHub::send reaches the current connection.
    h.gw.hub().send(node_id, ServerMsg::Resume {}).unwrap();
    assert_eq!(second.recv().await, Some(ServerMsg::Resume {}));
}

/// §6 "Liveness": no heartbeat for `lease_ttl_s` makes the node offline, closes it, calls the hook and logs the
/// disconnection.
#[tokio::test]
async fn a_node_goes_offline_after_the_ttl_without_heartbeats() {
    let mut h = start(test_limits()).await;
    let (mut agent, node_id) = h.joined(&SecretKey::generate(), "n").await;
    // A heartbeat at +30 s restarts the TTL.
    h.app.clock.advance(Duration::seconds(30));
    agent.heartbeat(1).await;
    assert_eq!(agent.recv().await, Some(ServerMsg::HeartbeatAck { seq: 1 }));
    h.app.clock.advance(Duration::seconds(59));
    h.gw.sweep_liveness().await;
    assert!(h.gw.hub().is_connected(node_id));
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Online);
    h.app.clock.advance(Duration::seconds(1));
    h.gw.sweep_liveness().await;
    agent.expect_closed().await;
    assert_eq!(h.event().await, (node_id, "offline:lost".to_string()));
    let row = h.node(node_id).await;
    assert_eq!(row.state, nodes::DbState::Offline);
    assert_eq!(row.last_seen_at, Some(T0 + Duration::seconds(30)));
    let mut c = h.app.db.acquire().await.unwrap();
    let log = nodes::disconnections(&mut c, node_id).await.unwrap();
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].last_contact_at, T0 + Duration::seconds(30));
    assert_eq!(log[0].resolved_at, Some(T0 + Duration::seconds(90)));
    assert_eq!(log[0].outcome.as_deref(), Some("offline"));
}

/// Asserts that no `NodeEvents` call is pending: every hook call is awaited inside the gateway call that makes it,
/// so an event would already be in the channel.
fn assert_no_event(h: &mut Harness) {
    if let Ok(e) = h.events.try_recv() {
        panic!("unexpected event {e:?}");
    }
}

/// Connects, disconnects and lets the TTL pass: the node is expired in the hub, waiting for the sweep.
async fn expired_node(h: &mut Harness, key: &SecretKey) -> NodeId {
    let (agent, node_id) = h.joined(key, "n").await;
    agent.close().await;
    h.disconnected(node_id).await;
    h.app.clock.advance(Duration::seconds(61));
    node_id
}

/// P2 (review of PR #14): the sweep and a reconnect interleave as `take_expired` → reconnect (`register`, then the
/// `online` write) → the sweep's offline write. The sweep's `has_session` check, inside its transaction, sees the
/// registration: it writes nothing and fires no `Lost`. The row stays `online` and the node stays connected.
#[tokio::test]
async fn a_reconnect_between_expiry_and_the_offline_write_wins() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let node_id = expired_node(&mut h, &key).await;
    let expired = h.gw.sweep_take_expired();
    assert_eq!(expired.len(), 1);
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    again.welcome().await;
    h.connected(node_id).await;
    h.gw.sweep_finish(expired).await;
    assert_no_event(&mut h);
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Online);
    assert!(h.gw.hub().is_connected(node_id));
    again.heartbeat(1).await;
    assert_eq!(again.recv().await, Some(ServerMsg::HeartbeatAck { seq: 1 }));
}

/// The other order: the sweep decides before the reconnect registers. The node really had no contact for the TTL, so
/// `Lost` fires; the reconnect's `online` write comes after the sweep's commit and overrides it. What is guaranteed
/// in every order: **the row ends `online` while a session is registered**.
#[tokio::test]
async fn a_reconnect_after_the_offline_write_overrides_it() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let node_id = expired_node(&mut h, &key).await;
    let expired = h.gw.sweep_take_expired();
    h.gw.sweep_finish(expired).await;
    assert_eq!(h.event().await, (node_id, "offline:lost".to_string()));
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Offline);
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    again.welcome().await;
    h.connected(node_id).await;
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Online);
    assert_no_event(&mut h);
}

/// No `Lost` after `Deleted`: a node deleted between its expiry and the sweep's write gets only `Deleted`.
#[tokio::test]
async fn a_node_deleted_after_its_expiry_gets_no_lost() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let node_id = expired_node(&mut h, &key).await;
    let expired = h.gw.sweep_take_expired();
    let r = h
        .app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/{node_id}"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(h.event().await, (node_id, "offline:deleted".to_string()));
    h.gw.sweep_finish(expired).await;
    assert_no_event(&mut h);
    // Nothing is left for later sweeps either.
    h.app.clock.advance(Duration::hours(1));
    h.gw.sweep_liveness().await;
    assert_no_event(&mut h);
}

/// A failed offline write fires no hook, and the node is put back so the next sweep retries.
#[tokio::test]
async fn a_failed_offline_write_is_retried_by_the_next_sweep() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let node_id = expired_node(&mut h, &key).await;
    sqlx::query(
        "CREATE TRIGGER force_offline_failure BEFORE UPDATE OF state ON nodes WHEN NEW.state = 'offline' \
         BEGIN SELECT RAISE(ABORT, 'forced failure'); END",
    )
    .execute(&h.app.db)
    .await
    .unwrap();
    h.gw.sweep_liveness().await;
    assert_no_event(&mut h);
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Online);
    assert!(h.gw.hub().last_seen(node_id).is_some(), "the node is tracked again");
    sqlx::query("DROP TRIGGER force_offline_failure")
        .execute(&h.app.db)
        .await
        .unwrap();
    h.gw.sweep_liveness().await;
    assert_eq!(h.event().await, (node_id, "offline:lost".to_string()));
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Offline);
}

/// The disconnection log accepts the outcome T06 writes when it requeues a node's leases.
#[tokio::test]
async fn the_disconnection_log_accepts_requeued() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let node_id = expired_node(&mut h, &key).await;
    let mut c = h.app.db.acquire().await.unwrap();
    let when = h.app.clock.now();
    // `end()` recorded the open disconnection before emitting `Disconnected`, which `expired_node` waited for.
    assert!(
        nodes::resolve_disconnection(&mut c, node_id, nodes::DisconnectOutcome::Requeued, when)
            .await
            .unwrap()
    );
    let log = nodes::disconnections(&mut c, node_id).await.unwrap();
    assert_eq!(log.last().unwrap().outcome.as_deref(), Some("requeued"));
}

/// §6 "Server restart": after a restart, nodes that were online count as seen at boot, so none is declared lost (no
/// `offline:lost`, no disconnection resolved) before `lease_ttl_s` has passed since the boot, however old its last
/// contact. Meanwhile it is listed `offline` (T05b real run), since it has no session.
#[tokio::test]
async fn after_a_restart_online_nodes_get_the_ttl_from_the_boot() {
    let mut h = start(test_limits()).await;
    let (agent, node_id) = h.joined(&SecretKey::generate(), "n").await;
    agent.close().await;
    h.disconnected(node_id).await;
    // The server stops, and boots again an hour later (the node's last contact is an hour old).
    let Harness { app, gw, .. } = h;
    gw.shutdown().await;
    app.clock.advance(Duration::hours(1));
    let boot = app.clock.now();
    let config = Config::load(&app.data_dir().join("server.toml")).unwrap();
    let state = AppState::load(app.db.clone(), config, app.clock.clone()).await.unwrap();
    let mut h = start_with(app, state, test_limits(), "127.0.0.1:9".parse().unwrap()).await;
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Offline);
    h.gw.sweep_liveness().await;
    h.app.clock.set(boot + Duration::seconds(59));
    h.gw.sweep_liveness().await;
    assert_no_event(&mut h);
    // T05 review: the boot grace is an expiry deadline, never a contact. The API still shows the real last contact.
    assert_eq!(h.gw.hub().last_seen(node_id), None, "no contact since the boot");
    let shown = h.app.get(&format!("/v1/nodes/{node_id}"), &h.app.admin).await.json();
    let shown = time::OffsetDateTime::parse(
        shown["last_seen"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(shown, T0);
    h.app.clock.set(boot + Duration::seconds(60));
    h.gw.sweep_liveness().await;
    assert_eq!(h.node(node_id).await.state, nodes::DbState::Offline);
    assert_eq!(h.event().await, (node_id, "offline:lost".to_string()));
    // Neither `last_seen_at` nor the disconnection log got the boot time: the last contact was at T0.
    assert_eq!(h.node(node_id).await.last_seen_at, Some(T0));
    let mut c = h.app.db.acquire().await.unwrap();
    let log = nodes::disconnections(&mut c, node_id).await.unwrap();
    assert!(log.iter().all(|d| d.last_contact_at == T0), "{log:?}");
}

/// T05b real run (carry-over): right after a restart, a node whose row still says `online` is listed `offline` until
/// its agent's `Hello`, never with its last-known data as if it were connected.
#[tokio::test]
async fn after_a_restart_nodes_are_listed_offline_until_their_hello() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "n").await;
    // The server stops with the node connected: its row says `online`.
    let Harness { app, gw, .. } = h;
    gw.shutdown().await;
    drop(agent);
    {
        let mut c = app.db.acquire().await.unwrap();
        assert_eq!(
            nodes::by_id(&mut c, node_id).await.unwrap().unwrap().state,
            nodes::DbState::Online
        );
    }
    let config = Config::load(&app.data_dir().join("server.toml")).unwrap();
    let state = AppState::load(app.db.clone(), config, app.clock.clone()).await.unwrap();
    let mut h = start_with(app, state, test_limits(), "127.0.0.1:9".parse().unwrap()).await;
    let admin = h.app.admin.clone();
    let listed = h.app.get("/v1/nodes", &admin).await.json();
    assert_eq!(listed["items"][0]["id"], node_id.to_string());
    assert_eq!(listed["items"][0]["state"], "offline");
    let one = h.app.get(&format!("/v1/nodes/{node_id}"), &admin).await.json();
    assert_eq!(one["state"], "offline");
    assert_eq!(
        h.app.get("/v1/nodes?state=online", &admin).await.json()["items"],
        json!([])
    );
    // Its agent reconnects: online again.
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    assert_eq!(again.welcome().await, node_id);
    h.connected(node_id).await;
    assert_eq!(
        h.app.get(&format!("/v1/nodes/{node_id}"), &admin).await.json()["state"],
        "online"
    );
}

/// Reads an HTTP/1.1 response from a tunnel stream until the server closes it.
async fn tunnel_request(conn: &Connection, request: String) -> Result<String, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let out = tokio::time::timeout(WAIT, recv.read_to_end(1 << 20))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out).to_string())
}

/// Waits until the server's tunnel handler runs for `a`: the REST target of these tests is unreachable, so a
/// stream it accepted comes back reset.
async fn tunnel_handler_runs(a: &mut Agent) {
    a.send.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    a.send.finish().unwrap();
    let r = tokio::time::timeout(WAIT, a.recv.read_to_end(1024)).await.unwrap();
    assert!(r.is_err(), "the stream should be reset: {r:?}");
}

#[tokio::test]
async fn tunnel_connections_are_rate_limited_per_node_id_and_capped_in_total() {
    let h = start(GatewayLimits {
        http_connections_per_node_per_minute: 2,
        http_connections_total: 3,
        ..test_limits()
    })
    .await;
    let key = SecretKey::generate();
    let mut open = Vec::new();
    for _ in 0..2 {
        let mut a = Agent::connect(h.addr(), &key, PROTOCOL_ALPN_HTTP).await;
        tunnel_handler_runs(&mut a).await;
        open.push(a);
    }
    // The third connection from the same NodeId this minute is closed.
    let third = Agent::connect(h.addr(), &key, PROTOCOL_ALPN_HTTP).await;
    tokio::time::timeout(WAIT, third.conn.closed())
        .await
        .expect("rate limit not applied");
    // Another NodeId takes the last slot; a fourth connection while three are open is closed.
    let mut other = Agent::connect(h.addr(), &SecretKey::generate(), PROTOCOL_ALPN_HTTP).await;
    tunnel_handler_runs(&mut other).await;
    open.push(other);
    let fourth = Agent::connect(h.addr(), &SecretKey::generate(), PROTOCOL_ALPN_HTTP).await;
    tokio::time::timeout(WAIT, fourth.conn.closed())
        .await
        .expect("the total cap was not applied");
    for a in open {
        a.close().await;
    }
}

/// T05 review: one NodeId (they cost nothing) may hold only a few tunnel connections at once, so it cannot take
/// every slot of `http_connections_total`. A slot it frees is usable again.
#[tokio::test]
async fn tunnel_connections_are_capped_per_node_id() {
    let h = start(GatewayLimits {
        http_connections_per_node: 2,
        ..test_limits()
    })
    .await;
    let key = SecretKey::generate();
    let mut open = Vec::new();
    for _ in 0..2 {
        let mut a = Agent::connect(h.addr(), &key, PROTOCOL_ALPN_HTTP).await;
        tunnel_handler_runs(&mut a).await;
        open.push(a);
    }
    let third = Agent::connect(h.addr(), &key, PROTOCOL_ALPN_HTTP).await;
    tokio::time::timeout(WAIT, third.conn.closed())
        .await
        .expect("the per-NodeId cap was not applied");
    // Another NodeId is not affected.
    let mut other = Agent::connect(h.addr(), &SecretKey::generate(), PROTOCOL_ALPN_HTTP).await;
    tunnel_handler_runs(&mut other).await;
    // Closing one connection frees its slot for the same NodeId.
    let first = open.remove(0);
    let closed = first.conn.clone();
    first.close().await;
    tokio::time::timeout(WAIT, closed.closed()).await.unwrap();
    // The server may not have processed the close yet; a connection refused by the cap is closed at once (and costs
    // no rate-limit slot), so try again until one is accepted.
    let again = tokio::time::timeout(WAIT, async {
        loop {
            let mut a = Agent::connect(h.addr(), &key, PROTOCOL_ALPN_HTTP).await;
            a.send.write_all(b"GET / HTTP/1.1\r\n\r\n").await.ok();
            a.send.finish().ok();
            let read = a.recv.read_to_end(1024).await;
            assert!(read.is_err(), "the stream is reset or the connection closed: {read:?}");
            if a.conn.close_reason().is_none() {
                return a;
            }
            a.close().await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the freed slot was never usable again");
    for a in open.into_iter().chain([other, again]) {
        a.close().await;
    }
}

/// §10 option B: REST over `p2pc/http/1`, authenticated by the REST layer like any request.
#[tokio::test]
async fn the_http_tunnel_relays_rest_requests_and_caps_streams() {
    let app = TestApp::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rest = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(p2pc_server::serve::serve_on(listener, app.state.clone(), async {
        let _ = stopped.await;
    }));
    let state = app.state.clone();
    let admin = app.admin.clone();
    let key_id = app.admin_key.key_id().to_string();
    let h = start_with(
        app,
        state,
        GatewayLimits {
            http_streams_per_connection: 2,
            ..test_limits()
        },
        rest,
    )
    .await;
    let client = Agent::connect(h.addr(), &SecretKey::generate(), PROTOCOL_ALPN_HTTP).await;
    // The helper opened a first stream; use it for /healthz.
    let Agent {
        conn,
        mut send,
        mut recv,
        _ep,
    } = client;
    send.write_all(b"GET /healthz HTTP/1.1\r\nHost: p2pc.example.invalid\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    send.finish().unwrap();
    let out = tokio::time::timeout(WAIT, recv.read_to_end(1 << 20))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains(r#"{"status":"ok"}"#), "{text}");
    // Authenticated: the key is checked by the REST layer.
    let resp = tunnel_request(
        &conn,
        format!(
            "GET /v1/whoami HTTP/1.1\r\nHost: p2pc.example.invalid\r\nAuthorization: Bearer {admin}\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await
    .unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains(&key_id), "{resp}");
    // Nothing is trusted because it came over iroh: no key, no access.
    let resp = tunnel_request(
        &conn,
        "GET /v1/whoami HTTP/1.1\r\nHost: p2pc.example.invalid\r\nConnection: close\r\n\r\n".into(),
    )
    .await
    .unwrap();
    assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
    // The cap, on a fresh connection: two streams held open (incomplete requests), so a third is refused. Streams
    // are accepted in order, so the two held ones have their permits before the third arrives.
    let fresh = Agent::connect(h.addr(), &SecretKey::generate(), PROTOCOL_ALPN_HTTP).await;
    let mut held = Vec::new();
    let Agent {
        conn: fresh_conn,
        send: mut s0,
        recv: r0,
        _ep: fresh_ep,
    } = fresh;
    s0.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();
    held.push((s0, r0));
    let (mut s1, r1) = fresh_conn.open_bi().await.unwrap();
    s1.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();
    held.push((s1, r1));
    let refused = tunnel_request(
        &fresh_conn,
        "GET /healthz HTTP/1.1\r\nHost: p2pc.example.invalid\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    assert!(refused.is_err(), "the third stream must be reset: {refused:?}");
    // A client that gives up resets its streams; the relays end at once, without waiting for the REST side.
    for (mut s, _) in held {
        s.reset(0u32.into()).unwrap();
    }
    fresh_ep.close().await;
    h.gw.shutdown().await;
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// The gateway with the real scheduler as its `NodeEvents` and `LeaseReconciler` (as `serve` wires it).
async fn start_scheduled() -> (Harness, p2pc_server::scheduler::Scheduler) {
    let app = TestApp::new().await;
    let state = app.state.clone();
    let scheduler = p2pc_server::scheduler::Scheduler::new(&state, Arc::new(state.hub.clone()));
    let hub_events = state.hub.subscribe();
    let mut config = GatewayConfig::new(
        EndpointOptions::loopback_without_relays(),
        "127.0.0.1:9".parse().unwrap(),
    );
    config.limits = test_limits();
    config.reconciler = Arc::new(scheduler.clone());
    config.events = Arc::new(scheduler.clone());
    let gw = Gateway::start(state, config).await.unwrap();
    let h = Harness {
        app,
        gw,
        events: mpsc::unbounded_channel().1,
        hub_events,
        seen: Vec::new(),
    };
    (h, scheduler)
}

/// Sends a heartbeat and waits for its ack: every message the agent sent before it has been handled (one ordered
/// control stream), with no sleep.
async fn sync(agent: &mut Agent, seq: u64) {
    agent.heartbeat(seq).await;
    loop {
        match agent.recv().await {
            Some(ServerMsg::HeartbeatAck { seq: got }) if got == seq => return,
            // A drained node gets `Drain` after its `Welcome`; it is not what this waits for.
            Some(ServerMsg::Drain {} | ServerMsg::Resume {}) => {}
            other => panic!("expected HeartbeatAck {{ seq: {seq} }}, got {other:?}"),
        }
    }
}

/// T06 end to end over iroh, with the real scheduler as the gateway's `NodeEvents` and `LeaseReconciler`: a lease
/// reaches the agent through the hub, its `LeaseAccepted` comes back through the gateway, and a reconnect whose
/// `Hello` does not list the lease loses it at once (reconciled after the `Welcome`), so the job is offered again with
/// the next epoch and attempt.
#[tokio::test]
async fn a_lease_travels_over_iroh_and_a_hello_without_it_requeues_the_job() {
    let (mut h, scheduler) = start_scheduled().await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "node-1").await;
    let body = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "env": {"TOKEN": "fake-value-for-tests"}, "resources": {"cpu": 1, "memory_mb": 256}}); // gitleaks:allow (fake test value)
    let r = h
        .app
        .call(Method::POST, "/v1/jobs", Some(&h.app.admin), Some(body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let job_id = r.json()["id"].as_str().unwrap().to_string();
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    let Some(ServerMsg::Lease {
        lease_id,
        epoch,
        job,
        account_id,
        ..
    }) = agent.recv().await
    else {
        panic!("expected a Lease");
    };
    assert_eq!((epoch, account_id), (1, h.app.account_id));
    assert_eq!(job.parse_strict().unwrap().env["TOKEN"], "fake-value-for-tests");
    agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    sync(&mut agent, 1).await;
    let path = format!("/v1/jobs/{job_id}");
    let admin = h.app.admin.clone();
    assert_eq!(h.app.get(&path, &admin).await.json()["status"], "assigned");
    // The agent restarts and forgets the lease: its fresh Hello lists nothing.
    agent.close().await;
    h.disconnected(node_id).await;
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    assert_eq!(again.welcome().await, node_id);
    sync(&mut again, 2).await;
    let v = h.app.get(&path, &admin).await.json();
    assert_eq!((v["status"].as_str(), v["attempt"].as_u64()), (Some("queued"), Some(2)));
    // Offered again, fenced by the next epoch.
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    match again.recv().await {
        Some(ServerMsg::Lease {
            epoch, lease_id: l2, ..
        }) => assert_eq!((epoch, l2 != lease_id), (2, true)),
        other => panic!("expected a Lease, got {other:?}"),
    }
    // The old lease's report is fenced.
    again.send(&AgentMsg::LeaseAccepted { lease_id, epoch: 1 }).await;
    assert_eq!(
        again.recv().await,
        Some(ServerMsg::Cancel {
            lease_id,
            epoch: 1,
            reason: "stale_epoch".into()
        })
    );
}

/// §5 "Re-enrolling the same machine": a `Join` lists no running lease, so a re-enrolled node is reconciled like a
/// fresh `Hello` with none: a lease the server still held for it is lost at once and its job requeued, instead of
/// keeping its reservation until the agent's next `Hello`.
#[tokio::test]
async fn re_enrolling_a_node_loses_the_leases_it_held() {
    let (mut h, scheduler) = start_scheduled().await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "node-1").await;
    let body = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256}});
    let r = h
        .app
        .call(Method::POST, "/v1/jobs", Some(&h.app.admin), Some(body))
        .await;
    let job_id = r.json()["id"].as_str().unwrap().to_string();
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    let (lease_id, epoch) = next_lease(&mut agent).await;
    agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    sync(&mut agent, 1).await;
    let path = format!("/v1/jobs/{job_id}");
    let admin = h.app.admin.clone();
    assert_eq!(h.app.get(&path, &admin).await.json()["status"], "assigned");
    // `join --force` with a new token: the agent starts over.
    agent.close().await;
    h.disconnected(node_id).await;
    let token = h.token(json!({})).await;
    let mut again = h.agent(&key).await;
    again.join(&token, "node-1").await;
    assert_eq!(again.welcome().await, node_id);
    sync(&mut again, 2).await;
    let v = h.app.get(&path, &admin).await.json();
    assert_eq!((v["status"].as_str(), v["attempt"].as_u64()), (Some("queued"), Some(2)));
}

/// Submits a job and has `agent` refuse it until the offer cap (§8): it then stays queued with a reason and gets no
/// more offers. Returns its ID.
async fn capped_job(h: &Harness, scheduler: &p2pc_server::scheduler::Scheduler, agent: &mut Agent) -> String {
    let body = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256}});
    let r = h
        .app
        .call(Method::POST, "/v1/jobs", Some(&h.app.admin), Some(body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let job_id = r.json()["id"].as_str().unwrap().to_string();
    for i in 0..p2pc_server::scheduler::OFFER_CAP {
        assert_eq!(scheduler.tick().await.clean().offered, 1, "offer {i}");
        let (lease_id, epoch) = next_lease(agent).await;
        agent
            .send(&AgentMsg::LeaseRejected {
                lease_id,
                epoch,
                reason: p2pc_proto::protocol::LeaseRejectReason::InsufficientCapacity,
            })
            .await;
        sync(agent, 1000 + u64::from(i)).await;
        // Past the 60 s cooldown of the (job, node) pair.
        h.app.clock.advance(Duration::seconds(61));
    }
    assert_eq!(scheduler.tick().await.clean().offered, 0, "capped");
    let v = h.app.get(&format!("/v1/jobs/{job_id}"), &h.app.admin).await.json();
    assert_eq!(
        v["reason"],
        "no node accepted the job: the nodes refused it for capacity (insufficient_capacity)"
    );
    job_id
}

/// The next `Lease` the agent receives, skipping `Drain`/`Resume`.
async fn next_lease(agent: &mut Agent) -> (LeaseId, u64) {
    loop {
        match agent.recv().await {
            Some(ServerMsg::Lease { lease_id, epoch, .. }) => return (lease_id, epoch),
            Some(ServerMsg::Drain {} | ServerMsg::Resume {}) => {}
            other => panic!("expected a Lease, got {other:?}"),
        }
    }
}

async fn offer_count(h: &Harness, job_id: &str) -> i64 {
    sqlx::query_scalar("SELECT offer_count FROM jobs WHERE job_id = ?")
        .bind(job_id)
        .fetch_one(&h.app.db)
        .await
        .unwrap()
}

/// §8 "Offer cap" (amended a8ef531): a capped job is offered again once an eligible node **reconnects**.
#[tokio::test]
async fn the_offer_cap_re_arms_when_the_node_reconnects() {
    let (mut h, scheduler) = start_scheduled().await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "node-1").await;
    let job = capped_job(&h, &scheduler, &mut agent).await;
    agent.close().await;
    h.disconnected(node_id).await;
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    assert_eq!(again.welcome().await, node_id);
    sync(&mut again, 1).await;
    assert_eq!(offer_count(&h, &job).await, 0);
    let v = h.app.get(&format!("/v1/jobs/{job}"), &h.app.admin).await.json();
    assert_eq!(v["reason"], Value::Null, "the cap reason is cleared");
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    next_lease(&mut again).await;
}

/// `inventory("node-1")` with two GPUs, listed in the order given.
fn inventory_with_gpus(order: [u32; 2], offered_memory_mb: u64) -> p2pc_proto::api::Inventory {
    let mut v = serde_json::to_value(inventory("node-1")).unwrap();
    v["gpus"] = order
        .iter()
        .map(|i| {
            json!({"uuid": format!("GPU-00000000-0000-0000-0000-00000000000{i}"), "index": i,
            "name": "Example GPU", "driver_version": "1", "vram_mb": 8192})
        })
        .collect();
    v["offered"]["memory_mb"] = json!(offered_memory_mb);
    serde_json::from_value(v).unwrap()
}

/// … when the node sends an `InventoryUpdate` that **changes** its inventory; review P3: not for one that is the same
/// once normalized (here the same GPUs, listed in another order).
#[tokio::test]
async fn the_offer_cap_re_arms_on_an_inventory_update_that_changes_something() {
    let (mut h, scheduler) = start_scheduled().await;
    let (mut agent, _) = h.joined(&SecretKey::generate(), "node-1").await;
    agent
        .send(&AgentMsg::InventoryUpdate {
            inventory: inventory_with_gpus([0, 1], 12_288),
        })
        .await;
    sync(&mut agent, 1).await;
    let job = capped_job(&h, &scheduler, &mut agent).await;
    let cap = i64::from(p2pc_server::scheduler::OFFER_CAP);
    // The same inventory, its GPUs in another order: nothing changed.
    agent
        .send(&AgentMsg::InventoryUpdate {
            inventory: inventory_with_gpus([1, 0], 12_288),
        })
        .await;
    sync(&mut agent, 2).await;
    assert_eq!(
        offer_count(&h, &job).await,
        cap,
        "an unchanged inventory re-arms nothing"
    );
    assert_eq!(scheduler.tick().await.clean().offered, 0);
    // The owner offers more memory: a real change.
    agent
        .send(&AgentMsg::InventoryUpdate {
            inventory: inventory_with_gpus([1, 0], 14_336),
        })
        .await;
    sync(&mut agent, 3).await;
    assert_eq!(offer_count(&h, &job).await, 0);
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    next_lease(&mut agent).await;
}

/// Review P3: a draining node that reconnects is not an eligible node changing: the cap stays until it is resumed.
#[tokio::test]
async fn a_draining_node_that_reconnects_re_arms_nothing() {
    let (mut h, scheduler) = start_scheduled().await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "node-1").await;
    let job = capped_job(&h, &scheduler, &mut agent).await;
    let r = h
        .app
        .call(
            Method::POST,
            &format!("/v1/nodes/{node_id}/drain"),
            Some(&h.app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    agent.close().await;
    h.disconnected(node_id).await;
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    assert_eq!(again.welcome().await, node_id);
    sync(&mut again, 1).await;
    assert_eq!(
        offer_count(&h, &job).await,
        i64::from(p2pc_server::scheduler::OFFER_CAP)
    );
    // An `InventoryUpdate` that changes something does not re-arm a draining node either.
    again
        .send(&AgentMsg::InventoryUpdate {
            inventory: inventory_with_gpus([0, 1], 14_336),
        })
        .await;
    sync(&mut again, 2).await;
    assert_eq!(
        offer_count(&h, &job).await,
        i64::from(p2pc_server::scheduler::OFFER_CAP)
    );
}

/// … when the node is resumed.
#[tokio::test]
async fn the_offer_cap_re_arms_when_the_node_is_resumed() {
    let (mut h, scheduler) = start_scheduled().await;
    let (mut agent, node_id) = h.joined(&SecretKey::generate(), "node-1").await;
    let job = capped_job(&h, &scheduler, &mut agent).await;
    for action in ["drain", "resume"] {
        let r = h
            .app
            .call(
                Method::POST,
                &format!("/v1/nodes/{node_id}/{action}"),
                Some(&h.app.admin),
                None,
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{action}: {:?}", r.body);
    }
    assert_eq!(offer_count(&h, &job).await, 0);
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    next_lease(&mut agent).await;
}

/// … when a new node joins; but never for a node of another account.
#[tokio::test]
async fn the_offer_cap_re_arms_when_a_node_joins_only_in_the_same_account() {
    let (mut h, scheduler) = start_scheduled().await;
    let (mut agent, _) = h.joined(&SecretKey::generate(), "node-1").await;
    let job = capped_job(&h, &scheduler, &mut agent).await;
    // A node of another account joins: nothing changes for this account's job.
    let (stranger, _) = common::second_account(&h.app).await;
    let r = h
        .app
        .call(Method::POST, "/v1/nodes/join-tokens", Some(&stranger), Some(json!({})))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();
    let mut other = h.agent(&SecretKey::generate()).await;
    other.join(&token, "other").await;
    let other_id = other.welcome().await;
    h.connected(other_id).await;
    sync(&mut other, 1).await;
    assert_eq!(
        offer_count(&h, &job).await,
        i64::from(p2pc_server::scheduler::OFFER_CAP)
    );
    assert_eq!(scheduler.tick().await.clean().offered, 0);
    // A node of the same account joins: the job is offered again.
    let (mut second, _) = h.joined(&SecretKey::generate(), "node-2").await;
    sync(&mut second, 1).await;
    assert_eq!(offer_count(&h, &job).await, 0);
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    let offered: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM leases WHERE job_id = ? AND state = 'offered'")
        .bind(&job)
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    assert_eq!(offered, 1);
}

/// A reconciler whose database is down.
#[derive(Debug)]
struct FailingReconciler;

impl p2pc_server::gateway::LeaseReconciler for FailingReconciler {
    fn reconcile<'a>(
        &'a self,
        _node_id: NodeId,
        _running: &'a [RunningLease],
    ) -> BoxFuture<'a, Result<Vec<ServerMsg>, p2pc_server::gateway::ReconcileFailed>> {
        Box::pin(async { Err(p2pc_server::gateway::ReconcileFailed) })
    }
}

/// Review P3: when the leases of a `Hello` cannot be reconciled, the session is closed with no `Cancel`, so the agent
/// reconnects and reconciles again; a server-side failure never cancels a healthy job (§6 "Server restart").
#[tokio::test]
async fn a_failed_reconciliation_closes_the_session_without_cancelling() {
    let mut h = start(test_limits()).await;
    let key = SecretKey::generate();
    let (agent, node_id) = h.joined(&key, "node-1").await;
    agent.close().await;
    h.disconnected(node_id).await;
    // The same gateway state, with a reconciler that fails.
    let Harness { app, gw, .. } = h;
    gw.shutdown().await;
    let state = app.state.clone();
    let hub_events = state.hub.subscribe();
    let mut config = GatewayConfig::new(
        EndpointOptions::loopback_without_relays(),
        "127.0.0.1:9".parse().unwrap(),
    );
    config.limits = test_limits();
    config.reconciler = Arc::new(FailingReconciler);
    let gw = Gateway::start(state, config).await.unwrap();
    let h = Harness {
        app,
        gw,
        events: mpsc::unbounded_channel().1,
        hub_events,
        seen: Vec::new(),
    };
    let lease: LeaseId = "lse_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![RunningLease::new(lease, 3)]).await;
    assert_eq!(again.welcome().await, node_id);
    again.expect_closed().await;
}

async fn job_status(h: &Harness, path: &str) -> String {
    h.app.get(path, &h.app.admin).await.json()["status"]
        .as_str()
        .unwrap()
        .to_string()
}

/// SI-8 (§13), over the real gateway path: a message whose `(lease_id, epoch)` is not the job's current lease is
/// rejected, it changes nothing, and the server answers `Cancel` for that lease. Three stale forms: a wrong epoch of
/// the current lease, the old lease after the job was requeued, and the old lease's `JobFinished`. The acceptance
/// harness (AC-11) finds this test by its `si8_` name.
#[tokio::test]
async fn si8_stale_epoch_is_fenced() {
    let (mut h, scheduler) = start_scheduled().await;
    let key = SecretKey::generate();
    let (mut agent, node_id) = h.joined(&key, "node-1").await;
    let body = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256}});
    let r = h
        .app
        .call(Method::POST, "/v1/jobs", Some(&h.app.admin), Some(body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let job = r.json()["id"].as_str().unwrap().to_string();
    let path = format!("/v1/jobs/{job}");
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    let (old, old_epoch) = next_lease(&mut agent).await;
    agent
        .send(&AgentMsg::LeaseAccepted {
            lease_id: old,
            epoch: old_epoch,
        })
        .await;
    sync(&mut agent, 1).await;
    assert_eq!(job_status(&h, &path).await, "assigned");

    // 1. The current lease with an epoch that is not its own.
    let wrong = old_epoch + 1;
    agent
        .send(&AgentMsg::JobStarted {
            lease_id: old,
            epoch: wrong,
            started_at: h.app.clock.now(),
        })
        .await;
    assert_eq!(
        agent.recv().await,
        Some(ServerMsg::Cancel {
            lease_id: old,
            epoch: wrong,
            reason: "stale_epoch".into()
        })
    );
    assert_eq!(
        job_status(&h, &path).await,
        "assigned",
        "the stale JobStarted changed nothing"
    );

    // 2. The job is requeued (the agent's fresh Hello does not list the lease) and offered again with a new epoch.
    agent.close().await;
    h.disconnected(node_id).await;
    let mut again = h.agent(&key).await;
    again.hello("0.1.0", vec![]).await;
    assert_eq!(again.welcome().await, node_id);
    sync(&mut again, 2).await;
    assert_eq!(scheduler.tick().await.clean().offered, 1);
    let (new, new_epoch) = next_lease(&mut again).await;
    assert!(new_epoch > old_epoch);
    again
        .send(&AgentMsg::LeaseAccepted {
            lease_id: new,
            epoch: new_epoch,
        })
        .await;
    sync(&mut again, 3).await;

    // 3. The old lease reports, with its own (now stale) epoch: rejected, Cancel for that lease, no effect.
    for msg in [
        AgentMsg::JobStarted {
            lease_id: old,
            epoch: old_epoch,
            started_at: h.app.clock.now(),
        },
        AgentMsg::JobFinished {
            lease_id: old,
            epoch: old_epoch,
            outcome: p2pc_proto::protocol::Outcome::Exited,
            exit_code: Some(0),
            error: None,
            usage: p2pc_proto::protocol::Usage {
                wall_ms: 1000,
                cpu_used_ms: 1,
                max_rss_mb: 1,
            },
            outputs: vec![],
        },
    ] {
        again.send(&msg).await;
        assert_eq!(
            again.recv().await,
            Some(ServerMsg::Cancel {
                lease_id: old,
                epoch: old_epoch,
                reason: "stale_epoch".into()
            }),
            "{}",
            msg.kind()
        );
    }
    let v = h.app.get(&path, &h.app.admin).await.json();
    assert_eq!(v["status"], "assigned", "the current attempt is untouched: {v}");
    assert_eq!(v["attempt"], 2);
    assert_eq!(
        v["exit_code"],
        Value::Null,
        "the old attempt's exit did not finish the job"
    );
}
