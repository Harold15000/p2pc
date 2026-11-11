// SPDX-License-Identifier: AGPL-3.0-only

//! The server as `serve` wires it (gateway with the real scheduler, its log and output stores), and fake agents over
//! real iroh connections on loopback with relays disabled. Nothing here sleeps to synchronise: an agent waits for
//! the `HeartbeatAck` of a heartbeat sent after its other messages (one ordered control stream).

// Helpers are not `#[test]` functions: a failed `expect` here is a test failure with its message.
#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::http::{Method, StatusCode};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use p2pc_proto::PROTOCOL_ALPN_AGENT;
use p2pc_proto::api::{LogStream, OutputFile, Sha256Digest};
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{LeaseId, NodeId};
use p2pc_proto::protocol::{
    AgentMsg, LogData, MAX_FRAME_LEN, Outcome, RunningLease, ServerMsg, UploadAck, UploadHeader, Usage, decode_frame,
    read_frame_bytes, write_frame,
};
use p2pc_server::config::Config;
use p2pc_server::gateway::endpoint::bind;
use p2pc_server::gateway::{EndpointOptions, Gateway, GatewayConfig, GatewayLimits};
use p2pc_server::scheduler::Scheduler;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::TestApp;

/// The bound for anything that should happen promptly. Only reached when something is broken.
pub const WAIT: StdDuration = StdDuration::from_secs(20);

pub struct Fleet {
    pub app: TestApp,
    pub gw: Gateway,
    pub scheduler: Scheduler,
}

pub fn sha(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

pub fn output(path: &str, bytes: &[u8]) -> OutputFile {
    OutputFile {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: sha(bytes),
    }
}

impl Fleet {
    pub async fn start() -> Self {
        Self::start_with(|_| {}, GatewayLimits::default()).await
    }

    /// With the config edited before the state is built, and gateway limits.
    pub async fn start_with(edit: impl FnOnce(&mut Config), mut limits: GatewayLimits) -> Self {
        let app = TestApp::with_config(edit).await;
        let state = app.state.clone();
        let scheduler = Scheduler::new(&state, Arc::new(state.hub.clone()));
        let mut config = GatewayConfig::new(
            EndpointOptions::loopback_without_relays(),
            "127.0.0.1:9".parse().unwrap(),
        );
        // The background sweep never runs during a test.
        limits.sweep_interval = StdDuration::from_secs(3600);
        config.limits = limits;
        config.reconciler = Arc::new(scheduler.clone());
        config.events = Arc::new(scheduler.clone());
        let gw = Gateway::start(state, config).await.unwrap();
        Self { app, gw, scheduler }
    }

    pub fn addr(&self) -> EndpointAddr {
        let ep = self.gw.endpoint();
        EndpointAddr::new(ep.id()).with_ip_addr(ep.bound_sockets()[0])
    }

    /// Enrolls a new agent and returns it, welcomed.
    pub async fn agent(&self) -> FakeAgent {
        let r = self
            .app
            .call(
                Method::POST,
                "/v1/nodes/join-tokens",
                Some(&self.app.admin),
                Some(json!({})),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();
        let mut agent = FakeAgent::connect(self.addr(), &SecretKey::generate()).await;
        agent
            .send(&AgentMsg::Join {
                token,
                inventory: super::inventory("node"),
            })
            .await;
        match agent.recv().await {
            Some(ServerMsg::Welcome { node_id, .. }) => agent.node_id = Some(node_id),
            other => panic!("expected Welcome, got {other:?}"),
        }
        agent.sync().await;
        agent
    }

    /// A `Join` with `token` from a new connection of the agent whose iroh key is `key` (so the test knows its NodeId
    /// beforehand, as for a join request, H2 §5.4). Returns the agent and the server's first answer; `None` means it
    /// closed without one.
    pub async fn join_as(&self, key: &SecretKey, token: JoinToken) -> (FakeAgent, Option<ServerMsg>) {
        let mut agent = FakeAgent::connect(self.addr(), key).await;
        agent
            .send(&AgentMsg::Join {
                token,
                inventory: super::inventory("node"),
            })
            .await;
        let answer = agent.recv().await;
        if let Some(ServerMsg::Welcome { node_id, .. }) = &answer {
            agent.node_id = Some(*node_id);
        }
        (agent, answer)
    }

    /// The agent restarts: a new connection with the same key, whose `Hello` lists no running lease (so the server
    /// loses its leases at once, §6 "Reconnects").
    pub async fn restart(&self, agent: FakeAgent) -> FakeAgent {
        self.restart_with(agent, &[]).await
    }

    /// [`Fleet::restart`] with the capabilities the agent declares in its `Hello` (H2 §6.1). A `Join` carries none,
    /// so an agent that runs services reconnects once after it joined.
    pub async fn restart_with(&self, agent: FakeAgent, features: &[&str]) -> FakeAgent {
        let node_id = agent.node_id;
        let key = agent.key.clone();
        agent.conn.close(0u32.into(), b"restart");
        let mut again = FakeAgent::connect(self.addr(), &key).await;
        again
            .send(&AgentMsg::Hello {
                agent_version: "0.1.0".into(),
                inventory: super::inventory("node"),
                running: vec![],
                features: features.iter().map(ToString::to_string).collect(),
            })
            .await;
        loop {
            match again.recv().await {
                Some(ServerMsg::Welcome { node_id: id, .. }) => {
                    assert_eq!(Some(id), node_id);
                    break;
                }
                // The old connection's messages may still be queued for the node.
                Some(_) => {}
                None => panic!("closed before Welcome"),
            }
        }
        again.node_id = node_id;
        again.sync().await;
        again
    }

    /// Submits a job with the admin key and returns its ID.
    pub async fn submit(&self, body: Value) -> String {
        let r = self
            .app
            .call(Method::POST, "/v1/jobs", Some(&self.app.admin), Some(body))
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        r.json()["id"].as_str().unwrap().to_string()
    }

    /// Submits a small job and has `agent` accept and start it. Returns the job ID and its lease.
    pub async fn running(&self, agent: &mut FakeAgent) -> (String, LeaseId, u64) {
        self.running_with(agent, json!({})).await
    }

    /// [`Fleet::running`] with fields merged into the job body.
    pub async fn running_with(&self, agent: &mut FakeAgent, extra: Value) -> (String, LeaseId, u64) {
        let mut body = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 256}});
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let job = self.submit(body).await;
        assert_eq!(self.scheduler.tick().await.errors, 0);
        let (lease_id, epoch) = agent.next_lease().await;
        agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
        agent
            .send(&AgentMsg::JobStarted {
                lease_id,
                epoch,
                started_at: self.app.clock.now_for_tests(),
            })
            .await;
        agent.sync().await;
        (job, lease_id, epoch)
    }
}

/// `ManualClock::now` without importing the trait in every test file.
pub trait NowForTests {
    fn now_for_tests(&self) -> time::OffsetDateTime;
}

impl NowForTests for p2pc_server::clock::ManualClock {
    fn now_for_tests(&self) -> time::OffsetDateTime {
        p2pc_server::clock::Clock::now(self)
    }
}

pub struct FakeAgent {
    key: SecretKey,
    _ep: Endpoint,
    pub conn: Connection,
    send: SendStream,
    recv: RecvStream,
    pub node_id: Option<NodeId>,
    heartbeat: u64,
}

impl FakeAgent {
    async fn connect(addr: EndpointAddr, key: &SecretKey) -> Self {
        let ep = bind(key.clone(), &EndpointOptions::loopback_without_relays())
            .await
            .unwrap();
        let conn = tokio::time::timeout(WAIT, ep.connect(addr, PROTOCOL_ALPN_AGENT))
            .await
            .unwrap()
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        Self {
            key: key.clone(),
            _ep: ep,
            conn,
            send,
            recv,
            node_id: None,
            heartbeat: 0,
        }
    }

    pub async fn send(&mut self, msg: &impl Serialize) {
        write_frame(&mut self.send, msg).await.unwrap();
    }

    pub async fn recv(&mut self) -> Option<ServerMsg> {
        tokio::time::timeout(WAIT, read_frame_bytes(&mut self.recv, MAX_FRAME_LEN))
            .await
            .expect("no frame and no close")
            .ok()
            .flatten()
            .map(|b| decode_frame(&b).unwrap())
    }

    /// Sends a heartbeat and waits for its ack: everything sent before it has been handled. Returns what else came
    /// in meanwhile.
    pub async fn sync(&mut self) -> Vec<ServerMsg> {
        self.heartbeat_listing(&[]).await
    }

    /// [`FakeAgent::sync`] with a `Heartbeat.running` that lists `running` (the leases that still hold resources on
    /// the node, as an agent after T06e sends them).
    pub async fn heartbeat_listing(&mut self, running: &[(LeaseId, u64)]) -> Vec<ServerMsg> {
        self.heartbeat += 1;
        let seq = self.heartbeat;
        self.send(&AgentMsg::Heartbeat {
            seq,
            load: serde_json::from_value(json!({"cpu_pct": 1, "mem_used_mb": 1})).unwrap(),
            running: running
                .iter()
                .map(|(lease_id, epoch)| RunningLease::new(*lease_id, *epoch))
                .collect(),
        })
        .await;
        let mut other = Vec::new();
        loop {
            match self.recv().await {
                Some(ServerMsg::HeartbeatAck { seq: got }) if got == seq => return other,
                Some(m) => other.push(m),
                None => panic!("the connection closed"),
            }
        }
    }

    pub async fn next_lease(&mut self) -> (LeaseId, u64) {
        loop {
            match self.recv().await {
                Some(ServerMsg::Lease { lease_id, epoch, .. }) => return (lease_id, epoch),
                Some(ServerMsg::Drain {} | ServerMsg::Resume {}) => {}
                other => panic!("expected a Lease, got {other:?}"),
            }
        }
    }

    pub async fn log(&mut self, lease_id: LeaseId, epoch: u64, seq: u64, stream: LogStream, data: &[u8]) {
        self.send(&AgentMsg::LogChunk {
            lease_id,
            epoch,
            stream,
            seq,
            data_b64: LogData(data_encoding::BASE64.encode(data)),
        })
        .await;
    }

    pub async fn finished(&mut self, lease_id: LeaseId, epoch: u64, code: i32, outputs: Vec<OutputFile>) {
        self.finished_held(lease_id, epoch, code, outputs).await;
        self.sync().await;
    }

    /// `JobFinished` alone: the node still holds the lease's resources (its cleanup), so no heartbeat follows.
    pub async fn finished_held(&mut self, lease_id: LeaseId, epoch: u64, code: i32, outputs: Vec<OutputFile>) {
        self.send(&AgentMsg::JobFinished {
            lease_id,
            epoch,
            outcome: Outcome::Exited,
            exit_code: Some(code),
            error: None,
            usage: Usage {
                wall_ms: 1000,
                cpu_used_ms: 10,
                max_rss_mb: 1,
            },
            outputs,
        })
        .await;
    }

    /// One upload stream: the header, `body`, then the end of the stream; returns the ack.
    pub async fn upload(&self, header: &UploadHeader, body: &[u8]) -> UploadAck {
        self.upload_raw(&serde_json::to_vec(header).unwrap(), body).await
    }

    /// An upload whose header frame is `header_json` as given (it may be invalid).
    pub async fn upload_raw(&self, header_json: &[u8], body: &[u8]) -> UploadAck {
        self.upload_chunks(header_json, std::iter::once(body.to_vec())).await
    }

    /// An upload whose body is streamed from `chunks` (large files are never held in memory).
    pub async fn upload_chunks(&self, header_json: &[u8], chunks: impl Iterator<Item = Vec<u8>>) -> UploadAck {
        let (mut send, mut recv) = self.conn.open_bi().await.unwrap();
        let len = u32::try_from(header_json.len()).unwrap().to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut send, &len).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut send, header_json)
            .await
            .unwrap();
        // The server may stop reading early (a refusal); its answer is what matters.
        for chunk in chunks {
            if tokio::io::AsyncWriteExt::write_all(&mut send, &chunk).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
        let frame = tokio::time::timeout(WAIT, read_frame_bytes(&mut recv, MAX_FRAME_LEN))
            .await
            .expect("no ack")
            .unwrap()
            .expect("the stream ended without an ack");
        serde_json::from_slice(&frame).unwrap()
    }
}

pub fn header(lease_id: LeaseId, epoch: u64, path: &str, body: &[u8]) -> UploadHeader {
    UploadHeader {
        lease_id,
        epoch,
        path: path.into(),
        size: body.len() as u64,
        sha256: sha(body),
    }
}
