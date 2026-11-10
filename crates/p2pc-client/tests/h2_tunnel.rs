// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The H2 calls that need more than a JSON body (a blob upload, a `HEAD`, a port upgrade) over the `p2pc/http/1`
//! tunnel, against the in-process fake tunnel server (iroh on loopback, relays disabled). No real network.

use p2pc_client::testing::{MockResponse, MockTunnelServer};
use p2pc_client::tunnel::{Tunnel, TunnelOptions};
use p2pc_client::{Client, RetryPolicy};
use p2pc_proto::api::Sha256Digest;
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::JobId;
use p2pc_proto::net::DirectAddresses;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tunnel_client(server: &MockTunnelServer) -> Client {
    let tunnel = Tunnel::new(TunnelOptions {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        server_addrs: server.addrs(),
        ..TunnelOptions::new(server.address())
    })
    .unwrap();
    Client::builder_tunnel(tunnel, ApiKey::generate())
        .retry(RetryPolicy::immediate(3))
        .build()
        .unwrap()
}

#[tokio::test]
async fn head_blob_over_the_tunnel_reads_the_announced_size() {
    let server = MockTunnelServer::start(|_| MockResponse::head(200, 5_000_000_000));
    let digest = Sha256Digest(Sha256::digest(b"x").into());
    assert_eq!(
        tunnel_client(&server).head_blob(&digest).await.unwrap(),
        Some(5_000_000_000)
    );
}

#[tokio::test]
async fn put_blob_over_the_tunnel_streams_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.bin");
    let bytes: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(&path, &bytes).unwrap();
    let digest = Sha256Digest(Sha256::digest(&bytes).into());
    let answer = json!({
        "sha256": digest.to_string(), "size": bytes.len(),
        "created_at": "2023-11-14T22:13:20Z", "expires_at": null,
    });
    let server = MockTunnelServer::start(move |_| MockResponse::json(201, &answer));

    tunnel_client(&server)
        .put_blob(&path, &digest, bytes.len() as u64)
        .await
        .unwrap();
    let req = &server.requests()[0];
    assert_eq!(req.route(), "POST /v1/blobs");
    assert_eq!(req.header("x-p2pc-sha256"), Some(digest.to_string().as_str()));
    assert_eq!(req.header("content-length"), Some(bytes.len().to_string().as_str()));
    assert_eq!(req.body, bytes);
}

#[tokio::test]
async fn a_port_connection_over_the_tunnel_upgrades_and_carries_raw_bytes() {
    let server = MockTunnelServer::start(|_| MockResponse::upgrade_echo());
    let job = JobId::generate();
    let mut stream = tunnel_client(&server).open_port(&job, 8080, true).await.unwrap();
    stream.write_all(b"hello through the tunnel").await.unwrap();
    let mut back = vec![0u8; 24];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(back, b"hello through the tunnel");

    let req = &server.requests()[0];
    assert_eq!(req.route(), format!("POST /v1/jobs/{job}/ports/8080/connect"));
    assert_eq!(req.query.as_deref(), Some("wait_ready=true"));
    assert_eq!(req.header("upgrade"), Some("p2pc-port/1"));
    assert!(
        req.header("connection")
            .is_some_and(|c| c.to_ascii_lowercase().contains("upgrade"))
    );
}

#[tokio::test]
async fn a_refused_port_connection_over_the_tunnel_is_the_hubs_error() {
    let server = MockTunnelServer::start(|_| MockResponse::problem(422, "port_not_exposed", "port 9 is not exposed"));
    let err = tunnel_client(&server)
        .open_port(&JobId::generate(), 9, false)
        .await
        .expect_err("an error");
    let api = err.as_api().expect("an API error");
    assert_eq!((api.status, api.code.as_str()), (422, "port_not_exposed"));
}
