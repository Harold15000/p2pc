// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-client`'s log and output calls against the **real** server over TCP (T10b acceptance): the client's own
//! tests only run against its mock. The server is `serve_on` with the state of a [`Fleet`], so a fake agent produces
//! the logs and outputs.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::fleet::{Fleet, header as upload_header, output};
use p2pc_client::{Client, DownloadError, ListParams, RetryPolicy};
use p2pc_proto::api::LogStream;
use p2pc_proto::ids::JobId;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct Served {
    url: String,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn serve(f: &Fleet) -> Served {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = oneshot::channel::<()>();
    let state = f.app.state.clone();
    let task = tokio::spawn(p2pc_server::serve::serve_on(listener, state, async {
        let _ = stopped.await;
    }));
    Served {
        url,
        stop: Some(stop),
        task,
    }
}

impl Served {
    fn client(&self, f: &Fleet) -> Client {
        Client::builder(self.url.clone(), f.app.admin_key.clone())
            .retry(RetryPolicy::immediate(0))
            .build()
            .unwrap()
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn the_client_reads_log_pages_lists_and_downloads_outputs_from_the_real_server() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    let served = serve(&f).await;
    let client = served.client(&f);

    // No logs yet: an empty page.
    let page = client.log_page(&job_id, 0, None, 1 << 20).await.unwrap();
    assert!(page.lines.is_empty() && !page.more);

    for seq in 0..6 {
        agent
            .log(lease, epoch, seq, LogStream::Stdout, format!("line {seq}\n").as_bytes())
            .await;
    }
    agent.sync().await;
    // `since_seq` is inclusive, and the client resumes with `last + 1`.
    let page = client.log_page(&job_id, 2, None, 1 << 20).await.unwrap();
    assert_eq!(page.lines.iter().map(|l| l.seq).collect::<Vec<_>>(), vec![2, 3, 4, 5]);
    assert_eq!(page.lines[0].data, "line 2\n");
    // A small budget cuts the page short; the next one starts after the last line.
    let first = client.log_page(&job_id, 0, None, 120).await.unwrap();
    assert!(first.more);
    let last = first.lines.last().unwrap().seq;
    let next = client.log_page(&job_id, last + 1, None, 1 << 20).await.unwrap();
    assert_eq!(next.lines.first().unwrap().seq, last + 1);

    // Outputs: one with a space in its path (percent-encoded by the client), and a nested one.
    let a = b"col1,col2\n1,2\n".to_vec();
    let b = vec![0x5Au8; 256 * 1024];
    assert!(
        agent
            .upload(&upload_header(lease, epoch, "results/a b.csv", &a), &a)
            .await
            .ok
    );
    assert!(
        agent
            .upload(&upload_header(lease, epoch, "model/w.bin", &b), &b)
            .await
            .ok
    );
    agent
        .finished(
            lease,
            epoch,
            0,
            vec![output("results/a b.csv", &a), output("model/w.bin", &b)],
        )
        .await;

    let page = client
        .list_outputs(&job_id, None, &ListParams::default())
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);
    let all = client.list_all_outputs(&job_id, None, 10).await.unwrap();
    assert_eq!(all, vec![output("model/w.bin", &b), output("results/a b.csv", &a)]);
    let one = client
        .list_outputs(
            &job_id,
            None,
            &ListParams {
                limit: Some(1),
                cursor: None,
            },
        )
        .await
        .unwrap();
    assert!(one.next_cursor.is_some());

    let mut sink = Vec::new();
    client.download_output(&job_id, None, &all[1], &mut sink).await.unwrap();
    assert_eq!(sink, a);
    let root = tempfile::tempdir().unwrap();
    let saved = client.save_output(&job_id, None, &all[0], root.path()).await.unwrap();
    assert_eq!(saved, root.path().join("model/w.bin"));
    assert_eq!(std::fs::read(saved).unwrap(), b);

    // A file the job never published: the API error passes through.
    match client
        .download_output(&job_id, None, &output("nope.txt", b"?"), &mut Vec::new())
        .await
    {
        Err(DownloadError::Request(e)) => assert_eq!(e.api_code(), Some("not_found")),
        other => panic!("expected not_found, got {other:?}"),
    }
    // Content that does not match what the client was told is refused by its own check.
    let mut lie = all[1].clone();
    lie.sha256 = output("x", b"x").sha256;
    assert!(matches!(
        client.download_output(&job_id, None, &lie, &mut Vec::new()).await,
        Err(DownloadError::DigestMismatch { .. })
    ));

    // The same outputs asked for by attempt, explicitly (T11b2's `attempt`): attempt 1 is this job's only one.
    let by_attempt = client.list_all_outputs(&job_id, Some(1), 10).await.unwrap();
    assert_eq!(by_attempt, all);
    let first = client
        .list_outputs(
            &job_id,
            Some(1),
            &ListParams {
                limit: Some(1),
                cursor: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(first.items, vec![all[0].clone()]);
    let next = client
        .list_outputs(
            &job_id,
            Some(1),
            &ListParams {
                limit: Some(1),
                cursor: first.next_cursor.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!((next.items, next.next_cursor), (vec![all[1].clone()], None));
    let root1 = tempfile::tempdir().unwrap();
    for o in &by_attempt {
        let saved = client.save_output(&job_id, Some(1), o, root1.path()).await.unwrap();
        assert_eq!(saved, root1.path().join(&o.path));
        assert_eq!(std::fs::metadata(&saved).unwrap().len(), o.size);
    }
    let mut sink = Vec::new();
    client
        .download_output(&job_id, Some(1), &all[1], &mut sink)
        .await
        .unwrap();
    assert_eq!(sink, a);
    // The attempt reaches the server: one this job never had is not found.
    match client.list_all_outputs(&job_id, Some(2), 10).await {
        Err(e) => assert_eq!(e.api_code(), Some("not_found")),
        Ok(v) => panic!("attempt 2 does not exist, got {v:?}"),
    }
    match client.download_output(&job_id, Some(2), &all[1], &mut Vec::new()).await {
        Err(DownloadError::Request(e)) => assert_eq!(e.api_code(), Some("not_found")),
        other => panic!("expected not_found, got {other:?}"),
    }
    served.stop().await;
}

/// One MiB of a deterministic pattern, chunk `i` of a file whose `salt` tells it apart.
fn chunk(salt: u8, i: usize) -> Vec<u8> {
    let mut c = vec![0u8; 1 << 20];
    for (k, b) in c.iter_mut().enumerate() {
        *b = salt ^ (i as u8) ^ (k as u8).rotate_left(3);
    }
    c
}

fn big_file(path: &str, salt: u8, mib: usize) -> p2pc_proto::api::OutputFile {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for i in 0..mib {
        h.update(chunk(salt, i));
    }
    p2pc_proto::api::OutputFile {
        path: path.into(),
        size: (mib as u64) << 20,
        sha256: p2pc_proto::api::Sha256Digest(h.finalize().into()),
    }
}

/// AC-5 shape (§14): an inline input at the 512 KiB limit reaches the agent intact in its `Lease`, and two outputs
/// totalling 1 GiB (the job's `outputs.max_mb = 1024`) round-trip with sha256 verification: uploaded through a fake
/// agent, published on `JobFinished`, downloaded and verified by the real client.
///
/// The task brief asked for a 600 KiB input; §7 caps `files` at 512 KiB decoded, so a 600 KiB input is refused
/// (`422`) and the round trip uses 512 KiB.
///
/// Slow (1 GiB through loopback QUIC, written, hashed and read back), so ignored by default. Run it with:
/// `cargo test -p p2pc-server --release --test client_compat -- --ignored ac5` (about 3 s in release).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves 1 GiB through loopback and the disk; run with --ignored"]
async fn ac5_inline_input_and_one_gib_of_outputs_round_trip_with_sha256() {
    use axum::http::{Method, StatusCode};
    use p2pc_proto::protocol::{AgentMsg, ServerMsg};
    use serde_json::json;

    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let input: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    let body = |bytes: &[u8]| {
        json!({"image": "docker.io/library/alpine:3", "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 256}, "outputs": {"max_mb": 1024},
            "files": [{"path": "/inputs/data.bin", "content_b64": data_encoding::BASE64.encode(bytes)}]})
    };
    let too_big = vec![1u8; 600 * 1024];
    let r = f
        .app
        .call(Method::POST, "/v1/jobs", Some(&f.app.admin), Some(body(&too_big)))
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.body);
    let job = f.submit(body(&input)).await;
    let job_id: JobId = job.parse().unwrap();
    assert_eq!(f.scheduler.tick().await.errors, 0);
    let (lease, epoch, spec) = loop {
        match agent.recv().await {
            Some(ServerMsg::Lease {
                lease_id, epoch, job, ..
            }) => break (lease_id, epoch, job.parse_strict().unwrap()),
            Some(_) => {}
            None => panic!("closed"),
        }
    };
    assert_eq!(
        data_encoding::BASE64
            .decode(spec.files[0].content_b64.as_bytes())
            .unwrap(),
        input
    );
    agent.send(&AgentMsg::LeaseAccepted { lease_id: lease, epoch }).await;
    agent.sync().await;

    let outputs = [big_file("big/a.bin", 1, 768), big_file("b.bin", 2, 256)];
    for (o, salt, mib) in [(&outputs[0], 1u8, 768usize), (&outputs[1], 2, 256)] {
        let header = serde_json::to_vec(&p2pc_proto::protocol::UploadHeader {
            lease_id: lease,
            epoch,
            path: o.path.clone(),
            size: o.size,
            sha256: o.sha256,
        })
        .unwrap();
        let ack = agent.upload_chunks(&header, (0..mib).map(|i| chunk(salt, i))).await;
        assert!(ack.ok, "{ack:?}");
    }
    agent.finished(lease, epoch, 0, outputs.to_vec()).await;
    let v = f.app.get(&format!("/v1/jobs/{job}"), &f.app.admin).await.json();
    assert_eq!((v["status"].as_str(), v["error"].as_str()), (Some("succeeded"), None));

    let served = serve(&f).await;
    let client = served.client(&f);
    let listed = client.list_all_outputs(&job_id, None, 10).await.unwrap();
    assert_eq!(listed.iter().map(|o| o.size).sum::<u64>(), 1 << 30);
    let root = tempfile::tempdir().unwrap();
    for o in &listed {
        // `save_output` checks the size and the sha256 before the file takes its place.
        let saved = client.save_output(&job_id, None, o, root.path()).await.unwrap();
        assert_eq!(std::fs::metadata(saved).unwrap().len(), o.size);
    }
    served.stop().await;
}
