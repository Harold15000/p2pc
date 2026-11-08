// SPDX-License-Identifier: AGPL-3.0-only

//! T10d item 4 acceptance: the CLI's `StreamFollower` (what `p2pc run` and `p2pc logs --follow` use) against the
//! **real** server over TCP, across a quiet stretch. The server's idle limit is short here, so it cuts the follow
//! several times while the job says nothing; each cut now breaks the response body instead of ending it cleanly.
//! The follower must reconnect from the last `seq + 1`, lose and repeat no line, and finish only with the job.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io;
use std::net::SocketAddr;

use common::fleet::{Fleet, WAIT};
use p2pc_cli::follow::{Followed, LogSink, PollSchedule, Progress, StreamFollower, TokioSleeper};
use p2pc_client::{Client, RetryPolicy};
use p2pc_proto::api::{Job, JobStatus, LogLine, LogStream};
use p2pc_proto::ids::JobId;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};

/// Forwards `127.0.0.1:<port>` to `target` and counts the connections it accepts: a follow that the server cuts makes
/// the client open a new one.
fn proxy(listener: TcpListener, target: SocketAddr) -> watch::Receiver<usize> {
    let (count, seen) = watch::channel(0);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            count.send_modify(|n| *n += 1);
            tokio::spawn(async move {
                if let Ok(mut server) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                }
            });
        }
    });
    seen
}

#[derive(Default)]
struct Recorded {
    lines: Vec<LogLine>,
    statuses: Vec<JobStatus>,
}

impl Progress for Recorded {
    fn on_status(&mut self, job: &Job) {
        self.statuses.push(job.status);
    }
}

impl LogSink for Recorded {
    fn line(&mut self, line: &LogLine) -> io::Result<()> {
        self.lines.push(line.clone());
        Ok(())
    }
}

/// Follows a running job through `cuts` idle cuts of the server, then logs more and finishes the job.
/// `attempt` is `Some(1)` for `p2pc logs --attempt 1 --follow`, `None` for `p2pc run` / `p2pc logs --follow`.
async fn follow_across_idle_cuts(attempt: Option<u32>) {
    const CUTS: usize = 4;
    let f = Fleet::start_with(|c| c.http.keepalive_idle_ms = 250, Default::default()).await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    for seq in 0..3 {
        agent
            .log(
                lease,
                epoch,
                seq,
                LogStream::Stdout,
                format!("early {seq}\n").as_bytes(),
            )
            .await;
    }
    agent.sync().await;

    // The real server on a TCP port, behind a connection-counting forwarder.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(p2pc_server::serve::serve_on(upstream, f.app.state.clone(), async {
        let _ = stopped.await;
    }));
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", front.local_addr().unwrap());
    let mut connections = proxy(front, upstream_addr);

    let client = Client::builder(url, f.app.admin_key.clone())
        .retry(RetryPolicy::immediate(0))
        .build()
        .unwrap();
    let submitted = client.get_job(&job_id).await.unwrap();
    // The CLI runs on one thread (its futures are not `Send`): the follow and the script are driven together here.
    let ended = std::cell::Cell::new(false);
    let follow = async {
        let mut events = Recorded::default();
        let mut follower = StreamFollower::new(PollSchedule::default(), TokioSleeper, 0, attempt);
        let end = follower
            .follow(&client, submitted, &mut events, std::future::pending())
            .await;
        ended.set(true);
        (end, events)
    };
    let script = async {
        // Quiet: the follow is cut by the server again and again, and the client keeps coming back.
        connections
            .wait_for(|n| *n >= CUTS)
            .await
            .expect("the forwarder stopped");
        assert!(!ended.get(), "the follow ended while the job was still running");
        // The job speaks again and finishes.
        for seq in 3..6 {
            agent
                .log(lease, epoch, seq, LogStream::Stdout, format!("late {seq}\n").as_bytes())
                .await;
        }
        agent.finished(lease, epoch, 0, vec![]).await;
    };
    let ((end, events), ()) = tokio::time::timeout(WAIT * 3, async { tokio::join!(follow, script) })
        .await
        .expect("the follower never came back after the idle cuts, or did not end with the job");
    match end {
        Ok(Followed::Finished(job)) => assert_eq!(job.status, JobStatus::Succeeded),
        other => panic!("the follow did not finish with the job: {other:?}"),
    }
    let seqs: Vec<u64> = events.lines.iter().map(|l| l.seq).collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5], "a line was lost or repeated");
    assert_eq!(events.statuses.last(), Some(&JobStatus::Succeeded));

    let _ = stop.send(());
    server.await.unwrap().unwrap();
}

/// `p2pc run` and `p2pc logs --follow`: the latest attempt.
#[tokio::test]
async fn the_cli_follows_the_latest_attempt_across_idle_cuts_of_the_real_server() {
    follow_across_idle_cuts(None).await;
}

/// `p2pc logs --attempt 1 --follow`: a fixed attempt.
#[tokio::test]
async fn the_cli_follows_a_fixed_attempt_across_idle_cuts_of_the_real_server() {
    follow_across_idle_cuts(Some(1)).await;
}
