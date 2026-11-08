// SPDX-License-Identifier: Apache-2.0

//! Log capture (spec §6 `LogChunk`, §9 "Logs on the node").
//!
//! One task reads the container's stdout and stderr and turns them into [`LogChunk`]s of at most 64 KiB, numbered
//! with one sequence across both streams. At most [`LOG_CAP_BYTES`] (64 MiB) per attempt are passed on; then one
//! truncation marker is sent, and the pump **keeps reading and discarding** until both streams end, so the job
//! never blocks on a full pipe and the agent's memory and disk stay bounded. If the receiver goes away, the pump
//! drains in the same way.

use p2pc_proto::api::LogStream;
use p2pc_proto::protocol::MAX_LOG_CHUNK_BYTES;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

use super::SandboxEvent;

/// Most log bytes passed on per attempt (§9).
pub const LOG_CAP_BYTES: u64 = 64 * 1024 * 1024;
/// The single marker sent, on stderr, once the cap is reached.
pub const TRUNCATION_MARKER: &str =
    "\n[p2pc] log truncated: the 64 MiB per-attempt cap was reached; further output was discarded\n";

/// A chunk of output.
#[derive(Clone, PartialEq, Eq)]
pub struct LogChunk {
    /// Source stream.
    pub stream: LogStream,
    /// Sequence number within the attempt, across both streams, from 0.
    pub seq: u64,
    /// At most 64 KiB.
    pub data: Vec<u8>,
    /// Whether this is the truncation marker.
    pub marker: bool,
}

impl std::fmt::Debug for LogChunk {
    // Job output may contain anything, including secrets the job printed: show only its size.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogChunk")
            .field("stream", &self.stream)
            .field("seq", &self.seq)
            .field("len", &self.data.len())
            .field("marker", &self.marker)
            .finish()
    }
}

/// What the pump did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogSummary {
    /// Bytes passed on (without the marker).
    pub bytes_kept: u64,
    /// Bytes read and discarded after the cap, or after the receiver went away.
    pub bytes_discarded: u64,
    /// Chunks sent, the marker included.
    pub chunks: u64,
    /// Whether the cap was reached.
    pub truncated: bool,
}

struct Pump {
    tx: mpsc::Sender<SandboxEvent>,
    cap: u64,
    seq: u64,
    summary: LogSummary,
    closed: bool,
}

impl Pump {
    async fn send(&mut self, chunk: LogChunk) {
        if self.closed {
            return;
        }
        if self.tx.send(SandboxEvent::Log(chunk)).await.is_err() {
            self.closed = true;
        } else {
            self.summary.chunks += 1;
        }
    }

    async fn handle(&mut self, stream: LogStream, data: &[u8]) {
        let room = self.cap.saturating_sub(self.summary.bytes_kept);
        let keep = usize::try_from(room).unwrap_or(usize::MAX).min(data.len());
        if keep > 0 && !self.closed {
            self.summary.bytes_kept += keep as u64;
            let chunk = LogChunk {
                stream,
                seq: self.seq,
                data: data[..keep].to_vec(),
                marker: false,
            };
            self.seq += 1;
            self.send(chunk).await;
        } else if keep > 0 {
            self.summary.bytes_discarded += keep as u64;
        }
        let rest = (data.len() - keep) as u64;
        if rest > 0 {
            self.summary.bytes_discarded += rest;
            if !self.summary.truncated {
                self.summary.truncated = true;
                let marker = LogChunk {
                    stream: LogStream::Stderr,
                    seq: self.seq,
                    data: TRUNCATION_MARKER.as_bytes().to_vec(),
                    marker: true,
                };
                self.seq += 1;
                self.send(marker).await;
            }
        }
    }
}

/// Reads both streams to the end, sending chunks to `tx`, with [`LOG_CAP_BYTES`].
pub async fn pump<O, E>(stdout: O, stderr: E, tx: mpsc::Sender<SandboxEvent>) -> LogSummary
where
    O: AsyncRead + Unpin,
    E: AsyncRead + Unpin,
{
    pump_with_cap(stdout, stderr, tx, LOG_CAP_BYTES).await
}

/// [`pump`] with another cap, for tests.
pub async fn pump_with_cap<O, E>(mut stdout: O, mut stderr: E, tx: mpsc::Sender<SandboxEvent>, cap: u64) -> LogSummary
where
    O: AsyncRead + Unpin,
    E: AsyncRead + Unpin,
{
    let mut p = Pump {
        tx,
        cap,
        seq: 0,
        summary: LogSummary::default(),
        closed: false,
    };
    let mut out_buf = vec![0u8; MAX_LOG_CHUNK_BYTES];
    let mut err_buf = vec![0u8; MAX_LOG_CHUNK_BYTES];
    let (mut out_open, mut err_open) = (true, true);
    while out_open || err_open {
        tokio::select! {
            r = stdout.read(&mut out_buf), if out_open => match r {
                Ok(0) | Err(_) => out_open = false,
                Ok(n) => p.handle(LogStream::Stdout, &out_buf[..n]).await,
            },
            r = stderr.read(&mut err_buf), if err_open => match r {
                Ok(0) | Err(_) => err_open = false,
                Ok(n) => p.handle(LogStream::Stderr, &err_buf[..n]).await,
            },
        }
    }
    p.summary
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    async fn drain(mut rx: mpsc::Receiver<SandboxEvent>) -> Vec<LogChunk> {
        let mut out = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let SandboxEvent::Log(c) = ev {
                out.push(c);
            }
        }
        out
    }

    #[tokio::test]
    async fn chunks_are_at_most_64_kib_and_numbered_across_streams() {
        let (tx, rx) = mpsc::channel(1024);
        let big = vec![b'x'; 200 * 1024];
        let summary = pump(&big[..], &b"oops\n"[..], tx).await;
        let chunks = drain(rx).await;
        assert!(chunks.iter().all(|c| c.data.len() <= MAX_LOG_CHUNK_BYTES));
        let seqs: Vec<u64> = chunks.iter().map(|c| c.seq).collect();
        assert_eq!(seqs, (0..chunks.len() as u64).collect::<Vec<_>>());
        let stdout: usize = chunks
            .iter()
            .filter(|c| c.stream == LogStream::Stdout)
            .map(|c| c.data.len())
            .sum();
        assert_eq!(stdout, big.len());
        assert!(
            chunks
                .iter()
                .any(|c| c.stream == LogStream::Stderr && c.data == b"oops\n")
        );
        assert_eq!(summary.bytes_kept, big.len() as u64 + 5);
        assert!(!summary.truncated);
        assert!(chunks.iter().all(|c| !c.marker));
    }

    #[tokio::test]
    async fn the_cap_sends_one_marker_and_keeps_draining() {
        let (tx, rx) = mpsc::channel(1024);
        let out = vec![b'a'; 10_000];
        let err = vec![b'b'; 10_000];
        let summary = pump_with_cap(&out[..], &err[..], tx, 4096).await;
        let chunks = drain(rx).await;
        let kept: usize = chunks.iter().filter(|c| !c.marker).map(|c| c.data.len()).sum();
        assert_eq!(kept, 4096);
        assert_eq!(chunks.iter().filter(|c| c.marker).count(), 1);
        let marker = chunks.iter().find(|c| c.marker).unwrap();
        assert_eq!(marker.stream, LogStream::Stderr);
        assert_eq!(marker.data, TRUNCATION_MARKER.as_bytes());
        assert!(summary.truncated);
        assert_eq!(summary.bytes_kept, 4096);
        assert_eq!(summary.bytes_discarded, 20_000 - 4096, "everything was read");
    }

    #[tokio::test]
    async fn a_writer_never_blocks_after_the_cap() {
        // A real pipe with a small buffer: the writer finishes only if the pump keeps reading after the cap.
        let (mut w, r) = tokio::io::duplex(1024);
        let (tx, rx) = mpsc::channel(4);
        let consumer = tokio::spawn(drain(rx));
        let writer = tokio::spawn(async move {
            let block = vec![b'z'; 8192];
            for _ in 0..256 {
                w.write_all(&block).await.unwrap();
            }
        });
        let summary = pump_with_cap(r, tokio::io::empty(), tx, 64 * 1024).await;
        writer.await.unwrap();
        let chunks = consumer.await.unwrap();
        assert!(summary.truncated);
        assert_eq!(summary.bytes_kept + summary.bytes_discarded, 256 * 8192);
        assert_eq!(chunks.iter().filter(|c| c.marker).count(), 1);
    }

    #[tokio::test]
    async fn a_gone_receiver_does_not_stop_the_drain() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let data = vec![b'q'; 300_000];
        let summary = pump(&data[..], tokio::io::empty(), tx).await;
        assert_eq!(summary.chunks, 0);
        assert_eq!(summary.bytes_kept + summary.bytes_discarded, 300_000);
    }

    #[test]
    fn debug_hides_the_content() {
        let c = LogChunk {
            stream: LogStream::Stdout,
            seq: 1,
            data: b"API_KEY=hunter2".to_vec(),
            marker: false,
        };
        assert!(!format!("{c:?}").contains("hunter2"));
    }
}
