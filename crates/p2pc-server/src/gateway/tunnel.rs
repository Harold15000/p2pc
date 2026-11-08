// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc/http/1` (spec §10, option B): each bidirectional QUIC stream is relayed to the local REST listener, both
//! ways.
//!
//! Nothing is trusted because it arrived over iroh: the request reaches the REST layer like any other, and the API
//! key is checked there, with the same slow-client limits (§10). Limits here: at most 64 streams at once per
//! connection and the tunnel budget in total (an extra stream is reset at once), at most 256 connections at once
//! and 8 per NodeId (NodeIds cost nothing, so one peer must not hold every slot), and new connections are
//! rate-limited per NodeId.

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use super::Inner;
use super::hub::CLOSE_BY_SERVER;

/// QUIC stream error code for a stream refused over the cap.
pub const STREAM_REFUSED: u32 = 1;

/// Handles one `p2pc/http/1` connection until it ends.
pub(super) async fn handle(inner: Arc<Inner>, conn: Connection) {
    let iroh_id = conn.remote_id().to_string();
    let Ok(_open) = inner.http_connections_open.clone().try_acquire_owned() else {
        tracing::debug!("tunnel connection refused: too many open");
        conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
        return;
    };
    // Before the rate limit: a connection refused here costs the peer no rate slot.
    let Some(_peer) = PeerSlot::take(&inner, &iroh_id) else {
        tracing::debug!("tunnel connection refused: too many open for this NodeId");
        conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
        return;
    };
    if !inner.http_connections().try_take(&iroh_id, inner.state.clock.now()) {
        tracing::debug!("tunnel connection refused: rate limit");
        conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
        return;
    }
    let per_connection = Arc::new(Semaphore::new(inner.limits.http_streams_per_connection));
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let permits = (
            per_connection.clone().try_acquire_owned(),
            inner.http_streams.clone().try_acquire_owned(),
        );
        let (Ok(a), Ok(b)) = permits else {
            let _ = send.reset(VarInt::from_u32(STREAM_REFUSED));
            let _ = recv.stop(VarInt::from_u32(STREAM_REFUSED));
            continue;
        };
        let rest = inner.rest_addr;
        tokio::spawn(async move {
            let _permits = (a, b);
            relay(send, recv, rest).await;
        });
    }
}

/// One open tunnel connection of a NodeId, counted in `Inner::http_peers` until it is dropped.
struct PeerSlot {
    inner: Arc<Inner>,
    peer: String,
}

impl PeerSlot {
    fn take(inner: &Arc<Inner>, peer: &str) -> Option<Self> {
        let mut map = inner.http_peers();
        let count = map.entry(peer.to_string()).or_insert(0);
        if *count >= inner.limits.http_connections_per_node {
            return None;
        }
        *count += 1;
        drop(map);
        Some(Self {
            inner: inner.clone(),
            peer: peer.to_string(),
        })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut map = self.inner.http_peers();
        if let Some(count) = map.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.peer);
            }
        }
    }
}

/// Copies one stream to a new TCP connection to the REST listener and back. Ends when the REST side is done with
/// the connection (its keep-alive and request limits bound how long that is).
async fn relay(mut send: SendStream, mut recv: RecvStream, rest: std::net::SocketAddr) {
    let tcp = match TcpStream::connect(rest).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "tunnel: cannot reach the REST listener");
            let _ = send.reset(VarInt::from_u32(STREAM_REFUSED));
            let _ = recv.stop(VarInt::from_u32(STREAM_REFUSED));
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    {
        let up = async {
            // Client → REST. The client's end of stream is **not** passed on as a TCP half-close: hyper drops a
            // connection whose client half-closes, possibly before the response. The REST side ends the
            // connection itself (`Connection: close`, or its keep-alive idle limit).
            // A reset stream or a lost connection is an error: the relay then ends at once.
            tokio::io::copy(&mut recv, &mut tcp_write).await.is_ok()
        };
        let down = async {
            // REST → client.
            let _ = tokio::io::copy(&mut tcp_read, &mut send).await;
            let _ = send.finish();
        };
        tokio::pin!(up, down);
        tokio::select! {
            () = &mut down => {}
            clean = &mut up => if clean { down.await },
        }
    }
    drop(tcp_write);
    // The REST side is done: stop reading whatever the client still sends.
    let _ = recv.stop(VarInt::from_u32(0));
}
