// SPDX-License-Identifier: Apache-2.0

//! What a session runs over: a bidirectional byte stream to the server, opened by a [`Connector`].
//!
//! Production uses iroh ([`super::endpoint::IrohConnector`]): one QUIC connection on ALPN `p2pc/agent/1`, whose first
//! bidirectional stream is the control stream (§6). Tests plug in in-memory pipes, so that the timing of heartbeats,
//! the lease timer and the backoff can be checked with tokio's paused clock.
//!
//! A connection also opens more bidirectional streams after the control stream: one per output upload (§6
//! "Uploads", T10a). A [`Link`] carries a [`StreamOpener`] for them; a transport without extra streams uses
//! [`NoStreams`].
//!
//! H2 adds streams in the other direction: the server opens them on the same connection (H2 §6.1, port streams). A
//! [`Link`] may carry a [`StreamAcceptor`] for those; a transport without them has none, and nothing is ever
//! accepted.

use std::fmt;
use std::sync::Arc;

use p2pc_proto::net::SelectedAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;

use super::BoxFuture;
use super::streams::StreamAcceptor;

/// The sending half of a stream.
pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;
/// The receiving half of a stream.
pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;

/// Opens further bidirectional streams on a connection (uploads, §6).
pub trait StreamOpener: Send + Sync + fmt::Debug + 'static {
    /// A new bidirectional stream: agent → server, then server → agent. Callers bound the time it takes.
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxWrite, BoxRead), ConnectError>>;
}

/// A transport with no streams beyond the control stream: every open fails.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStreams;

impl StreamOpener for NoStreams {
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxWrite, BoxRead), ConnectError>> {
        Box::pin(async { Err(ConnectError("this connection opens no extra streams".into())) })
    }
}

/// One connection's control stream, and how to open more streams on the same connection.
pub struct Link {
    /// Agent → server.
    pub send: BoxWrite,
    /// Server → agent.
    pub recv: BoxRead,
    /// Closes the connection cleanly (QUIC `CONNECTION_CLOSE`), when the transport has such a thing.
    pub close: Box<dyn FnOnce() + Send + Sync>,
    /// Opens the upload streams of this connection.
    pub streams: Arc<dyn StreamOpener>,
    /// Where the streams the server opens on this connection arrive (H2 §6.1), if the transport has them.
    pub incoming: Option<Arc<dyn StreamAcceptor>>,
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

impl Link {
    /// A link with no extra streams ([`NoStreams`]).
    #[must_use]
    pub fn new(send: BoxWrite, recv: BoxRead, close: Box<dyn FnOnce() + Send + Sync>) -> Self {
        Self {
            send,
            recv,
            close,
            streams: Arc::new(NoStreams),
            incoming: None,
        }
    }

    /// The same link, opening its extra streams with `streams`.
    #[must_use]
    pub fn with_streams(mut self, streams: Arc<dyn StreamOpener>) -> Self {
        self.streams = streams;
        self
    }

    /// The same link, with the streams the server opens arriving at `incoming`.
    #[must_use]
    pub fn with_incoming(mut self, incoming: Arc<dyn StreamAcceptor>) -> Self {
        self.incoming = Some(incoming);
        self
    }

    /// Closes the connection.
    pub fn close(self) {
        (self.close)();
    }
}

/// Why a connection could not be opened. The text never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConnectError(pub String);

/// Opens connections to the server.
pub trait Connector: Send + Sync + fmt::Debug + 'static {
    /// Connects and opens the control stream. Implementations bound the time it takes.
    fn connect(&self) -> BoxFuture<'_, Result<Link, ConnectError>>;

    /// The network changed: bind to `addrs` from now on (empty: relay only). Open connections may break.
    fn set_addresses(&self, addrs: Vec<SelectedAddr>) -> BoxFuture<'_, ()>;

    /// What the connector signals when it needs its endpoint bound again with the addresses it has (the egress gate
    /// watcher saw the default route move, T10l): the daemon waits on it next to the network watcher's changes and calls
    /// [`Connector::renew_endpoint`]. A [`Notify`] keeps one permit, so requests made while the daemon is busy, or many in a
    /// row, give one rebind. A connector that never asks keeps the default, which is never signalled.
    fn rebind_signal(&self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }

    /// Binds again with the same addresses and reconnects: [`Connector::set_addresses`] without a new selection.
    fn renew_endpoint(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    /// Closes everything, at shutdown.
    fn shutdown(&self) -> BoxFuture<'_, ()>;
}
