// SPDX-License-Identifier: Apache-2.0

//! `p2pc proxy` (spec §10, option B): the REST API of a server address on a local port.
//!
//! - Each accepted TCP connection is spliced onto its own QUIC bidirectional stream of the process's one tunnel
//!   connection ([`p2pc_client::tunnel::relay_tcp`]). Bytes pass as they are: **no API key is added**; clients send
//!   their own, and the server checks it like any other request.
//! - Loopback only by default. Another address needs `--allow-non-loopback`, and a warning is printed: anyone who
//!   can reach the port can then try keys against the server.
//! - The network is watched ([`p2pc_client::tunnel::Tunnel::watch_network`]): when the machine's addresses change,
//!   the tunnel binds a new endpoint and reconnects on the next local connection.
//! - At most [`MAX_CONNECTIONS`] local connections at once (further ones wait in the listen backlog), each ended
//!   after [`RelayLimits::idle`] without traffic.
//! - Ctrl-C (SIGINT) or SIGTERM stops accepting, ends the open connections and closes the tunnel. The exit code
//!   follows spec §7: 130 after Ctrl-C, 0 after SIGTERM (a service manager's clean stop).

use std::sync::Arc;
use std::time::Duration;

use p2pc_client::tunnel::{RelayLimits, Tunnel, relay_tcp};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::app::{CliError, Ctx};
use crate::cli::ProxyArgs;
use crate::config::{Server, resolve_profile, resolve_server};
use crate::outcome::{EXIT_INTERRUPTED, EXIT_OK};

/// Local connections served at once.
pub const MAX_CONNECTIONS: usize = 64;

/// `p2pc proxy`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: ProxyArgs) -> Result<u8, CliError> {
    if !args.listen.ip().is_loopback() && !args.allow_non_loopback {
        return Err(CliError::usage(format!(
            "--listen {} is not a loopback address: it would expose the server's API to that network. Pass \
             --allow-non-loopback if that is what you want.",
            args.listen
        )));
    }
    // Only the server is needed: the proxy never uses a key.
    let config = ctx.store()?.load_config()?;
    let profile = resolve_profile(&ctx.flags, ctx.host.env, &config);
    let server = resolve_server(&ctx.flags, ctx.host.env, &config, &profile)?.ok_or_else(|| {
        CliError::usage("no server: pass --server p2pc_srv_… (or set P2PC_SERVER, or log in with a server address)")
    })?;
    let Server::Address(address) = Server::parse(&server)? else {
        return Err(CliError::usage(
            "p2pc proxy needs a server address (p2pc_srv_…); this server is a URL, which clients can use directly",
        ));
    };
    if !args.listen.ip().is_loopback() {
        writeln!(
            ctx.host.err,
            "warning: listening on {}, which is not loopback: the server's API is exposed to that network. Clients \
             still need an API key, but anyone who can reach the port can try one.",
            args.listen
        )?;
    }
    let tunnel = ctx.tunnel(address)?;
    // A laptop that moves from Wi-Fi to 4G gets a new endpoint on its new addresses (§10).
    let _network_watch = ctx.watch_networks().await;
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| CliError::usage(format!("cannot listen on {}: {e}", args.listen)))?;
    let local = listener.local_addr()?;
    writeln!(
        ctx.host.err,
        "p2pc proxy: listening on http://{local}, tunnelled to server {}. Clients send their own API key. Stop with \
         Ctrl-C.",
        tunnel.server_short()
    )?;
    ctx.host.err.flush()?;

    let (interrupt, terminate) = (ctx.host.interrupt.take(), ctx.host.terminate.take());
    let mut interrupt = std::pin::pin!(signal_or_never(interrupt));
    let mut terminate = std::pin::pin!(signal_or_never(terminate));
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let (notes, mut notes_rx) = mpsc::unbounded_channel::<String>();
    let mut connections = JoinSet::new();
    let code = loop {
        tokio::select! {
            biased;
            () = &mut interrupt => break EXIT_INTERRUPTED,
            () = &mut terminate => break EXIT_OK,
            Some(note) = notes_rx.recv() => {
                let _ = writeln!(ctx.host.err, "p2pc proxy: {note}");
            }
            // Reap finished connection tasks so the set does not grow.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = accept(&listener, &slots) => match accepted {
                Ok((tcp, permit)) => {
                    let (tunnel, notes) = (tunnel.clone(), notes.clone());
                    connections.spawn(async move {
                        let _permit = permit;
                        serve(tunnel, tcp, notes).await;
                    });
                }
                Err(e) => {
                    let _ = writeln!(ctx.host.err, "p2pc proxy: accept failed: {e}");
                    // Out of file descriptors, for example: do not spin.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    };
    connections.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), tunnel.close()).await;
    writeln!(ctx.host.err, "p2pc proxy: stopped")?;
    Ok(code)
}

/// The signal's future, or one that never completes.
pub(crate) async fn signal_or_never(signal: Option<crate::app::Interrupt<'_>>) {
    match signal {
        Some(signal) => signal.await,
        None => std::future::pending().await,
    }
}

/// Waits for a free slot, then for a connection.
async fn accept(
    listener: &TcpListener,
    slots: &Arc<Semaphore>,
) -> std::io::Result<(tokio::net::TcpStream, tokio::sync::OwnedSemaphorePermit)> {
    let permit = slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| std::io::Error::other("the proxy is shutting down"))?;
    let (tcp, _) = listener.accept().await?;
    Ok((tcp, permit))
}

/// One local connection: a stream of the tunnel, then the relay. A failure is reported once, without the request.
async fn serve(tunnel: Tunnel, tcp: tokio::net::TcpStream, notes: mpsc::UnboundedSender<String>) {
    match tunnel.open_stream().await {
        Ok(stream) => {
            relay_tcp(stream, tcp, RelayLimits::default()).await;
        }
        Err(e) => {
            let _ = notes.send(format!("could not reach the server: {e}"));
            // Dropping the connection tells the local client.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T11b1 review: with every slot taken, the next local connection waits (in the listen backlog) until one frees.
    /// The clock is paused, so "waits" is checked without real time passing: a timeout fires only once nothing else
    /// can run, and a connection that is ready is accepted before it.
    #[tokio::test(start_paused = true)]
    async fn the_65th_connection_waits_until_a_slot_frees() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let served = accept(&listener, &slots).await.unwrap();
            held.push((client, served));
        }
        assert_eq!(slots.available_permits(), 0);
        let _waiting = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(60), accept(&listener, &slots))
                .await
                .is_err(),
            "the 65th connection must wait while 64 are served"
        );
        // One connection ends and frees its slot: the 65th is accepted.
        drop(held.pop());
        let (_tcp, _permit) = tokio::time::timeout(Duration::from_secs(60), accept(&listener, &slots))
            .await
            .expect("accepted once a slot is free")
            .unwrap();
        assert_eq!(slots.available_permits(), 0);
    }
}
