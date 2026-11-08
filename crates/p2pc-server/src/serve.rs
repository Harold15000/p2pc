// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-server serve`: opens the database and serves the API on `bind` until SIGINT or SIGTERM.
//!
//! Connections get the limits of spec §10 "Slow clients" (`[http]` in `server.toml`):
//! - at most `max_connections` open at once: the accept loop takes a semaphore permit **before** `accept`, so an
//!   extra client waits in the listen backlog until another connection closes;
//! - the header and keep-alive idle limits, per connection ([`crate::conn::ConnIo`]);
//! - the body and whole-request limits, as tower layers on the router ([`crate::app::router`]).
//!
//! Connections are served by hyper's own HTTP/1 builder (the API speaks nothing else, and the limits above are
//! HTTP/1 limits), with a `TokioTimer`. hyper-util's `server-auto` feature (and the HTTP/2 code it pulls in) is not
//! compiled at all.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::app::{AppState, router};
use crate::clock::SystemClock;
use crate::config::Config;
use crate::conn::{ConnIo, ConnState, Tracked};
use crate::gateway::{EndpointOptions, Gateway, GatewayConfig};
use crate::scheduler::Scheduler;
use crate::store::{self, OpenMode};

/// Pause after a failed `accept` (for example, out of file descriptors), so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Runs the server with a validated config until SIGINT or SIGTERM, then drains in-flight requests.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let db = store::open(&config.db_path(), OpenMode::Existing).await?;
    let bind = config.bind;
    // The iroh key: created on the first start if `init` predates it; refused if group or others can read it.
    crate::identity::load_or_create(&config.data_dir)?;
    let mut state = AppState::load(db.clone(), config, Arc::new(SystemClock)).await?;
    // The scheduler (T06), created before the gateway: its boot time, from which no lease expires before
    // `lease_ttl_s`, is then never later than the gateway's restart grace. It answers the estimates too.
    let scheduler = Scheduler::new(&state, Arc::new(state.hub.clone()));
    state.nodes = Arc::new(scheduler.clone());
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| anyhow::anyhow!("cannot listen on {bind}: {e}"))?;
    tracing::info!(%bind, "p2pc-server listening");
    let failures = state.auth_failures.clone();
    let options = EndpointOptions::from_config(&state.config, &state.server).await;
    let mut gateway_config = GatewayConfig::new(options, rest_target(bind));
    // §10 "Tunnel budget", validated at load against `http.max_connections`.
    gateway_config.limits.http_streams_total = state.config.iroh.tunnel_max_streams as usize;
    gateway_config.reconciler = Arc::new(scheduler.clone());
    gateway_config.events = Arc::new(scheduler.clone());
    let gateway = Gateway::start(state.clone(), gateway_config).await?;
    let scheduling = scheduler.spawn(Some(state.hub.subscribe()));
    // §12: the logs and artifacts of old jobs, and staging that never finalised.
    let gc = crate::gc::spawn(state.clone());
    tracing::info!(address = %state.server.address(), "server address");
    serve_on(listener, state, shutdown_signal()).await?;
    scheduling.abort();
    gc.abort();
    gateway.shutdown().await;
    // Write the failed authentications still queued before closing the database.
    failures.flush().await;
    db.close().await;
    tracing::info!("p2pc-server stopped");
    Ok(())
}

/// Serves on an already-bound listener until `shutdown` completes. Then it stops accepting, closes the listener,
/// lets in-flight requests finish (idle keep-alive connections close at once) and returns, waiting at most the
/// whole-request limit plus one second.
pub async fn serve_on(
    listener: TcpListener,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let http = state.config.http.clone();
    let app = router(state);
    let permits = Arc::new(Semaphore::new(http.max_connections as usize));
    let graceful = GracefulShutdown::new();
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        // `ConnIo` enforces the header limit, counted from a request's first byte: hyper's timer would also run
        // while a keep-alive connection is idle (see `crate::conn`).
        .header_read_timeout(None)
        .keep_alive(true);
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        // A slot first, then the connection: over the cap, clients wait in the backlog.
        let permit = tokio::select! {
            biased;
            () = &mut shutdown => break,
            p = permits.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break,
            },
        };
        let stream = tokio::select! {
            biased;
            () = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok((stream, _peer)) => stream,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    drop(permit);
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let conn_state = Arc::new(ConnState::default());
        let io = TokioIo::new(ConnIo::new(
            stream,
            conn_state.clone(),
            http.header_read_timeout(),
            http.keepalive_idle(),
        ));
        let service = Tracked::new(TowerToHyperService::new(app.clone()), conn_state);
        let conn = graceful.watch(builder.serve_connection(io, service));
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "connection closed with an error");
            }
            drop(permit);
        });
    }
    drop(listener);
    let grace = http.request_timeout() + Duration::from_secs(1);
    if tokio::time::timeout(grace, graceful.shutdown()).await.is_err() {
        tracing::warn!("connections still open after the shutdown grace period");
    }
    Ok(())
}

/// Where `p2pc/http/1` streams connect: the REST listener, through loopback when it listens on every address.
#[must_use]
pub fn rest_target(bind: std::net::SocketAddr) -> std::net::SocketAddr {
    let ip = match bind.ip() {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        std::net::IpAddr::V6(v6) if v6.is_unspecified() => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    std::net::SocketAddr::new(ip, bind.port())
}

/// Completes on SIGINT (Ctrl-C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = ctrl_c => tracing::info!("SIGINT received, shutting down"),
        () = term => tracing::info!("SIGTERM received, shutting down"),
    }
}
