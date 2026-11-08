// SPDX-License-Identifier: AGPL-3.0-only

//! Logging setup (`tracing`), on stderr.
//!
//! What is never logged (SI-6): the `Authorization` header, API keys, request bodies and job `env` values. The only
//! per-request line is method, path, status and latency (see `app::log_request`).

use tracing_subscriber::EnvFilter;

/// Installs the global subscriber. `RUST_LOG`, when set, overrides `level` (a filter from `server.toml`).
pub fn init(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    // Fails only if a subscriber is already installed, which is fine.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        // No colour codes in journald or log files.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .try_init();
}

/// Replaces the default panic hook, which prints the panic message (it could contain data), with one log line
/// that only says where the panic happened.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        tracing::error!(%location, "panic");
    }));
}
