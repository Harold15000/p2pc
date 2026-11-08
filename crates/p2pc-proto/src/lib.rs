// SPDX-License-Identifier: Apache-2.0

//! API and agent-protocol types, framing and validation for P2PC. No I/O.
//!
//! This crate is the single source of truth for every wire type and every input-validation rule. The server, the
//! agent, the CLI and the shim all depend on it. It does no networking and keeps no runtime state: the only I/O
//! surface is the frame codec in [`protocol`], which works over any [`tokio::io::AsyncRead`] or
//! [`tokio::io::AsyncWrite`] that the caller provides.
//!
//! See `docs/specs/H1-personal-cloud.md` §4-§7 and §11.
//!
//! - [`ids`]: typed IDs (`job_…`, `node_…`, `lse_…`, `prj_…`, `acc_…`) and API key IDs.
//! - [`api`]: the REST models of §7, including the job state machine.
//! - [`validate`]: the §7 validation table, image references, image globs and egress domain matching.
//! - [`auth`]: API keys, join tokens and redacted secrets (§5).
//! - [`protocol`]: the agent protocol messages of §6 and the length-prefixed JSON codec.
//! - [`units`]: compute units and the cost estimate (§11).
//! - [`net`]: address hygiene for the iroh endpoints (§10): which local addresses to bind and advertise.

#![warn(missing_docs)]

pub mod api;
pub mod auth;
pub mod ids;
pub mod net;
pub mod protocol;
pub mod units;
pub mod validate;

mod timestamp;

/// ALPN of the agent ↔ control-plane protocol (spec §6).
pub const PROTOCOL_ALPN_AGENT: &[u8] = b"p2pc/agent/1";

/// ALPN of the REST tunnel used by `p2pc proxy` (spec §10).
pub const PROTOCOL_ALPN_HTTP: &[u8] = b"p2pc/http/1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_constants_match_the_spec() {
        assert_eq!(PROTOCOL_ALPN_AGENT, b"p2pc/agent/1");
        assert_eq!(PROTOCOL_ALPN_HTTP, b"p2pc/http/1");
    }

    #[test]
    fn alpn_constants_are_distinct() {
        assert_ne!(PROTOCOL_ALPN_AGENT, PROTOCOL_ALPN_HTTP);
    }
}
