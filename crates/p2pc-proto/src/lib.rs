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
//!
//! Milestone 2 (`docs/specs/H2-desktop-app.md` §5-§6) adds:
//!
//! - [`pair`]: pairing tickets (`p2pc_pair_…`) and the `p2pc/pair/1` messages (H2 §5.2-§5.3).
//! - [`invite`]: invites (`p2pc_inv_…`), the listener commitment and nonces, the `p2pc/invite/1` messages and the
//!   three 6-word check phrases (H2 §5.4, §5.5, §6.2).
//! - [`device`]: the constants and limits of `p2pc/device/1`, which carries HTTP/1.1 and has no messages of its own
//!   (H2 §6.3).
//! - In [`protocol`]: the H2 agent capabilities, the stream headers of the new agent-connection streams and the
//!   payloads of the new agent messages (H2 §6.1).

#![warn(missing_docs)]

pub mod api;
pub mod auth;
pub mod device;
pub mod ids;
pub mod invite;
pub mod net;
pub mod pair;
pub mod protocol;
pub mod units;
pub mod validate;

mod timestamp;

/// ALPN of the agent ↔ control-plane protocol (spec §6).
pub const PROTOCOL_ALPN_AGENT: &[u8] = b"p2pc/agent/1";

/// ALPN of the REST tunnel used by `p2pc proxy` (spec §10).
pub const PROTOCOL_ALPN_HTTP: &[u8] = b"p2pc/http/1";

/// ALPN of pairing, device → hub, authenticated by the one-time ticket in the message (H2 §5.3, §6).
pub const PROTOCOL_ALPN_PAIR: &[u8] = b"p2pc/pair/1";

/// ALPN of paired devices, device → hub: one HTTP/1.1 connection per stream, authenticated by the device's NodeId
/// through iroh's TLS (H2 §6.3).
pub const PROTOCOL_ALPN_DEVICE: &[u8] = b"p2pc/device/1";

/// ALPN of the invite listener of a PC that is joining, phone → that PC's app, authenticated by the one-time code in
/// the message (H2 §5.4, §6.2).
pub const PROTOCOL_ALPN_INVITE: &[u8] = b"p2pc/invite/1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_constants_match_the_spec() {
        assert_eq!(PROTOCOL_ALPN_AGENT, b"p2pc/agent/1");
        assert_eq!(PROTOCOL_ALPN_HTTP, b"p2pc/http/1");
        // H2 spec §6 table.
        assert_eq!(PROTOCOL_ALPN_PAIR, b"p2pc/pair/1");
        assert_eq!(PROTOCOL_ALPN_DEVICE, b"p2pc/device/1");
        assert_eq!(PROTOCOL_ALPN_INVITE, b"p2pc/invite/1");
    }

    #[test]
    fn alpn_constants_are_distinct() {
        let all = [
            PROTOCOL_ALPN_AGENT,
            PROTOCOL_ALPN_HTTP,
            PROTOCOL_ALPN_PAIR,
            PROTOCOL_ALPN_DEVICE,
            PROTOCOL_ALPN_INVITE,
        ];
        let unique: std::collections::BTreeSet<&[u8]> = all.into_iter().collect();
        assert_eq!(unique.len(), all.len());
    }
}
