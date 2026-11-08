// SPDX-License-Identifier: Apache-2.0

//! `p2pc-agent join <token>` (§5 "Join tokens", §6): one connection, `Join{token, inventory}`, one answer.
//!
//! - `Welcome`: the caller writes `[server]` into `agent.toml` (the server's NodeId and relays from the token, the
//!   `account_id` and our `node_id` from the `Welcome`). The stored `account_id` is the owner for SI-1.
//! - `Error`: one [`JoinError`] per code, each with its own exit code ([`super::exit`]) and a message that says what
//!   to do.
//!
//! The token is a secret (SI-6): it travels only inside the `Join` frame, and is never printed, logged, or put in an
//! error. `JoinToken`'s `Debug` hides its code.

use std::path::Path;
use std::time::Duration;

use p2pc_proto::api::Inventory;
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{AccountId, NodeId};
use p2pc_proto::protocol::{AgentMsg, MAX_FRAME_LEN, ServerMsg, error_code, read_frame, write_frame};
use tokio::io::AsyncWriteExt as _;

use super::exit;
use super::state::StateFile;
use super::transport::Connector;
use crate::config::{Env, ServerSection, write_server_section};

/// The longest a whole `join` may take: dial, `Join`, `Welcome`.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(30);

/// How far past its expiry a token is still sent to the server. The server's row is the only expiry that counts
/// (SI-11); the local check only spares a pointless dial. A clock that runs ahead (WSL2 after the host sleeps) must
/// not refuse a token that is still valid (T05b final review).
pub const CLOCK_SKEW_TOLERANCE: time::Duration = time::Duration::minutes(5);

/// Whether `token` is expired beyond any plausible clock skew at `now`: then it is refused without dialling. One that
/// only looks expired, within [`CLOCK_SKEW_TOLERANCE`], is sent anyway with a warning, and the server decides.
#[must_use]
pub fn expired_locally(token: &JoinToken, now: time::OffsetDateTime) -> bool {
    if !token.is_expired(now) {
        return false;
    }
    if token.is_expired(now - CLOCK_SKEW_TOLERANCE) {
        return true;
    }
    tracing::warn!(
        tolerance_s = CLOCK_SKEW_TOLERANCE.whole_seconds(),
        "the join token looks expired by this machine's clock, by less than the tolerance; sending it anyway, the \
         server decides (check this machine's clock)"
    );
    false
}

/// What the `Welcome` of a `Join` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    /// This node's ID on the server.
    pub node_id: NodeId,
    /// The account it is enrolled into: its owner.
    pub account_id: AccountId,
    /// The server's version.
    pub server_version: String,
}

/// Why a join failed. No variant ever holds the token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JoinError {
    /// The server could not be reached.
    #[error("cannot reach the server: {0}")]
    Connect(String),
    /// No answer within [`JOIN_TIMEOUT`].
    #[error("the server did not answer within {} s", JOIN_TIMEOUT.as_secs())]
    Timeout,
    /// The token's own expiry has passed (checked locally before dialling).
    #[error(
        "the join token has expired; create a new one with `p2pc join-token create` (tokens last 15 minutes by \
         default)"
    )]
    Expired,
    /// `Error{invalid_token}`.
    #[error(
        "the server refused the join token: it is unknown, expired, revoked, or already used by another machine; \
         create a new one with `p2pc join-token create`"
    )]
    InvalidToken,
    /// `Error{agent_too_old}`.
    #[error(
        "the server refuses this agent version ({}); upgrade p2pc-agent and join again",
        crate::inventory::AGENT_VERSION
    )]
    AgentTooOld,
    /// Another `Error`.
    #[error("the server refused the join ({code}): {message}")]
    Server {
        /// The code.
        code: String,
        /// The server's message.
        message: String,
    },
    /// The connection closed with no answer: the server is over one of its limits for machines that are not
    /// enrolled yet (§6 "Before Join").
    #[error("the server closed the connection without an answer (too many join attempts?); try again in a minute")]
    NoAnswer,
    /// The answer made no sense.
    #[error("unexpected answer from the server: {0}")]
    Protocol(String),
    /// Enrolled, but `[server]` could not be saved: join again with `--force` once the file is fixed.
    #[error("enrolled, but the config file could not be updated: {0}")]
    Save(String),
}

impl JoinError {
    /// The exit code of `p2pc-agent join` for this error.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            JoinError::Expired => exit::TOKEN_EXPIRED,
            JoinError::InvalidToken => exit::INVALID_TOKEN,
            JoinError::AgentTooOld => exit::AGENT_TOO_OLD,
            JoinError::Connect(_)
            | JoinError::Timeout
            | JoinError::Server { .. }
            | JoinError::NoAnswer
            | JoinError::Protocol(_)
            | JoinError::Save(_) => exit::FAILURE,
        }
    }
}

/// `p2pc-agent join`: [`join`], then `[server]` written into the config file at `config_path` (atomically, mode
/// 0600), from the token (the server's NodeId and relay hints) and the `Welcome` (the owner account and our node ID).
///
/// The local files of the earlier enrollment's connection, in `data_dir` (the state file behind `status`, and the
/// running leases), are deleted: nothing of it is shown for the new one (T05b real run, round 2).
pub async fn enroll(
    connector: &dyn Connector,
    token: &JoinToken,
    inventory: Inventory,
    config_path: &Path,
    env: &Env,
    data_dir: &Path,
) -> Result<(Joined, ServerSection), JoinError> {
    let joined = join(connector, token, inventory).await?;
    let section = ServerSection {
        node_id: token.server.clone(),
        relays: token.relays.iter().map(ToString::to_string).collect(),
        account_id: joined.account_id,
        agent_node_id: joined.node_id,
    };
    write_server_section(config_path, &section, env).map_err(|e| JoinError::Save(e.to_string()))?;
    forget_connection_state(data_dir);
    // Never the token (SI-6): IDs only.
    tracing::info!(node_id = %joined.node_id, account_id = %joined.account_id, "enrolled with the server");
    Ok((joined, section))
}

/// Deletes what `run` recorded of the earlier enrollment's connection. A failure is logged, never fatal: `status`
/// also checks that a state file is this enrollment's.
pub fn forget_connection_state(data_dir: &Path) {
    if let Err(e) = StateFile::in_dir(data_dir).reset() {
        tracing::warn!(error = %e, "cannot delete the earlier enrollment's state file");
    }
    let leases = data_dir.join(crate::executor::status::LEASES_FILE);
    if let Err(e) = std::fs::remove_file(&leases)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(error = %e, "cannot delete the earlier enrollment's leases file");
    }
}

/// Enrolls this machine: sends `Join{token, inventory}` and waits for the answer. The connection is closed after
/// it either way.
pub async fn join(connector: &dyn Connector, token: &JoinToken, inventory: Inventory) -> Result<Joined, JoinError> {
    if expired_locally(token, time::OffsetDateTime::now_utc()) {
        return Err(JoinError::Expired);
    }
    let result = tokio::time::timeout(JOIN_TIMEOUT, exchange(connector, token, inventory))
        .await
        .unwrap_or(Err(JoinError::Timeout));
    connector.shutdown().await;
    result
}

async fn exchange(connector: &dyn Connector, token: &JoinToken, inventory: Inventory) -> Result<Joined, JoinError> {
    let mut link = connector.connect().await.map_err(|e| JoinError::Connect(e.0))?;
    let msg = AgentMsg::Join {
        token: token.clone(),
        inventory,
    };
    write_frame(&mut link.send, &msg)
        .await
        .map_err(|e| JoinError::Connect(e.to_string()))?;
    let answer = read_frame::<ServerMsg, _>(&mut link.recv, MAX_FRAME_LEN).await;
    let _ = link.send.shutdown().await;
    link.close();
    let answer = match answer {
        Ok(Some(answer)) => answer,
        Ok(None) | Err(p2pc_proto::protocol::FrameError::Io(_) | p2pc_proto::protocol::FrameError::Truncated) => {
            return Err(JoinError::NoAnswer);
        }
        Err(e) => return Err(JoinError::Protocol(e.to_string())),
    };
    answer.validate().map_err(|e| JoinError::Protocol(e.to_string()))?;
    match answer {
        ServerMsg::Welcome {
            server_version,
            node_id,
            account_id,
            ..
        } => Ok(Joined {
            node_id,
            account_id,
            server_version,
        }),
        ServerMsg::Error { code, .. } if code == error_code::INVALID_TOKEN => Err(JoinError::InvalidToken),
        ServerMsg::Error { code, .. } if code == error_code::AGENT_TOO_OLD => Err(JoinError::AgentTooOld),
        ServerMsg::Error { code, message } => Err(JoinError::Server { code, message }),
        other => Err(JoinError::Protocol(format!("`{}` instead of Welcome", other.kind()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T05b final review: the token's own expiry is only a hint. Within 5 minutes past it, the token is still sent.
    #[test]
    fn a_token_that_only_looks_expired_is_still_sent() {
        let issued = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let token = JoinToken::generate(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
            vec![],
            time::Duration::minutes(15),
            issued,
        )
        .unwrap();
        let at = |m: i64| issued + time::Duration::minutes(15) + time::Duration::seconds(m);
        assert!(!expired_locally(&token, at(-60)), "valid");
        assert!(!expired_locally(&token, at(0)), "just expired: the server decides");
        assert!(!expired_locally(&token, at(4 * 60 + 59)), "within the tolerance");
        assert!(expired_locally(&token, at(5 * 60)), "beyond it");
        assert!(expired_locally(&token, at(2 * 3600)));
    }

    #[test]
    fn each_error_has_its_exit_code() {
        assert_eq!(JoinError::Expired.exit_code(), exit::TOKEN_EXPIRED);
        assert_eq!(JoinError::InvalidToken.exit_code(), exit::INVALID_TOKEN);
        assert_eq!(JoinError::AgentTooOld.exit_code(), exit::AGENT_TOO_OLD);
        assert_eq!(JoinError::Timeout.exit_code(), exit::FAILURE);
        // The messages say what to do.
        assert!(JoinError::InvalidToken.to_string().contains("join-token create"));
        assert!(JoinError::Expired.to_string().contains("expired"));
        assert!(JoinError::AgentTooOld.to_string().contains("upgrade"));
    }
}
