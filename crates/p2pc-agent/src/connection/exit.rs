// SPDX-License-Identifier: Apache-2.0

//! Exit codes of `p2pc-agent join` and `p2pc-agent run`: one per outcome a script or a service manager may want to
//! tell apart. `2` is clap's code for a usage error and is left to it.

/// Success.
pub const OK: u8 = 0;
/// Any other error (network, files, configuration).
pub const FAILURE: u8 = 1;
/// `join`: this machine is already enrolled; `--force` enrolls it again.
pub const ALREADY_ENROLLED: u8 = 3;
/// `join`: the token is malformed, or the server refused it (`invalid_token`: unknown, revoked or used by another
/// machine).
pub const INVALID_TOKEN: u8 = 4;
/// `join`: the token has expired.
pub const TOKEN_EXPIRED: u8 = 5;
/// `join` or `run`: the server refuses agents this old (`agent_too_old`); upgrade the agent.
pub const AGENT_TOO_OLD: u8 = 6;
/// `run`: the server says this machine is not enrolled (`not_enrolled`): it was removed; join again.
pub const NOT_ENROLLED: u8 = 7;
/// `run`: this machine never joined (no `[server]` in `agent.toml`).
pub const NOT_JOINED: u8 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct_and_avoid_clap_usage_errors() {
        let all = [
            OK,
            FAILURE,
            ALREADY_ENROLLED,
            INVALID_TOKEN,
            TOKEN_EXPIRED,
            AGENT_TOO_OLD,
            NOT_ENROLLED,
            NOT_JOINED,
        ];
        let unique: std::collections::BTreeSet<u8> = all.iter().copied().collect();
        assert_eq!(unique.len(), all.len());
        assert!(!unique.contains(&2));
    }
}
