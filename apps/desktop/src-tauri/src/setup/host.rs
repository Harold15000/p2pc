// SPDX-License-Identifier: Apache-2.0

//! What first run does on this PC, behind one trait (H2 §8.2, §8.3).
//!
//! [`SetupHost`] is every Windows and WSL action of steps 2 to 4: the checks, the elevated WSL install of step 2a and
//! its `RunOnce` entry, the image download, the import, the scheduled task, the node's hardware, WSL's networking
//! mode, the share, the hub's init, config and flag, and the local agent's join. The flow ([`super::flow`]) decides
//! when to call what and is tested with a fake; [`super::wsl_host::WslHost`] is the real one, over `p2pc-wsl`.
//!
//! Every method is blocking (it waits for `wsl.exe`, PowerShell or the network): the app calls the flow from a
//! blocking thread.

use std::fmt;
use std::ops::ControlFlow;

use zeroize::Zeroizing;

use p2pc_wsl::checks::ChecksReport;
use p2pc_wsl::image::Progress;

use super::errors::SetupError;
use super::record::{NetworkingMode, ShareRecord};

/// How the elevated `wsl --install --no-distribution` of step 2a ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslInstall {
    /// It finished; the checks run again.
    Installed,
    /// It finished and Windows needs the one reboot (the Virtual Machine Platform was enabled).
    RebootRequired,
    /// It failed, or the user declined the UAC prompt (`exit_code` is then `None`).
    Failed { exit_code: Option<i32> },
}

/// What the node reports about this PC's hardware (step 3's controls).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeFacts {
    /// The WSL VM's processors.
    pub cpu_cores: u32,
    /// The WSL VM's memory, in MiB.
    pub memory_mb: u64,
    /// A GPU the node can offer (detected, with a working driver and CDI).
    pub gpu_offerable: bool,
    /// What the agent offers by default.
    pub default_cpu: u32,
    pub default_memory_mb: u64,
}

/// What `p2pc-server init --owner-device` printed. Nothing secret: the device proves itself with its own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubInit {
    pub owner_device_id: String,
    pub server_address: String,
}

/// How `p2pc-agent join -` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinResult {
    /// Enrolled.
    Joined,
    /// The agent is already enrolled (exit 3).
    AlreadyEnrolled,
    /// The hub refused the token, or it expired (exits 4 and 5).
    Rejected,
    /// Anything else.
    Failed { exit_code: Option<i32> },
}

/// A join token. Secret (hard rule 5): never logged, never in an error, never on a command line, never in
/// `setup.json`; it goes from the hub's answer to the agent's stdin and is wiped when dropped.
pub struct JoinToken(Zeroizing<String>);

impl JoinToken {
    /// A token as the hub returned it.
    pub fn new(token: String) -> Self {
        Self(Zeroizing::new(token))
    }

    /// The token, for the agent's stdin only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinToken(<redacted>)")
    }
}

/// The Windows and WSL side of first run.
pub trait SetupHost: Send + Sync {
    /// Step 2: every check (`p2pc_wsl::checks`), with the default thresholds (`B = 0`: the role is not known yet).
    fn checks(&self) -> Result<ChecksReport, SetupError>;

    /// The free bytes on the profile's drive, measured now (the disk arithmetic of steps 3 and 4).
    fn free_bytes(&self) -> Result<u64, SetupError>;

    /// Step 2a: `wsl.exe --install --no-distribution`, elevated (one UAC prompt).
    fn install_wsl(&self) -> WslInstall;

    /// Step 2a: the `HKCU\…\RunOnce` entry that reopens the app after the reboot.
    fn reopen_after_reboot(&self) -> Result<(), SetupError>;

    /// Downloads the pinned image (resuming), and verifies it. Returns at once when it is already there and verifies.
    /// `progress` returning `Break` stops it (what was downloaded is kept).
    fn download_image(&self, progress: &mut dyn FnMut(Progress) -> ControlFlow<()>) -> Result<(), SetupError>;

    /// Step 3: verifies the downloaded image, imports the distro unless it exists, verifies it and waits for its boot
    /// status, then registers the scheduled task **disabled** (it is enabled at step 4, once there is a cloud for the
    /// node: an agent started before it joined would stop for good). Returns the image version line.
    fn install_distro(&self) -> Result<String, SetupError>;

    /// The node's hardware, from `p2pc-agent inventory --json` in the distro.
    fn node_facts(&self) -> Result<NodeFacts, SetupError>;

    /// WSL's networking mode, from `wslinfo --networking-mode` in the distro (§10.5).
    fn networking_mode(&self) -> NetworkingMode;

    /// Step 3: `p2pc-agent share set --cpu … --memory-mb … --gpu … --disk-mb … --volumes-mb …` (§8.4).
    fn apply_share(&self, share: &ShareRecord) -> Result<(), SetupError>;

    /// The hub's data dir in the distro is already initialised (`server.toml` exists).
    fn hub_initialised(&self) -> Result<bool, SetupError>;

    /// Step 4: `p2pc-server init --owner-device <NodeId> --label <label>` in the distro.
    fn init_hub(&self, owner_node_id: &str, label: &str) -> Result<HubInit, SetupError>;

    /// The hub's `p2pc_srv_…` address (`p2pc-server info`), for a data dir initialised earlier.
    fn hub_address(&self) -> Result<String, SetupError>;

    /// Step 4: sets `[blobs] blobs_quota_mb` in the hub's `server.toml`.
    fn set_blobs_quota(&self, quota_mb: u64) -> Result<(), SetupError>;

    /// Step 4: writes `hub.enabled`, then enables and starts the scheduled task, so `p2pc-run` starts the hub (§8.5).
    fn enable_hub(&self) -> Result<(), SetupError>;

    /// Step 4: `p2pc-agent join -` in the distro, the token on stdin.
    fn join_agent(&self, token: &JoinToken) -> JoinResult;

    /// Step 4: restarts the node's supervisor (task disabled, ended, distro terminated, then enabled and started), so
    /// the agent, now enrolled, runs.
    fn restart_node(&self) -> Result<(), SetupError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_join_token_never_shows_in_debug() {
        let t = JoinToken::new("p2pc_join_EXAMPLEONLY".into()); // gitleaks:allow
        assert_eq!(format!("{t:?}"), "JoinToken(<redacted>)");
        assert_eq!(t.expose(), "p2pc_join_EXAMPLEONLY"); // gitleaks:allow
    }
}
