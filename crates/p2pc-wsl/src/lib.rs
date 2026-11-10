// SPDX-License-Identifier: Apache-2.0

//! WSL management for the P2PC desktop app (H2 spec §4.1 and §8.3).
//!
//! A Rust port of the parts of `deploy/wsl/install.ps1` the app needs (§8.3: the script stays the developer path; the
//! app never calls it). This task (T2-40) covers the first half of §8.3:
//!
//! - [`checks`]: the checks of §8.2 step 2, with H1's thresholds;
//! - [`image`]: the image download (HTTP range resume) and its SHA-256 verification before import;
//! - [`import`]: `wsl --import p2pc-node … --version 2`, the verification of the new distro and the boot-status
//!   freshness rule (`init_starttime`);
//! - [`task`]: the scheduled task "P2PC node" (its wrapper, its task XML through `schtasks /Create /XML`, its rights).
//!
//! T2-45 adds upgrade and uninstall.
//!
//! **How it reaches Windows.** Every Windows program (`wsl.exe`, `schtasks.exe`, PowerShell) runs through
//! [`runner::CommandRunner`], so every behaviour is unit-tested on any OS with a fake runner; only
//! [`runner::SystemRunner`] starts real processes. `wsl.exe` calls are retried on the WSL service timeout
//! (`Wsl/Service/0x8007274c`) exactly as `install.ps1` does. No secret ever goes on a command line: the runner refuses an
//! argument or an environment value that looks like a join token or an API key.
//!
//! **What it never touches** (§8.3): other distros, `.wslconfig`, Windows features, the firewall, or anything outside
//! `%LOCALAPPDATA%\P2PC` ([`Layout`]).
//!
//! The functions are blocking (they wait for `wsl.exe`, and the download uses reqwest's blocking client): the app calls
//! them from a blocking thread (for example `tokio::task::spawn_blocking`), never from inside an async task.

use std::path::{Path, PathBuf};

pub mod checks;
pub mod image;
pub mod import;
pub mod runner;
pub mod task;

/// The one distro this crate creates, verifies or runs commands in (`$DistroName` in `install.ps1`).
pub const DISTRO_NAME: &str = "p2pc-node";

/// Where P2PC keeps its files on Windows: `%LOCALAPPDATA%\P2PC` and the fixed names under it (H2 §8.2, §8.3, §8.7;
/// the same layout as `install.ps1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// The layout under a given `%LOCALAPPDATA%` directory.
    pub fn new(local_app_data: impl AsRef<Path>) -> Self {
        Self {
            root: local_app_data.as_ref().join("P2PC"),
        }
    }

    /// The layout under the `LOCALAPPDATA` of this process, or `None` when it is not set (not Windows).
    pub fn from_env() -> Option<Self> {
        let dir = std::env::var_os("LOCALAPPDATA")?;
        if dir.is_empty() {
            return None;
        }
        Some(Self::new(PathBuf::from(dir)))
    }

    /// `%LOCALAPPDATA%\P2PC`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `%LOCALAPPDATA%\P2PC\wsl\p2pc-node`: where WSL keeps the distro's virtual disk (`install.ps1 -InstallDir`'s
    /// default, and the path of §8.3).
    pub fn distro_dir(&self) -> PathBuf {
        self.root.join("wsl").join(DISTRO_NAME)
    }

    /// `%LOCALAPPDATA%\P2PC\images`: where the downloaded node image is kept until it is imported.
    pub fn images_dir(&self) -> PathBuf {
        self.root.join("images")
    }

    /// `%LOCALAPPDATA%\P2PC\node-task.cmd`: the task's wrapper, which the app writes and owns.
    pub fn task_wrapper(&self) -> PathBuf {
        self.root.join("node-task.cmd")
    }

    /// `%LOCALAPPDATA%\P2PC\stopped-by-node`: the wrapper's record of a terminal stop.
    pub fn stop_record(&self) -> PathBuf {
        self.root.join("stopped-by-node")
    }

    /// `%LOCALAPPDATA%\P2PC\node-task.xml`: the task XML handed to `schtasks /Create /XML`, deleted afterwards.
    pub fn task_xml(&self) -> PathBuf {
        self.root.join("node-task.xml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_names_the_install_ps1_paths() {
        let l = Layout::new("LAD");
        let p = |parts: &[&str]| parts.iter().fold(PathBuf::from("LAD"), |acc, s| acc.join(s));
        assert_eq!(l.root(), p(&["P2PC"]));
        assert_eq!(l.distro_dir(), p(&["P2PC", "wsl", "p2pc-node"]));
        assert_eq!(l.task_wrapper(), p(&["P2PC", "node-task.cmd"]));
        assert_eq!(l.stop_record(), p(&["P2PC", "stopped-by-node"]));
        assert_eq!(l.task_xml(), p(&["P2PC", "node-task.xml"]));
        assert_eq!(l.images_dir(), p(&["P2PC", "images"]));
    }
}
