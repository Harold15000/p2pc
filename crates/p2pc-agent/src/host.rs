// SPDX-License-Identifier: Apache-2.0

//! Read-only access to the machine's files (`/proc`, `/etc`, `/sys`, `/dev`) under a configurable root, so that
//! tests run the real detection code against a temporary directory.
//!
//! The agent never reads the Windows filesystem (CONTRIBUTING hard rule 8): nothing here touches `/mnt`.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

/// Most bytes read from a single system file. `/proc/cpuinfo` on a 256-core machine is well under this.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The machine being inspected.
///
/// Clones share one [`SingleFlight`]: keep one `Host` for the life of the agent, so that a blocking read stuck on a
/// hung filesystem is never started a second time by the next detection.
#[derive(Debug, Clone)]
pub struct Host {
    root: PathBuf,
    wsl_interop_env: bool,
    /// Whether `WSL_DISTRO_NAME` is set: WSL sets it for what runs in a distro.
    wsl_distro_env: bool,
    /// The agent's own `PATH`, for the §9.0 "no Windows `PATH` entries" check.
    path_env: Option<String>,
    flights: Arc<SingleFlight>,
    /// What is left of the process's wait for a fresh WSL2 boot status ([`crate::inventory::boot`]).
    boot_wait: Arc<Mutex<Option<tokio::time::Instant>>>,
}

/// One guard per kind of blocking work (T07b review, carry-over 2).
///
/// A detection gives up on a blocking read at its deadline, but the thread doing the read cannot be cancelled: it
/// stays stuck until the read returns. Starting a new one at every detection (every 10 minutes, every `Hello`) would
/// pile up threads on a hung `/proc` or network filesystem. So each kind of work runs at most once at a time: while
/// the previous one is still running, [`SingleFlight::start`] refuses, and the caller reports the part as unknown.
/// The first refusal of a stuck episode is logged once, at warning level.
#[derive(Debug, Default)]
pub struct SingleFlight {
    state: Mutex<HashMap<&'static str, FlightState>>,
}

#[derive(Debug, Default)]
struct FlightState {
    running: bool,
    warned: bool,
    started: u64,
}

/// Held by the blocking work while it runs; dropping it (when the work returns, or unwinds) frees the slot.
#[derive(Debug)]
pub struct FlightToken {
    flights: Arc<SingleFlight>,
    key: &'static str,
}

impl Drop for FlightToken {
    fn drop(&mut self) {
        let mut state = self.flights.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(s) = state.get_mut(self.key) {
            s.running = false;
            s.warned = false;
        }
    }
}

impl SingleFlight {
    /// Starts the work `key`, or `None` while a previous run of it is still going.
    pub fn start(self: &Arc<Self>, key: &'static str) -> Option<FlightToken> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let s = state.entry(key).or_default();
        if s.running {
            if !s.warned {
                s.warned = true;
                tracing::warn!(
                    work = key,
                    "a blocking read from an earlier detection is still stuck; not starting another one until it \
                     returns (reported as unknown meanwhile)"
                );
            }
            return None;
        }
        s.running = true;
        s.started += 1;
        Some(FlightToken {
            flights: self.clone(),
            key,
        })
    }

    /// How many times the work `key` was started (tests).
    #[must_use]
    pub fn started(&self, key: &str) -> u64 {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.get(key).map_or(0, |s| s.started)
    }
}

impl Host {
    /// The real machine: root `/`, and the agent's own environment.
    #[must_use]
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
            wsl_interop_env: std::env::var_os("WSL_INTEROP").is_some(),
            wsl_distro_env: std::env::var_os("WSL_DISTRO_NAME").is_some_and(|v| !v.is_empty()),
            path_env: std::env::var("PATH").ok(),
            flights: Arc::default(),
            boot_wait: Arc::default(),
        }
    }

    /// A fake machine whose filesystem lives under `root` (tests).
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            wsl_interop_env: false,
            wsl_distro_env: false,
            path_env: None,
            flights: Arc::default(),
            boot_wait: Arc::default(),
        }
    }

    /// The single-flight guards of this host's blocking work.
    #[must_use]
    pub fn flights(&self) -> &Arc<SingleFlight> {
        &self.flights
    }

    /// The deadline of the boot-status wait: [`BOOT_STATUS_WAIT`](crate::inventory::boot::BOOT_STATUS_WAIT)
    /// after the first call, the same for the life of this host (and its clones).
    pub fn boot_wait_deadline(&self) -> tokio::time::Instant {
        let mut deadline = self.boot_wait.lock().unwrap_or_else(PoisonError::into_inner);
        *deadline.get_or_insert_with(|| tokio::time::Instant::now() + crate::inventory::boot::BOOT_STATUS_WAIT)
    }

    /// Sets whether `WSL_INTEROP` is present in the environment (tests).
    #[must_use]
    pub fn wsl_interop_env(mut self, set: bool) -> Self {
        self.wsl_interop_env = set;
        self
    }

    /// Sets whether `WSL_DISTRO_NAME` is present in the environment (tests).
    #[must_use]
    pub fn wsl_distro_env(mut self, set: bool) -> Self {
        self.wsl_distro_env = set;
        self
    }

    /// Whether `WSL_DISTRO_NAME` is set: the agent runs inside a WSL distro.
    #[must_use]
    pub fn has_wsl_distro_env(&self) -> bool {
        self.wsl_distro_env
    }

    /// Sets the agent's `PATH` (tests).
    #[must_use]
    pub fn path_env(mut self, path: impl Into<String>) -> Self {
        self.path_env = Some(path.into());
        self
    }

    /// The agent's `PATH`, if known.
    #[must_use]
    pub fn path_var(&self) -> Option<&str> {
        self.path_env.as_deref()
    }

    /// Whether the `WSL_INTEROP` variable is set, which means Windows interop is enabled.
    #[must_use]
    pub fn has_wsl_interop_env(&self) -> bool {
        self.wsl_interop_env
    }

    /// The real path of the absolute machine path `abs`.
    #[must_use]
    pub fn path(&self, abs: impl AsRef<Path>) -> PathBuf {
        let abs = abs.as_ref();
        self.root.join(abs.strip_prefix("/").unwrap_or(abs))
    }

    /// Reads a text file, at most [`MAX_FILE_BYTES`].
    pub fn read(&self, abs: impl AsRef<Path>) -> io::Result<String> {
        let mut text = String::new();
        fs::File::open(self.path(abs))?
            .take(MAX_FILE_BYTES)
            .read_to_string(&mut text)?;
        Ok(text)
    }

    /// Whether the path exists (devices and dangling symlinks included).
    #[must_use]
    pub fn exists(&self, abs: impl AsRef<Path>) -> bool {
        fs::symlink_metadata(self.path(abs)).is_ok()
    }

    /// Modification time of a file.
    pub fn modified(&self, abs: impl AsRef<Path>) -> io::Result<SystemTime> {
        fs::metadata(self.path(abs))?.modified()
    }

    /// Names of the entries of a directory, sorted, at most `limit`. A missing directory is empty.
    #[must_use]
    pub fn list_dir(&self, abs: impl AsRef<Path>, limit: usize) -> Vec<String> {
        let Ok(entries) = fs::read_dir(self.path(abs)) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().into_string().ok())
            .take(limit)
            .collect();
        names.sort();
        names
    }

    /// The process's effective UID, from `/proc/self/status`.
    #[must_use]
    pub fn euid(&self) -> Option<u32> {
        self.read("/proc/self/status")
            .ok()
            .as_deref()
            .and_then(crate::parse::effective_uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_rebased_under_the_root() {
        let host = Host::with_root("/tmp/fake");
        assert_eq!(host.path("/proc/cpuinfo"), PathBuf::from("/tmp/fake/proc/cpuinfo"));
        assert_eq!(Host::system().path("/proc/cpuinfo"), PathBuf::from("/proc/cpuinfo"));
    }

    #[test]
    fn reads_and_lists_under_the_root() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc/cdi")).unwrap();
        fs::write(dir.path().join("etc/cdi/b.yaml"), "x").unwrap();
        fs::write(dir.path().join("etc/cdi/a.json"), "y").unwrap();
        fs::create_dir_all(dir.path().join("proc/self")).unwrap();
        fs::write(
            dir.path().join("proc/self/status"),
            "Name:\tx\nUid:\t1000\t0\t1000\t1000\n",
        )
        .unwrap();
        let host = Host::with_root(dir.path());
        assert_eq!(host.read("/etc/cdi/b.yaml").unwrap(), "x");
        assert_eq!(host.list_dir("/etc/cdi", 10), vec!["a.json", "b.yaml"]);
        assert!(host.list_dir("/var/run/cdi", 10).is_empty());
        assert!(host.exists("/etc/cdi") && !host.exists("/dev/dxg"));
        assert_eq!(host.euid(), Some(0), "the effective UID is the second field");
    }
}
