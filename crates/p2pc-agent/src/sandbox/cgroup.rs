// SPDX-License-Identifier: Apache-2.0

//! The per-lease cgroup (spec §9 fixed arguments, "Memory").
//!
//! Each lease gets its own parent cgroup, passed with `--cgroup-parent`:
//! - **WSL2 (cgroupfs):** `/p2pc/<lease_id>`, which the agent creates as `/sys/fs/cgroup/p2pc/<lease_id>`
//!   ([`FsCgroups`]);
//! - **rootless Linux (systemd):** `p2pc-<lease_id>.slice`, a child of `p2pc.slice` under the `p2pc` user's
//!   delegated `user@<uid>.service` tree, started and stopped with `systemctl --user` ([`SystemdCgroups`]).
//!
//! After the run the agent reads `memory.events` and `pids.events` there. The counters are hierarchical, so they
//! include Podman's `libpod-<id>` child: this is how an OOM kill is seen even when Podman never sets
//! `State.OOMKilled` (measured on WSL2 with Podman 4.9.3 and cgroupfs, §9 "Memory").
//!
//! The paths sit behind the [`Cgroups`] trait, so that tests use a fake tree in a temporary directory.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};

use p2pc_proto::ids::LeaseId;

use crate::runner::CommandRunner;

/// The directory (cgroupfs) or slice prefix (systemd) of P2PC's cgroups.
pub const BASE: &str = "p2pc";
/// `CGROUP2_SUPER_MAGIC`: the filesystem type of a cgroup v2 mount.
const CGROUP2_MAGIC: i64 = 0x6367_7270;
/// How deep below the lease cgroup the event counters are looked for (`libpod-<id>/container/…`).
const MAX_EVENT_DEPTH: usize = 3;
/// Most cgroups below the lease cgroup read for event counters.
const MAX_EVENT_CGROUPS: usize = 64;
/// Controllers enabled for the lease cgroups.
const CONTROLLERS: [&str; 3] = ["+cpu", "+memory", "+pids"];

/// Counters read from a lease cgroup. Missing files read as 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupStats {
    /// `memory.events` `oom_kill`: processes killed by the OOM killer.
    pub oom_kill: u64,
    /// `pids.events` `max`: forks refused by the pids limit.
    pub pids_max: u64,
    /// `cpu.stat` `usage_usec`.
    pub cpu_usage_usec: u64,
    /// `memory.peak`, in bytes (kernel 5.19 and later).
    pub memory_peak_bytes: u64,
}

impl CgroupStats {
    /// The larger of each counter: they only grow, and a later read may find the cgroup gone.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        Self {
            oom_kill: self.oom_kill.max(other.oom_kill),
            pids_max: self.pids_max.max(other.pids_max),
            cpu_usage_usec: self.cpu_usage_usec.max(other.cpu_usage_usec),
            memory_peak_bytes: self.memory_peak_bytes.max(other.memory_peak_bytes),
        }
    }

    /// Reads the counters of the cgroup at `dir`.
    #[must_use]
    pub fn read(dir: &Path) -> Self {
        // `memory.events` is hierarchical, but before Linux 6.13 `pids.events` counts only in the cgroup whose
        // limit was hit: Podman's `libpod-<id>` child (or a `container` cgroup below it), where `--pids-limit`
        // is set. So the event counters are also read a few levels down, within a small bound.
        let mut acc = Self::read_one(dir);
        let mut stack = vec![(dir.to_path_buf(), 0usize)];
        let mut visited = 0usize;
        while let Some((d, depth)) = stack.pop() {
            if depth >= MAX_EVENT_DEPTH {
                continue;
            }
            let Ok(children) = std::fs::read_dir(&d) else { continue };
            for child in children.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())) {
                visited += 1;
                if visited > MAX_EVENT_CGROUPS {
                    return acc;
                }
                let c = Self::read_one(&child.path());
                acc.oom_kill = acc.oom_kill.max(c.oom_kill);
                acc.pids_max = acc.pids_max.max(c.pids_max);
                stack.push((child.path(), depth + 1));
            }
        }
        acc
    }

    fn read_one(dir: &Path) -> Self {
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
        Self {
            oom_kill: keyed(&read("memory.events"), "oom_kill"),
            pids_max: keyed(&read("pids.events"), "max"),
            cpu_usage_usec: keyed(&read("cpu.stat"), "usage_usec"),
            memory_peak_bytes: read("memory.peak").trim().parse().unwrap_or(0),
        }
    }
}

/// The value of `key` in a flat-keyed cgroup file (`key value` lines). Missing or malformed: 0.
#[must_use]
pub fn keyed(text: &str, key: &str) -> u64 {
    text.lines()
        .filter_map(|l| l.split_once(' '))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
}

/// The lease cgroups of one platform profile.
pub trait Cgroups: Send + Sync + 'static {
    /// The `--cgroup-parent` value.
    fn parent_arg(&self, lease: &LeaseId) -> String;
    /// Where the lease cgroup is on the host.
    fn path(&self, lease: &LeaseId) -> PathBuf;
    /// Creates the lease cgroup before the run.
    fn create(&self, lease: &LeaseId) -> impl Future<Output = io::Result<()>> + Send;
    /// Removes it, in the cleanup guard. Missing is fine.
    fn remove(&self, lease: &LeaseId) -> impl Future<Output = io::Result<()>> + Send;
    /// The names (lease IDs as strings) of every lease cgroup present, for the orphan sweep.
    fn present(&self) -> impl Future<Output = Vec<String>> + Send;
    /// The counters of the lease cgroup.
    fn stats(&self, lease: &LeaseId) -> CgroupStats {
        CgroupStats::read(&self.path(lease))
    }
}

/// Removes the cgroup directory `dir` and every child cgroup in it, depth first.
///
/// On cgroupfs a cgroup is removed with `rmdir` even though its control files are listed in it. Anywhere else (a
/// fake tree in tests) the directory holds real files, so it is removed recursively; that never happens on a real
/// cgroup v2 mount, where a recursive delete would try to unlink control files.
fn remove_tree(dir: &Path) -> io::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        if std::fs::symlink_metadata(entry.path()).is_ok_and(|m| m.is_dir()) {
            remove_tree(&entry.path())?;
        }
    }
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {
            #[allow(
                clippy::useless_conversion,
                reason = "f_type is i64 on x86_64 but not on every target"
            )]
            let on_cgroupfs = rustix::fs::statfs(dir).is_ok_and(|s| i64::from(s.f_type) == CGROUP2_MAGIC);
            if on_cgroupfs {
                Err(e)
            } else {
                std::fs::remove_dir_all(dir)
            }
        }
        Err(e) => Err(e),
    }
}

/// Enables the controllers in `dir/cgroup.subtree_control`, one at a time, ignoring the ones that fail (already
/// on, or not available to this cgroup).
fn enable_controllers(dir: &Path) {
    for c in CONTROLLERS {
        let _ = std::fs::write(dir.join("cgroup.subtree_control"), c);
    }
}

/// cgroupfs lease cgroups (WSL2): `<root>/p2pc/<lease_id>`, `--cgroup-parent=/p2pc/<lease_id>`.
#[derive(Debug, Clone)]
pub struct FsCgroups {
    root: PathBuf,
}

impl FsCgroups {
    /// Lease cgroups under the cgroup v2 mount at `root` (`/sys/fs/cgroup` in production).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The real mount.
    #[must_use]
    pub fn system() -> Self {
        Self::new("/sys/fs/cgroup")
    }
}

impl Cgroups for FsCgroups {
    fn parent_arg(&self, lease: &LeaseId) -> String {
        format!("/{BASE}/{lease}")
    }

    fn path(&self, lease: &LeaseId) -> PathBuf {
        self.root.join(BASE).join(lease.to_string())
    }

    async fn create(&self, lease: &LeaseId) -> io::Result<()> {
        let (root, path) = (self.root.clone(), self.path(lease));
        blocking(move || {
            let base = root.join(BASE);
            match std::fs::create_dir(&base) {
                Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                _ => {}
            }
            enable_controllers(&root);
            enable_controllers(&base);
            match std::fs::create_dir(&path) {
                Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                _ => {}
            }
            enable_controllers(&path);
            Ok(())
        })
        .await
    }

    async fn remove(&self, lease: &LeaseId) -> io::Result<()> {
        let path = self.path(lease);
        blocking(move || remove_tree(&path)).await
    }

    async fn present(&self) -> Vec<String> {
        let base = self.root.join(BASE);
        blocking(move || Ok(list_names(&base, |n| Some(n.to_string()))))
            .await
            .unwrap_or_default()
    }
}

/// Runs filesystem work off the runtime thread (cgroup trees can be deep, and a sweep touches many).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> io::Result<T> + Send + 'static) -> io::Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(io::Error::other)?
}

fn list_names(dir: &Path, map: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().and_then(&map))
        .collect();
    names.sort();
    names
}

/// The `user@<uid>.service` cgroup of the agent, from `/proc/self/cgroup` (`0::/user.slice/…/user@1001.service/…`),
/// as a path relative to the cgroup mount.
#[must_use]
pub fn user_service_cgroup(proc_self_cgroup: &str) -> Option<String> {
    crate::parse::user_manager_cgroup(proc_self_cgroup).map(|m| m.path.trim_start_matches('/').to_owned())
}

/// systemd lease cgroups (rootless Linux): `p2pc-<lease_id>.slice` under the user's `user@<uid>.service`.
#[derive(Debug)]
pub struct SystemdCgroups<R> {
    runner: R,
    service_root: PathBuf,
}

impl<R: CommandRunner> SystemdCgroups<R> {
    /// Slices under `service_root`, the host path of the agent's `user@<uid>.service` cgroup.
    pub fn new(runner: R, service_root: impl Into<PathBuf>) -> Self {
        Self {
            runner,
            service_root: service_root.into(),
        }
    }

    fn unit(lease: &LeaseId) -> String {
        format!("{BASE}-{lease}.slice")
    }

    async fn systemctl(&self, verb: &str, lease: &LeaseId) -> io::Result<()> {
        let unit = Self::unit(lease);
        match self.runner.run("systemctl", &["--user", verb, "--", &unit]).await {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => Err(io::Error::other(format!(
                "systemctl --user {verb} {unit}: {}",
                out.first_line()
            ))),
            Err(e) => Err(io::Error::other(format!("systemctl --user {verb} {unit}: {e}"))),
        }
    }
}

impl<R: CommandRunner + 'static> Cgroups for SystemdCgroups<R> {
    fn parent_arg(&self, lease: &LeaseId) -> String {
        Self::unit(lease)
    }

    fn path(&self, lease: &LeaseId) -> PathBuf {
        // systemd nests `a-b.slice` inside `a.slice`.
        self.service_root.join(format!("{BASE}.slice")).join(Self::unit(lease))
    }

    async fn create(&self, lease: &LeaseId) -> io::Result<()> {
        // Starting the slice explicitly keeps it (and its counters) alive after the container's scope ends.
        self.systemctl("start", lease).await
    }

    async fn remove(&self, lease: &LeaseId) -> io::Result<()> {
        self.systemctl("stop", lease).await
    }

    async fn present(&self) -> Vec<String> {
        let dir = self.service_root.join(format!("{BASE}.slice"));
        blocking(move || {
            Ok(list_names(&dir, |n| {
                n.strip_prefix(&format!("{BASE}-"))?
                    .strip_suffix(".slice")
                    .map(String::from)
            }))
        })
        .await
        .unwrap_or_default()
    }
}

/// The lease cgroups of whichever profile this host runs.
#[derive(Debug)]
pub enum HostCgroups<R> {
    /// WSL2.
    Fs(FsCgroups),
    /// Rootless Linux.
    Systemd(SystemdCgroups<R>),
}

impl<R: CommandRunner + 'static> Cgroups for HostCgroups<R> {
    fn parent_arg(&self, lease: &LeaseId) -> String {
        match self {
            Self::Fs(c) => c.parent_arg(lease),
            Self::Systemd(c) => c.parent_arg(lease),
        }
    }

    fn path(&self, lease: &LeaseId) -> PathBuf {
        match self {
            Self::Fs(c) => c.path(lease),
            Self::Systemd(c) => c.path(lease),
        }
    }

    async fn create(&self, lease: &LeaseId) -> io::Result<()> {
        match self {
            Self::Fs(c) => c.create(lease).await,
            Self::Systemd(c) => c.create(lease).await,
        }
    }

    async fn remove(&self, lease: &LeaseId) -> io::Result<()> {
        match self {
            Self::Fs(c) => c.remove(lease).await,
            Self::Systemd(c) => c.remove(lease).await,
        }
    }

    async fn present(&self) -> Vec<String> {
        match self {
            Self::Fs(c) => c.present().await,
            Self::Systemd(c) => c.present().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::str::FromStr;

    use super::*;
    use crate::runner::FakeRunner;

    fn lease() -> LeaseId {
        LeaseId::from_str("lse_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()
    }

    #[test]
    fn parses_flat_keyed_files() {
        let events = "low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 0\n";
        assert_eq!(keyed(events, "oom_kill"), 1);
        assert_eq!(keyed(events, "max"), 12);
        assert_eq!(keyed(events, "oom"), 1, "not confused with oom_kill");
        assert_eq!(keyed("", "oom_kill"), 0);
        assert_eq!(keyed("oom_kill x\n", "oom_kill"), 0);
    }

    #[tokio::test]
    async fn cgroupfs_lifecycle_on_a_fake_tree() {
        let root = tempfile::tempdir().unwrap();
        let cg = FsCgroups::new(root.path());
        assert_eq!(cg.parent_arg(&lease()), "/p2pc/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV");
        cg.create(&lease()).await.unwrap();
        let dir = root.path().join("p2pc/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert!(dir.is_dir());
        assert_eq!(cg.present().await, ["lse_01ARZ3NDEKTSV4RRFFQ69G5FAV"]);
        // What the kernel would show after an OOM kill in Podman's child cgroup.
        fs::create_dir(dir.join("libpod-0123")).unwrap();
        fs::write(dir.join("memory.events"), "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n").unwrap();
        fs::write(dir.join("pids.events"), "max 7\n").unwrap();
        fs::write(dir.join("cpu.stat"), "usage_usec 2500000\nuser_usec 2000000\n").unwrap();
        fs::write(dir.join("memory.peak"), "134217728\n").unwrap();
        assert_eq!(
            cg.stats(&lease()),
            CgroupStats {
                oom_kill: 1,
                pids_max: 7,
                cpu_usage_usec: 2_500_000,
                memory_peak_bytes: 134_217_728,
            }
        );
        cg.remove(&lease()).await.unwrap();
        assert!(!dir.exists());
        assert_eq!(
            cg.stats(&lease()),
            CgroupStats::default(),
            "a removed cgroup reads as zeros"
        );
        cg.remove(&lease()).await.unwrap();
    }

    #[test]
    fn pids_events_of_podmans_child_cgroup_count() {
        // Before Linux 6.13 the parent's pids.events stays 0 when the child's pids.max is hit.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pids.events"), "max 0\n").unwrap();
        fs::create_dir(dir.path().join("libpod-0123")).unwrap();
        fs::write(dir.path().join("libpod-0123/pids.events"), "max 4\n").unwrap();
        fs::write(dir.path().join("libpod-0123/cpu.stat"), "usage_usec 99\n").unwrap();
        let s = CgroupStats::read(dir.path());
        assert_eq!(s.pids_max, 4);
        assert_eq!(
            s.cpu_usage_usec, 0,
            "CPU time is hierarchical: only the lease cgroup's own counter"
        );
        // crun may nest the container one level further (`libpod-<id>/container`).
        fs::create_dir(dir.path().join("libpod-0123/container")).unwrap();
        fs::write(dir.path().join("libpod-0123/container/pids.events"), "max 9\n").unwrap();
        assert_eq!(CgroupStats::read(dir.path()).pids_max, 9);
        // Bounded: deeper than MAX_EVENT_DEPTH is not read.
        let deep = dir.path().join("libpod-0123/container/a/b");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("pids.events"), "max 99\n").unwrap();
        assert_eq!(CgroupStats::read(dir.path()).pids_max, 9);
    }

    #[test]
    fn stats_keep_the_maximum() {
        let a = CgroupStats {
            oom_kill: 1,
            ..CgroupStats::default()
        };
        let b = CgroupStats {
            cpu_usage_usec: 5,
            ..CgroupStats::default()
        };
        assert_eq!(
            a.max(b),
            CgroupStats {
                oom_kill: 1,
                cpu_usage_usec: 5,
                ..CgroupStats::default()
            }
        );
    }

    #[test]
    fn finds_the_user_service_cgroup() {
        assert_eq!(
            user_service_cgroup("0::/user.slice/user-1001.slice/user@1001.service/app.slice/p2pc-agent.service\n")
                .as_deref(),
            Some("user.slice/user-1001.slice/user@1001.service")
        );
        assert_eq!(user_service_cgroup("0::/system.slice/p2pc-agent.service\n"), None);
        assert_eq!(user_service_cgroup("12:memory:/x\n"), None);
        // T10j review P3 1: one parser decides (`parse::user_manager_cgroup`), so a non-numeric UID is no user manager
        // here either, and the readiness check and the lease slices never pick different units.
        assert_eq!(user_service_cgroup("0::/a/user@x1.service/b\n"), None);
        assert_eq!(user_service_cgroup("0::/a/user@.service/b\n"), None);
    }

    #[tokio::test]
    async fn systemd_slices_through_systemctl() {
        let root = tempfile::tempdir().unwrap();
        let unit = "p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV.slice";
        let runner = FakeRunner::new()
            .ok(&["systemctl", "--user", "start", "--", unit], "")
            .exits(
                &["systemctl", "--user", "stop", "--", unit],
                5,
                "",
                "Unit not loaded.\n",
            );
        let cg = SystemdCgroups::new(runner, root.path());
        assert_eq!(cg.parent_arg(&lease()), unit);
        assert_eq!(cg.path(&lease()), root.path().join("p2pc.slice").join(unit));
        cg.create(&lease()).await.unwrap();
        let e = cg.remove(&lease()).await.unwrap_err();
        assert!(e.to_string().contains("Unit not loaded"), "{e}");
        fs::create_dir_all(root.path().join("p2pc.slice").join(unit)).unwrap();
        fs::create_dir_all(root.path().join("p2pc.slice/other.slice")).unwrap();
        assert_eq!(cg.present().await, ["lse_01ARZ3NDEKTSV4RRFFQ69G5FAV"]);
    }
}
