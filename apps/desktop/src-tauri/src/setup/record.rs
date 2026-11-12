// SPDX-License-Identifier: Apache-2.0

//! `%LOCALAPPDATA%\P2PC\setup.json`: what each first-run step finished (H2 §8.2 "Resumable").
//!
//! Each step writes its result here as soon as it has one. A crash, a closed window or the reboot of step 2a resumes at
//! the first unfinished step ([`SetupRecord::step`]), and a finished step is never redone. Step 4 records its own
//! progress too ([`HubRecord`]), so that a crash in the middle of "Create my cloud" never runs `p2pc-server init` twice
//! and never leaves the hub half made.
//!
//! The file holds no secret: no join token, no pairing ticket, no key (§8.9). Missing fields take their default, so an
//! older file still loads; unknown fields are ignored, so a newer file still loads after a downgrade. §8.7 step 5
//! deletes it on uninstall.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::state::Role;

/// The file name under `%LOCALAPPDATA%\P2PC` (§8.2, §8.7 step 5).
pub const SETUP_FILE: &str = "setup.json";

/// The format version this app writes.
pub const RECORD_VERSION: u32 = 1;

/// The largest `setup.json` the app reads.
pub const MAX_FILE_LEN: u64 = 64 * 1024;

/// The screens of first run, in order (§8.2). Step 2a ("Install WSL") is part of [`Step::Checks`]: the checks say
/// whether it is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// 1: what P2PC does, and the update-check choice.
    Welcome,
    /// 2 (and 2a): the checks; installing WSL when it is missing or too old.
    Checks,
    /// 3: import of the distro, then the share.
    Share,
    /// 4: "Create my cloud" or "Join my cloud".
    CreateOrJoin,
    /// 5: "Add my phone".
    AddPhone,
    /// "Your cloud is ready".
    Ready,
}

/// WSL's networking mode, as the distro reports it (`wslinfo --networking-mode`, §10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkingMode {
    /// The default: the WSL VM sits behind the Windows host's NAT.
    Nat,
    /// `networkingMode=mirrored`: the distro's sockets sit on the host's own addresses (the app warns, §10.5).
    Mirrored,
    /// Another mode WSL reported (`none`, `virtioproxy`, …).
    Other,
    /// It could not be read.
    Unknown,
}

/// The distro is imported and verified, and the scheduled task registered (step 3, before the share is chosen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    /// The `image_version=` line of `/etc/p2pc-distro-version`.
    pub image_version: String,
    /// The WSL VM's processors: the top of the CPU control.
    pub cpu_cores: u32,
    /// The WSL VM's memory in MiB: the top of the RAM control.
    pub memory_mb: u64,
    /// The node reports a GPU it can offer: only then is the GPU switch shown.
    pub gpu_offerable: bool,
    /// What the agent offers by default (H1 share defaults): the controls start there.
    pub default_cpu: u32,
    pub default_memory_mb: u64,
    /// WSL's networking mode (§10.5).
    pub networking: NetworkingMode,
}

/// The share chosen at step 3 and applied with `p2pc-agent share set` (§8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRecord {
    pub cpu: u32,
    pub memory_mb: u64,
    pub gpu: bool,
    /// `D`, in GiB.
    pub share_gib: u64,
    /// `offered.disk_mb`.
    pub disk_mb: u64,
    /// `volumes_mb`.
    pub volumes_mb: u64,
}

/// "Create my cloud" (step 4), one flag per sub-step, in the order they run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HubRecord {
    /// The hub's blob quota, computed from the disk arithmetic before anything else runs.
    pub blobs_quota_mb: Option<u64>,
    /// `p2pc-server init --owner-device` ran (or the hub's data dir was already initialised: `found_existing`).
    pub initialised: bool,
    /// The data dir was initialised before this run of step 4 (an earlier, unrecorded attempt): the local agent may
    /// already be enrolled with it.
    pub found_existing: bool,
    /// The hub's `p2pc_srv_…` address (public: the hub's NodeId and relays).
    pub server_address: Option<String>,
    /// The owner device's id (`init --owner-device` prints it; public).
    pub owner_device_id: Option<String>,
    /// `blobs_quota_mb` is in `server.toml`.
    pub quota_written: bool,
    /// `hub.enabled` exists and the scheduled task is enabled and started.
    pub hub_enabled: bool,
    /// The hub's name is set (`PATCH /v1/server {hub_name}`).
    pub named: bool,
    /// A join token for the local agent was minted (so an "already enrolled" answer is ours).
    pub join_started: bool,
    /// The local agent is enrolled.
    pub joined: bool,
    /// The node runs: the task was started again after the join, so the agent runs enrolled.
    pub node_started: bool,
}

/// How step 5 ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum PhoneOutcome {
    /// A phone paired; its platform hint as the hub recorded it.
    Paired { platform: String },
    /// "Skip for now".
    Skipped,
}

/// `setup.json`. [`Default`] is a fresh install's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SetupRecord {
    /// The format version.
    pub version: u32,
    /// Step 1: automatic update checks, yes or no. `None` until the user picked one (nothing preselected).
    pub update_checks: Option<bool>,
    /// Step 2: every check passed.
    pub checks_passed: bool,
    /// Step 2a ran: WSL was installed or updated (a WSL still too old afterwards is `wsl_too_old`).
    pub wsl_installed: bool,
    /// Step 2a asked for the reboot and registered the `RunOnce` entry.
    pub reboot_pending: bool,
    /// Step 3: the distro is in place.
    pub node: Option<NodeRecord>,
    /// Step 3: the share is applied.
    pub share: Option<ShareRecord>,
    /// Step 4: "Create my cloud" in progress or done.
    pub hub: Option<HubRecord>,
    /// Step 4: done, with this PC's role.
    pub role: Option<Role>,
    /// Step 5: done.
    pub phone: Option<PhoneOutcome>,
}

impl Default for SetupRecord {
    fn default() -> Self {
        Self {
            version: RECORD_VERSION,
            update_checks: None,
            checks_passed: false,
            wsl_installed: false,
            reboot_pending: false,
            node: None,
            share: None,
            hub: None,
            role: None,
            phone: None,
        }
    }
}

impl SetupRecord {
    /// The first unfinished step: where setup resumes.
    pub fn step(&self) -> Step {
        if self.update_checks.is_none() {
            Step::Welcome
        } else if !self.checks_passed {
            Step::Checks
        } else if self.node.is_none() || self.share.is_none() {
            Step::Share
        } else if self.role.is_none() {
            Step::CreateOrJoin
        } else if self.phone.is_none() {
            Step::AddPhone
        } else {
            Step::Ready
        }
    }

    /// First run has finished: the role, once [`Step::Ready`] is reached.
    pub fn finished(&self) -> Option<Role> {
        (self.step() == Step::Ready).then_some(self.role).flatten()
    }
}

/// Why `setup.json` could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// Reading or writing the file failed.
    #[error("setup file: {0}")]
    Io(#[from] io::Error),
    /// The file is not valid setup JSON, or is too large.
    #[error("setup file is not valid")]
    Invalid,
}

/// `setup.json` on disk.
#[derive(Debug, Clone)]
pub struct RecordFile {
    path: PathBuf,
}

impl RecordFile {
    /// `setup.json` in `%LOCALAPPDATA%\P2PC` (`p2pc_wsl::Layout::root`).
    pub fn in_dir(p2pc_dir: &Path) -> Self {
        Self {
            path: p2pc_dir.join(SETUP_FILE),
        }
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The stored record, or a fresh one when there is no file yet.
    pub fn load(&self) -> Result<SetupRecord, RecordError> {
        let file = match fs::File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(SetupRecord::default()),
            Err(e) => return Err(e.into()),
        };
        let mut data = Vec::new();
        file.take(MAX_FILE_LEN + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_FILE_LEN {
            return Err(RecordError::Invalid);
        }
        // An object only: serde would also read a struct from a JSON array, field by field in order.
        let value: serde_json::Value = serde_json::from_slice(&data).map_err(|_| RecordError::Invalid)?;
        if !value.is_object() {
            return Err(RecordError::Invalid);
        }
        serde_json::from_value(value).map_err(|_| RecordError::Invalid)
    }

    /// Writes `record` atomically (temporary file, flush to disk, rename), so a crash leaves the old record or the new
    /// one, never half of one.
    pub fn save(&self, record: &SetupRecord) -> Result<(), RecordError> {
        let data = serde_json::to_vec_pretty(record).map_err(|_| RecordError::Invalid)?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let temp = self.path.with_file_name(format!("{SETUP_FILE}.tmp"));
        let written = (|| -> io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)?;
            file.write_all(&data)?;
            file.sync_all()
        })();
        if let Err(e) = written.and_then(|()| fs::rename(&temp, &self.path)) {
            let _ = fs::remove_file(&temp);
            return Err(e.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> NodeRecord {
        NodeRecord {
            image_version: "image_version=1".into(),
            cpu_cores: 8,
            memory_mb: 16_000,
            gpu_offerable: false,
            default_cpu: 7,
            default_memory_mb: 12_000,
            networking: NetworkingMode::Nat,
        }
    }

    fn share() -> ShareRecord {
        ShareRecord {
            cpu: 4,
            memory_mb: 8192,
            gpu: false,
            share_gib: 90,
            disk_mb: 46_080,
            volumes_mb: 46_080,
        }
    }

    #[test]
    fn a_fresh_install_starts_at_welcome_with_nothing_chosen() {
        let r = SetupRecord::default();
        assert_eq!(r.step(), Step::Welcome);
        assert_eq!(r.update_checks, None, "nothing preselected (§8.2 step 1)");
        assert_eq!(r.finished(), None);
    }

    #[test]
    fn each_finished_step_moves_to_the_next() {
        let mut r = SetupRecord {
            update_checks: Some(false),
            ..SetupRecord::default()
        };
        assert_eq!(r.step(), Step::Checks);
        r.checks_passed = true;
        assert_eq!(r.step(), Step::Share);
        r.node = Some(node());
        assert_eq!(r.step(), Step::Share, "imported, share not chosen yet");
        r.share = Some(share());
        assert_eq!(r.step(), Step::CreateOrJoin);
        r.hub = Some(HubRecord {
            initialised: true,
            ..HubRecord::default()
        });
        assert_eq!(r.step(), Step::CreateOrJoin, "create in progress");
        r.role = Some(Role::Hub);
        assert_eq!(r.step(), Step::AddPhone);
        r.phone = Some(PhoneOutcome::Skipped);
        assert_eq!(r.step(), Step::Ready);
        assert_eq!(r.finished(), Some(Role::Hub));
    }

    #[test]
    fn the_first_unfinished_step_wins_whatever_comes_later() {
        // A later field without an earlier one (a hand-edited file): resume at the earlier step.
        let r = SetupRecord {
            update_checks: Some(true),
            checks_passed: false,
            share: Some(share()),
            role: Some(Role::Hub),
            phone: Some(PhoneOutcome::Skipped),
            ..SetupRecord::default()
        };
        assert_eq!(r.step(), Step::Checks);
        assert_eq!(r.finished(), None);
    }

    #[test]
    fn no_file_is_a_fresh_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = RecordFile::in_dir(dir.path());
        assert_eq!(file.load().expect("load"), SetupRecord::default());
    }

    #[test]
    fn a_saved_record_loads_back_and_no_temporary_file_is_left() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = RecordFile::in_dir(&dir.path().join("P2PC"));
        let r = SetupRecord {
            update_checks: Some(true),
            checks_passed: true,
            node: Some(node()),
            share: Some(share()),
            hub: Some(HubRecord {
                blobs_quota_mb: Some(20_480),
                initialised: true,
                server_address: Some("p2pc_srv_example".into()),
                ..HubRecord::default()
            }),
            role: Some(Role::Hub),
            phone: Some(PhoneOutcome::Paired {
                platform: "iOS Safari".into(),
            }),
            ..SetupRecord::default()
        };
        file.save(&r).expect("save");
        assert_eq!(file.load().expect("load"), r);
        let names: Vec<_> = fs::read_dir(dir.path().join("P2PC"))
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(SETUP_FILE)]);
    }

    #[test]
    fn the_json_names_are_stable() {
        let r = SetupRecord {
            update_checks: Some(true),
            role: Some(Role::Hub),
            phone: Some(PhoneOutcome::Paired {
                platform: "Android Chrome".into(),
            }),
            ..SetupRecord::default()
        };
        let v = serde_json::to_value(&r).expect("json");
        assert_eq!(v["version"], 1);
        assert_eq!(v["update_checks"], true);
        assert_eq!(v["role"], "hub");
        assert_eq!(
            v["phone"],
            serde_json::json!({"outcome": "paired", "platform": "Android Chrome"})
        );
        assert_eq!(
            serde_json::to_value(PhoneOutcome::Skipped).expect("json"),
            serde_json::json!({"outcome": "skipped"})
        );
        assert_eq!(
            serde_json::to_value(Step::CreateOrJoin).expect("json"),
            "create_or_join"
        );
    }

    #[test]
    fn missing_fields_take_their_default_and_unknown_fields_are_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = RecordFile::in_dir(dir.path());
        fs::write(file.path(), br#"{}"#).expect("write");
        assert_eq!(file.load().expect("load"), SetupRecord::default());
        fs::write(
            file.path(),
            br#"{"update_checks": false, "checks_passed": true, "from_a_newer_app": [1]}"#,
        )
        .expect("write");
        let r = file.load().expect("load");
        assert_eq!(r.step(), Step::Share);
        assert_eq!(r.update_checks, Some(false));
    }

    #[test]
    fn an_invalid_or_oversized_file_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = RecordFile::in_dir(dir.path());
        for bad in [
            &b"not json"[..],
            br#"{"checks_passed": "yes"}"#,
            br#"{"role": "admin"}"#,
            b"[]",
            b"null",
        ] {
            fs::write(file.path(), bad).expect("write");
            assert!(matches!(file.load(), Err(RecordError::Invalid)), "{bad:?}");
        }
        let mut big = br#"{"pad": ""#.to_vec();
        big.resize(MAX_FILE_LEN as usize + 10, b'x');
        big.extend_from_slice(br#""}"#);
        fs::write(file.path(), big).expect("write");
        assert!(matches!(file.load(), Err(RecordError::Invalid)));
    }
}
