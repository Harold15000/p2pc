// SPDX-License-Identifier: Apache-2.0

//! The running leases, as `p2pc-agent status` shows them (§3 of T10a), with no network.
//!
//! `<data_dir>/agent-leases.json`, mode 0600, replaced atomically by `run` when a lease starts, changes phase or ends,
//! and every few seconds while leases run (for the log bytes). It holds, per lease: its ID and epoch, the job's
//! `name` if it has one, the phase, when it was accepted and started, and how many log bytes went to the server.
//! **Never** an env value, a command, an input or an output: nothing of the job's content.
//!
//! The `Lease` message carries no job ID in v0.1 (§6), so the lease ID is what identifies the run here; the server
//! maps it to the job.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use p2pc_proto::ids::LeaseId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::connection::state::write_atomic;

/// The file name inside the data dir.
pub const LEASES_FILE: &str = "agent-leases.json";

/// Where a run is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    /// Accepted; the job directory and the sandbox are being set up.
    Preparing,
    /// Pulling the image.
    Pulling,
    /// Creating the container.
    Creating,
    /// Starting it.
    Starting,
    /// The job runs.
    Running,
    /// Listing its outputs.
    Collecting,
    /// Uploading its outputs.
    Uploading,
    /// Sending `JobFinished` and cleaning up.
    Finishing,
}

impl RunPhase {
    /// The word `status` shows.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RunPhase::Preparing => "preparing",
            RunPhase::Pulling => "pulling the image",
            RunPhase::Creating => "creating the container",
            RunPhase::Starting => "starting",
            RunPhase::Running => "running",
            RunPhase::Collecting => "collecting outputs",
            RunPhase::Uploading => "uploading outputs",
            RunPhase::Finishing => "finishing",
        }
    }
}

/// One running lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseStatus {
    /// The lease.
    pub lease_id: LeaseId,
    /// Its epoch.
    pub epoch: u64,
    /// The job's `name`, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_name: Option<String>,
    /// Where it is.
    pub phase: RunPhase,
    /// When the agent accepted it.
    #[serde(with = "time::serde::rfc3339")]
    pub accepted_at: OffsetDateTime,
    /// When the job process started, once it did.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    /// Log bytes handed to the server so far.
    pub log_bytes_sent: u64,
}

/// What the file holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasesState {
    /// When it was written.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// The running leases.
    pub leases: Vec<LeaseStatus>,
}

/// The leases file.
#[derive(Debug, Clone)]
pub struct LeasesFile {
    path: PathBuf,
}

impl LeasesFile {
    /// The file in `data_dir`.
    #[must_use]
    pub fn in_dir(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(LEASES_FILE),
        }
    }

    /// Its path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Replaces it (atomically, 0600). A failure is logged, never fatal.
    pub fn write(&self, state: &LeasesState) {
        let result = serde_json::to_vec(state)
            .map_err(std::io::Error::other)
            .and_then(|json| write_atomic(&self.path, &json));
        if let Err(e) = result {
            tracing::debug!(error = %e, path = %self.path.display(), "cannot write the leases file");
        }
    }

    /// Reads it; `None` when it is missing or unreadable.
    #[must_use]
    pub fn read(&self) -> Option<LeasesState> {
        serde_json::from_slice(&std::fs::read(&self.path).ok()?).ok()
    }
}

/// `90` → `1m 30s`.
fn duration(d: time::Duration) -> String {
    let s = d.whole_seconds().max(0);
    match (s / 3600, s / 60 % 60, s % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, m, _) => format!("{h}h {m}m"),
    }
}

/// `1536` → `1.5 KiB`.
fn bytes(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    match n {
        0..1024 => format!("{n} B"),
        1024..1_048_576 => format!("{:.1} KiB", f / 1024.0),
        _ => format!("{:.1} MiB", f / 1_048_576.0),
    }
}

/// The running-leases part of `p2pc-agent status`, as of `now`.
#[must_use]
pub fn render_leases(state: Option<&LeasesState>, now: OffsetDateTime) -> String {
    let mut out = String::new();
    let Some(state) = state else {
        let _ = writeln!(
            out,
            "Running leases: unknown (`p2pc-agent run` has not written any yet)"
        );
        return out;
    };
    let as_of = state
        .updated_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    if state.leases.is_empty() {
        let _ = writeln!(out, "Running leases: none (as of {as_of})");
        return out;
    }
    let _ = writeln!(out, "Running leases: {} (as of {as_of})", state.leases.len());
    for l in &state.leases {
        let job = l
            .job_name
            .as_deref()
            .map_or_else(|| "(no name)".to_string(), |n| format!("\"{n}\""));
        let ran = match l.started_at {
            Some(t) => format!("running for {}", duration(now - t)),
            None => format!("accepted {} ago", duration(now - l.accepted_at)),
        };
        let _ = writeln!(
            out,
            "  {} epoch {}  job {job}  {}  {ran}  logs sent {}",
            l.lease_id,
            l.epoch,
            l.phase.as_str(),
            bytes(l.log_bytes_sent)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn the_file_round_trips_with_mode_0600_and_the_text_shows_the_runs() {
        let dir = tempfile::tempdir().unwrap();
        let file = LeasesFile::in_dir(dir.path());
        assert_eq!(file.read(), None);
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let id = LeaseId::generate();
        let state = LeasesState {
            updated_at: now,
            leases: vec![
                LeaseStatus {
                    lease_id: id,
                    epoch: 2,
                    job_name: Some("train".into()),
                    phase: RunPhase::Running,
                    accepted_at: now - time::Duration::seconds(100),
                    started_at: Some(now - time::Duration::seconds(90)),
                    log_bytes_sent: 1536,
                },
                LeaseStatus {
                    lease_id: LeaseId::generate(),
                    epoch: 1,
                    job_name: None,
                    phase: RunPhase::Pulling,
                    accepted_at: now - time::Duration::seconds(5),
                    started_at: None,
                    log_bytes_sent: 0,
                },
            ],
        };
        file.write(&state);
        assert_eq!(file.read(), Some(state.clone()));
        let mode = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let text = render_leases(Some(&state), now + time::Duration::seconds(3600));
        assert!(
            text.contains("Running leases: 2 (as of 2027-01-15T08:00:00Z)"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "{id} epoch 2  job \"train\"  running  running for 1h 1m  logs sent 1.5 KiB"
            )),
            "{text}"
        );
        assert!(
            text.contains("job (no name)  pulling the image  accepted 1h 0m ago  logs sent 0 B"),
            "{text}"
        );
        assert!(render_leases(None, now).contains("unknown"));
        let empty = LeasesState {
            updated_at: now,
            leases: vec![],
        };
        assert!(render_leases(Some(&empty), now).contains("Running leases: none"));
        assert_eq!(duration(time::Duration::seconds(75)), "1m 15s");
        assert_eq!(bytes(3 << 20), "3.0 MiB");
    }
}
