// SPDX-License-Identifier: Apache-2.0

//! The egress gate for `p2pc-agent status` (T10l): `<data_dir>/egress-gate.json`, which `p2pc-agent run` keeps up to
//! date and `status` reads with no network.
//!
//! An egress job fails with `egress_unavailable` while the gate is closed, and the gate says why in the agent's log
//! ([`p2pc_net::GateReport`]). This file puts the same words where the owner looks first. It holds the gate's name, the
//! reason and since when: no address, public or not. Mode 0600, replaced atomically on every change of the report.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use p2pc_net::GateReport;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::watch;

use super::state::write_atomic;

/// The file name inside the data dir.
pub const GATE_FILE: &str = "egress-gate.json";

/// What the file holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRecord {
    /// The gate's name ([`p2pc_net::EgressGate::label`]).
    pub state: String,
    /// Why ([`GateReport::reason`]).
    pub reason: String,
    /// Since when the report has been this one.
    #[serde(with = "time::serde::rfc3339")]
    pub since: OffsetDateTime,
}

impl GateRecord {
    /// The record of `report`, as of `since`.
    #[must_use]
    pub fn of(report: &GateReport, since: OffsetDateTime) -> Self {
        Self {
            state: report.state.label().to_string(),
            reason: report.reason().to_string(),
            since,
        }
    }
}

/// The text `p2pc-agent status` prints for the gate: the same words as the log's `state` and `reason`. When the agent
/// is not running (`running`: [`crate::node::agent_running`]) the file is the last run's, and the line says so: it is
/// not the gate of a process that is not there (review of PR #48, P3-3).
#[must_use]
pub fn render_gate(record: Option<&GateRecord>, running: bool) -> String {
    let last = if running { "" } else { "(last run) " };
    match record {
        None if running => "Egress gate:   unknown (no verdict yet: the iroh endpoint is not bound yet)\n".to_string(),
        None => "Egress gate:   unknown (`p2pc-agent run` has not run yet)\n".to_string(),
        Some(r) => {
            let since = r
                .since
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| r.since.unix_timestamp().to_string());
            format!("Egress gate:   {last}{}: {} (since {since})\n", r.state, r.reason)
        }
    }
}

/// The gate file.
#[derive(Debug, Clone)]
pub struct GateFile {
    path: PathBuf,
    /// Whether a failure to write was already reported at `warn`: the first one is, the rest are `debug`.
    warned: Arc<AtomicBool>,
}

impl GateFile {
    /// The gate file in `data_dir`.
    #[must_use]
    pub fn in_dir(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(GATE_FILE),
            warned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Replaces the file atomically. A failure is never fatal (the agent runs without it), and the first one is logged
    /// at `warn`, so a `status` that shows no gate has a reason in the log.
    pub fn write(&self, record: &GateRecord) {
        let result = serde_json::to_vec(record)
            .map_err(std::io::Error::other)
            .and_then(|json| write_atomic(&self.path, &json));
        if let Err(e) = result {
            if self.warned.swap(true, Ordering::Relaxed) {
                tracing::debug!(error = %e, path = %self.path.display(), "cannot write the egress gate file");
            } else {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "cannot write the egress gate file; `p2pc-agent status` will not show the gate"
                );
            }
        }
    }

    /// Deletes the file: `run` does it at start, so `status` never shows an earlier run's gate as this one's.
    pub fn reset(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    /// Reads the file; `None` when it is missing or unreadable.
    #[must_use]
    pub fn read(&self) -> Option<GateRecord> {
        serde_json::from_slice(&std::fs::read(&self.path).ok()?).ok()
    }

    /// Keeps the file at `report`, until the report's sender is gone. Each write runs on the blocking pool, in order;
    /// when reports come faster than the disk, the latest wins. `now` gives the time of a change (a test passes a
    /// fixed one).
    pub async fn keep(self, mut report: watch::Receiver<GateReport>, now: impl Fn() -> OffsetDateTime + Send) {
        // The report starts as the default: nothing is written until the watcher has said something, and the gate
        // closing again with the same words is no change.
        let mut last: Option<(String, String)> = None;
        while report.changed().await.is_ok() {
            let current = report.borrow_and_update().clone();
            let key = (current.state.label().to_string(), current.reason().to_string());
            if last.as_ref() == Some(&key) {
                continue;
            }
            last = Some(key);
            let record = GateRecord::of(&current, now());
            let file = self.clone();
            let _ = tokio::task::spawn_blocking(move || file.write(&record)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use p2pc_net::{EgressGate, GateInputs};

    use super::*;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    fn closed() -> GateReport {
        GateReport {
            state: EgressGate::Closed,
            inputs: GateInputs {
                host_ipv4: true,
                default_route: Some("wlan0".into()),
                ipv4_bound: true,
                ..GateInputs::default()
            },
        }
    }

    #[test]
    fn the_status_line_has_the_logs_words_for_every_state() {
        assert_eq!(
            render_gate(None, false),
            "Egress gate:   unknown (`p2pc-agent run` has not run yet)\n"
        );
        let mut open = closed();
        open.state = EgressGate::Open;
        open.inputs.public_ipv4_here = true;
        let unbound = GateReport {
            state: EgressGate::NoIpv4Bound,
            inputs: GateInputs {
                ipv4_bound: false,
                ..closed().inputs
            },
        };
        let bridge = GateReport {
            state: EgressGate::BridgeNamedUplink,
            ..unbound.clone()
        };
        for report in [closed(), open, unbound, bridge] {
            let text = render_gate(Some(&GateRecord::of(&report, at(1_800_000_000))), true);
            // The state and the reason, as the log has them: `GateReport::line`.
            assert_eq!(
                text,
                format!("Egress gate:   {} (since 2027-01-15T08:00:00Z)\n", report.line())
            );
        }
        assert!(
            render_gate(Some(&GateRecord::of(&closed(), at(1_800_000_000))), true).contains(
                "Egress gate:   closed: waiting for a public IPv4 from the relay (QUIC address discovery); none seen yet"
            )
        );
    }

    /// Review of PR #48, P3-3: with no agent running, the line is the last run's and says so.
    #[test]
    fn a_gate_file_of_an_agent_that_is_not_running_is_marked_as_the_last_run() {
        let record = GateRecord::of(&closed(), at(1_800_000_000));
        let text = render_gate(Some(&record), false);
        assert!(text.starts_with("Egress gate:   (last run) closed: "), "{text}");
        assert!(text.ends_with("(since 2027-01-15T08:00:00Z)\n"), "{text}");
        assert_eq!(
            render_gate(None, false),
            "Egress gate:   unknown (`p2pc-agent run` has not run yet)\n"
        );
    }

    /// Review of PR #48, round 2, P3-1: a live agent with no verdict yet says so, not that it has not run.
    #[test]
    fn a_running_agent_with_no_verdict_yet_says_so() {
        assert_eq!(
            render_gate(None, true),
            "Egress gate:   unknown (no verdict yet: the iroh endpoint is not bound yet)\n"
        );
    }

    /// P3-2: only the first failure to write is a `warn`; the file is never required.
    #[test]
    fn a_failed_write_is_not_fatal_and_warns_once() {
        let dir = tempfile::tempdir().unwrap();
        let file = GateFile::in_dir(&dir.path().join("missing").join("dir"));
        let record = GateRecord::of(&closed(), at(1_800_000_000));
        assert!(!file.warned.load(Ordering::Relaxed));
        file.write(&record);
        assert!(file.warned.load(Ordering::Relaxed), "the first failure was reported");
        file.write(&record);
        assert_eq!(file.read(), None);
    }

    #[test]
    fn the_file_round_trips_with_mode_0600_and_holds_no_address() {
        let dir = tempfile::tempdir().unwrap();
        let file = GateFile::in_dir(dir.path());
        assert_eq!(file.read(), None);
        let record = GateRecord::of(&closed(), at(1_800_000_000));
        file.write(&record);
        assert_eq!(file.read(), Some(record));
        let mode = std::fs::metadata(dir.path().join(GATE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let text = std::fs::read_to_string(dir.path().join(GATE_FILE)).unwrap();
        assert!(!text.contains("wlan0"), "not even the interface: {text}");
    }

    /// P3-1: the first report of a watcher is written even when it equals the default report.
    #[tokio::test]
    async fn keep_writes_a_first_report_that_equals_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let file = GateFile::in_dir(dir.path());
        let (tx, rx) = watch::channel(GateReport::default());
        let task = tokio::spawn(file.clone().keep(rx, || at(1_800_000_000)));
        // What the watcher does for its first verdict: send it whether or not it differs.
        tx.send_modify(|_| {});
        drop(tx);
        task.await.unwrap();
        assert_eq!(file.read().expect("written").state, "closed");
    }

    #[tokio::test]
    async fn keep_writes_each_change_of_the_gate_and_skips_repeats() {
        let dir = tempfile::tempdir().unwrap();
        let file = GateFile::in_dir(dir.path());
        let (tx, rx) = watch::channel(GateReport::default());
        let task = tokio::spawn(file.clone().keep(rx, || at(1_800_000_000)));
        tx.send_replace(closed());
        // The task ends when the sender is dropped, after it has written the last change.
        drop(tx);
        task.await.unwrap();
        let record = file.read().expect("written");
        assert_eq!(record.state, "closed");
        assert!(record.reason.contains("waiting for a public IPv4"), "{record:?}");
    }
}
