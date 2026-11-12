// SPDX-License-Identifier: Apache-2.0

//! When the app may contact the update endpoint, and what it tells the user (H2 §14.1, §8.2 step 1, hard rule 6).
//!
//! - **Opt-in.** Only when the user said yes (first run or Settings) does the app check on its own: at start and at most
//!   once a day, never during first run. Without a yes it contacts the endpoint only when the user clicks "Check for
//!   updates"; [`auto_check_due`] is then always false.
//! - **A frozen endpoint is visible.** With automatic checks on, after 14 days without a successful check the app shows
//!   "Could not check for updates since <date>".
//! - **A local reminder.** With automatic checks off, Settings shows the date of the last check, and after 30 days
//!   without one the app shows a reminder. It sends nothing.
//! - **Installing.** The app downloads in the background and installs when the user agrees or at the next start; never
//!   in the middle of first run.
//!
//! The times are seconds since the Unix epoch from the wall clock (dates shown to the user, days between checks); a
//! clock that went back makes a check due rather than suppressing it for the clock's error.
//!
//! [`UpdateState`] is the app's own record in `update-state.json` (its local data folder): the check times and the
//! web app's high-water mark (§9.6).

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A day, in seconds.
pub const DAY_SECS: u64 = 86_400;
/// Automatic checks: at most once a day.
pub const AUTO_CHECK_INTERVAL_SECS: u64 = DAY_SECS;
/// "Could not check for updates since <date>" after 14 days without a successful check.
pub const STALE_AFTER_SECS: u64 = 14 * DAY_SECS;
/// The local reminder after 30 days without a check.
pub const REMINDER_AFTER_SECS: u64 = 30 * DAY_SECS;

/// The file name in the app's local data folder.
pub const STATE_FILE: &str = "update-state.json";
/// The largest state file the app reads.
pub const MAX_STATE_LEN: u64 = 64 * 1024;

/// What the app remembers about its checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateState {
    /// When this record was first written (the start of the clocks below when nothing happened yet).
    pub first_seen: Option<u64>,
    /// The last check that was started (automatic or by hand).
    pub last_attempt: Option<u64>,
    /// The last check that reached the endpoint and read its answer.
    pub last_success: Option<u64>,
    /// The highest `web_version` this app verified (§9.6). The effective mark is never below the app's own release's
    /// web build ([`super::web::effective_mark`]).
    pub web_mark: Option<String>,
}

impl UpdateState {
    /// Records a check that was started now.
    pub fn attempted(&mut self, now: u64) {
        self.first_seen.get_or_insert(now);
        self.last_attempt = Some(now);
    }

    /// Records a check that succeeded now.
    pub fn succeeded(&mut self, now: u64) {
        self.attempted(now);
        self.last_success = Some(now);
    }
}

/// An automatic check is due: the user said yes, first run is over, and the last attempt is a day old (or none, or in
/// the future of a clock that went back).
pub fn auto_check_due(update_checks: Option<bool>, in_first_run: bool, state: &UpdateState, now: u64) -> bool {
    if update_checks != Some(true) || in_first_run {
        return false;
    }
    match state.last_attempt {
        None => true,
        Some(t) if t > now => true,
        Some(t) => now - t >= AUTO_CHECK_INTERVAL_SECS,
    }
}

/// What the app shows about its checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Notice {
    /// Automatic checks on, and none succeeded for 14 days: "Could not check for updates since <date>".
    CouldNotCheck { since: String },
    /// Automatic checks off, and none for 30 days: a local reminder.
    Reminder { last_check: Option<String> },
}

impl Notice {
    /// The fixed sentence.
    pub fn message(&self) -> String {
        match self {
            Notice::CouldNotCheck { since } => format!("Could not check for updates since {since}."),
            Notice::Reminder { last_check: Some(d) } => {
                format!("You last checked for updates on {d}. Check for updates in Settings.")
            }
            Notice::Reminder { last_check: None } => {
                "You have not checked for updates yet. Check for updates in Settings.".to_owned()
            }
        }
    }
}

/// `YYYY-MM-DD` (UTC) of a time.
pub fn date(secs: u64) -> String {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    p2pc_wsl::task::start_boundary(at)[..10].to_owned()
}

/// The notice to show now, if any. `None` while the user has not chosen (first run asks).
pub fn notice(update_checks: Option<bool>, state: &UpdateState, now: u64) -> Option<Notice> {
    let since = |t: Option<u64>| t.or(state.first_seen);
    let older = |t: u64, limit: u64| now.saturating_sub(t) >= limit;
    match update_checks? {
        true => {
            let from = since(state.last_success)?;
            older(from, STALE_AFTER_SECS).then(|| Notice::CouldNotCheck {
                since: state
                    .last_success
                    .map_or_else(|| "this app was installed".to_owned(), date),
            })
        }
        false => {
            let from = since(state.last_attempt)?;
            older(from, REMINDER_AFTER_SECS).then(|| Notice::Reminder {
                last_check: state.last_attempt.map(date),
            })
        }
    }
}

/// Why a downloaded update is being installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMoment {
    /// The user clicked "Install now" (or agreed in the prompt).
    UserAgreed,
    /// The app is starting, with an update downloaded earlier.
    AppStart,
    /// Neither: the update waits.
    NotYet,
}

/// A downloaded update may be installed now: the user agreed or the app is starting, and first run is over.
pub fn may_install(moment: InstallMoment, in_first_run: bool) -> bool {
    !in_first_run && matches!(moment, InstallMoment::UserAgreed | InstallMoment::AppStart)
}

/// `update-state.json` on disk.
#[derive(Debug, Clone)]
pub struct UpdateStateFile {
    path: PathBuf,
}

impl UpdateStateFile {
    /// The file in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(STATE_FILE),
        }
    }

    /// The stored record; an empty one when there is none. A damaged file is replaced by an empty record, except the
    /// web mark, which [`super::web::effective_mark`] keeps at least at the app's own release.
    pub fn load(&self) -> UpdateState {
        let Ok(file) = fs::File::open(&self.path) else {
            return UpdateState::default();
        };
        let mut data = Vec::new();
        if file.take(MAX_STATE_LEN + 1).read_to_end(&mut data).is_err() || data.len() as u64 > MAX_STATE_LEN {
            return UpdateState::default();
        }
        serde_json::from_slice::<serde_json::Value>(&data)
            .ok()
            .filter(serde_json::Value::is_object)
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }

    /// Writes the record atomically (a temporary file, then a rename).
    pub fn save(&self, state: &UpdateState) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(state).map_err(io::Error::other)?)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_762_939_800; // 2025-11-12T09:30:00Z

    #[test]
    fn without_a_yes_the_app_never_checks_on_its_own() {
        let s = UpdateState::default();
        assert!(!auto_check_due(None, false, &s, NOW));
        assert!(!auto_check_due(Some(false), false, &s, NOW));
        assert!(auto_check_due(Some(true), false, &s, NOW));
        assert!(!auto_check_due(Some(true), true, &s, NOW), "never during first run");
    }

    #[test]
    fn automatic_checks_run_at_most_once_a_day() {
        let mut s = UpdateState::default();
        s.attempted(NOW);
        assert!(!auto_check_due(Some(true), false, &s, NOW + DAY_SECS - 1));
        assert!(auto_check_due(Some(true), false, &s, NOW + DAY_SECS));
        assert!(
            auto_check_due(Some(true), false, &s, NOW - 10),
            "a clock that went back"
        );
    }

    #[test]
    fn fourteen_days_without_a_successful_check_are_shown() {
        let mut s = UpdateState::default();
        s.succeeded(NOW);
        for d in 1..14 {
            s.attempted(NOW + d * DAY_SECS);
        }
        assert_eq!(notice(Some(true), &s, NOW + 14 * DAY_SECS - 1), None);
        let n = notice(Some(true), &s, NOW + 14 * DAY_SECS).unwrap();
        assert_eq!(n.message(), "Could not check for updates since 2025-11-12.");
        // Never succeeded: counted from the first record.
        let mut never = UpdateState::default();
        never.attempted(NOW);
        assert!(notice(Some(true), &never, NOW + 14 * DAY_SECS).is_some());
    }

    #[test]
    fn without_opt_in_a_reminder_after_thirty_days_and_nothing_sent() {
        let mut s = UpdateState::default();
        s.first_seen = Some(NOW);
        assert_eq!(notice(Some(false), &s, NOW + 30 * DAY_SECS - 1), None);
        assert_eq!(
            notice(Some(false), &s, NOW + 30 * DAY_SECS).unwrap().message(),
            "You have not checked for updates yet. Check for updates in Settings."
        );
        s.attempted(NOW + 10 * DAY_SECS);
        assert_eq!(notice(Some(false), &s, NOW + 39 * DAY_SECS), None);
        assert_eq!(
            notice(Some(false), &s, NOW + 40 * DAY_SECS),
            Some(Notice::Reminder {
                last_check: Some("2025-11-22".into())
            })
        );
        assert_eq!(notice(None, &s, NOW + 400 * DAY_SECS), None, "not chosen yet");
    }

    #[test]
    fn an_update_installs_only_when_agreed_or_at_start_and_never_in_first_run() {
        assert!(may_install(InstallMoment::UserAgreed, false));
        assert!(may_install(InstallMoment::AppStart, false));
        assert!(!may_install(InstallMoment::NotYet, false));
        assert!(!may_install(InstallMoment::AppStart, true));
        assert!(!may_install(InstallMoment::UserAgreed, true));
    }

    #[test]
    fn the_state_file_round_trips_and_a_damaged_one_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = UpdateStateFile::in_dir(&dir.path().join("sub"));
        assert_eq!(f.load(), UpdateState::default());
        let mut s = UpdateState::default();
        s.succeeded(NOW);
        s.web_mark = Some("0.3.0".into());
        f.save(&s).unwrap();
        assert_eq!(f.load(), s);
        fs::write(dir.path().join("sub").join(STATE_FILE), b"[1,2]").unwrap();
        assert_eq!(f.load(), UpdateState::default());
    }
}
