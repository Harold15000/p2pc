// SPDX-License-Identifier: Apache-2.0

//! The uninstall log, `%TEMP%\p2pc-uninstall-<time>.log` (§8.7): the only file left afterwards, deleted by Windows'
//! own temp cleanup. Every line is the app's own text (step results, ids of nodes, paths): no secret, ticket, token or
//! key ever reaches it (SI-H2-1).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The log of one uninstall.
#[derive(Debug)]
pub struct UninstallLog {
    path: PathBuf,
    file: Option<File>,
}

/// `p2pc-uninstall-20261112T093000Z.log`.
pub fn file_name(at: SystemTime) -> String {
    let stamp: String = p2pc_wsl::task::start_boundary(at).replace([':', '-'], "");
    format!("p2pc-uninstall-{stamp}.log")
}

impl UninstallLog {
    /// Creates the log in `temp_dir`. A log that cannot be created is not an error: the steps still run, unlogged.
    pub fn create(temp_dir: &Path, at: SystemTime) -> Self {
        let path = temp_dir.join(file_name(at));
        let file = OpenOptions::new().create(true).append(true).open(&path).ok();
        Self { path, file }
    }

    /// The log's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path as text, for the final page.
    pub fn path_text(&self) -> String {
        self.path.display().to_string()
    }

    /// Appends one line, with the time.
    pub fn line(&mut self, text: &str) {
        if let Some(f) = &mut self.file {
            let at = p2pc_wsl::task::start_boundary(SystemTime::now());
            let _ = writeln!(f, "{at} {text}\r");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn the_log_is_named_by_its_time_and_appends_lines() {
        let at = UNIX_EPOCH + Duration::from_secs(1_762_939_800);
        assert_eq!(file_name(at), "p2pc-uninstall-20251112T093000Z.log");
        let dir = tempfile::tempdir().unwrap();
        let mut log = UninstallLog::create(dir.path(), at);
        log.line("step 3: scheduled task removed");
        log.line("step 4: done");
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("step 3: scheduled task removed\r\n"));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn a_log_that_cannot_be_created_does_not_stop_anything() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = UninstallLog::create(&dir.path().join("missing"), SystemTime::now());
        log.line("still runs");
        assert!(!log.path().exists());
    }
}
