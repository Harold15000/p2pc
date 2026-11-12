// SPDX-License-Identifier: Apache-2.0

//! An app update that was downloaded and passed the gate, kept until the user agrees or the app starts again (§14.1:
//! "downloads in the background and installs when the user agrees or at the next start").
//!
//! Two files in the app's local data folder: the artifact's bytes and the endpoint's answer for it (Tauri's
//! `raw_json`, from which the updater plugin restores the update). Nothing here is trusted on the way back: the restored
//! update passes [`super::artifact::check_artifact`] again before it is installed, and the plugin itself requires the
//! signed version of a restored update.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The artifact's file.
pub const ARTIFACT_FILE: &str = "pending-update.bin";
/// The endpoint's answer's file.
pub const ANSWER_FILE: &str = "pending-update.json";
/// The largest artifact kept.
pub const MAX_ARTIFACT_BYTES: u64 = 512 << 20;
/// The largest answer kept.
pub const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// The pending update's files in a folder.
#[derive(Debug, Clone)]
pub struct PendingFiles {
    dir: PathBuf,
}

fn read_capped(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    fs::File::open(path)?.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(io::Error::other("too large"));
    }
    Ok(out)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

impl PendingFiles {
    pub fn in_dir(dir: &Path) -> Self {
        Self { dir: dir.to_owned() }
    }

    /// Keeps an update: the artifact first, then the answer, so a half-written pair has no answer and is ignored.
    pub fn save(&self, answer: &serde_json::Value, artifact: &[u8]) -> io::Result<()> {
        if artifact.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(io::Error::other("the update is too large to keep"));
        }
        fs::create_dir_all(&self.dir)?;
        let _ = fs::remove_file(self.dir.join(ANSWER_FILE));
        write_atomic(&self.dir.join(ARTIFACT_FILE), artifact)?;
        write_atomic(
            &self.dir.join(ANSWER_FILE),
            &serde_json::to_vec(answer).map_err(io::Error::other)?,
        )
    }

    /// The kept update, if both files are there and readable.
    pub fn load(&self) -> Option<(serde_json::Value, Vec<u8>)> {
        let answer = read_capped(&self.dir.join(ANSWER_FILE), MAX_ANSWER_BYTES).ok()?;
        let answer: serde_json::Value = serde_json::from_slice(&answer).ok()?;
        let artifact = read_capped(&self.dir.join(ARTIFACT_FILE), MAX_ARTIFACT_BYTES).ok()?;
        Some((answer, artifact))
    }

    /// Forgets it (installed, refused or stale).
    pub fn clear(&self) {
        for f in [ANSWER_FILE, ARTIFACT_FILE] {
            let _ = fs::remove_file(self.dir.join(f));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_is_kept_until_cleared_and_half_a_pair_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let p = PendingFiles::in_dir(&dir.path().join("local"));
        assert!(p.load().is_none());
        let answer = serde_json::json!({"version": "0.3.0", "platforms": {}});
        p.save(&answer, b"MZ installer").unwrap();
        assert_eq!(p.load(), Some((answer, b"MZ installer".to_vec())));
        fs::remove_file(dir.path().join("local").join(ANSWER_FILE)).unwrap();
        assert!(p.load().is_none());
        p.clear();
        assert!(!dir.path().join("local").join(ARTIFACT_FILE).exists());
    }
}
