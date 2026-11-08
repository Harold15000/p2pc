// SPDX-License-Identifier: Apache-2.0

//! Output collection (spec §9 "Outputs", SI-9).
//!
//! After the container is gone, the agent walks `outputs/` **without following symlinks**. Only regular files are
//! collected, up to `outputs.max_mb` in total. Each one:
//! - has a relative path that passes [`validate_output_path`] (no `..`, `.`, empty segments, control characters or
//!   backslashes; valid UTF-8);
//! - is opened with `O_NOFOLLOW`, checked to be a regular file on the open descriptor, and checked to lie inside
//!   the canonicalized `outputs/` directory;
//! - is hashed (SHA-256) and sized from that same descriptor.
//!
//! Everything else is skipped **with a reason**, so the owner can see why a file is missing. T10 uploads the list.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use p2pc_proto::api::{OutputFile, Sha256Digest};
use p2pc_proto::protocol::MAX_OUTPUT_FILES;
use p2pc_proto::validate::validate_output_path;
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};

/// Deepest directory nesting walked under `outputs/`.
pub const MAX_DEPTH: usize = 64;
/// Most directory entries looked at in total, collected or not. Bounds the walk, and its memory, on a hostile tree.
pub const MAX_ENTRIES: usize = 100_000;
/// Most skip records kept with their path; past that, skips are only counted ([`CollectedOutputs::skip_counts`]).
pub const MAX_SKIP_RECORDS: usize = 1000;
/// Longest path kept in a skip record, in bytes; longer ones are cut and end with `…`.
pub const MAX_SKIP_PATH_LEN: usize = 256;

/// The bounds of one walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    /// Most entries read from directories, in total ([`MAX_ENTRIES`]).
    pub max_entries: usize,
    /// Most files collected ([`MAX_OUTPUT_FILES`]).
    pub max_files: usize,
    /// Deepest nesting ([`MAX_DEPTH`]).
    pub max_depth: usize,
    /// Most skip records with a path ([`MAX_SKIP_RECORDS`]).
    pub max_skip_records: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_ENTRIES,
            max_files: MAX_OUTPUT_FILES,
            max_depth: MAX_DEPTH,
            max_skip_records: MAX_SKIP_RECORDS,
        }
    }
}

/// Why an entry of `outputs/` was not collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SkipReason {
    /// A symbolic link (never followed).
    Symlink,
    /// A FIFO, socket, device or anything else that is not a regular file or directory.
    NotRegular,
    /// The name is not valid UTF-8, or the path fails [`validate_output_path`].
    InvalidName,
    /// The file would take the total over `outputs.max_mb`.
    OverCap,
    /// The file resolves outside `outputs/` once canonicalized.
    OutsideRoot,
    /// More than [`MAX_OUTPUT_FILES`] files, [`MAX_ENTRIES`] entries or [`MAX_DEPTH`] levels.
    TooMany,
    /// It could not be read.
    Unreadable,
}

impl SkipReason {
    /// A stable short code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Symlink => "symlink",
            Self::NotRegular => "not_regular",
            Self::InvalidName => "invalid_name",
            Self::OverCap => "over_cap",
            Self::OutsideRoot => "outside_root",
            Self::TooMany => "too_many",
            Self::Unreadable => "unreadable",
        }
    }
}

/// A collected output file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedFile {
    /// Path relative to `/outputs`, `/`-separated.
    pub path: String,
    /// Where it is on the host.
    pub host_path: PathBuf,
    /// Size in bytes (what was hashed).
    pub size: u64,
    /// SHA-256 of the content.
    pub sha256: Sha256Digest,
}

impl CollectedFile {
    /// The wire form for `JobFinished.outputs`.
    #[must_use]
    pub fn to_wire(&self) -> OutputFile {
        OutputFile {
            path: self.path.clone(),
            size: self.size,
            sha256: self.sha256,
        }
    }
}

/// An entry that was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Its path relative to `/outputs`, lossily decoded, cut to [`MAX_SKIP_PATH_LEN`] bytes.
    pub path: String,
    /// Why.
    pub reason: SkipReason,
}

/// The result of a walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectedOutputs {
    /// Files to upload, in path order.
    pub files: Vec<CollectedFile>,
    /// The first [`MAX_SKIP_RECORDS`] entries left out, with the reason.
    pub skipped: Vec<Skipped>,
    /// Every entry left out, counted by reason (including those past the record cap).
    pub skip_counts: std::collections::BTreeMap<SkipReason, u64>,
}

impl CollectedOutputs {
    /// Total bytes collected.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// How many entries were left out in total.
    #[must_use]
    pub fn total_skipped(&self) -> u64 {
        self.skip_counts.values().sum()
    }
}

struct Walk {
    root: PathBuf,
    max_bytes: u64,
    limits: WalkLimits,
    total: u64,
    entries: usize,
    out: CollectedOutputs,
}

/// Collects the regular files under `root` (the job's `outputs/`), up to `max_bytes` in total, with the default
/// [`WalkLimits`].
///
/// # Errors
/// Only if `root` itself cannot be canonicalized or read. Problems with entries are reported in
/// [`CollectedOutputs::skipped`].
pub fn collect(root: &Path, max_bytes: u64) -> io::Result<CollectedOutputs> {
    collect_with(root, max_bytes, WalkLimits::default())
}

/// [`collect`] with explicit limits.
///
/// Memory stays bounded whatever the tree holds: directories are read lazily and at most the remaining entry
/// budget of each is kept (and sorted); skip records are capped, with per-reason counters for the rest.
///
/// # Errors
/// As [`collect`].
pub fn collect_with(root: &Path, max_bytes: u64, limits: WalkLimits) -> io::Result<CollectedOutputs> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() {
        return Err(io::Error::other("outputs/ is not a directory"));
    }
    let mut walk = Walk {
        root: fs::canonicalize(root)?,
        max_bytes,
        limits,
        total: 0,
        entries: 0,
        out: CollectedOutputs::default(),
    };
    let real_root = walk.root.clone();
    walk.dir(&real_root, "", 0)?;
    Ok(walk.out)
}

/// `path` cut to at most [`MAX_SKIP_PATH_LEN`] bytes on a character boundary, ending with `…` when cut.
fn shorten(path: String) -> String {
    if path.len() <= MAX_SKIP_PATH_LEN {
        return path;
    }
    let mut end = MAX_SKIP_PATH_LEN - '…'.len_utf8();
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &path[..end])
}

fn join(rel: &str, name: &str) -> String {
    if rel.is_empty() {
        name.to_string()
    } else {
        format!("{rel}/{name}")
    }
}

impl Walk {
    fn skip(&mut self, path: String, reason: SkipReason) {
        *self.out.skip_counts.entry(reason).or_insert(0) += 1;
        if self.out.skipped.len() < self.limits.max_skip_records {
            self.out.skipped.push(Skipped {
                path: shorten(path),
                reason,
            });
        }
    }

    fn dir(&mut self, dir: &Path, rel: &str, depth: usize) -> io::Result<()> {
        // Read lazily, and keep at most what the entry budget still allows: a directory with millions of entries
        // costs no more memory than the budget.
        let remaining = self.limits.max_entries.saturating_sub(self.entries);
        let mut entries: Vec<fs::DirEntry> = Vec::new();
        let mut truncated = false;
        for item in fs::read_dir(dir)? {
            if entries.len() >= remaining {
                truncated = true;
                break;
            }
            match item {
                Ok(entry) => entries.push(entry),
                // A per-entry error (for example a directory changing under us) skips that entry only.
                Err(_) => {
                    self.entries += 1;
                    self.skip(join(rel, "?"), SkipReason::Unreadable);
                }
            }
        }
        // The budget is taken now, so that what the subdirectories read below adds to it, never on top of it.
        self.entries += entries.len();
        if truncated {
            self.skip(join(rel, "…"), SkipReason::TooMany);
        }
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            let shown = name.to_string_lossy().into_owned();
            let child_rel = join(rel, &shown);
            let valid = name.to_str().is_some() && validate_output_path(&child_rel).is_ok();
            if !valid {
                self.skip(child_rel, SkipReason::InvalidName);
                continue;
            }
            // lstat: a symlink is reported as a symlink, never as its target.
            let file_type = match fs::symlink_metadata(entry.path()) {
                Ok(m) => m.file_type(),
                Err(_) => {
                    self.skip(child_rel, SkipReason::Unreadable);
                    continue;
                }
            };
            if file_type.is_symlink() {
                self.skip(child_rel, SkipReason::Symlink);
            } else if file_type.is_dir() {
                if depth + 1 >= self.limits.max_depth {
                    self.skip(child_rel, SkipReason::TooMany);
                } else if self.dir(&entry.path(), &child_rel, depth + 1).is_err() {
                    self.skip(child_rel, SkipReason::Unreadable);
                }
            } else if file_type.is_file() {
                self.file(&entry.path(), child_rel);
            } else {
                // FIFOs (which would block a reader), sockets and devices.
                self.skip(child_rel, SkipReason::NotRegular);
            }
        }
        Ok(())
    }

    fn file(&mut self, path: &Path, rel: String) {
        if self.out.files.len() >= self.limits.max_files {
            self.skip(rel, SkipReason::TooMany);
            return;
        }
        match fs::canonicalize(path) {
            Ok(real) if real.starts_with(&self.root) && real != self.root => {}
            Ok(_) => return self.skip(rel, SkipReason::OutsideRoot),
            Err(_) => return self.skip(rel, SkipReason::Unreadable),
        }
        // O_NOFOLLOW | O_NONBLOCK: never follow a symlink swapped in, never block on a FIFO swapped in.
        let fd = match rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::LOOP) => return self.skip(rel, SkipReason::Symlink),
            Err(_) => return self.skip(rel, SkipReason::Unreadable),
        };
        let stat = match rustix::fs::fstat(&fd) {
            Ok(s) => s,
            Err(_) => return self.skip(rel, SkipReason::Unreadable),
        };
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
            return self.skip(rel, SkipReason::NotRegular);
        }
        let declared = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
        if self.total.saturating_add(declared) > self.max_bytes {
            return self.skip(rel, SkipReason::OverCap);
        }
        // Read at most what still fits (plus one byte to notice growth), hashing as we go.
        let budget = self.max_bytes - self.total;
        let mut reader = fs::File::from(fd).take(budget.saturating_add(1));
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buf[..n]);
                    size += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return self.skip(rel, SkipReason::Unreadable),
            }
        }
        if size > budget {
            return self.skip(rel, SkipReason::OverCap);
        }
        self.total += size;
        self.out.files.push(CollectedFile {
            path: rel,
            host_path: path.to_path_buf(),
            size,
            sha256: Sha256Digest(hasher.finalize().into()),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn sha(data: &[u8]) -> Sha256Digest {
        Sha256Digest(Sha256::digest(data).into())
    }

    fn reasons(out: &CollectedOutputs) -> Vec<(&str, &'static str)> {
        out.skipped.iter().map(|s| (s.path.as_str(), s.reason.code())).collect()
    }

    #[test]
    fn collects_regular_files_with_hashes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        fs::create_dir_all(dir.path().join("results/deep")).unwrap();
        fs::write(dir.path().join("results/deep/b.bin"), [1u8, 2, 3]).unwrap();
        fs::write(dir.path().join("empty"), b"").unwrap();
        let out = collect(dir.path(), 1024).unwrap();
        let paths: Vec<&str> = out.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["a.txt", "empty", "results/deep/b.bin"]);
        assert_eq!(out.files[0].size, 5);
        assert_eq!(out.files[0].sha256, sha(b"hello"));
        assert_eq!(out.files[2].to_wire().sha256, sha(&[1, 2, 3]));
        assert_eq!(out.total_bytes(), 8);
        assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    }

    /// SI-9: symlinks (to /etc/passwd, out of the directory, or to `..`), bad names, FIFOs and a file over the cap
    /// are all skipped, each with its reason.
    #[test]
    fn si9_hostile_entries_are_skipped_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"top secret").unwrap();
        let root = dir.path();
        symlink("/etc/passwd", root.join("passwd")).unwrap();
        symlink(outside.path().join("secret"), root.join("escape")).unwrap();
        symlink("..", root.join("up")).unwrap();
        symlink(outside.path(), root.join("outdir")).unwrap();
        fs::write(root.join("back\\slash"), b"x").unwrap();
        fs::write(root.join("new\nline"), b"x").unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            root.join("fifo"),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        fs::write(root.join("big"), vec![0u8; 2048]).unwrap();
        fs::write(root.join("ok"), b"fine").unwrap();

        let out = collect(root, 1024).unwrap();
        let paths: Vec<&str> = out.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["ok"]);
        let mut got = reasons(&out);
        got.sort_unstable();
        assert_eq!(
            got,
            [
                ("back\\slash", "invalid_name"),
                ("big", "over_cap"),
                ("escape", "symlink"),
                ("fifo", "not_regular"),
                ("new\nline", "invalid_name"),
                ("outdir", "symlink"),
                ("passwd", "symlink"),
                ("up", "symlink"),
            ]
        );
        assert!(!out.files.iter().any(|f| f.sha256 == sha(b"top secret")));
    }

    #[test]
    fn the_cap_is_on_the_total() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("1"), vec![1u8; 600]).unwrap();
        fs::write(dir.path().join("2"), vec![2u8; 600]).unwrap();
        fs::write(dir.path().join("3"), vec![3u8; 400]).unwrap();
        let out = collect(dir.path(), 1000).unwrap();
        let paths: Vec<&str> = out.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["1", "3"], "the second file does not fit, the third does");
        assert_eq!(reasons(&out), [("2", "over_cap")]);
        assert_eq!(out.total_bytes(), 1000);
        // A cap of zero collects nothing.
        assert!(collect(dir.path(), 0).unwrap().files.is_empty());
    }

    /// A directory over the entry budget: only the budget is read (and sorted), the rest is reported, not kept.
    #[test]
    fn a_directory_over_the_entry_budget_is_cut() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..25 {
            fs::write(dir.path().join(format!("f{i:02}")), b"x").unwrap();
        }
        let limits = WalkLimits {
            max_entries: 10,
            ..WalkLimits::default()
        };
        let out = collect_with(dir.path(), 1024, limits).unwrap();
        assert!(out.files.len() <= 10, "{}", out.files.len());
        assert_eq!(out.skip_counts.get(&SkipReason::TooMany), Some(&1));
        assert_eq!(reasons(&out), [("…", "too_many")]);
        // The batch that was read is in path order.
        let paths: Vec<&str> = out.files.iter().map(|f| f.path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        // A subdirectory can only use what is left of the budget, never more.
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/inner"), b"y").unwrap();
        let limits = WalkLimits {
            max_entries: 26,
            ..WalkLimits::default()
        };
        let out = collect_with(dir.path(), 1024, limits).unwrap();
        assert_eq!(out.files.len(), 25, "the 26 top-level entries fill the budget");
        assert_eq!(reasons(&out), [("sub/…", "too_many")]);
    }

    #[test]
    fn skip_records_are_capped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            symlink("/etc/passwd", dir.path().join(format!("l{i}"))).unwrap();
        }
        let long = "n".repeat(250);
        fs::create_dir(dir.path().join(&long)).unwrap();
        fs::write(dir.path().join(&long).join(format!("{long}\\x")), b"x").unwrap();
        let limits = WalkLimits {
            max_skip_records: 3,
            ..WalkLimits::default()
        };
        let out = collect_with(dir.path(), 1024, limits).unwrap();
        assert_eq!(out.skipped.len(), 3, "only 3 records are kept");
        assert_eq!(out.skip_counts.get(&SkipReason::Symlink), Some(&10));
        assert_eq!(out.skip_counts.get(&SkipReason::InvalidName), Some(&1));
        assert_eq!(out.total_skipped(), 11);

        // With room for every record, the long path is cut.
        let out = collect(dir.path(), 1024).unwrap();
        let bad = out
            .skipped
            .iter()
            .find(|s| s.reason == SkipReason::InvalidName)
            .unwrap();
        assert!(bad.path.len() <= MAX_SKIP_PATH_LEN, "{}", bad.path.len());
        assert!(bad.path.ends_with('…'));
        assert_eq!(shorten("short".into()), "short");
    }

    #[test]
    fn a_symlinked_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("outputs");
        symlink("/etc", &link).unwrap();
        assert!(collect(&link, 1024).is_err());
    }
}
