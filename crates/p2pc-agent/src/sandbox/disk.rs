// SPDX-License-Identifier: Apache-2.0

//! Disk accounting (spec §9 "Disk" and "Disk floor"). Both **fail closed**.
//!
//! - [`tree_usage`] measures `outputs/`: each entry counts as the larger of its apparent size and its allocated
//!   blocks (so `fallocate` cannot hide space, and a sparse file cannot either), and reaching the entry budget means
//!   "over the limit", never "probably fine".
//! - [`FreeSpace`] is the node's free space on the data disk, behind a trait so tests inject it. Below
//!   [`floor_bytes`] (the larger of 5 GiB and 5 % of the disk), running jobs are killed with `disk_floor` and new
//!   leases are refused: the owner's disk always comes first.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The absolute part of the floor: 5 GiB.
pub const FLOOR_MIN_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// The relative part of the floor: 5 % of the disk.
pub const FLOOR_PERCENT: u64 = 5;
/// Measurement failures in a row that count as over the limit.
pub const MAX_FAILED_MEASUREMENTS: u32 = 3;

/// What a measurement of a tree found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeUsage {
    /// Every entry was counted: this many bytes.
    Bytes(u64),
    /// The entry budget was reached before the end: over the limit, whatever was counted so far.
    OverBudget,
}

/// What one entry occupies: the larger of its apparent size and its allocated blocks.
#[must_use]
pub fn entry_bytes(meta: &fs::Metadata) -> u64 {
    meta.len().max(meta.blocks().saturating_mul(512))
}

/// Measures everything under `root` without following symlinks, with at most `max_entries` entries.
///
/// # Errors
/// Any error reading a directory or an entry: the caller counts it as a failed measurement (fail closed), never as
/// zero bytes.
pub fn tree_usage(root: &Path, max_entries: usize) -> io::Result<TreeUsage> {
    let mut total = entry_bytes(&fs::symlink_metadata(root)?);
    let mut seen = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            seen += 1;
            if seen > max_entries {
                return Ok(TreeUsage::OverBudget);
            }
            let meta = fs::symlink_metadata(entry.path())?;
            total = total.saturating_add(entry_bytes(&meta));
            if meta.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    Ok(TreeUsage::Bytes(total))
}

/// Space on a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    /// Bytes available to the agent (`f_bavail`).
    pub free_bytes: u64,
    /// The filesystem's size.
    pub total_bytes: u64,
}

impl DiskSpace {
    /// Whether free space is below the floor.
    #[must_use]
    pub fn below_floor(&self) -> bool {
        self.free_bytes < floor_bytes(self.total_bytes)
    }
}

/// The floor for a disk of `total_bytes`: the larger of 5 GiB and 5 %.
#[must_use]
pub fn floor_bytes(total_bytes: u64) -> u64 {
    FLOOR_MIN_BYTES.max(total_bytes / 100 * FLOOR_PERCENT)
}

/// The free space of the filesystem that holds a path.
pub trait FreeSpace: Send + Sync + fmt::Debug {
    /// Space on the filesystem of `path`.
    ///
    /// # Errors
    /// Why it could not be read; callers fail closed.
    fn space(&self, path: &Path) -> io::Result<DiskSpace>;
}

/// The real source: `statvfs(2)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Statvfs;

impl FreeSpace for Statvfs {
    fn space(&self, path: &Path) -> io::Result<DiskSpace> {
        let s = rustix::fs::statvfs(path)?;
        Ok(DiskSpace {
            free_bytes: s.f_bavail.saturating_mul(s.f_frsize),
            total_bytes: s.f_blocks.saturating_mul(s.f_frsize),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn bytes(u: TreeUsage) -> u64 {
        match u {
            TreeUsage::Bytes(b) => b,
            TreeUsage::OverBudget => panic!("over budget"),
        }
    }

    #[test]
    fn counts_files_dirs_and_links_without_following() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), vec![0u8; 100_000]).unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        fs::write(dir.path().join("d/b"), vec![0u8; 50_000]).unwrap();
        symlink("/etc", dir.path().join("etc")).unwrap();
        let used = bytes(tree_usage(dir.path(), 100).unwrap());
        assert!(used >= 150_000, "{used}");
        assert!(used < 1_000_000, "the symlink target is not counted: {used}");
    }

    /// `fallocate(KEEP_SIZE)` allocates blocks beyond EOF: st_size stays 0, the blocks count.
    #[test]
    fn blocks_allocated_beyond_eof_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hidden");
        let f = fs::File::create(&path).unwrap();
        let four_mib = 4 * 1024 * 1024;
        if let Err(e) = rustix::fs::fallocate(&f, rustix::fs::FallocateFlags::KEEP_SIZE, 0, four_mib) {
            eprintln!("SKIPPED: this filesystem has no fallocate(KEEP_SIZE): {e}");
            return;
        }
        assert_eq!(fs::metadata(&path).unwrap().len(), 0, "the apparent size is 0");
        assert!(bytes(tree_usage(dir.path(), 100).unwrap()) >= four_mib);
    }

    #[test]
    fn a_sparse_file_counts_its_apparent_size() {
        let dir = tempfile::tempdir().unwrap();
        let f = fs::File::create(dir.path().join("sparse")).unwrap();
        f.set_len(1 << 30).unwrap();
        assert!(bytes(tree_usage(dir.path(), 100).unwrap()) >= 1 << 30);
    }

    #[test]
    fn reaching_the_entry_budget_is_over_budget() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..11 {
            fs::write(dir.path().join(i.to_string()), b"").unwrap();
        }
        assert_eq!(tree_usage(dir.path(), 10).unwrap(), TreeUsage::OverBudget);
        assert!(matches!(tree_usage(dir.path(), 11).unwrap(), TreeUsage::Bytes(_)));
    }

    #[test]
    fn read_failures_are_errors_not_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert!(tree_usage(&dir.path().join("missing"), 10).is_err());
        if !rustix::process::geteuid().is_root() {
            let locked = dir.path().join("locked");
            fs::create_dir(&locked).unwrap();
            fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
            assert!(
                tree_usage(dir.path(), 10).is_err(),
                "an unreadable directory fails the measurement"
            );
            fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn the_floor_is_the_larger_of_5_gib_and_5_percent() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(floor_bytes(50 * GIB), 5 * GIB);
        assert_eq!(floor_bytes(1000 * GIB), 50 * GIB);
        let space = |free, total| DiskSpace {
            free_bytes: free,
            total_bytes: total,
        };
        assert!(space(4 * GIB, 50 * GIB).below_floor());
        assert!(!space(6 * GIB, 50 * GIB).below_floor());
        assert!(space(40 * GIB, 1000 * GIB).below_floor());
        assert!(Statvfs.space(Path::new("/")).unwrap().total_bytes > 0);
    }
}
