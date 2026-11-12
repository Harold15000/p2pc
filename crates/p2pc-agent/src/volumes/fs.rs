// SPDX-License-Identifier: Apache-2.0

//! The volume directories on disk (H2 §11.3, SI-H2-9), reached only through directory descriptors.
//!
//! Nothing in this file follows a symbolic link, and nothing in it takes a path from a job:
//!
//! - **The chain** `volumes/<account_id>/<hash>/data` is entered one name at a time with
//!   `openat(O_NOFOLLOW | O_DIRECTORY)`, and created with `mkdirat` (0700; `data/` 0755) under the parent's descriptor when it is
//!   missing. A symbolic link, or anything that is not a directory, at any level is an error, never followed.
//! - **The check before a mount** ([`check_tree`]) walks `data/` with `openat(O_NOFOLLOW | O_DIRECTORY)` for
//!   directories and an `lstat` (`fstatat(AT_SYMLINK_NOFOLLOW)`) for every entry. It refuses a symbolic link, an entry
//!   that is neither a directory nor a regular file, and a regular file with more than one hard link: `:U` changes the
//!   owner of everything it reaches, and a chown through a second name would reach a file outside the volume.
//! - **The measurement** ([`tree_usage`]) is the same walk without the refusals, counting each entry as H1 counts
//!   job disk: the larger of its apparent size and its allocated blocks, under an entry budget.
//! - **Deletion** ([`remove_volume`]) uses `unlinkat` only. A tree deeper than the descriptors it may hold at once is
//!   flattened with `renameat`, which never follows a link either.

use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::{DATA_DIR, META_FILE, VOLUMES_DIR};
use crate::sandbox::disk::TreeUsage;

/// Mode of the directories of the chain that only the agent writes (`volumes/`, `<account_id>/`, `<hash>/`), as it
/// creates them. They are what keeps every other user of the host out of a volume.
pub const DIR_MODE: u32 = 0o700;
/// Mode of `data/`, the directory that is mounted, as the agent creates it: the same as H1's mounted job
/// directories ([`crate::sandbox::jobdir::SUBDIR_MODE`]), and for the same reason. `:U` gives `data/` to the image's
/// user; with rootless Podman that is one of the agent's subordinate UIDs when the image does not run as root, and
/// the agent must still be able to open the directory to measure it and to check it before the next mount.
pub const DATA_MODE: u32 = 0o755;
/// Mode of `meta.json`.
pub const META_MODE: u32 = 0o600;
/// Deepest nesting the check and the measurement walk: each level holds a descriptor. Deeper is refused (the check)
/// or counts as over the limit (the measurement).
pub const MAX_DEPTH: usize = 64;
/// Largest `meta.json` that is read.
pub const MAX_META_BYTES: usize = 16 * 1024;
/// Levels of a tree being deleted whose descriptors are held at once; a deeper subtree is moved up first.
const DELETE_DEPTH: usize = 32;
/// Entries of one directory handled per pass of a deletion.
const BATCH: usize = 1024;
/// Prefix of a subtree that a deletion moved up, next to `data/`.
const MOVED_PREFIX: &str = ".p2pc-del-";

/// Why a level of the chain cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// A symbolic link, or anything else that is not a directory, where a directory of the chain belongs.
    #[error("{what} is a symbolic link or not a directory")]
    NotADirectory {
        /// Which level.
        what: &'static str,
    },
    /// A directory the agent creates itself belongs to somebody else.
    #[error("{what} belongs to uid {owner}, not to the agent")]
    WrongOwner {
        /// Which level.
        what: &'static str,
        /// Its owner.
        owner: u32,
    },
    /// The level does not exist (and was not to be created).
    #[error("{what} does not exist")]
    Missing {
        /// Which level.
        what: &'static str,
    },
    /// A name that could be read as a path. Names come from the agent (an account id, a hash); this is a second
    /// lock.
    #[error("{what}: not a plain directory name")]
    BadName {
        /// Which level.
        what: &'static str,
    },
    /// Any other error.
    #[error("{what}: {source}")]
    Io {
        /// Which level.
        what: &'static str,
        /// The error.
        source: io::Error,
    },
}

impl ChainError {
    /// Whether the chain itself is not what the agent made (as opposed to an I/O failure): the mount is refused as
    /// `volume_unsafe`.
    #[must_use]
    pub fn is_unsafe(&self) -> bool {
        matches!(self, Self::NotADirectory { .. } | Self::WrongOwner { .. })
    }
}

impl From<ChainError> for io::Error {
    fn from(e: ChainError) -> Self {
        match e {
            ChainError::Missing { .. } => io::Error::new(io::ErrorKind::NotFound, e.to_string()),
            ChainError::Io { source, .. } => source,
            other => io::Error::other(other.to_string()),
        }
    }
}

/// Opens the directory `name` under `at`, never through a symbolic link.
fn open_dir_at<P: rustix::path::Arg>(at: BorrowedFd<'_>, name: P) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn is_dir(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
}

/// Whether `name` is one plain path component.
fn is_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// Enters the directory `name` under `at`: created with `mkdirat` when `create` is set and it is missing, opened
/// with `O_NOFOLLOW | O_DIRECTORY` either way, and verified. `owned` levels are the ones only the agent writes: they
/// are created 0700 ([`DIR_MODE`]), must belong to the agent, and their mode is tightened to 0700. `data/` is not one
/// of them: it is created 0755 ([`DATA_MODE`]), and `:U` gives it to the container's user.
pub fn enter(
    at: BorrowedFd<'_>,
    name: &str,
    what: &'static str,
    create: bool,
    owned: bool,
) -> Result<OwnedFd, ChainError> {
    let io = |source: Errno| ChainError::Io {
        what,
        source: source.into(),
    };
    if !is_component(name) {
        return Err(ChainError::BadName { what });
    }
    let mode = if owned { DIR_MODE } else { DATA_MODE };
    let mut created = false;
    if create {
        match rustix::fs::mkdirat(at, name, Mode::from_raw_mode(mode)) {
            Ok(()) => created = true,
            Err(Errno::EXIST) => {}
            Err(e) => return Err(io(e)),
        }
    }
    let fd = match open_dir_at(at, name) {
        Ok(fd) => fd,
        // `O_NOFOLLOW` on a symbolic link: ELOOP, or ENOTDIR with `O_DIRECTORY` (which a file gives too).
        Err(Errno::LOOP | Errno::NOTDIR) => return Err(ChainError::NotADirectory { what }),
        Err(Errno::NOENT) => return Err(ChainError::Missing { what }),
        Err(e) => return Err(io(e)),
    };
    let stat = rustix::fs::fstat(&fd).map_err(io)?;
    if !is_dir(&stat) {
        return Err(ChainError::NotADirectory { what });
    }
    if created {
        // `mkdirat` honours the umask: make the mode exact.
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(mode)).map_err(io)?;
    } else if owned {
        let euid = rustix::process::geteuid().as_raw();
        if stat.st_uid != euid {
            return Err(ChainError::WrongOwner {
                what,
                owner: stat.st_uid,
            });
        }
        if stat.st_mode & 0o077 != 0 {
            rustix::fs::fchmod(&fd, Mode::from_raw_mode(DIR_MODE)).map_err(io)?;
        }
    }
    Ok(fd)
}

/// Opens `<data_dir>/volumes`, created 0700 when `create` is set. The data dir is the agent's own configured
/// directory (0700, [`crate::identity::ensure_private_dir`]); everything below it is entered without following links.
pub fn open_root(data_dir: &Path, create: bool) -> Result<OwnedFd, ChainError> {
    let base = rustix::fs::open(
        data_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ChainError::Io {
        what: "the data directory",
        source: e.into(),
    })?;
    enter(base.as_fd(), VOLUMES_DIR, "volumes/", create, true)
}

/// The open directories of one volume.
#[derive(Debug)]
pub struct Chain {
    /// `volumes/<account_id>/`.
    pub account: OwnedFd,
    /// `volumes/<account_id>/<hash>/`, which holds `meta.json`.
    pub volume: OwnedFd,
    /// `volumes/<account_id>/<hash>/data/`, the directory that is mounted.
    pub data: OwnedFd,
}

/// Enters `<account>/<dir>/data` under `root` ([`open_root`]): each level recreated with `mkdirat` when `create` is
/// set and it is missing, and verified otherwise.
pub fn open_chain(root: BorrowedFd<'_>, account: &str, dir: &str, create: bool) -> Result<Chain, ChainError> {
    let account = enter(root, account, "the account's volume directory", create, true)?;
    let volume = enter(account.as_fd(), dir, "the volume directory", create, true)?;
    let data = enter(volume.as_fd(), DATA_DIR, "the volume's data directory", create, false)?;
    Ok(Chain { account, volume, data })
}

/// Why a volume's tree may not be mounted (`error="volume_unsafe"`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unsafe {
    /// A symbolic link.
    #[error("a symbolic link at {0:?}")]
    Symlink(String),
    /// A FIFO, a socket or a device.
    #[error("an entry that is neither a directory nor a regular file at {0:?}")]
    Special(String),
    /// A regular file with a second name: a chown through it would reach its other name.
    #[error("a regular file with more than one hard link at {0:?}")]
    HardLink(String),
    /// More entries than the budget of the disk measurement.
    #[error("more than {0} entries")]
    TooManyEntries(usize),
    /// Nested deeper than [`MAX_DEPTH`].
    #[error("directories nested deeper than {}", MAX_DEPTH)]
    TooDeep,
    /// The tree could not be read to the end, so it cannot be vouched for.
    #[error("the tree cannot be read: {0}")]
    Unreadable(String),
}

/// What a walk found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tree {
    /// Entries below the root.
    pub entries: usize,
    /// Bytes, each entry counted as the larger of its apparent size and its allocated blocks.
    pub bytes: u64,
}

/// What one entry occupies: the larger of its apparent size and its allocated blocks (H1 §9 "Disk").
fn stat_bytes(stat: &Stat) -> u64 {
    // The widths of these fields differ between architectures: widen first, then narrow once.
    let size = u64::try_from(i128::from(stat.st_size)).unwrap_or(0);
    let blocks = u64::try_from(i128::from(stat.st_blocks)).unwrap_or(0);
    size.max(blocks.saturating_mul(512))
}

enum Stop {
    Unsafe(Unsafe),
    OverBudget,
    TooDeep,
    Io(io::Error),
}

impl From<Errno> for Stop {
    fn from(e: Errno) -> Self {
        Self::Io(e.into())
    }
}

struct Walk {
    /// Refuse what may not be mounted.
    strict: bool,
    max_entries: usize,
    entries: usize,
    bytes: u64,
    /// The names from the root to the directory being read, for messages.
    path: Vec<Vec<u8>>,
}

/// Longest path shown in a message.
const MAX_SHOWN: usize = 200;

impl Walk {
    fn shown(&self, name: &CStr) -> String {
        let mut bytes = Vec::new();
        for part in &self.path {
            bytes.extend_from_slice(part);
            bytes.push(b'/');
        }
        bytes.extend_from_slice(name.to_bytes());
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        if text.len() > MAX_SHOWN {
            let mut end = MAX_SHOWN;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push('…');
        }
        text
    }

    fn dir(&mut self, dir: BorrowedFd<'_>, depth: usize) -> Result<(), Stop> {
        for entry in Dir::read_from(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            self.entries += 1;
            if self.entries > self.max_entries {
                return Err(Stop::OverBudget);
            }
            let stat = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
            self.bytes = self.bytes.saturating_add(stat_bytes(&stat));
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    if depth >= MAX_DEPTH {
                        return Err(Stop::TooDeep);
                    }
                    let child = open_dir_at(dir, name)?;
                    // The directory that was opened is the one that was looked at.
                    let opened = rustix::fs::fstat(&child)?;
                    if (opened.st_dev, opened.st_ino) != (stat.st_dev, stat.st_ino) {
                        return Err(Stop::Io(io::Error::other("an entry changed while it was walked")));
                    }
                    self.path.push(name.to_bytes().to_vec());
                    self.dir(child.as_fd(), depth + 1)?;
                    self.path.pop();
                }
                FileType::RegularFile => {
                    if self.strict && stat.st_nlink > 1 {
                        return Err(Stop::Unsafe(Unsafe::HardLink(self.shown(name))));
                    }
                }
                FileType::Symlink => {
                    if self.strict {
                        return Err(Stop::Unsafe(Unsafe::Symlink(self.shown(name))));
                    }
                }
                _ => {
                    if self.strict {
                        return Err(Stop::Unsafe(Unsafe::Special(self.shown(name))));
                    }
                }
            }
        }
        Ok(())
    }

    fn run(strict: bool, root: BorrowedFd<'_>, max_entries: usize) -> Result<Tree, Stop> {
        let mut walk = Self {
            strict,
            max_entries,
            entries: 0,
            bytes: stat_bytes(&rustix::fs::fstat(root)?),
            path: Vec::new(),
        };
        walk.dir(root, 1)?;
        Ok(Tree {
            entries: walk.entries,
            bytes: walk.bytes,
        })
    }
}

/// The check before every mount (H2 §11.3): walks everything under `data` without following links, with at most
/// `max_entries` entries.
///
/// # Errors
/// [`Unsafe`] for the first entry that may not be mounted, for a tree over the entry budget or too deep, and for a
/// tree that cannot be read to the end (fail closed).
pub fn check_tree(data: BorrowedFd<'_>, max_entries: usize) -> Result<Tree, Unsafe> {
    Walk::run(true, data, max_entries).map_err(|stop| match stop {
        Stop::Unsafe(why) => why,
        Stop::OverBudget => Unsafe::TooManyEntries(max_entries),
        Stop::TooDeep => Unsafe::TooDeep,
        Stop::Io(e) => Unsafe::Unreadable(e.to_string()),
    })
}

/// Measures everything under `data` without following links, as H1 measures job disk: reaching the entry budget
/// (or [`MAX_DEPTH`]) is "over the limit", never "probably fine".
///
/// # Errors
/// Any error reading the tree: the caller counts it as a failed measurement (fail closed), never as zero bytes.
pub fn tree_usage(data: BorrowedFd<'_>, max_entries: usize) -> io::Result<TreeUsage> {
    match Walk::run(false, data, max_entries) {
        Ok(tree) => Ok(TreeUsage::Bytes(tree.bytes)),
        Err(Stop::OverBudget | Stop::TooDeep) => Ok(TreeUsage::OverBudget),
        Err(Stop::Io(e)) => Err(e),
        // Not reachable without `strict`; an unsafe entry is still never "zero bytes".
        Err(Stop::Unsafe(why)) => Err(io::Error::other(why.to_string())),
    }
}

/// Up to [`BATCH`] entries of `dir`, each with whether it is a directory (by `lstat`).
fn batch(dir: BorrowedFd<'_>) -> io::Result<Vec<(CString, bool)>> {
    let mut out = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let stat = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        out.push((name.to_owned(), is_dir(&stat)));
        if out.len() >= BATCH {
            break;
        }
    }
    Ok(out)
}

/// Empties `dir`. Files, links, FIFOs, sockets and devices are unlinked (which never follows anything); directories
/// are emptied first, and one that is too deep to hold another descriptor is moved up into `top`, where the caller
/// finds it.
fn clear(top: BorrowedFd<'_>, dir: BorrowedFd<'_>, depth: usize) -> io::Result<()> {
    loop {
        let entries = batch(dir)?;
        if entries.is_empty() {
            return Ok(());
        }
        for (name, is_dir) in entries {
            if !is_dir {
                rustix::fs::unlinkat(dir, &name, AtFlags::empty())?;
            } else if depth >= DELETE_DEPTH {
                let moved = format!("{MOVED_PREFIX}{:016x}", rand::random::<u64>());
                rustix::fs::renameat(dir, &name, top, moved)?;
            } else {
                let child = open_dir_at(dir, &name)?;
                clear(top, child.as_fd(), depth + 1)?;
                drop(child);
                rustix::fs::unlinkat(dir, &name, AtFlags::REMOVEDIR)?;
            }
        }
    }
}

/// Deletes the volume directory `name` under `account`, with everything in it, without following a link
/// (SI-H2-9). A missing directory is fine. `meta.json` goes last, so a deletion that is interrupted still says what
/// it was.
///
/// # Errors
/// The first error; what was deleted until then stays deleted, and the call can be repeated.
pub fn remove_volume(account: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    if !is_component(name) {
        return Err(io::Error::other("not a plain directory name"));
    }
    let volume = match open_dir_at(account, name) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        // Something took the directory's place (a symbolic link, a file): the name goes, its target is not touched.
        Err(Errno::LOOP | Errno::NOTDIR) => return Ok(rustix::fs::unlinkat(account, name, AtFlags::empty())?),
        Err(e) => return Err(e.into()),
    };
    // The directories: `data/`, and the subtrees a deep tree moved up next to it.
    loop {
        let dirs: Vec<CString> = batch(volume.as_fd())?
            .into_iter()
            .filter_map(|(name, is_dir)| is_dir.then_some(name))
            .collect();
        if dirs.is_empty() {
            break;
        }
        for dir in dirs {
            let child = open_dir_at(volume.as_fd(), &dir)?;
            clear(volume.as_fd(), child.as_fd(), 1)?;
            drop(child);
            rustix::fs::unlinkat(&volume, &dir, AtFlags::REMOVEDIR)?;
        }
    }
    // Then the files (temporary files of `meta.json`), and `meta.json` itself last.
    loop {
        let files: Vec<CString> = batch(volume.as_fd())?
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| name.to_bytes() != META_FILE.as_bytes())
            .collect();
        if files.is_empty() {
            break;
        }
        for file in files {
            rustix::fs::unlinkat(&volume, &file, AtFlags::empty())?;
        }
    }
    match rustix::fs::unlinkat(&volume, META_FILE, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => return Err(e.into()),
    }
    drop(volume);
    Ok(rustix::fs::unlinkat(account, name, AtFlags::REMOVEDIR)?)
}

/// Reads `meta.json` of the volume directory `volume`: a regular file of at most [`MAX_META_BYTES`], opened with
/// `O_NOFOLLOW`.
///
/// # Errors
/// Any I/O error, a file that is not regular, or one that is too large.
pub fn read_meta(volume: BorrowedFd<'_>) -> io::Result<Vec<u8>> {
    // `O_NONBLOCK`: a FIFO in its place must not hang the agent.
    let fd = rustix::fs::openat(
        volume,
        META_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(MAX_META_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_META_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    Ok(bytes)
}

/// Replaces `meta.json` of the volume directory `volume` atomically and durably: a temporary file (0600,
/// `O_EXCL | O_NOFOLLOW`), `fsync`, `rename`, then `fsync` of the directory (H2 §11.3 "It survives agent restarts").
///
/// # Errors
/// Any I/O error; the temporary file is removed.
pub fn write_meta(volume: BorrowedFd<'_>, bytes: &[u8]) -> io::Result<()> {
    let tmp = format!(".{META_FILE}.{:016x}.tmp", rand::random::<u64>());
    let result = (|| {
        let fd = rustix::fs::openat(
            volume,
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(META_MODE),
        )?;
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(META_MODE))?;
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)?;
        file.sync_all()?;
        rustix::fs::renameat(volume, &tmp, volume, META_FILE)?;
        rustix::fs::fsync(volume)?;
        io::Result::Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(volume, &tmp, AtFlags::empty());
    }
    result
}

/// The names of up to `max` directories in `dir` (by `lstat`; names that are not UTF-8 are skipped).
///
/// # Errors
/// Any error reading the directory.
pub fn subdirs(dir: BorrowedFd<'_>, max: usize) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let Ok(text) = name.to_str() else { continue };
        if is_dir(&rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?) {
            out.push(text.to_string());
            if out.len() >= max {
                break;
            }
        }
    }
    Ok(out)
}

/// When the directory `dir` was last modified, if it can be told.
#[must_use]
pub fn modified(dir: BorrowedFd<'_>) -> Option<time::OffsetDateTime> {
    let stat = rustix::fs::fstat(dir).ok()?;
    let seconds = i64::try_from(i128::from(stat.st_mtime)).ok()?;
    time::OffsetDateTime::from_unix_timestamp(seconds).ok()
}
