// SPDX-License-Identifier: AGPL-3.0-only

//! Filesystem helpers for the data dir's `logs/` and `artifacts/` trees (spec §12, SI-9).
//!
//! Every path below a trusted base (the data dir) is walked one segment at a time with `openat(O_NOFOLLOW)`, so a
//! symbolic link planted anywhere in the store is never followed: opening through it fails (`ELOOP` or `ENOTDIR`).
//! Files are opened with `O_NONBLOCK`, so a FIFO planted in the store cannot block a thread in `open`; anything but a
//! regular file is then refused, and the flag is cleared on the descriptor before it is used. Directories are created
//! `0700` and files `0600`. Everything here is blocking: call it from `spawn_blocking`.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};

/// Mode of every directory the store creates.
pub const DIR_MODE: u32 = 0o700;
/// Mode of every file the store creates.
pub const FILE_MODE: u32 = 0o600;

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Opens `base` (followed: it is the operator's data dir), then each of `segments` below it without following a
/// link. With `create`, missing directories are created with mode `0700`.
pub fn open_dir<'a>(base: &Path, segments: impl IntoIterator<Item = &'a str>, create: bool) -> io::Result<OwnedFd> {
    let mut dir = rustix::fs::open(
        base,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for seg in segments {
        dir = open_child_dir(&dir, seg, create)?;
    }
    Ok(dir)
}

/// Opens the directory `name` in `dir` without following a link, creating it (`0700`) if asked.
pub fn open_child_dir(dir: &OwnedFd, name: &str, create: bool) -> io::Result<OwnedFd> {
    check_segment(name)?;
    match rustix::fs::openat(dir, name, dir_flags(), Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(rustix::io::Errno::NOENT) if create => {
            match rustix::fs::mkdirat(dir, name, Mode::from_raw_mode(DIR_MODE)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
            Ok(rustix::fs::openat(dir, name, dir_flags(), Mode::empty())?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Opens `name` in `dir` with `flags`, without following a link and without blocking on a FIFO, and keeps it only
/// if it is a regular file.
fn open_file(dir: &OwnedFd, name: &str, flags: OFlags) -> io::Result<File> {
    check_segment(name)?;
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = rustix::fs::openat(dir, name, flags, Mode::from_raw_mode(FILE_MODE))?;
    let file = regular(fd)?;
    // A regular file: blocking I/O from here on, as every caller expects.
    let flags = rustix::fs::fcntl_getfl(&file)?;
    rustix::fs::fcntl_setfl(&file, flags - OFlags::NONBLOCK)?;
    Ok(file)
}

/// Opens (or creates, `0600`) `name` in `dir` for appending, without following a link.
pub fn open_append(dir: &OwnedFd, name: &str) -> io::Result<File> {
    open_file(dir, name, OFlags::RDWR | OFlags::APPEND | OFlags::CREATE)
}

/// Creates (or truncates) `name` in `dir` for writing, `0600`, without following a link.
pub fn create_truncate(dir: &OwnedFd, name: &str) -> io::Result<File> {
    open_file(dir, name, OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC)
}

/// Creates `name` in `dir` for writing, `0600`; fails with `AlreadyExists` if anything has that name.
pub fn create_new(dir: &OwnedFd, name: &str) -> io::Result<File> {
    open_file(dir, name, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)
}

/// Opens the regular file `name` in `dir` for reading, without following a link.
pub fn open_read(dir: &OwnedFd, name: &str) -> io::Result<File> {
    open_file(dir, name, OFlags::RDONLY)
}

/// Removes the file `name` from `dir` (a link is removed, never followed). A missing file is not an error.
pub fn unlink(dir: &OwnedFd, name: &str) -> io::Result<()> {
    check_segment(name)?;
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Removes the directory `name` of `dir` if it is empty. A missing one, or one that still holds something, is left as it
/// is and is not an error (whoever put something in it removes its own, and then tries this again).
pub fn remove_dir_if_empty(dir: &OwnedFd, name: &str) -> io::Result<()> {
    check_segment(name)?;
    match rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR) {
        Ok(()) | Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTEMPTY) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Flushes a directory's entries (renames, creations, removals in it) to disk.
pub fn fsync(dir: &OwnedFd) -> io::Result<()> {
    Ok(rustix::fs::fsync(dir)?)
}

/// Renames `from_name` in `from` to `to_name` in `to` (both names are single segments; no link is followed).
pub fn rename(from: &OwnedFd, from_name: &str, to: &OwnedFd, to_name: &str) -> io::Result<()> {
    check_segment(from_name)?;
    check_segment(to_name)?;
    Ok(rustix::fs::renameat(from, from_name, to, to_name)?)
}

/// Renames `from_name` in `from` to `to_name` in `to`, failing with `AlreadyExists` if `to_name` exists
/// (`renameat2(RENAME_NOREPLACE)`): nothing that is already there is ever replaced.
pub fn rename_noreplace(from: &OwnedFd, from_name: &str, to: &OwnedFd, to_name: &str) -> io::Result<()> {
    check_segment(from_name)?;
    check_segment(to_name)?;
    Ok(rustix::fs::renameat_with(
        from,
        from_name,
        to,
        to_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

/// How deep [`remove_tree`] descends. The store's own trees are a handful of levels (an output path has at most
/// 16 segments); a tree deeper than this was not made by the server.
const MAX_REMOVE_DEPTH: usize = 64;

/// Removes the last of `segments` below `base`, and everything under it, without ever resolving a link.
///
/// `base` is followed (it is the operator's data dir); the parent of the last segment is reached segment by segment
/// with `openat(O_NOFOLLOW)` ([`open_dir`]), so a link planted in the middle of the path is an error, not a way out of
/// the store. The last segment is then removed relative to that descriptor (`unlinkat`), recursively and also by
/// descriptor: a link in it, the last segment included, is removed itself, never followed. A missing path is not an
/// error. Returns whether something was removed.
pub fn remove_tree(base: &Path, segments: &[&str]) -> io::Result<bool> {
    let Some((name, parents)) = segments.split_last() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no path to remove"));
    };
    check_segment(name)?;
    let parent = match open_dir(base, parents.iter().copied(), false) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let name = CString::new(*name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path segment"))?;
    remove_entry(&parent, &name, 0)
}

/// Removes the entry `name` of `parent`: a directory with all it holds, anything else (a link included) itself.
fn remove_entry(parent: &OwnedFd, name: &CStr, depth: usize) -> io::Result<bool> {
    let stat = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        return match rustix::fs::unlinkat(parent, name, AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(e.into()),
        };
    }
    if depth >= MAX_REMOVE_DEPTH {
        return Err(io::Error::other(
            "a tree to remove is deeper than the store ever makes it",
        ));
    }
    // `O_NOFOLLOW`: a directory replaced by a link since the `stat` is refused, not followed.
    let dir = rustix::fs::openat(parent, name, dir_flags(), Mode::empty())?;
    for child in list_names(&dir)? {
        remove_entry(&dir, &child, depth + 1)?;
    }
    drop(dir);
    match rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The names in `dir`, without `.` and `..`.
fn list_names(dir: &OwnedFd) -> io::Result<Vec<CString>> {
    let mut names = Vec::new();
    let mut entries = rustix::fs::Dir::read_from(dir)?;
    while let Some(entry) = entries.read() {
        let name = entry?.file_name().to_owned();
        if name.as_bytes() != b"." && name.as_bytes() != b".." {
            names.push(name);
        }
    }
    Ok(names)
}

/// Only regular files: a FIFO or a device in the store is refused.
fn regular(fd: OwnedFd) -> io::Result<File> {
    let stat = rustix::fs::fstat(&fd)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(File::from(fd))
}

/// One path segment: not empty, `.` or `..`, no `/` and no NUL. Callers validate paths first (SI-9); this is the
/// last line.
fn check_segment(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid path segment"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    #[test]
    fn directories_and_files_are_private_and_links_are_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = open_dir(tmp.path(), ["a", "b"], true).unwrap();
        let mut f = open_append(&dir, "x.ndjson").unwrap();
        f.write_all(b"hi\n").unwrap();
        let meta = std::fs::metadata(tmp.path().join("a/b")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, DIR_MODE);
        let meta = std::fs::metadata(tmp.path().join("a/b/x.ndjson")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, FILE_MODE);
        let mut s = String::new();
        open_read(&dir, "x.ndjson").unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hi\n");

        // A link to a file outside, and a link to a directory outside: neither is followed.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"no").unwrap();
        symlink(outside.path().join("secret"), tmp.path().join("a/b/link")).unwrap();
        symlink(outside.path(), tmp.path().join("a/dirlink")).unwrap();
        assert!(open_read(&dir, "link").is_err());
        assert!(open_append(&dir, "link").is_err());
        assert!(create_truncate(&dir, "link").is_err());
        assert!(open_dir(tmp.path(), ["a", "dirlink"], false).is_err());
        assert!(open_dir(tmp.path(), ["a", "dirlink"], true).is_err());
        assert_eq!(std::fs::read(outside.path().join("secret")).unwrap(), b"no");
        for bad in ["", ".", "..", "a/b", "nul\0"] {
            assert!(open_read(&dir, bad).is_err(), "{bad:?}");
        }
    }

    /// Review P3: a FIFO planted in the store is refused at once, never waited on (with no writer, a blocking
    /// `open` for reading would hang a thread forever).
    #[test]
    fn a_fifo_in_the_store_is_refused_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = open_dir(tmp.path(), ["d"], true).unwrap();
        rustix::fs::mknodat(&dir, "fifo", rustix::fs::FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        let base = tmp.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let dir = open_dir(&base, ["d"], false).unwrap();
            let read = open_read(&dir, "fifo").map(|_| ()).map_err(|e| e.kind());
            let append = open_append(&dir, "fifo").map(|_| ()).map_err(|e| e.kind());
            let _ = tx.send((read, append));
        });
        let (read, append) = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("opening a FIFO blocked");
        assert_eq!(read, Err(io::ErrorKind::InvalidInput));
        assert!(append.is_err());
        // A regular file opened the same way is in blocking mode.
        let f = create_truncate(&dir, "plain").unwrap();
        assert!(!rustix::fs::fcntl_getfl(&f).unwrap().contains(OFlags::NONBLOCK));
    }

    #[test]
    fn create_new_and_rename_noreplace_never_replace_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let d = open_dir(tmp.path(), ["d"], true).unwrap();
        create_new(&d, "a").unwrap().write_all(b"first").unwrap();
        assert_eq!(create_new(&d, "a").unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        create_new(&d, "b").unwrap().write_all(b"second").unwrap();
        assert_eq!(
            rename_noreplace(&d, "b", &d, "a").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(tmp.path().join("d/a")).unwrap(), b"first");
        rename_noreplace(&d, "b", &d, "c").unwrap();
        assert_eq!(std::fs::read(tmp.path().join("d/c")).unwrap(), b"second");
    }

    #[test]
    fn remove_tree_removes_links_without_following_them() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), b"keep").unwrap();
        std::fs::create_dir_all(tmp.path().join("t/sub")).unwrap();
        std::fs::write(tmp.path().join("t/sub/file"), b"x").unwrap();
        symlink(outside.path(), tmp.path().join("t/sub/link")).unwrap();
        assert!(remove_tree(tmp.path(), &["t"]).unwrap());
        assert!(!tmp.path().join("t").exists());
        assert!(outside.path().join("keep").exists());
        assert!(!remove_tree(tmp.path(), &["t"]).unwrap());
        // A link as the last segment is removed itself.
        symlink(outside.path(), tmp.path().join("r")).unwrap();
        assert!(remove_tree(tmp.path(), &["r"]).unwrap());
        assert!(outside.path().join("keep").exists());
    }

    /// T10d item 2: a link in the middle of the path is never resolved. The old `remove_tree` took a whole path and
    /// `remove_dir_all` resolved the links in front of the last segment.
    #[test]
    fn remove_tree_never_resolves_a_link_in_the_middle_of_the_path() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("1/.staging")).unwrap();
        std::fs::write(outside.path().join("1/.staging/keep"), b"keep").unwrap();
        std::fs::create_dir(tmp.path().join("artifacts")).unwrap();
        symlink(outside.path(), tmp.path().join("artifacts/job")).unwrap();
        let err = remove_tree(tmp.path(), &["artifacts", "job", "1", ".staging"]).unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::NotFound, "{err}");
        assert_eq!(std::fs::read(outside.path().join("1/.staging/keep")).unwrap(), b"keep");
        // Nothing there at all is not an error; a missing base neither.
        assert!(!remove_tree(tmp.path(), &["artifacts", "nope", "1"]).unwrap());
        assert!(!remove_tree(&tmp.path().join("missing"), &["a", "b"]).unwrap());
        // The link itself, as the last segment, is removed without touching what it points at.
        assert!(remove_tree(tmp.path(), &["artifacts", "job"]).unwrap());
        assert!(outside.path().join("1/.staging/keep").exists());
        // Bad segments are refused.
        for bad in [&[][..], &[".."][..], &["a", ""][..], &["a/b"][..]] {
            assert!(remove_tree(tmp.path(), bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn remove_tree_removes_nested_trees_with_mixed_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let d = open_dir(tmp.path(), ["t", "a", "b"], true).unwrap();
        create_truncate(&d, "f").unwrap().write_all(b"1").unwrap();
        rustix::fs::mknodat(&d, "fifo", rustix::fs::FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        std::fs::create_dir_all(tmp.path().join("t/empty")).unwrap();
        assert!(remove_tree(tmp.path(), &["t"]).unwrap());
        assert!(!tmp.path().join("t").exists());
    }

    #[test]
    fn remove_dir_if_empty_removes_only_an_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let d = open_dir(tmp.path(), ["d"], true).unwrap();
        open_child_dir(&d, "full", true).unwrap();
        open_child_dir(&d, "empty", true).unwrap();
        create_new(&open_child_dir(&d, "full", false).unwrap(), "f").unwrap();
        remove_dir_if_empty(&d, "empty").unwrap();
        remove_dir_if_empty(&d, "full").unwrap();
        remove_dir_if_empty(&d, "never-there").unwrap();
        assert!(!tmp.path().join("d/empty").exists());
        assert!(tmp.path().join("d/full/f").exists());
    }

    #[test]
    fn rename_and_unlink_stay_in_their_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let a = open_dir(tmp.path(), ["a"], true).unwrap();
        let b = open_dir(tmp.path(), ["b"], true).unwrap();
        create_truncate(&a, "f").unwrap().write_all(b"1").unwrap();
        rename(&a, "f", &b, "g").unwrap();
        assert_eq!(std::fs::read(tmp.path().join("b/g")).unwrap(), b"1");
        unlink(&b, "g").unwrap();
        unlink(&b, "g").unwrap();
        assert!(!tmp.path().join("b/g").exists());
    }
}
