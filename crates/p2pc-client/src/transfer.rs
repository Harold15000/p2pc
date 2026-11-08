// SPDX-License-Identifier: Apache-2.0

//! The pieces behind the client's log, output and key-limit methods: the NDJSON splitter, the caller's limits and the
//! safe way to put a downloaded file on disk (spec §7 and SI-9).

use std::io;
use std::path::{Path, PathBuf};

use p2pc_proto::api::{LogLine, OutputFile, Scope};
use p2pc_proto::ids::KeyId;
use p2pc_proto::units::Units;
use p2pc_proto::validate::validate_output_path;
use serde::Deserialize;

use crate::client::MAX_RESPONSE_BYTES;
use crate::error::{Error, UnexpectedResponse};

/// The longest single log line the client buffers.
pub const MAX_LOG_LINE_BYTES: usize = 1024 * 1024;

/// What a key may do, read from `GET /v1/whoami` (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLimits {
    /// The key's public ID.
    pub key_id: KeyId,
    /// The key's scopes.
    pub scopes: Vec<Scope>,
    /// The daily cap in milli-units. `None` when the key has no cap **or** the server did not say: see
    /// [`KeyLimits::cap_reported`].
    pub daily_unit_cap: Option<Units>,
    /// Whether the answer had a `daily_unit_cap` member at all (`null` counts). A server older than the cap fields
    /// does not send it, and then the cap is unknown, which is not the same as "capped".
    pub cap_reported: bool,
    /// The image allowlist, if the key has one and the server reported it.
    pub allowed_images: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct WhoAmIHead {
    key_id: KeyId,
    scopes: Vec<Scope>,
}

impl KeyLimits {
    /// Reads the limits from the JSON of `GET /v1/whoami`. The error says what is wrong, without quoting the body.
    pub(crate) fn from_whoami(value: &serde_json::Value) -> Result<Self, String> {
        let head = WhoAmIHead::deserialize(value)
            .map_err(|_| "the whoami answer does not have the documented shape".to_string())?;
        let cap = value.get("daily_unit_cap");
        let daily_unit_cap = match cap {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => {
                Some(Units::deserialize(v).map_err(|_| "the whoami answer has an invalid daily_unit_cap".to_string())?)
            }
        };
        let allowed_images = match value.get("allowed_images") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(
                Vec::<String>::deserialize(v)
                    .map_err(|_| "the whoami answer has an invalid allowed_images".to_string())?,
            ),
        };
        Ok(Self {
            key_id: head.key_id,
            scopes: head.scopes,
            daily_unit_cap,
            cap_reported: cap.is_some(),
            allowed_images,
        })
    }
}

/// One page of a job's logs, as [`crate::Client::log_page`] returns it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogPage {
    /// The lines, in order, from the requested `since_seq`.
    pub lines: Vec<LogLine>,
    /// The byte budget cut the page short: ask again from the last `seq` plus one.
    pub more: bool,
}

/// Splits an NDJSON stream into [`LogLine`]s as the bytes arrive, and stops at a byte budget.
#[derive(Debug)]
pub(crate) struct LogSplitter {
    since_seq: u64,
    max_bytes: usize,
    buf: Vec<u8>,
    used: usize,
    read: usize,
    page: LogPage,
}

impl LogSplitter {
    pub(crate) fn new(since_seq: u64, max_bytes: usize) -> Self {
        Self {
            since_seq,
            max_bytes,
            buf: Vec::new(),
            used: 0,
            read: 0,
            page: LogPage::default(),
        }
    }

    /// Feeds a chunk. Returns `true` once the page is full and the rest of the stream is not needed.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<bool, Error> {
        self.read = self.read.saturating_add(chunk.len());
        if self.read > MAX_RESPONSE_BYTES {
            return Err(unexpected(format!(
                "the log stream is larger than {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        let mut buf = std::mem::take(&mut self.buf);
        buf.extend_from_slice(chunk);
        let mut start = 0;
        while let Some(offset) = buf[start..].iter().position(|b| *b == b'\n') {
            let end = start + offset;
            if self.line(&buf[start..end])? {
                return Ok(true);
            }
            start = end + 1;
        }
        buf.drain(..start);
        if buf.len() > MAX_LOG_LINE_BYTES {
            return Err(unexpected(format!(
                "a log line is longer than {MAX_LOG_LINE_BYTES} bytes"
            )));
        }
        self.buf = buf;
        Ok(false)
    }

    /// The stream ended: a last line without a newline still counts.
    pub(crate) fn end_of_stream(&mut self) -> Result<(), Error> {
        let rest = std::mem::take(&mut self.buf);
        if !rest.is_empty() {
            self.line(&rest)?;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> LogPage {
        self.page
    }

    /// Takes one line (no `\n`). Returns `true` when the budget says to stop before it.
    fn line(&mut self, raw: &[u8]) -> Result<bool, Error> {
        let text = raw.strip_suffix(b"\r").unwrap_or(raw);
        if text.iter().all(u8::is_ascii_whitespace) {
            return Ok(false);
        }
        let line: LogLine = serde_json::from_slice(text).map_err(|e| {
            // The text is job output: say where it went wrong, never what it said.
            unexpected(format!(
                "a log line is not a log record (line {}, column {})",
                e.line(),
                e.column()
            ))
        })?;
        if line.seq < self.since_seq {
            return Ok(false);
        }
        let cost = raw.len() + 1;
        if !self.page.lines.is_empty() && self.used.saturating_add(cost) > self.max_bytes {
            self.page.more = true;
            return Ok(true);
        }
        self.used = self.used.saturating_add(cost);
        self.page.lines.push(line);
        Ok(false)
    }
}

fn unexpected(message: String) -> Error {
    Error::Unexpected(UnexpectedResponse::new(Some(200), message))
}

/// Why an output could not be downloaded or saved.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    /// The request failed: no answer, or an API error (for example `404 output_not_found`).
    #[error(transparent)]
    Request(#[from] Error),
    /// The output's path would leave the results directory, or something on the way is not a plain directory
    /// (SI-9). The path is not repeated here: it came from the job.
    #[error("refusing the output path: {0}")]
    UnsafePath(String),
    /// The file does not have the size the job listed.
    #[error("the output does not have the {expected} bytes the job listed")]
    SizeMismatch {
        /// The listed size.
        expected: u64,
    },
    /// The file's SHA-256 is not the listed one.
    #[error("the SHA-256 of the output {path} does not match the one the job listed")]
    DigestMismatch {
        /// The output's path (already checked to be a plain relative path).
        path: String,
    },
    /// A file is already there and the caller asked not to replace it.
    #[error("{path} already exists")]
    Exists {
        /// The output's path (already checked to be a plain relative path).
        path: String,
    },
    /// Reading or writing the local file failed.
    #[error("{0}")]
    Io(String),
}

/// The SI-9 check on an output path from the server: relative, no `..`, no `.`, no empty segment, no control
/// character or backslash, and on Windows no `:` (a drive or a stream name).
pub(crate) fn validate_remote_path(path: &str) -> Result<(), DownloadError> {
    validate_output_path(path).map_err(|e| DownloadError::UnsafePath(e.to_string()))?;
    if cfg!(windows) && path.contains(':') {
        return Err(DownloadError::UnsafePath("the path contains a colon".into()));
    }
    Ok(())
}

fn io_error(what: &str, e: &io::Error) -> DownloadError {
    DownloadError::Io(format!("{what}: {e}"))
}

/// Where `rel` goes under `root`, with the directories in place. Refuses a path that fails
/// [`validate_remote_path`], a directory of the path that is a symbolic link or a file, and a directory where the
/// file should go. `root` itself may be a link (it is the user's choice).
pub(crate) async fn prepare_destination(root: &Path, rel: &str) -> Result<PathBuf, DownloadError> {
    validate_remote_path(rel)?;
    tokio::fs::create_dir_all(root)
        .await
        .map_err(|e| io_error("could not create the results directory", &e))?;
    let segments: Vec<&str> = rel.split('/').collect();
    let (name, directories) = segments
        .split_last()
        .ok_or_else(|| DownloadError::UnsafePath("empty path".into()))?;
    let mut current = root.to_path_buf();
    for segment in directories {
        current.push(segment);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(meta) if meta.is_symlink() => {
                return Err(DownloadError::UnsafePath(
                    "a directory of the path is a symbolic link".into(),
                ));
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(DownloadError::UnsafePath(
                    "a directory of the path is already a file".into(),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // `create_dir`, not `create_dir_all`: one level at a time, so that no level is skipped unchecked.
                if let Err(e) = tokio::fs::create_dir(&current).await
                    && e.kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(io_error("could not create a directory", &e));
                }
            }
            Err(e) => return Err(io_error("could not inspect the results directory", &e)),
        }
    }
    current.push(name);
    if tokio::fs::symlink_metadata(&current)
        .await
        .is_ok_and(|meta| meta.is_dir())
    {
        return Err(DownloadError::UnsafePath(
            "a directory is where the file should go".into(),
        ));
    }
    Ok(current)
}

/// Removes a temporary download file when dropped, unless [`PartFile::disarm`] was called once it was renamed into
/// place. The removal is a single synchronous `unlink`, so it also runs when the download's future is dropped.
pub(crate) struct PartFile {
    path: Option<PathBuf>,
}

impl PartFile {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub(crate) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Saves the content of an output that is already in memory to `root/<file.path>`, as
/// [`crate::Client::save_output`] would after downloading it: the size and SHA-256 are checked against `file`, the path
/// follows SI-9, and the bytes go to a temporary file that replaces the destination only once complete.
pub async fn save_verified_output(root: &Path, file: &OutputFile, bytes: &[u8]) -> Result<PathBuf, DownloadError> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    if bytes.len() as u64 != file.size {
        return Err(DownloadError::SizeMismatch { expected: file.size });
    }
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if digest != file.sha256.0 {
        return Err(DownloadError::DigestMismatch {
            path: file.path.clone(),
        });
    }
    let destination = prepare_destination(root, &file.path).await?;
    let temp = destination.with_file_name(format!(".p2pc-part-{}", ulid::Ulid::generate()));
    let mut guard = PartFile::new(temp.clone());
    let mut out = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .await
        .map_err(|e| io_error("could not create a file in the results directory", &e))?;
    out.write_all(bytes)
        .await
        .map_err(|e| io_error("could not write the output", &e))?;
    out.flush()
        .await
        .map_err(|e| io_error("could not write the output", &e))?;
    drop(out);
    replace_file(&temp, &destination).await?;
    guard.disarm();
    Ok(destination)
}

/// Puts the verified temporary file at `destination` only if nothing is there, not even a symbolic link: the link is
/// created by the system call that refuses an existing name, so a file created meanwhile is never replaced. The caller
/// removes the temporary file afterwards. A file system without hard links gets a copy, created the same way.
pub(crate) async fn place_new_file(temp: &Path, destination: &Path, rel: &str) -> Result<(), DownloadError> {
    let exists = || DownloadError::Exists { path: rel.to_string() };
    match tokio::fs::hard_link(temp, destination).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(exists()),
        Err(_) => {
            let mut dest = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .await
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        exists()
                    } else {
                        io_error("could not create the file", &e)
                    }
                })?;
            let mut source = tokio::fs::File::open(temp)
                .await
                .map_err(|e| io_error("could not read the downloaded file", &e))?;
            if let Err(e) = tokio::io::copy(&mut source, &mut dest).await {
                drop(dest);
                let _ = tokio::fs::remove_file(destination).await;
                return Err(io_error("could not write the file", &e));
            }
            Ok(())
        }
    }
}

/// Moves the verified temporary file over the destination. On Unix `rename` replaces a file or a symbolic link
/// atomically; Windows needs the old file gone first.
pub(crate) async fn replace_file(temp: &Path, destination: &Path) -> Result<(), DownloadError> {
    if cfg!(windows) {
        let _ = tokio::fs::remove_file(destination).await;
    }
    if let Err(e) = tokio::fs::rename(temp, destination).await {
        let _ = tokio::fs::remove_file(temp).await;
        return Err(io_error("could not move the downloaded file into place", &e));
    }
    Ok(())
}
