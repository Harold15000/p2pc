// SPDX-License-Identifier: Apache-2.0

//! The node image: its download and its SHA-256 verification before import (H2 §8.3).
//!
//! - **Pinned.** The app build compiles in the URL and the SHA-256 of the image version it matches ([`ImagePin`]).
//! - **Resumable.** The download goes to `<dest>.part`; a later call asks the server for the rest with an HTTP `Range`
//!   request and appends (`206`), or starts over when the server ignores the range (`200`).
//! - **Verified before import.** The whole file is hashed after the download; only a match is renamed into place, and
//!   only [`verify_image`] (or a download, which ends with it) hands out the [`VerifiedImage`] that
//!   [`crate::import`] requires. A mismatch deletes the file and is reported as such: it is never retried silently
//!   (§8.8 `image_hash_mismatch`).
//! - **Bounded.** A server cannot fill the disk: the pin carries a size cap, checked against the announced length and
//!   while writing.
//!
//! The developer path of `install.ps1` (a local tar and its `<tar>.sha256` file, `Test-Image`) is
//! [`verify_with_checksum_file`].

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// The default size cap of a downloaded image: 4 GiB (the H1 image is about 430 MB).
pub const DEFAULT_MAX_IMAGE_BYTES: u64 = 4 << 30;

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// From 64 hex digits, either case.
    pub fn from_hex(hex: &str) -> Result<Self, ImageError> {
        let hex = hex.trim();
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ImageError::BadDigest);
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| ImageError::BadDigest)?;
        }
        Ok(Self(out))
    }

    /// From the text of a `.sha256` file: its first line must start with 64 hex digits, then a word boundary
    /// (`Test-Image`'s `^\s*([0-9a-fA-F]{64})\b`), as `sha256sum` and `build-rootfs.sh` write it.
    pub fn from_checksum_file(text: &str) -> Result<Self, ImageError> {
        let first = text
            .trim_start_matches('\u{FEFF}')
            .lines()
            .next()
            .unwrap_or_default()
            .trim_start();
        let hex = first.get(..64).ok_or(ImageError::BadChecksumFile)?;
        let boundary_ok = first[64..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        if !boundary_ok {
            return Err(ImageError::BadChecksumFile);
        }
        Self::from_hex(hex).map_err(|_| ImageError::BadChecksumFile)
    }

    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({})", self.to_hex())
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The image the app build is pinned to: where it is published, its SHA-256 and a size cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePin {
    url: String,
    sha256: Sha256Digest,
    max_bytes: u64,
}

impl ImagePin {
    /// A pin. The URL must be `https://`; the cap is [`DEFAULT_MAX_IMAGE_BYTES`].
    pub fn new(url: impl Into<String>, sha256_hex: &str) -> Result<Self, ImageError> {
        let url = url.into();
        let https = url.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://"));
        if !https || url.len() <= 8 || url.chars().any(char::is_whitespace) {
            return Err(ImageError::BadUrl);
        }
        Ok(Self {
            url,
            sha256: Sha256Digest::from_hex(sha256_hex)?,
            max_bytes: DEFAULT_MAX_IMAGE_BYTES,
        })
    }

    /// The same pin with another size cap.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

/// An image file whose SHA-256 was checked against the expected one. Only this module makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedImage {
    path: PathBuf,
    sha256: Sha256Digest,
}

impl VerifiedImage {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    #[cfg(test)]
    pub(crate) fn for_tests(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            sha256: Sha256Digest([0; 32]),
        }
    }
}

/// What can go wrong with the image.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("not a SHA-256 (64 hex digits)")]
    BadDigest,
    #[error("the image URL must be an https:// URL")]
    BadUrl,
    /// `install.ps1` exit 17.
    #[error("image not found: {0}")]
    ImageMissing(PathBuf),
    /// `install.ps1` exit 17.
    #[error("checksum file not found: {0}")]
    ChecksumFileMissing(PathBuf),
    /// `install.ps1` exit 17.
    #[error("the checksum file does not start with a SHA-256 (64 hex digits)")]
    BadChecksumFile,
    /// `install.ps1` exit 18; §8.8 `image_hash_mismatch`. The file was deleted (except a developer's own tar).
    #[error("SHA-256 mismatch: expected {expected}, computed {actual}; the image is corrupt or not the pinned one")]
    HashMismatch {
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    /// §8.8 `image_download_failed`. What was downloaded is kept for the next try.
    #[error("the image download failed: {0}")]
    Download(String),
    /// The server announced or sent more than the cap. The partial file was deleted.
    #[error("the image is larger than the {max_bytes}-byte cap")]
    TooLarge { max_bytes: u64 },
    /// The caller stopped it. What was downloaded is kept for the next try.
    #[error("the image download was cancelled")]
    Cancelled,
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

impl ImageError {
    /// The H2 §8.8 code.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            ImageError::HashMismatch { .. } => Some("image_hash_mismatch"),
            ImageError::Download(_) | ImageError::TooLarge { .. } | ImageError::Cancelled | ImageError::Io { .. } => {
                Some("image_download_failed")
            }
            ImageError::ImageMissing(_) | ImageError::ChecksumFileMissing(_) | ImageError::BadChecksumFile => {
                Some("image_download_failed")
            }
            ImageError::BadDigest | ImageError::BadUrl => None,
        }
    }
}

fn io_err(context: impl Into<String>) -> impl FnOnce(io::Error) -> ImageError {
    let context = context.into();
    move |source| ImageError::Io { context, source }
}

/// The SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> io::Result<Sha256Digest> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Sha256Digest(hasher.finalize().into()))
}

/// Checks a file against the expected SHA-256 (`Get-FileHash` and the comparison of `Test-Image`). It never deletes.
pub fn verify_image(path: &Path, expected: Sha256Digest) -> Result<VerifiedImage, ImageError> {
    if !path.is_file() {
        return Err(ImageError::ImageMissing(path.to_owned()));
    }
    let actual = sha256_file(path).map_err(io_err(format!("reading {}", path.display())))?;
    if actual != expected {
        return Err(ImageError::HashMismatch { expected, actual });
    }
    tracing::info!(sha256 = %actual, "image SHA-256 verified");
    Ok(VerifiedImage {
        path: path.to_owned(),
        sha256: actual,
    })
}

/// `install.ps1`'s `Test-Image`: a local tar and its checksum file (`<tar>.sha256` unless another is given).
pub fn verify_with_checksum_file(tar: &Path, checksum_file: Option<&Path>) -> Result<VerifiedImage, ImageError> {
    if !tar.is_file() {
        return Err(ImageError::ImageMissing(tar.to_owned()));
    }
    let sha_path = match checksum_file {
        Some(p) => p.to_owned(),
        None => {
            let mut s = tar.as_os_str().to_owned();
            s.push(".sha256");
            PathBuf::from(s)
        }
    };
    if !sha_path.is_file() {
        return Err(ImageError::ChecksumFileMissing(sha_path));
    }
    let text = fs::read_to_string(&sha_path).map_err(|_| ImageError::BadChecksumFile)?;
    verify_image(tar, Sha256Digest::from_checksum_file(&text)?)
}

/// `Content-Range: bytes <start>-<end>/<total or *>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
}

impl ContentRange {
    /// Parses a `206` response's header (`bytes */N`, the form of a `416`, is not a range: `None`).
    pub fn parse(header: &str) -> Option<Self> {
        let rest = header.trim().strip_prefix("bytes ")?;
        let (range, total) = rest.split_once('/')?;
        let (start, end) = range.split_once('-')?;
        let (start, end): (u64, u64) = (start.trim().parse().ok()?, end.trim().parse().ok()?);
        if end < start {
            return None;
        }
        let total = match total.trim() {
            "*" => None,
            t => Some(t.parse().ok()?),
        };
        Some(Self { start, end, total })
    }
}

/// One answer to a ranged GET.
pub struct FetchResponse {
    /// The HTTP status.
    pub status: u16,
    /// The `Content-Range` header, parsed.
    pub content_range: Option<ContentRange>,
    /// The `Content-Length` header.
    pub content_length: Option<u64>,
    /// The body.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for FetchResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchResponse")
            .field("status", &self.status)
            .field("content_range", &self.content_range)
            .field("content_length", &self.content_length)
            .finish_non_exhaustive()
    }
}

/// A GET from a byte offset (`Range: bytes=<offset>-` when the offset is not 0). Faked in tests.
pub trait RangeFetch {
    fn fetch(&self, url: &str, offset: u64) -> Result<FetchResponse, String>;
}

/// Progress of a download: bytes on disk, and the total when the server said it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub done: u64,
    pub total: Option<u64>,
}

/// `<dest>.part`.
pub fn part_path(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

/// Deletes a file, best effort, and returns `err`.
fn discard(path: &Path, err: ImageError) -> ImageError {
    if let Err(e) = fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %e, "could not delete a rejected image file");
    }
    err
}

/// Downloads the pinned image to `dest` and verifies it.
///
/// - A `dest` that already verifies is kept (setup is resumable, §8.2); one that does not is deleted and reported as a
///   mismatch, never re-downloaded silently.
/// - Otherwise the download resumes from `<dest>.part`. A network error or a cancel (`progress` returning
///   `Break`) keeps the part for the next call; a mismatch or an oversized answer deletes it.
pub fn download_image(
    fetch: &dyn RangeFetch,
    pin: &ImagePin,
    dest: &Path,
    progress: &mut dyn FnMut(Progress) -> ControlFlow<()>,
) -> Result<VerifiedImage, ImageError> {
    if dest.exists() {
        return verify_image(dest, pin.sha256).map_err(|e| match e {
            ImageError::HashMismatch { .. } => discard(dest, e),
            e => e,
        });
    }
    if let Some(dir) = dest.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(io_err(format!("creating {}", dir.display())))?;
    }
    let part = part_path(dest);
    let mut offset = match fs::metadata(&part) {
        Ok(m) if m.is_file() => m.len(),
        _ => 0,
    };
    if offset > pin.max_bytes {
        let _ = fs::remove_file(&part);
        offset = 0;
    }
    let resp = fetch.fetch(&pin.url, offset).map_err(ImageError::Download)?;
    let (start, total) = match resp.status {
        206 => {
            let range = resp.content_range.filter(|r| r.start == offset).ok_or_else(|| {
                discard(
                    &part,
                    ImageError::Download("the server answered a different range than the one asked for".into()),
                )
            })?;
            (offset, range.total)
        }
        200 => (0, resp.content_length),
        // The part already holds everything there is: verify it as it is.
        416 if offset > 0 => {
            // Nothing is left to download, so a cancel has nothing to stop.
            let _ = progress(Progress {
                done: offset,
                total: Some(offset),
            });
            return finish(&part, dest, pin);
        }
        status => {
            return Err(ImageError::Download(format!("the server answered HTTP {status}")));
        }
    };
    if total.is_some_and(|t| t > pin.max_bytes) {
        return Err(discard(
            &part,
            ImageError::TooLarge {
                max_bytes: pin.max_bytes,
            },
        ));
    }
    let mut file = if start == 0 {
        File::create(&part)
    } else {
        OpenOptions::new().append(true).open(&part)
    }
    .map_err(io_err(format!("opening {}", part.display())))?;
    let mut done = start;
    let mut body = resp.body;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = match body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = file.sync_all();
                return Err(ImageError::Download(format!(
                    "the connection broke after {done} bytes ({e}); the next try resumes there"
                )));
            }
        };
        if done + n as u64 > pin.max_bytes {
            drop(file);
            return Err(discard(
                &part,
                ImageError::TooLarge {
                    max_bytes: pin.max_bytes,
                },
            ));
        }
        file.write_all(&buf[..n])
            .map_err(io_err(format!("writing {}", part.display())))?;
        done += n as u64;
        if progress(Progress { done, total }).is_break() {
            let _ = file.sync_all();
            return Err(ImageError::Cancelled);
        }
    }
    file.sync_all().map_err(io_err(format!("writing {}", part.display())))?;
    drop(file);
    if let Some(t) = total
        && done != t
    {
        return Err(ImageError::Download(format!(
            "the download stopped at {done} of {t} bytes; the next try resumes there"
        )));
    }
    finish(&part, dest, pin)
}

/// Verifies the finished part and renames it into place; a mismatch deletes it.
fn finish(part: &Path, dest: &Path, pin: &ImagePin) -> Result<VerifiedImage, ImageError> {
    match verify_image(part, pin.sha256) {
        Ok(_) => {}
        Err(e @ ImageError::HashMismatch { .. }) => return Err(discard(part, e)),
        Err(e) => return Err(e),
    }
    fs::rename(part, dest).map_err(io_err(format!("renaming {}", part.display())))?;
    Ok(VerifiedImage {
        path: dest.to_owned(),
        sha256: pin.sha256,
    })
}

/// The real [`RangeFetch`]: reqwest's blocking client over rustls (`ring`, the OS certificate store), HTTPS only (a
/// redirect to plain HTTP is refused too), redirects followed (release assets live behind one), a 30 s connect
/// timeout and a 60 s timeout on the response and on every read of the body.
///
/// Blocking: never call it from inside an async task (use `spawn_blocking`).
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    client: reqwest::blocking::Client,
}

/// The connect timeout of [`HttpFetcher`].
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// The response and per-read timeout of [`HttpFetcher`].
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);

impl HttpFetcher {
    /// An HTTPS-only fetcher.
    pub fn new() -> Result<Self, ImageError> {
        Self::build(true)
    }

    fn build(https_only: bool) -> Result<Self, ImageError> {
        use rustls_platform_verifier::BuilderVerifierExt;
        let tls_err = |e: &dyn fmt::Display| ImageError::Download(format!("TLS setup failed: {e}"));
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| tls_err(&e))?
            .with_platform_verifier()
            .map_err(|e| tls_err(&e))?
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let client = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(https_only)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(READ_TIMEOUT)
            .user_agent(concat!("p2pc-desktop/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ImageError::Download(format!("HTTP client setup failed: {e}")))?;
        Ok(Self { client })
    }

    #[cfg(test)]
    fn plain_http_for_tests() -> Self {
        match Self::build(false) {
            Ok(f) => f,
            Err(e) => panic!("{e}"),
        }
    }
}

impl RangeFetch for HttpFetcher {
    fn fetch(&self, url: &str, offset: u64) -> Result<FetchResponse, String> {
        let mut req = self.client.get(url);
        if offset > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={offset}-"));
        }
        let resp = req.send().map_err(|e| e.to_string())?;
        let header = |name| {
            resp.headers()
                .get(name)
                .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
                .map(str::to_owned)
        };
        let content_range = header(reqwest::header::CONTENT_RANGE)
            .as_deref()
            .and_then(ContentRange::parse);
        let content_length = header(reqwest::header::CONTENT_LENGTH).and_then(|v| v.parse().ok());
        Ok(FetchResponse {
            status: resp.status().as_u16(),
            content_range,
            content_length,
            body: Box::new(resp),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Cursor;

    use super::*;

    fn digest(data: &[u8]) -> Sha256Digest {
        Sha256Digest(Sha256::digest(data).into())
    }

    fn pin_for(data: &[u8]) -> ImagePin {
        ImagePin::new("https://example.invalid/p2pc-node-0.3.0.tar.gz", &digest(data).to_hex()).unwrap()
    }

    /// Serves `data` with range support; `cut` stops a body after that many bytes with an error (a broken
    /// connection); `ignore_range` answers 200 with everything.
    struct FakeServer {
        data: Vec<u8>,
        cut: RefCell<Option<usize>>,
        ignore_range: bool,
        asked: RefCell<Vec<u64>>,
    }

    impl FakeServer {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                cut: RefCell::new(None),
                ignore_range: false,
                asked: RefCell::new(Vec::new()),
            }
        }
    }

    struct Broken(Cursor<Vec<u8>>);

    impl Read for Broken {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
                n => Ok(n),
            }
        }
    }

    impl RangeFetch for FakeServer {
        fn fetch(&self, _url: &str, offset: u64) -> Result<FetchResponse, String> {
            self.asked.borrow_mut().push(offset);
            let len = self.data.len() as u64;
            if offset > 0 && !self.ignore_range && offset >= len {
                return Ok(FetchResponse {
                    status: 416,
                    content_range: None,
                    content_length: Some(0),
                    body: Box::new(io::empty()),
                });
            }
            let (status, start, range) = if offset > 0 && !self.ignore_range {
                (
                    206,
                    offset,
                    Some(ContentRange {
                        start: offset,
                        end: len - 1,
                        total: Some(len),
                    }),
                )
            } else {
                (200, 0, None)
            };
            let body = self.data[start as usize..].to_vec();
            let content_length = Some(body.len() as u64);
            let body: Box<dyn Read + Send> = match self.cut.borrow_mut().take() {
                Some(n) => Box::new(Broken(Cursor::new(body[..n].to_vec()))),
                None => Box::new(Cursor::new(body)),
            };
            Ok(FetchResponse {
                status,
                content_range: range,
                content_length,
                body,
            })
        }
    }

    fn go(server: &dyn RangeFetch, pin: &ImagePin, dest: &Path) -> Result<VerifiedImage, ImageError> {
        download_image(server, pin, dest, &mut |_| ControlFlow::Continue(()))
    }

    #[test]
    fn a_download_is_verified_and_renamed_into_place() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("images").join("p2pc-node.tar.gz");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let server = FakeServer::new(&data);
        let mut seen = Vec::new();
        let img = download_image(&server, &pin_for(&data), &dest, &mut |p| {
            seen.push(p);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(img.path(), dest);
        assert_eq!(fs::read(&dest).unwrap(), data);
        assert!(!part_path(&dest).exists());
        assert_eq!(
            seen.last(),
            Some(&Progress {
                done: 200_000,
                total: Some(200_000)
            })
        );
        assert_eq!(*server.asked.borrow(), vec![0]);
    }

    #[test]
    fn a_broken_download_resumes_with_a_range_request() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let data: Vec<u8> = (0..150_000u32).map(|i| (i % 7) as u8).collect();
        let server = FakeServer::new(&data);
        *server.cut.borrow_mut() = Some(70_000);
        let err = go(&server, &pin_for(&data), &dest).unwrap_err();
        assert!(matches!(err, ImageError::Download(_)), "{err:?}");
        assert_eq!(err.code(), Some("image_download_failed"));
        assert_eq!(fs::metadata(part_path(&dest)).unwrap().len(), 70_000);
        go(&server, &pin_for(&data), &dest).unwrap();
        assert_eq!(*server.asked.borrow(), vec![0, 70_000]);
        assert_eq!(fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn a_server_that_ignores_the_range_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let data = b"the whole image, again".to_vec();
        fs::write(part_path(&dest), b"garbage!").unwrap();
        let server = FakeServer {
            ignore_range: true,
            ..FakeServer::new(&data)
        };
        go(&server, &pin_for(&data), &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn a_complete_part_is_verified_after_a_416() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let data = b"complete already".to_vec();
        fs::write(part_path(&dest), &data).unwrap();
        let server = FakeServer::new(&data);
        go(&server, &pin_for(&data), &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn a_mismatch_deletes_the_file_and_is_never_retried_silently() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let server = FakeServer::new(b"tampered bytes");
        let pin = pin_for(b"the real image");
        let err = go(&server, &pin, &dest).unwrap_err();
        assert!(matches!(err, ImageError::HashMismatch { .. }), "{err:?}");
        assert_eq!(err.code(), Some("image_hash_mismatch"));
        assert!(!dest.exists() && !part_path(&dest).exists());
        assert_eq!(server.asked.borrow().len(), 1, "one fetch, no silent retry");
    }

    #[test]
    fn an_existing_verified_image_is_kept_and_a_bad_one_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let data = b"image".to_vec();
        fs::write(&dest, &data).unwrap();
        let server = FakeServer::new(&data);
        go(&server, &pin_for(&data), &dest).unwrap();
        assert!(server.asked.borrow().is_empty(), "nothing downloaded");
        let err = go(&server, &pin_for(b"another image"), &dest).unwrap_err();
        assert!(matches!(err, ImageError::HashMismatch { .. }));
        assert!(!dest.exists());
        assert!(server.asked.borrow().is_empty());
    }

    #[test]
    fn the_size_cap_holds_against_the_announced_length_and_the_bytes_sent() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let data = vec![7u8; 10_000];
        let pin = pin_for(&data).with_max_bytes(9_999);
        let err = go(&FakeServer::new(&data), &pin, &dest).unwrap_err();
        assert!(matches!(err, ImageError::TooLarge { max_bytes: 9_999 }), "{err:?}");
        assert!(!part_path(&dest).exists());

        /// Announces nothing and sends too much.
        struct Silent(Vec<u8>);
        impl RangeFetch for Silent {
            fn fetch(&self, _: &str, _: u64) -> Result<FetchResponse, String> {
                Ok(FetchResponse {
                    status: 200,
                    content_range: None,
                    content_length: None,
                    body: Box::new(Cursor::new(self.0.clone())),
                })
            }
        }
        let err = go(&Silent(data), &pin, &dest).unwrap_err();
        assert!(matches!(err, ImageError::TooLarge { .. }), "{err:?}");
        assert!(!part_path(&dest).exists());
    }

    #[test]
    fn a_cancel_keeps_the_part_for_the_next_try() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let data = vec![1u8; 200_000];
        let server = FakeServer::new(&data);
        let err = download_image(&server, &pin_for(&data), &dest, &mut |_| ControlFlow::Break(())).unwrap_err();
        assert!(matches!(err, ImageError::Cancelled));
        assert!(part_path(&dest).exists());
        go(&server, &pin_for(&data), &dest).unwrap();
        assert_eq!(server.asked.borrow()[1], 1 << 16);
    }

    #[test]
    fn http_errors_and_wrong_ranges_fail_the_download() {
        struct Status(u16, Option<ContentRange>);
        impl RangeFetch for Status {
            fn fetch(&self, _: &str, _: u64) -> Result<FetchResponse, String> {
                Ok(FetchResponse {
                    status: self.0,
                    content_range: self.1,
                    content_length: None,
                    body: Box::new(io::empty()),
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let err = go(&Status(404, None), &pin_for(b"x"), &dest).unwrap_err();
        assert!(matches!(&err, ImageError::Download(m) if m.contains("404")), "{err:?}");
        fs::write(part_path(&dest), b"12345").unwrap();
        let wrong = ContentRange {
            start: 0,
            end: 9,
            total: Some(10),
        };
        let err = go(&Status(206, Some(wrong)), &pin_for(b"x"), &dest).unwrap_err();
        assert!(matches!(err, ImageError::Download(_)));
        assert!(
            !part_path(&dest).exists(),
            "a part the server disagrees with is dropped"
        );
    }

    #[test]
    fn content_range_parses_the_206_form_only() {
        assert_eq!(
            ContentRange::parse("bytes 100-199/200"),
            Some(ContentRange {
                start: 100,
                end: 199,
                total: Some(200)
            })
        );
        assert_eq!(
            ContentRange::parse("bytes 0-0/*"),
            Some(ContentRange {
                start: 0,
                end: 0,
                total: None
            })
        );
        assert_eq!(ContentRange::parse("bytes */200"), None);
        assert_eq!(ContentRange::parse("bytes 9-1/200"), None);
        assert_eq!(ContentRange::parse("items 0-1/2"), None);
    }

    #[test]
    fn a_pin_needs_https_and_a_sha256() {
        let hex = "a".repeat(64);
        assert!(ImagePin::new("https://example.invalid/i.tar.gz", &hex).is_ok());
        assert!(ImagePin::new("HTTPS://example.invalid/i.tar.gz", &hex.to_uppercase()).is_ok());
        assert!(matches!(
            ImagePin::new("http://example.invalid/i.tar.gz", &hex),
            Err(ImageError::BadUrl)
        ));
        assert!(matches!(ImagePin::new("https://", &hex), Err(ImageError::BadUrl)));
        assert!(matches!(
            ImagePin::new("https://example.invalid/a b", &hex),
            Err(ImageError::BadUrl)
        ));
        assert!(matches!(
            ImagePin::new("https://example.invalid/i", &hex[1..]),
            Err(ImageError::BadDigest)
        ));
        assert!(matches!(
            ImagePin::new("https://example.invalid/i", &"g".repeat(64)),
            Err(ImageError::BadDigest)
        ));
    }

    #[test]
    fn the_checksum_file_is_read_like_test_image() {
        let hex = "0123456789abcdefABCDEF0123456789abcdef0123456789abcdef0123456789";
        let d = Sha256Digest::from_checksum_file(&format!("{hex}  p2pc-node-0.3.0.tar.gz\n")).unwrap();
        assert_eq!(d.to_hex(), hex.to_lowercase());
        assert!(Sha256Digest::from_checksum_file(&format!("  {hex}\n")).is_ok());
        assert!(Sha256Digest::from_checksum_file(hex).is_ok());
        // Only the first line counts, and the digest must end at a word boundary.
        assert!(Sha256Digest::from_checksum_file(&format!("\n{hex}")).is_err());
        assert!(Sha256Digest::from_checksum_file(&format!("{hex}0")).is_err());
        assert!(Sha256Digest::from_checksum_file(&format!("{hex}x file")).is_err());
        assert!(Sha256Digest::from_checksum_file("not a digest").is_err());
    }

    #[test]
    fn a_local_tar_is_verified_against_its_sha256_file() {
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("p2pc-node-0.3.0.tar.gz");
        assert!(matches!(
            verify_with_checksum_file(&tar, None),
            Err(ImageError::ImageMissing(_))
        ));
        fs::write(&tar, b"rootfs").unwrap();
        assert!(matches!(
            verify_with_checksum_file(&tar, None),
            Err(ImageError::ChecksumFileMissing(_))
        ));
        let sha = dir.path().join("p2pc-node-0.3.0.tar.gz.sha256");
        fs::write(&sha, "nonsense\n").unwrap();
        assert!(matches!(
            verify_with_checksum_file(&tar, None),
            Err(ImageError::BadChecksumFile)
        ));
        fs::write(&sha, format!("{}  p2pc-node-0.3.0.tar.gz\n", digest(b"other"))).unwrap();
        assert!(matches!(
            verify_with_checksum_file(&tar, None),
            Err(ImageError::HashMismatch { .. })
        ));
        assert!(tar.exists(), "a developer's own tar is never deleted");
        fs::write(&sha, format!("{}  p2pc-node-0.3.0.tar.gz\n", digest(b"rootfs"))).unwrap();
        let img = verify_with_checksum_file(&tar, None).unwrap();
        assert_eq!(img.sha256(), digest(b"rootfs"));
        let other = dir.path().join("SHA256SUMS");
        fs::write(&other, format!("{}\n", digest(b"rootfs"))).unwrap();
        assert!(verify_with_checksum_file(&tar, Some(&other)).is_ok());
    }

    #[test]
    fn the_real_fetcher_refuses_plain_http() {
        let f = HttpFetcher::new().unwrap();
        let err = f.fetch("http://example.invalid/p2pc-node.tar.gz", 0).unwrap_err();
        assert!(!err.is_empty());
    }

    /// The real fetcher against a loopback HTTP server (no internet): a first request broken off, then a ranged one.
    #[test]
    fn the_real_fetcher_resumes_against_a_loopback_server() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;

        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let served = data.clone();
        let server = std::thread::spawn(move || {
            let mut ranges = Vec::new();
            for (n, conn) in listener.incoming().take(2).enumerate() {
                let mut conn = conn.unwrap();
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut range = None;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let l = line.trim_end();
                    if l.is_empty() {
                        break;
                    }
                    if let Some(v) = l.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        range = Some(v.trim_end_matches('-').parse::<usize>().unwrap());
                    }
                }
                ranges.push(range);
                let start = range.unwrap_or(0);
                let body = &served[start..];
                let head = match range {
                    None => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    ),
                    Some(s) => format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                        body.len(),
                        s,
                        served.len() - 1,
                        served.len()
                    ),
                };
                conn.write_all(head.as_bytes()).unwrap();
                // The first answer stops after 40 000 bytes: a broken connection.
                let send = if n == 0 { &body[..40_000] } else { body };
                conn.write_all(send).unwrap();
            }
            ranges
        });
        let fetcher = HttpFetcher::plain_http_for_tests();
        let url = format!("http://{addr}/p2pc-node.tar.gz");
        let pin = ImagePin {
            url,
            sha256: digest(&data),
            max_bytes: DEFAULT_MAX_IMAGE_BYTES,
        };
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("img.tar.gz");
        let err = go(&fetcher, &pin, &dest).unwrap_err();
        assert!(matches!(err, ImageError::Download(_)), "{err:?}");
        go(&fetcher, &pin, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), data);
        assert_eq!(server.join().unwrap(), vec![None, Some(40_000)]);
    }
}
