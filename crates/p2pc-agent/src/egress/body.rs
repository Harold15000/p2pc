// SPDX-License-Identifier: Apache-2.0

//! Forwarding **exactly one** plain-HTTP request body (spec §9: one request per plain-HTTP connection).
//!
//! The body is relayed as is, never decoded: `Content-Length` bytes, or a chunked body up to the last chunk and
//! its trailers. Anything the client sends after that, such as a pipelined second request, is never read from the
//! buffer into the upstream, so it can never reach the upstream unchecked.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::request::Body;

/// Longest chunk-size line or trailer line.
const MAX_LINE: usize = 4096;
/// Most trailer bytes after the last chunk.
const MAX_TRAILERS: usize = 16 * 1024;
/// Read size when the buffer runs dry.
const READ_CHUNK: usize = 16 * 1024;

/// Why a relay stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The byte cap was reached: the record says `ByteCap`.
    Cap,
    /// An I/O error, a peer that closed too early, or malformed framing.
    Other,
}

/// Where the forwarded bytes go (the upstream, through the byte cap and the counters).
pub(crate) trait Sink {
    /// Writes `bytes`. `Err` stops the relay.
    fn put(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), Stop>> + Send;
}

/// The client's read side, with the bytes already read past the head.
#[derive(Debug)]
pub(crate) struct Source<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: AsyncRead + Unpin + Send> Source<R> {
    pub(crate) fn new(inner: R, early: Vec<u8>) -> Self {
        Self {
            inner,
            buf: early,
            pos: 0,
        }
    }

    fn available(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }

    fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.buf.len());
    }

    /// Reads more from the client. `Err` on EOF or an error: a body cut short is an aborted request.
    async fn fill(&mut self) -> Result<(), Stop> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let read = match self.buf.get_mut(start..) {
            Some(dst) => self.inner.read(dst).await,
            None => Ok(0),
        };
        let n = read.unwrap_or(0);
        self.buf.truncate(start + n);
        if n == 0 { Err(Stop::Other) } else { Ok(()) }
    }

    /// Forwards exactly `n` bytes.
    async fn forward_exact<S: Sink + Send>(&mut self, mut n: u64, sink: &mut S) -> Result<(), Stop> {
        while n > 0 {
            if self.available().is_empty() {
                self.fill().await?;
            }
            let take = usize::try_from(n).unwrap_or(usize::MAX).min(self.available().len());
            let bytes = self.available().get(..take).ok_or(Stop::Other)?.to_vec();
            sink.put(&bytes).await?;
            self.consume(take);
            n -= take as u64;
        }
        Ok(())
    }

    /// Takes one CRLF-terminated line (CRLF included). A bare LF or a line over [`MAX_LINE`] is an error.
    async fn line(&mut self) -> Result<Vec<u8>, Stop> {
        loop {
            if let Some(lf) = self.available().iter().position(|&b| b == b'\n') {
                let line = self.available().get(..=lf).ok_or(Stop::Other)?.to_vec();
                if lf == 0 || line.get(lf - 1) != Some(&b'\r') || line.len() > MAX_LINE {
                    return Err(Stop::Other);
                }
                self.consume(lf + 1);
                return Ok(line);
            }
            if self.available().len() >= MAX_LINE {
                return Err(Stop::Other);
            }
            self.fill().await?;
        }
    }
}

/// Forwards the request body framed as `body`, and nothing after it. `Err` on malformed framing, a client that
/// closes early, or a sink error.
pub(crate) async fn forward_body<R, S>(src: &mut Source<R>, body: Body, sink: &mut S) -> Result<(), Stop>
where
    R: AsyncRead + Unpin + Send,
    S: Sink + Send,
{
    match body {
        Body::None => Ok(()),
        Body::Length(n) => src.forward_exact(n, sink).await,
        Body::Chunked => loop {
            let line = src.line().await?;
            let size = chunk_size(&line).map_err(|()| Stop::Other)?;
            sink.put(&line).await?;
            if size == 0 {
                return forward_trailers(src, sink).await;
            }
            src.forward_exact(size, sink).await?;
            let crlf = src.line().await?;
            if crlf != b"\r\n" {
                return Err(Stop::Other);
            }
            sink.put(&crlf).await?;
        },
    }
}

/// Trailer lines after the last chunk, up to and including the empty line.
async fn forward_trailers<R, S>(src: &mut Source<R>, sink: &mut S) -> Result<(), Stop>
where
    R: AsyncRead + Unpin + Send,
    S: Sink + Send,
{
    let mut total = 0usize;
    loop {
        let line = src.line().await?;
        total += line.len();
        if total > MAX_TRAILERS || !trailer_line_ok(&line) {
            return Err(Stop::Other);
        }
        sink.put(&line).await?;
        if line == b"\r\n" {
            return Ok(());
        }
    }
}

/// One trailer line, CRLF included: either the final empty line, or `token ":" value` (RFC 9110 §5.1, §5.5).
/// A `\r` anywhere but in the final CRLF, an empty or invalid field name, whitespace before the colon (obs-fold
/// included) and control characters other than tab in the value are all refused.
pub(crate) fn trailer_line_ok(line: &[u8]) -> bool {
    let Some(content) = line.strip_suffix(b"\r\n") else {
        return false;
    };
    if content.contains(&b'\r') || content.contains(&b'\n') {
        return false;
    }
    if content.is_empty() {
        return true;
    }
    let Some(colon) = content.iter().position(|&b| b == b':') else {
        return false;
    };
    let (name, value) = content.split_at(colon);
    let tchar = |b: &u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b);
    !name.is_empty() && name.iter().all(tchar) && value.iter().skip(1).all(|&b| b == b'\t' || !b.is_ascii_control())
}

/// `chunk-size [ chunk-ext ] CRLF` (RFC 9112 §7.1): 1-16 hex digits, then nothing, or extensions after `;`
/// (optionally preceded by spaces or tabs).
pub(crate) fn chunk_size(line: &[u8]) -> Result<u64, ()> {
    let line = line.strip_suffix(b"\r\n").ok_or(())?;
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 {
        return Err(());
    }
    let (hex, rest) = line.split_at(digits);
    let rest_ok = rest.is_empty()
        || (rest.trim_ascii_start().first() == Some(&b';')
            && rest.iter().all(|&b| b == b'\t' || (b' '..=b'~').contains(&b)));
    if !rest_ok {
        return Err(());
    }
    let hex = std::str::from_utf8(hex).map_err(drop)?;
    u64::from_str_radix(hex, 16).map_err(drop)
}
