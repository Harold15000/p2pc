// SPDX-License-Identifier: Apache-2.0

//! The streaming body of a blob upload (H2 §7.5): a file read in pieces, never held in memory.
//!
//! A blob is up to 2 GiB, so `p2pc blobs put` cannot build a `Vec<u8>` of it. The body announces its exact length (the
//! server requires a `Content-Length` and answers `411` to a chunked upload) and fails the request if the file is
//! shorter than that, so a file that shrinks while it is sent is an error here instead of a truncated blob.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::io::{AsyncRead, ReadBuf};

/// The largest piece read from the file at once.
const CHUNK: usize = 64 * 1024;

/// A file sent as a request body: exactly `remaining` more bytes.
pub(crate) struct FileBody {
    file: tokio::fs::File,
    remaining: u64,
    buf: Vec<u8>,
}

impl FileBody {
    /// Sends the first `len` bytes of `file`, which is read from its current position (the start).
    pub(crate) fn new(file: tokio::fs::File, len: u64) -> Self {
        Self {
            file,
            remaining: len,
            buf: Vec::new(),
        }
    }
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = &mut *self;
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let want = usize::try_from(this.remaining).map_or(CHUNK, |n| n.min(CHUNK));
        this.buf.resize(want, 0);
        let mut read = ReadBuf::new(&mut this.buf);
        match Pin::new(&mut this.file).poll_read(cx, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(())) => {
                let n = read.filled().len();
                if n == 0 {
                    // The file ended before the length we announced: sending less would be a truncated blob.
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the file is shorter than it was when it was measured",
                    ))));
                }
                this.remaining = this.remaining.saturating_sub(n as u64);
                let chunk = Bytes::copy_from_slice(this.buf.get(..n).unwrap_or_default());
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}
