// SPDX-License-Identifier: AGPL-3.0-only

//! The logs and outputs endpoints (spec §7): `GET /v1/jobs/{id}/logs`, `GET /v1/jobs/{id}/outputs` and
//! `GET /v1/jobs/{id}/outputs/{path}`.
//!
//! Every handler first reads the job with the caller's `account_id` and `project_id`: another account's job answers
//! `404`, exactly like one that does not exist (SI-7).
//!
//! **Streaming.** Logs and downloads are streamed from a pipe that a task fills. Those routes opt out of the
//! whole-request limit (§10) and use an idle limit instead (`http.keepalive_idle_ms`): a write the client does not
//! take within it, or a follow with no new line within it, ends the stream. A client resumes a log with
//! `since_seq = last seq + 1`.
//!
//! **How a log body ends.** A clean end (a complete HTTP body) means one thing: the lines asked for are all there. For
//! a page that is "everything stored now"; for a follow it is "the attempt is over and its log is flushed". Anything
//! else (the idle limit, a log that cannot be read, a database error) ends the body with an **error**: the
//! connection is cut without the end of the body, so a client sees a broken transfer, never a finished log, and
//! resumes from `since_seq = last seq + 1`.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{OUTPUT_SHA256_HEADER, OutputEntry, Page, Problem};
use p2pc_proto::ids::{AccountId, JobId};
use p2pc_proto::validate::{ErrorCode, validate_output_path};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};
use utoipa::IntoParams;

use crate::app::{AppState, bad_cursor, page_limit};
use crate::auth::{Authorized, JobsReadKey};
use crate::error::ApiError;
use crate::extract::ApiQuery;
use crate::store::{jobs, outputs};

/// Media type of the logs.
pub const NDJSON: &str = "application/x-ndjson";
/// How often a follower checks whether its attempt ended, when no line arrives.
pub const FOLLOW_POLL: Duration = Duration::from_secs(1);
/// The pipe between the task that reads the store and the response body.
const PIPE: usize = 64 * 1024;

/// `since_seq`, `follow` and `attempt`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct LogParams {
    /// The first `seq` to return, inclusive (default 0). Resume with the last `seq` seen plus one.
    pub since_seq: Option<u64>,
    /// Keep the stream open and send new lines as they are stored, until the attempt ends (default false).
    pub follow: Option<bool>,
    /// The attempt (default: the latest).
    pub attempt: Option<u32>,
}

/// `limit`, `cursor` and `attempt`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct OutputListParams {
    /// Page size, 1-100 (default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page (opaque).
    pub cursor: Option<String>,
    /// The attempt (default: the latest).
    pub attempt: Option<u32>,
}

/// `attempt`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct AttemptParams {
    /// The attempt (default: the latest).
    pub attempt: Option<u32>,
}

/// The caller's job and the attempt asked for: `404` for a job of another account (SI-7), for one that does not
/// exist, and for an attempt the job never reached; `422` for attempt 0.
async fn job_attempt(
    state: &AppState,
    account_id: AccountId,
    project_id: p2pc_proto::ids::ProjectId,
    id: &str,
    attempt: Option<u32>,
) -> Result<(JobId, u32), ApiError> {
    let job_id: JobId = id.parse().map_err(|_| ApiError::not_found())?;
    let mut conn = state.db.acquire().await?;
    let job = jobs::get(&mut conn, account_id, project_id, job_id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    match attempt {
        None => Ok((job_id, job.attempt)),
        Some(0) => Err(ApiError::field("attempt", ErrorCode::OutOfRange, "attempts start at 1")),
        Some(k) if k > job.attempt => Err(ApiError::not_found()),
        Some(k) => Ok((job_id, k)),
    }
}

/// The NDJSON log of an attempt: `{seq, stream, ts, data}` per line, `data` as UTF-8 with invalid bytes replaced.
///
/// - **Page** (default): the lines stored now with `seq >= since_seq`. A job with no logs yet gives an empty `200`.
/// - **Follow** (`follow=true`): the same, then new lines as they are stored; the stream ends once the attempt is
///   over and its log is flushed.
/// - **How the body ends.** A clean end (the HTTP body completes) means the lines asked for are all there: for a follow,
///   the attempt is over and its log is flushed. Anything else ends the body with an **error** (the connection is
///   cut without the end of the body, so a client sees a broken transfer): after `http.keepalive_idle_ms` (60 s by
///   default) with no new line, on a log that cannot be read and on a server error. The client resumes with
///   `since_seq = last seq + 1`, losing and repeating nothing.
/// - At most 64 MiB are stored per attempt; past that, one `stderr` line marks the truncation. That line also has
///   the member `truncated: true`, which no job output can produce (readers that do not know it ignore it).
#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/logs",
    tag = "jobs",
    params(("id" = String, Path, description = "The job ID (`job_…`)."), LogParams),
    responses(
        (status = 200, description = "NDJSON, one `LogLine` per line, in `seq` order.", content_type = "application/x-ndjson", body = p2pc_proto::api::LogLine),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks `jobs:read`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account, or no such attempt.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid query (for example `attempt=0`).", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_logs(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    Path(id): Path<String>,
    ApiQuery(q): ApiQuery<LogParams>,
) -> Result<Response, ApiError> {
    let (job_id, attempt) = job_attempt(&state, p.account_id, p.project_id, &id, q.attempt).await?;
    let follow = q.follow.unwrap_or(false);
    let since = q.since_seq.unwrap_or(0);
    let (w, r) = tokio::io::duplex(PIPE);
    let completed = Arc::new(AtomicBool::new(false));
    let request = LogRequest {
        account_id: p.account_id,
        job_id,
        attempt,
        since,
        follow,
    };
    tokio::spawn(pump(w, completed.clone(), async move |w| {
        follow_log(&state, request, w).await
    }));
    let mut resp = stream_response(CompleteReader { inner: r, completed });
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(NDJSON));
    Ok(resp)
}

fn stream_response(r: impl AsyncRead + Send + 'static) -> Response {
    let mut resp = Body::from_stream(tokio_util::io::ReaderStream::new(r)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The read side of a log pipe. Its end is a clean end of the body **only if** the writer said it `completed`; any other
/// end of the pipe (the pump hit an error, panicked, or was aborted at shutdown) is an I/O error once the data is
/// drained, which breaks the response body instead of finishing it. A clean end means "the log is complete", so it
/// must never be the default.
struct CompleteReader {
    inner: DuplexStream,
    completed: Arc<AtomicBool>,
}

impl AsyncRead for CompleteReader {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(())))
            && buf.filled().len() == before
            && !self.completed.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(io::Error::other("the log stream stopped before the attempt ended")));
        }
        polled
    }
}

/// How the task that fills a log body stopped.
#[derive(Debug, PartialEq, Eq)]
enum Pumped {
    /// Everything that was asked for is written: for a follow, the attempt is over and flushed. The body ends cleanly.
    Complete,
    /// The client went away, or does not read: nobody is left to tell.
    ClientGone,
    /// The server could not go on (the idle limit, an unreadable log, a database error): the body ends with an error.
    Broken,
}

/// What a log request asked for, once the job and attempt are resolved.
#[derive(Debug, Clone, Copy)]
struct LogRequest {
    account_id: AccountId,
    job_id: JobId,
    attempt: u32,
    since: u64,
    follow: bool,
}

/// Runs a pump over the pipe's write side `w`, which this function owns, and records a verdict only when it ran to the
/// end: `completed` is set only on [`Pumped::Complete`], **before** `w` is dropped. Dropping `w` wakes the reader with
/// the end of the pipe, which on another worker thread can run at once: it must find the flag already set, or it
/// would break a body that was complete. A pump that returns anything else, panics or is aborted leaves the flag
/// unset (`w` is dropped then too), and the reader breaks the body ([`CompleteReader`]).
async fn pump(mut w: DuplexStream, completed: Arc<AtomicBool>, pumping: impl AsyncFnOnce(&mut DuplexStream) -> Pumped) {
    if pumping(&mut w).await == Pumped::Complete {
        completed.store(true, Ordering::Release);
    }
    drop(w);
}

/// Writes the attempt's lines into `w`, then (following) new ones, until the attempt is over and flushed. It is
/// [`Pumped::Complete`] only then (and for a page, when what is stored now is written); the idle limit and internal
/// errors are [`Pumped::Broken`]. It only borrows `w`: [`pump`] drops it, after it has recorded the verdict.
async fn follow_log(state: &AppState, request: LogRequest, w: &mut DuplexStream) -> Pumped {
    let LogRequest {
        account_id,
        job_id,
        attempt,
        since,
        follow,
    } = request;
    let idle = state.config.http.keepalive_idle();
    let logs = &state.logs;
    // Subscribed before the first read, so no flush in between is missed.
    let mut follower = follow.then(|| logs.subscribe(job_id, attempt));
    // "The lines that exist now": what the writer holds in its buffer too.
    logs.flush(job_id, attempt).await;
    let mut offset = 0;
    let mut last_data = tokio::time::Instant::now();
    let mut ending = false;
    loop {
        let read = match logs.read(job_id, attempt, offset, since).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, %job_id, attempt, "cannot read a log file");
                return Pumped::Broken;
            }
        };
        if read.next != offset {
            offset = read.next;
            if !read.lines.is_empty() {
                match tokio::time::timeout(idle, w.write_all(&read.lines)).await {
                    Ok(Ok(())) => last_data = tokio::time::Instant::now(),
                    // The client went away, or does not read.
                    _ => return Pumped::ClientGone,
                }
            }
            continue;
        }
        let Some(f) = follower.as_mut() else {
            return Pumped::Complete;
        };
        if ending {
            return Pumped::Complete;
        }
        let over = async {
            let mut conn = state.db.acquire().await?;
            outputs::attempt_over(&mut conn, account_id, job_id, attempt).await
        };
        match over.await {
            Ok(Some(false)) => {}
            // Over: flush what its writer still holds, read it, and end.
            Ok(Some(true)) => {
                logs.flush(job_id, attempt).await;
                ending = true;
                continue;
            }
            // The job was readable when the request began and its row never goes away: not a clean end.
            Ok(None) => {
                tracing::warn!(%job_id, "a followed job is no longer there");
                return Pumped::Broken;
            }
            Err(e) => {
                tracing::warn!(error = %e, %job_id, "cannot check whether an attempt is over");
                return Pumped::Broken;
            }
        }
        let left = idle.saturating_sub(last_data.elapsed());
        if left.is_zero() {
            // Not over, and nothing for the whole idle limit: the body breaks, and the client comes back with
            // `since_seq`. A clean end here would tell it the log is complete.
            return Pumped::Broken;
        }
        tokio::select! {
            () = f.changed() => {}
            () = tokio::time::sleep(FOLLOW_POLL.min(left)) => {}
        }
    }
}

/// The published output files of an attempt, by path, with their size and sha256. After the retention period the
/// entries stay, with `expired: true`, and their downloads answer `410`.
#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/outputs",
    tag = "jobs",
    params(("id" = String, Path, description = "The job ID (`job_…`)."), OutputListParams),
    responses(
        (status = 200, description = "A page of output files.", body = Page<OutputEntry>),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks `jobs:read`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account, or no such attempt.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit`, `cursor` or `attempt`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_outputs(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    Path(id): Path<String>,
    ApiQuery(q): ApiQuery<OutputListParams>,
) -> Result<Json<Page<OutputEntry>>, ApiError> {
    let (job_id, attempt) = job_attempt(&state, p.account_id, p.project_id, &id, q.attempt).await?;
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| {
            data_encoding::BASE64URL_NOPAD
                .decode(c.as_bytes())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(bad_cursor)
        })
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let expired = outputs::expired(&mut conn, p.account_id, job_id).await?;
    let mut rows =
        outputs::published_page(&mut conn, p.account_id, job_id, attempt, after.as_deref(), limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more
        .then(|| {
            rows.last()
                .map(|f| data_encoding::BASE64URL_NOPAD.encode(f.path.as_bytes()))
        })
        .flatten();
    let items = rows
        .into_iter()
        .map(|f| OutputEntry {
            expired,
            ..OutputEntry::new(f)
        })
        .collect();
    Ok(Json(Page { items, next_cursor }))
}

/// Downloads one published output file. The path is checked like an upload's (no traversal, SI-9) and opened under
/// the attempt's published directory without following any link. Sends `Content-Length` and `X-P2PC-SHA256`;
/// `Range` is not supported (the whole file is sent).
#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/outputs/{path}",
    tag = "jobs",
    params(
        ("id" = String, Path, description = "The job ID (`job_…`)."),
        ("path" = String, Path, description = "The output's path relative to `/outputs`, for example `results/a.csv` (its segments percent-encoded)."),
        AttemptParams,
    ),
    responses(
        (status = 200, description = "The file.", content_type = "application/octet-stream", body = Vec<u8>,
            headers(
                ("X-P2PC-SHA256" = String, description = "The file's SHA-256, 64 lowercase hex characters."),
                ("Content-Length" = u64, description = "The file's size."),
            )),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks `jobs:read`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account, no such attempt, or no such output.", content_type = "application/problem+json", body = Problem),
        (status = 410, description = "`expired`: the output was deleted after the retention period.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn download_output(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    Path((id, path)): Path<(String, String)>,
    ApiQuery(q): ApiQuery<AttemptParams>,
) -> Result<Response, ApiError> {
    let (job_id, attempt) = job_attempt(&state, p.account_id, p.project_id, &id, q.attempt).await?;
    // SI-9: the same check as an upload's; anything else is simply not an output.
    validate_output_path(&path).map_err(|_| ApiError::not_found())?;
    let mut conn = state.db.acquire().await?;
    let file = outputs::published_one(&mut conn, p.account_id, job_id, attempt, &path)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if outputs::expired(&mut conn, p.account_id, job_id).await? {
        return Err(ApiError::expired());
    }
    drop(conn);
    let (handle, size) = state
        .outputs
        .open_published(job_id, attempt, &path)
        .await
        .map_err(|_| ApiError::not_found())?;
    if size != file.size {
        tracing::warn!(%job_id, attempt, "a published output does not have its recorded size");
        return Err(ApiError::not_found());
    }
    let (w, r) = tokio::io::duplex(PIPE);
    tokio::spawn(pump_file(
        tokio::fs::File::from_std(handle),
        w,
        state.config.http.keepalive_idle(),
    ));
    let mut resp = stream_response(r);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(file.size));
    if let Ok(v) = HeaderValue::from_str(&file.sha256.to_string()) {
        h.insert(OUTPUT_SHA256_HEADER, v);
    }
    h.insert(header::CONTENT_DISPOSITION, disposition(&path));
    Ok((StatusCode::OK, resp).into_response())
}

/// `attachment`, with the file name when it is plain ASCII that needs no quoting.
fn disposition(path: &str) -> HeaderValue {
    let name = path.rsplit('/').next().unwrap_or_default();
    let plain = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if plain && let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        return v;
    }
    HeaderValue::from_static("attachment")
}

/// Copies `file` into `w`; a write the client does not take within `idle` ends the body early (the client sees
/// fewer bytes than `Content-Length`).
async fn pump_file(mut file: tokio::fs::File, mut w: DuplexStream, idle: Duration) {
    let mut buf = vec![0u8; PIPE];
    loop {
        let n = match file.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        match tokio::time::timeout(idle, w.write_all(&buf[..n])).await {
            Ok(Ok(())) => {}
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_to_end(mut r: CompleteReader) -> (Vec<u8>, io::Result<()>) {
        let mut got = Vec::new();
        let end = r.read_to_end(&mut got).await.map(|_| ());
        (got, end)
    }

    fn pipe() -> (DuplexStream, Arc<AtomicBool>, CompleteReader) {
        let (w, r) = tokio::io::duplex(1024);
        let completed = Arc::new(AtomicBool::new(false));
        (w, completed.clone(), CompleteReader { inner: r, completed })
    }

    /// T10d review P3-1: a pump that is aborted mid-follow (a shutdown) has no verdict, so the body ends with an
    /// error after the data it had written: it never looks like a complete log.
    #[tokio::test]
    async fn a_pump_aborted_mid_follow_ends_the_body_with_an_error() {
        let (w, completed, reader) = pipe();
        let pumping = tokio::spawn(pump(w, completed, async |w| {
            w.write_all(b"{\"seq\":0}\n").await.unwrap();
            std::future::pending::<Pumped>().await
        }));
        // Let it write, then abort it.
        tokio::task::yield_now().await;
        pumping.abort();
        assert!(pumping.await.unwrap_err().is_cancelled());
        let (got, end) = read_to_end(reader).await;
        assert_eq!(got, b"{\"seq\":0}\n", "what was written is still delivered");
        assert!(end.is_err(), "an aborted pump ended the body cleanly");
    }

    #[tokio::test]
    async fn a_pump_that_panics_or_breaks_ends_the_body_with_an_error() {
        for verdict in [Pumped::Broken, Pumped::ClientGone] {
            let (w, completed, reader) = pipe();
            pump(w, completed, async |_| verdict).await;
            assert!(read_to_end(reader).await.1.is_err());
        }
        let (w, completed, reader) = pipe();
        let panicking = tokio::spawn(pump(w, completed, async |_| -> Pumped { panic!("a pump bug") }));
        assert!(panicking.await.unwrap_err().is_panic());
        assert!(read_to_end(reader).await.1.is_err());
    }

    /// T10g item 1: the writer is dropped (waking the reader with EOF) only after the verdict is stored, so a reader
    /// on another worker thread never sees the end of a complete body without its flag.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_complete_body_never_ends_with_an_error_on_a_multi_threaded_runtime() {
        for round in 0..3000 {
            let (w, completed, reader) = pipe();
            let pumping = tokio::spawn(pump(w, completed, async |w| {
                w.write_all(b"{\"seq\":0}\n").await.unwrap();
                Pumped::Complete
            }));
            let (got, end) = read_to_end(reader).await;
            pumping.await.unwrap();
            assert_eq!(got, b"{\"seq\":0}\n", "round {round}");
            assert!(end.is_ok(), "round {round}: a complete body ended with an error");
        }
    }

    #[tokio::test]
    async fn only_a_complete_pump_ends_the_body_cleanly() {
        let (w, completed, reader) = pipe();
        pump(w, completed, async |w| {
            w.write_all(b"x\n").await.unwrap();
            Pumped::Complete
        })
        .await;
        let (got, end) = read_to_end(reader).await;
        assert_eq!((got.as_slice(), end.is_ok()), (&b"x\n"[..], true));
    }

    #[test]
    fn the_disposition_names_only_plain_files() {
        assert_eq!(disposition("results/a.csv"), "attachment; filename=\"a.csv\"");
        assert_eq!(disposition("a b.txt"), "attachment");
        assert_eq!(disposition("q\"uote"), "attachment");
        assert_eq!(disposition("ñ.txt"), "attachment");
    }
}
