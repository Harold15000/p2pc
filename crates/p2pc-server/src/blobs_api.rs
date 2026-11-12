// SPDX-License-Identifier: AGPL-3.0-only

//! The blob routes (H2 §7.3, §7.5): `POST /v1/blobs`, `HEAD /v1/blobs/{sha256}`, `GET /v1/blobs` and
//! `DELETE /v1/blobs/{sha256}`. No route returns blob contents: the hub is not a file store; blobs reach nodes only
//! as job inputs, through `BlobFetch` (`gateway::blob_fetch`).
//!
//! **An upload**, in order:
//! 1. **before reading the body**: `Content-Length` is required (`411`), `X-P2PC-SHA256` must be 64 lowercase hex
//!    (`422`), the size at most `max_blob_mb` (`413 too_large`); then, in one short `BEGIN IMMEDIATE` transaction
//!    that re-checks the caller, the account's stored bytes plus its uploads in progress plus this size must fit
//!    `blobs_quota_mb`, and for a device with a quota the same over the blobs it holds a claim on (`507
//!    quota_exceeded`, both with `checked_add`), and the principal may have at most 2 uploads in progress (`429
//!    too_many_uploads`). The slot and the bytes are reserved in memory there, and given back on every exit path;
//! 2. **the body** streams to a staging file while it is hashed, with no whole-request limit but an idle limit (60 s)
//!    and a floor of 16 KiB/s over any 60 s ([`crate::blobs::Pace`]); a body shorter or longer than its
//!    `Content-Length`, or one that breaks, deletes the staging file (`400 body_length_mismatch`), as does a digest
//!    that does not match (`422 digest_mismatch`) or a timeout (`408`);
//! 3. **under the `(account, digest)` lock**: a live blob of the account is a deduplication (`200`, the caller gets
//!    its own claim); a tombstoned one is deleted first (file, then row: the steps an interrupted deletion had left),
//!    then stored as new; a new one is `fsync`ed and renamed into place, then its row and the caller's claim are
//!    inserted (`201`). No file I/O happens inside a transaction.

use axum::Json;
use axum::body::{Body, HttpBody};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{BLOB_SHA256_HEADER, BlobInfo, BlobList, BlobUploaded, Problem, Scope, Sha256Digest};
use p2pc_proto::validate::ErrorCode;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

use crate::app::{AppState, PageParams, bad_cursor, page_limit};
use crate::auth::{AnyKey, Authorized, JobsReadKey, Principal, recheck_caller};
use crate::blobs::{Pace, Quotas, Refusal, Staging, UploadLimits};
use crate::error::ApiError;
use crate::extract::ApiQuery;
use crate::store::{self, blobs};

/// One MiB.
const MIB: u64 = 1024 * 1024;

fn digest_param(text: &str) -> Result<Sha256Digest, ApiError> {
    text.parse().map_err(|_| ApiError::not_found())
}

fn mib(n: u64) -> u64 {
    n.saturating_mul(MIB)
}

/// The caller's account's blob, live or not, as the API shows it.
fn uploaded(view: &blobs::BlobView, retention: time::Duration) -> BlobUploaded {
    BlobUploaded {
        sha256: view.sha256,
        size: view.size,
        created_at: view.created_at,
        expires_at: view.expires_at(retention),
    }
}

/// Why a body was not received.
enum Failed {
    /// The idle limit or the rate floor.
    Timeout,
    /// Shorter or longer than `Content-Length`, or broken.
    Length,
    /// The staging file could not be written.
    Io(std::io::Error),
}

/// Streams `body` into `file`, exactly `size` bytes, hashing them. Returns their digest.
async fn receive(
    mut body: Body,
    file: &mut tokio::fs::File,
    size: u64,
    limits: UploadLimits,
) -> Result<Sha256Digest, Failed> {
    let mut pace = Pace::new(limits, Instant::now());
    let mut hasher = Sha256::new();
    loop {
        let next = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx));
        let frame = match tokio::time::timeout_at(pace.deadline(), next).await {
            Err(_) => return Err(Failed::Timeout),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(Failed::Length),
            Ok(Some(Ok(frame))) => frame,
        };
        // Trailers carry nothing an upload uses.
        let Ok(data) = frame.into_data() else { continue };
        let n = data.len() as u64;
        // Refused as soon as it passes `size`, before the extra bytes are written.
        if pace.total().saturating_add(n) > size {
            return Err(Failed::Length);
        }
        hasher.update(&data);
        file.write_all(&data).await.map_err(Failed::Io)?;
        pace.record(Instant::now(), n);
    }
    if pace.total() != size {
        return Err(Failed::Length);
    }
    file.flush().await.map_err(Failed::Io)?;
    Ok(Sha256Digest(hasher.finalize().into()))
}

/// `Content-Length` (required: a chunked upload gets `411`) and `X-P2PC-SHA256`.
fn upload_headers(headers: &HeaderMap) -> Result<(u64, Sha256Digest), ApiError> {
    let length_required = || {
        ApiError::with_status(
            StatusCode::LENGTH_REQUIRED,
            "length_required",
            "An upload needs Content-Length; chunked uploads are not accepted.",
        )
    };
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err(length_required());
    }
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
    let length = lengths.next().ok_or_else(length_required)?;
    let size = length
        .to_str()
        .ok()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|_| lengths.next().is_none())
        .ok_or_else(|| ApiError::bad_request("invalid_content_length", "Content-Length must be one decimal number."))?;
    let digest = headers
        .get(BLOB_SHA256_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<Sha256Digest>().ok())
        .ok_or_else(|| {
            ApiError::field(
                "X-P2PC-SHA256",
                ErrorCode::InvalidFormat,
                "required: the SHA-256 of the body, 64 lowercase hex characters",
            )
        })?;
    Ok((size, digest))
}

/// Uploads one blob into the caller's account (H2 §7.5): `201` when it is new, `200` with the same body when the
/// account already has it (the caller then holds a claim on it too).
///
/// The body is the raw bytes, with `Content-Length` and `X-P2PC-SHA256`. The size and the quotas are checked before
/// the body is read. There is no whole-request limit: an upload may take as long as it keeps an average of 16 KiB/s
/// over every 60 s and never idles for 60 s.
#[utoipa::path(
    post,
    path = "/v1/blobs",
    tag = "blobs",
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The blob's bytes."),
    params(
        ("X-P2PC-SHA256" = String, Header, description = "SHA-256 of the body, 64 lowercase hex characters."),
        ("Content-Length" = u64, Header, description = "Required; at most `max_blob_mb` MiB."),
    ),
    responses(
        (status = 201, description = "Stored.", body = BlobUploaded),
        (status = 200, description = "The account already had it; the caller now holds a claim on it too.", body = BlobUploaded),
        (status = 400, description = "`body_length_mismatch`: the body was shorter or longer than `Content-Length`, or broke. `invalid_content_length`.", content_type = "application/problem+json", body = Problem),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks `blobs:write`.", content_type = "application/problem+json", body = Problem),
        (status = 408, description = "The body idled for 60 s, or averaged under 16 KiB/s over 60 s.", content_type = "application/problem+json", body = Problem),
        (status = 411, description = "`length_required`: no `Content-Length` (chunked uploads are refused).", content_type = "application/problem+json", body = Problem),
        (status = 413, description = "`too_large`: over `max_blob_mb`.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "`digest_mismatch`: the body does not hash to `X-P2PC-SHA256`. `validation_failed`: the header is missing or malformed.", content_type = "application/problem+json", body = Problem),
        (status = 429, description = "`too_many_uploads`: the caller already has 2 uploads in progress.", content_type = "application/problem+json", body = Problem),
        (status = 507, description = "`quota_exceeded`: the account's blob quota, or the device's, would be exceeded.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn upload_blob(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    if !p.has_scope(Scope::BlobsWrite) {
        return Err(ApiError::forbidden(Scope::BlobsWrite));
    }
    let (size, digest) = upload_headers(&headers)?;
    let config = &state.config.blobs;
    if size > mib(config.max_blob_mb) {
        return Err(ApiError::with_status(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            format!("A blob is at most {} MiB.", config.max_blob_mb),
        ));
    }
    // The reservation, in one short transaction that holds the write lock: no blob row is inserted between the read
    // of the stored bytes and the check against them (an upload gives its reservation back only after its insert).
    let reservation = {
        let mut tx = store::begin_immediate(&state.db).await?;
        let now = state.clock.now();
        let caller = recheck_caller(&mut tx, &state, &p, now).await?;
        let account_stored = blobs::stored_bytes(&mut tx, p.account_id).await?;
        let device = match (caller.device_id(), caller.blobs_quota_mb) {
            (Some(d), Some(quota)) => Some((blobs::device_bytes(&mut tx, p.account_id, d).await?, mib(quota))),
            _ => None,
        };
        let quotas = Quotas {
            account_stored,
            account_quota: mib(config.blobs_quota_mb),
            device,
        };
        let reserved = state.blobs.try_reserve(p.account_id, p.id, size, quotas);
        drop(tx);
        reserved.map_err(|r| match r {
            Refusal::TooManyUploads => ApiError::too_many_requests(
                "too_many_uploads",
                "At most 2 uploads per principal may be in progress at once.",
            ),
            Refusal::QuotaExceeded => ApiError::with_status(
                StatusCode::INSUFFICIENT_STORAGE,
                "quota_exceeded",
                "This blob does not fit the blob quota.",
            ),
        })?
    };
    let mut staging = state.blobs.create_staging().await.map_err(|e| {
        tracing::error!(error = %e, "cannot create a blob staging file");
        ApiError::internal()
    })?;
    let limits = state.blobs.upload_limits();
    let received = match staging.file.as_mut() {
        Some(file) => receive(body, file, size, limits).await,
        None => Err(Failed::Io(std::io::Error::other("no staging file"))),
    };
    let actual = match received {
        Ok(actual) => actual,
        Err(failed) => {
            staging.discard().await;
            return Err(match failed {
                Failed::Timeout => ApiError::request_timeout(),
                Failed::Length => {
                    ApiError::bad_request("body_length_mismatch", "The body was not exactly Content-Length bytes.")
                }
                Failed::Io(e) => {
                    tracing::error!(error = %e, "cannot write a blob staging file");
                    ApiError::internal()
                }
            });
        }
    };
    if actual != digest {
        staging.discard().await;
        return Err(ApiError::unprocessable(
            "digest_mismatch",
            "The body does not hash to X-P2PC-SHA256.",
        ));
    }
    // Step 3 runs in its own task: a client that goes away now (hyper then drops this handler) cannot stop it between
    // the rename and the row insert, which would leave a file that no row refers to. The reservation is given back
    // once the row is in.
    let finish = {
        let (state, p) = (state.clone(), p.clone());
        tokio::spawn(async move {
            let stored = store_received(&state, &p, digest, size, staging).await;
            drop(reservation);
            stored
        })
    };
    let (status, view) = finish.await.map_err(|_| ApiError::internal())??;
    tracing::info!(sha256 = %digest, principal = %p.id, status = status.as_u16(), "blob upload");
    Ok((status, Json(uploaded(&view, state.config.storage.retention()))).into_response())
}

/// Step 3 of an upload, under the `(account, digest)` lock.
async fn store_received(
    state: &AppState,
    p: &Principal,
    digest: Sha256Digest,
    size: u64,
    staging: Staging,
) -> Result<(StatusCode, blobs::BlobView), ApiError> {
    let account = p.account_id;
    let _lock = state.blobs.lock(account, digest).await;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    recheck_caller(&mut tx, state, p, now).await?;
    match blobs::get(&mut tx, account, digest).await? {
        Some(live) if live.deleting_at.is_none() => {
            // Deduplicated: the caller gets its own claim (H2 §5.6).
            blobs::add_claim(&mut tx, account, digest, p.id, now).await?;
            tx.commit().await?;
            staging.discard().await;
            return Ok((StatusCode::OK, live));
        }
        Some(_tombstoned) => {
            // A deletion stopped after its tombstone: finish it (file, then row) before storing the blob as new.
            drop(tx);
            if let Err(e) = state.blobs.remove(account, digest).await {
                tracing::error!(error = %e, sha256 = %digest, "cannot delete a tombstoned blob's file");
                staging.discard().await;
                return Err(ApiError::internal());
            }
            let mut tx = store::begin_immediate(&state.db).await?;
            blobs::delete_tombstoned(&mut tx, account, digest).await?;
            tx.commit().await?;
        }
        None => drop(tx),
    }
    // New: the file first (no I/O under the write lock), then the row.
    if let Err(e) = state.blobs.publish(staging, account, digest).await {
        tracing::error!(error = %e, "cannot store a blob");
        return Err(ApiError::internal());
    }
    let inserted = async {
        let mut tx = store::begin_immediate(&state.db).await?;
        let now = state.clock.now();
        recheck_caller(&mut tx, state, p, now).await?;
        blobs::insert(&mut tx, account, digest, size, now).await?;
        blobs::add_claim(&mut tx, account, digest, p.id, now).await?;
        let view = blobs::get(&mut tx, account, digest)
            .await?
            .ok_or_else(ApiError::internal)?;
        tx.commit().await?;
        Ok::<_, ApiError>(view)
    }
    .await;
    match inserted {
        Ok(view) => Ok((StatusCode::CREATED, view)),
        Err(e) => {
            // No row refers to the file: it goes.
            if let Err(io) = state.blobs.remove(account, digest).await {
                tracing::error!(error = %io, "cannot delete a blob file without a row");
            }
            Err(e)
        }
    }
}

/// Whether the caller's account holds the blob: `200` with its size as `Content-Length`, else `404`. Another
/// account's blobs are never seen (SI-H2-8).
#[utoipa::path(
    head,
    path = "/v1/blobs/{sha256}",
    tag = "blobs",
    params(("sha256" = String, Path, description = "The blob's SHA-256, 64 lowercase hex characters.")),
    responses(
        (status = 200, description = "The account has it; `Content-Length` is its size. No body.", headers(("Content-Length" = u64, description = "The blob's size in bytes."))),
        (status = 401, description = "Missing or invalid key."),
        (status = 403, description = "The caller has neither `blobs:write` nor `jobs:read`."),
        (status = 404, description = "The account has no such blob."),
    )
)]
pub async fn head_blob(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(sha256): Path<String>,
) -> Result<Response, ApiError> {
    if !p.has_scope(Scope::BlobsWrite) && !p.has_scope(Scope::JobsRead) {
        return Err(ApiError::forbidden(Scope::BlobsWrite));
    }
    let digest = digest_param(&sha256)?;
    let mut conn = state.db.acquire().await?;
    let view = blobs::get_live(&mut conn, p.account_id, digest)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let mut resp = StatusCode::OK.into_response();
    resp.headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(view.size));
    Ok(resp)
}

/// The `cursor` of a blob page: `<created_at>.<sha256>` of the last item.
fn encode_cursor(view: &blobs::BlobView) -> String {
    format!("{}.{}", view.created_at.unix_timestamp(), view.sha256)
}

fn decode_cursor(text: &str) -> Option<(OffsetDateTime, Sha256Digest)> {
    let (at, sha) = text.split_once('.')?;
    if at.is_empty() || !at.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let at = OffsetDateTime::from_unix_timestamp(at.parse().ok()?).ok()?;
    Some((at, sha.parse().ok()?))
}

/// The caller's account's blobs, oldest first, with how many jobs reference each and when it expires, plus the
/// account's stored bytes and quota.
#[utoipa::path(
    get,
    path = "/v1/blobs",
    tag = "blobs",
    params(PageParams),
    responses(
        (status = 200, description = "A page of blobs. `expires_at` is `null` while a non-terminal job references the blob.", body = BlobList),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller lacks `jobs:read`.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_blobs(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    ApiQuery(q): ApiQuery<PageParams>,
) -> Result<Json<BlobList>, ApiError> {
    let limit = page_limit(q.limit)?;
    let after = q
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c).ok_or_else(bad_cursor))
        .transpose()?;
    let mut conn = state.db.acquire().await?;
    let mut rows = blobs::list(&mut conn, p.account_id, after, limit + 1).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more.then(|| rows.last().map(encode_cursor)).flatten();
    let total_bytes = blobs::stored_bytes(&mut conn, p.account_id).await?;
    let retention = state.config.storage.retention();
    let items: Vec<BlobInfo> = rows.iter().map(|v| v.info(retention)).collect();
    Ok(Json(BlobList {
        items,
        next_cursor,
        total_bytes,
        quota_mb: state.config.blobs.blobs_quota_mb,
    }))
}

/// Withdraws the caller's claim on a blob of its account (an `admin`: every claim); when no claim remains, the blob
/// is deleted at once (tombstone, file, row; H2 §7.5).
///
/// A caller without a claim gets `403` unless it is `admin`. While a non-terminal job references the blob, `409
/// blob_in_use` and nothing changes.
#[utoipa::path(
    delete,
    path = "/v1/blobs/{sha256}",
    tag = "blobs",
    params(("sha256" = String, Path, description = "The blob's SHA-256, 64 lowercase hex characters.")),
    responses(
        (status = 204, description = "The claim (or, for an admin, every claim) is gone; with the last one, the blob too."),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the caller lacks `blobs:write`, or holds no claim on the blob and is not `admin`.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "The account has no such blob.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`blob_in_use`: a non-terminal job references it.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn delete_blob(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path(sha256): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !p.has_scope(Scope::BlobsWrite) {
        return Err(ApiError::forbidden(Scope::BlobsWrite));
    }
    let digest = digest_param(&sha256)?;
    let account = p.account_id;
    let _lock = state.blobs.lock(account, digest).await;
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    let caller = recheck_caller(&mut tx, &state, &p, now).await?;
    let view = blobs::get_live(&mut tx, account, digest)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let admin = caller.is_admin();
    if !admin && !blobs::has_claim(&mut tx, account, digest, p.id).await? {
        return Err(ApiError::with_status(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Only a principal that uploaded this blob, or an admin, may delete it.",
        ));
    }
    if view.in_use {
        return Err(ApiError::conflict(
            "blob_in_use",
            "A job that has not finished uses this blob as an input.",
        ));
    }
    let left = blobs::remove_claims(&mut tx, account, digest, (!admin).then_some(p.id)).await?;
    let tombstoned = left == 0 && blobs::tombstone(&mut tx, account, digest, now).await?;
    tx.commit().await?;
    if tombstoned {
        delete_tombstoned(&state, account, digest).await;
    }
    tracing::info!(sha256 = %digest, principal = %p.id, deleted = tombstoned, "blob claim withdrawn");
    Ok(StatusCode::NO_CONTENT)
}

/// Steps 2 and 3 of a deletion whose tombstone is set, under the caller's lock: the file, then the row. A failure
/// leaves the tombstone, from which the GC resumes.
pub(crate) async fn delete_tombstoned(state: &AppState, account: p2pc_proto::ids::AccountId, digest: Sha256Digest) {
    let now = state.clock.now();
    if let Err(e) = state.blobs.remove(account, digest).await {
        tracing::warn!(error = %e, sha256 = %digest, "cannot delete a blob's file; the GC retries it");
        if let Ok(mut tx) = store::begin_immediate(&state.db).await
            && blobs::record_attempt(&mut tx, account, digest, now).await.is_ok()
        {
            let _ = tx.commit().await;
        }
        return;
    }
    let deleted = async {
        let mut tx = store::begin_immediate(&state.db).await?;
        blobs::delete_tombstoned(&mut tx, account, digest).await?;
        tx.commit().await?;
        Ok::<_, store::StoreError>(())
    }
    .await;
    if let Err(e) = deleted {
        tracing::warn!(error = %e, sha256 = %digest, "cannot delete a blob's row; the GC retries it");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip_and_refuse_garbage() {
        let view = blobs::BlobView {
            sha256: Sha256Digest([0xab; 32]),
            size: 1,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            deleting_at: None,
            referenced_by: 0,
            in_use: false,
            last_end: None,
        };
        let c = encode_cursor(&view);
        assert_eq!(decode_cursor(&c), Some((view.created_at, view.sha256)));
        for bad in ["", ".", "1.", "x.ab", "-1.abcd", &format!("1.{}", "A".repeat(64))] {
            assert_eq!(decode_cursor(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_upload_headers_are_required_and_strict() {
        let sha = "a".repeat(64);
        let headers = |pairs: &[(&str, &str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.append(
                    axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            h
        };
        assert_eq!(
            upload_headers(&headers(&[("content-length", "5"), (BLOB_SHA256_HEADER, &sha)]))
                .unwrap()
                .0,
            5
        );
        let status = |pairs: &[(&str, &str)]| upload_headers(&headers(pairs)).unwrap_err().status();
        assert_eq!(status(&[(BLOB_SHA256_HEADER, &sha)]), StatusCode::LENGTH_REQUIRED);
        assert_eq!(
            status(&[
                ("transfer-encoding", "chunked"),
                ("content-length", "5"),
                (BLOB_SHA256_HEADER, &sha)
            ]),
            StatusCode::LENGTH_REQUIRED
        );
        for bad in ["", "+5", "5 ", "0x5", "99999999999999999999"] {
            assert_eq!(
                status(&[("content-length", bad), (BLOB_SHA256_HEADER, &sha)]),
                StatusCode::BAD_REQUEST,
                "{bad}"
            );
        }
        assert_eq!(
            status(&[
                ("content-length", "5"),
                ("content-length", "5"),
                (BLOB_SHA256_HEADER, &sha)
            ]),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(status(&[("content-length", "5")]), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
