// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /v1/usage` (spec §7, §11, H2 §12): the usage ledger, grouped by job, node, key, device, principal, kind or
//! template.
//!
//! The ledger has one row per finished **slice** (`usage_records`, H2 §12): a batch attempt is one slice, a service
//! attempt is cut at every 00:00 UTC it runs through. Rows are written by the scheduler on `JobFinished` and at each
//! midnight, or estimated by the server when no report covers them (watchdog, cancel on an unreachable node, node
//! loss, a midnight with no usage report). The report covers the rows that **ended** in `[from, to)`, of the caller's
//! account and project only (SI-7). `attempts` counts finished attempts (last slices), so a week-long service is one
//! attempt; `estimated_attempts` counts those that are estimates, and `estimated_slices` every estimated row.

use axum::Json;
use axum::extract::State;
use p2pc_proto::api::{Problem, UsageGroupBy, UsageReport, UsageTotals};
use p2pc_proto::validate::ErrorCode;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::IntoParams;

use crate::app::{AppState, bad_cursor, page_limit};
use crate::auth::{Authorized, JobsReadKey};
use crate::error::ApiError;
use crate::extract::ApiQuery;
use crate::store::leases::{self, UsageQuery, UsageTotalsRow};

/// Seconds in a day: the default range is one UTC day.
const DAY: time::Duration = time::Duration::days(1);

/// `from`, `to`, `group_by`, `limit` and `cursor`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct UsageParams {
    /// Start of the range (RFC 3339, inclusive). Default: the start of the current UTC day, or one day before `to`.
    pub from: Option<String>,
    /// End of the range (RFC 3339, exclusive). Default: one day after `from`.
    pub to: Option<String>,
    /// `job` (default), `node`, `key`, `device`, `principal`, `kind` or `template`. `key` leaves device rows out,
    /// `device` leaves key rows out, `template` leaves out rows with no template; the others cover every row.
    #[param(value_type = Option<String>)]
    pub group_by: Option<UsageGroupBy>,
    /// Groups per page, 1-100 (default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page (opaque).
    pub cursor: Option<String>,
}

fn parse_time(field: &str, text: &str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::parse(text, &Rfc3339)
        .map_err(|_| ApiError::field(field, ErrorCode::InvalidFormat, "must be an RFC 3339 timestamp"))
}

/// A default bound computed from `field`, if it exists and RFC 3339 can write it (years 0000-9999); otherwise the
/// spec's `422` on `field`.
fn writable(t: Option<OffsetDateTime>, field: &str) -> Result<OffsetDateTime, ApiError> {
    t.filter(|t| (0..=9999).contains(&t.year())).ok_or_else(|| {
        ApiError::field(
            field,
            ErrorCode::OutOfRange,
            "too close to the edge of the calendar: give both `from` and `to`",
        )
    })
}

/// The opaque cursor: unpadded base64url of the last group key. A group key is an ID, `key:<id>` or `device:<id>`, a
/// kind or a template ID (`[a-z][a-z0-9-]*`), so anything else is refused.
fn decode_cursor(text: &str) -> Option<String> {
    let bytes = data_encoding::BASE64URL_NOPAD.decode(text.as_bytes()).ok()?;
    let key = String::from_utf8(bytes).ok()?;
    (!key.is_empty()
        && key.len() <= 72
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':')))
    .then_some(key)
}

fn encode_cursor(key: &str) -> String {
    data_encoding::BASE64URL_NOPAD.encode(key.as_bytes())
}

// `..Default::default()` sets nothing today, but it keeps this compiling when the shared type grows (CONTRIBUTING
// rule 7), which is exactly what clippy's `needless_update` cannot know.
#[allow(clippy::needless_update)]
fn totals(row: UsageTotalsRow, key: Option<String>) -> UsageTotals {
    UsageTotals {
        key,
        attempts: row.attempts,
        reserved_cpu_ms: row.reserved_cpu_ms,
        reserved_gpu_ms: row.reserved_gpu_ms,
        used_cpu_ms: row.used_cpu_ms,
        max_rss_mb: row.max_rss_mb,
        units: row.units,
        estimated_attempts: row.estimated_attempts,
        estimated_slices: row.estimated_slices,
        ..UsageTotals::default()
    }
}

/// The usage of the caller's project: the ledger rows (slices, H2 §12) that ended in `[from, to)`, grouped by
/// `group_by`, with cursor pagination over the groups and the total of the whole range, which covers every selected
/// row (so with devices in use the `key` groups may add up to less). `attempts` counts finished attempts. Only the
/// caller's own account and project are ever counted.
#[utoipa::path(
    get,
    path = "/v1/usage",
    tag = "usage",
    params(UsageParams),
    responses(
        (status = 200, description = "The grouped usage and the total of the range.", body = UsageReport),
        (status = 400, description = "Invalid query string (for example an unknown `group_by`).", content_type = "application/problem+json", body = Problem),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The key lacks `jobs:read`.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "Invalid `from`, `to` (`from` must be before `to`), `limit` or `cursor`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn get_usage(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: JobsReadKey,
    ApiQuery(q): ApiQuery<UsageParams>,
) -> Result<Json<UsageReport>, ApiError> {
    let limit = page_limit(q.limit)?;
    let from = q.from.as_deref().map(|t| parse_time("from", t)).transpose()?;
    let to = q.to.as_deref().map(|t| parse_time("to", t)).transpose()?;
    // The other bound defaults to one day away. Checked arithmetic, and a range the response can write in RFC 3339
    // (years 0000-9999): a bound at the edge of the calendar is the client's `422`, never a panic (review P2).
    let (from, to) = match (from, to) {
        (Some(f), Some(t)) => (f, t),
        (Some(f), None) => (f, writable(f.checked_add(DAY), "from")?),
        (None, Some(t)) => (writable(t.checked_sub(DAY), "to")?, t),
        (None, None) => {
            let (start, _) = crate::units::utc_day(state.clock.now());
            let start = OffsetDateTime::from_unix_timestamp(start).map_err(|_| ApiError::internal())?;
            (start, writable(start.checked_add(DAY), "from")?)
        }
    };
    if from >= to {
        return Err(ApiError::field("from", ErrorCode::OutOfRange, "must be before `to`"));
    }
    let after = q
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c).ok_or_else(bad_cursor))
        .transpose()?;
    let group_by = q.group_by.unwrap_or(UsageGroupBy::Job);
    let mut conn = state.db.acquire().await?;
    let query = UsageQuery {
        from,
        to,
        group_by,
        after: after.as_deref(),
        limit: limit + 1,
    };
    let (mut rows, total) = leases::usage_report(&mut conn, p.account_id, p.project_id, &query).await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = more.then(|| rows.last().map(|r| encode_cursor(&r.key))).flatten();
    let mut report = UsageReport::new(from, to, group_by, totals(total, None));
    report.items = rows
        .into_iter()
        .map(|r| {
            let key = r.key.clone();
            totals(r, Some(key))
        })
        .collect();
    report.next_cursor = next_cursor;
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip_and_refuse_anything_but_an_id() {
        for key in [
            "job_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "device:dev_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "key:key_01ARZ3NDEKTSV4RRFFQ69G5FAV", // gitleaks:allow (a key ID, not a secret)
            "service",
            "chat-llm",
        ] {
            assert_eq!(decode_cursor(&encode_cursor(key)).as_deref(), Some(key));
        }
        for bad in [
            "",
            "%%",
            &encode_cursor("a'b"),
            &encode_cursor(""),
            &encode_cursor("a b"),
            &encode_cursor(&"a".repeat(73)),
        ] {
            assert_eq!(decode_cursor(bad), None, "{bad}");
        }
    }
}
