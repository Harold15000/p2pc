// SPDX-License-Identifier: AGPL-3.0-only

//! What the port relay reads and writes (H2 spec §7.4, §12): the lease a `PortOpen` names, the last activity of a
//! service and its traffic per UTC day.
//!
//! These are protocol-side functions: the caller read the job with its account and project first
//! ([`crate::jobs_api::visible_job`]), so they take the job ID alone.

use p2pc_proto::api::ServiceTraffic;
use p2pc_proto::ids::{JobId, LeaseId};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::leases::{self, LeaseRow, LeaseState};
use super::{Conn, StoreError, from_ts, parse_col, ts};

/// Seconds in a UTC day.
const DAY_S: i64 = 86_400;

/// 00:00 UTC of the day of `t`, as `service_traffic.day` stores it.
#[must_use]
pub fn day_of(t: OffsetDateTime) -> i64 {
    ts(t).div_euclid(DAY_S) * DAY_S
}

/// The lease a port connection to `job_id` goes to: the job's current lease, while the service runs on it. `None`
/// when the service is not running (SI-H2-5), so no `PortOpen` ever names a lease that is not current (SI-H2-6).
pub async fn current_lease(conn: &mut Conn, job_id: JobId) -> Result<Option<LeaseRow>, StoreError> {
    let id: Option<String> = sqlx::query_scalar(
        "SELECT l.id FROM leases l JOIN jobs j ON j.job_id = l.job_id \
         WHERE l.job_id = ? AND l.state = 'running' AND l.epoch = j.epoch AND j.status = 'running' \
           AND j.kind = 'service' \
         ORDER BY l.offered_at_ms DESC, l.id LIMIT 1",
    )
    .bind(job_id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(id) = id else {
        return Ok(None);
    };
    let id: LeaseId = parse_col(&id, "leases.id")?;
    Ok(leases::get(conn, id).await?.filter(is_serving))
}

/// Whether `lease` is its job's current lease with the service running on it.
fn is_serving(lease: &LeaseRow) -> bool {
    lease.is_current() && lease.state == LeaseState::Running
}

/// Whether `(lease_id, epoch)` still is its job's current, running lease (SI-H2-6): read again after the agent
/// answered a `PortOpen`, so a connection is never handed over for a lease that was replaced meanwhile.
pub async fn still_current(conn: &mut Conn, lease_id: LeaseId, epoch: u64) -> Result<bool, StoreError> {
    Ok(leases::get(conn, lease_id)
        .await?
        .is_some_and(|lease| lease.epoch == epoch && is_serving(&lease)))
}

/// Moves the last activity of a service to `now` (H2 §7.4 "Idle accounting"); the relay calls it at most once every
/// 10 s per service. Never backwards, and never for an attempt that has not become healthy: `last_activity_at` is
/// `NULL` until then, and the restart policy reads a value as "this attempt became healthy".
pub async fn touch_activity(conn: &mut Conn, job_id: JobId, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE service_state SET last_activity_at = MAX(last_activity_at, ?1), updated_at = ?1 \
         WHERE job_id = ?2 AND last_activity_at IS NOT NULL",
    )
    .bind(ts(now))
    .bind(job_id.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Bytes and connections to add to a service's traffic of one day.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficDelta {
    /// Bytes from clients to the service.
    pub bytes_in: u64,
    /// Bytes from the service to clients.
    pub bytes_out: u64,
    /// Port connections opened.
    pub connections: u64,
}

impl TrafficDelta {
    /// Whether there is nothing to add.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn count(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Adds `delta` to the traffic of `job_id` for the UTC day of `now` (H2 §12): recorded, not billed.
pub async fn add_traffic(
    conn: &mut Conn,
    job_id: JobId,
    now: OffsetDateTime,
    delta: TrafficDelta,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO service_traffic (job_id, day, bytes_in, bytes_out, connections) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (job_id, day) DO UPDATE SET bytes_in = bytes_in + excluded.bytes_in, \
             bytes_out = bytes_out + excluded.bytes_out, connections = connections + excluded.connections",
    )
    .bind(job_id.to_string())
    .bind(day_of(now))
    .bind(count(delta.bytes_in))
    .bind(count(delta.bytes_out))
    .bind(count(delta.connections))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The traffic of `job_id` on the UTC day of `now`, as `GET /v1/jobs/{id}` shows it; `None` when the day has none.
pub async fn traffic_today(
    conn: &mut Conn,
    job_id: JobId,
    now: OffsetDateTime,
) -> Result<Option<ServiceTraffic>, StoreError> {
    let day = day_of(now);
    let row: Option<(i64, i64, i64)> =
        sqlx::query_as("SELECT bytes_in, bytes_out, connections FROM service_traffic WHERE job_id = ? AND day = ?")
            .bind(job_id.to_string())
            .bind(day)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((bytes_in, bytes_out, connections)) = row else {
        return Ok(None);
    };
    let count = |v: i64, name: &'static str| u64::try_from(v).map_err(|_| StoreError::Corrupt(name));
    let (bytes_in, bytes_out, connections) = (
        count(bytes_in, "service_traffic.bytes_in")?,
        count(bytes_out, "service_traffic.bytes_out")?,
        count(connections, "service_traffic.connections")?,
    );
    let day = from_ts(day, "service_traffic.day")?
        .format(&Rfc3339)
        .map_err(|_| StoreError::Corrupt("service_traffic.day"))?;
    // Built from its wire form rather than as a struct literal, so a field added to the type does not break this
    // crate (CONTRIBUTING "Shared types grow").
    serde_json::from_value(serde_json::json!({
        "day": day, "bytes_in": bytes_in, "bytes_out": bytes_out, "connections": connections,
    }))
    .map(Some)
    .map_err(|_| StoreError::Corrupt("service_traffic"))
}
