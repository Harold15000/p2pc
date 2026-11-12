// SPDX-License-Identifier: AGPL-3.0-only

//! The ledger's slices and the services' day reservations (H2 §12): the repository of [`crate::units`]'s metering.
//!
//! These are **protocol-side** functions, like [`super::leases`]: the metering runs for every account, and each row
//! it writes takes its principal, account and project from the job's own row, never from its caller.
//!
//! - A **slice** is one row of `usage_records`: a batch attempt is one slice, a service attempt is cut at every 00:00
//!   UTC it runs through. The ledger is append-only: a slice is written once ([`insert_slice`]).
//! - A **day reservation** is `service_state.cap_day` and `cap_reserved_units`: what a service of a capped principal
//!   holds against the cap of one UTC day ([`set_reservation`]).

use p2pc_proto::api::{JobStatus, Principal};
use p2pc_proto::ids::{AccountId, JobId, LeaseId, NodeId, ProjectId};
use p2pc_proto::units::Units;
use time::OffsetDateTime;

use super::{Conn, StoreError, parse_col, ts};
use crate::scheduler::fit::Reserved;
use crate::units::Amounts;

/// One slice to append to the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSlice {
    /// The job.
    pub job_id: JobId,
    /// Its attempt.
    pub attempt: u32,
    /// The attempt's lease.
    pub lease_id: LeaseId,
    /// The node that ran it.
    pub node_id: NodeId,
    /// The attempt's start (Unix seconds), the same on every slice of the attempt.
    pub started_at: i64,
    /// The slice's start.
    pub slice_start: i64,
    /// The slice's end (its `ended_at`).
    pub slice_end: i64,
    /// Whether it is the attempt's last slice.
    pub last_slice: bool,
    /// 00:00 UTC of the day it is charged to.
    pub charge_day: i64,
    /// Reserved time and units.
    pub amounts: Amounts,
    /// CPU time used in the slice.
    pub used_cpu_ms: u64,
    /// The attempt's peak resident memory so far.
    pub max_rss_mb: u64,
    /// A server estimate: no report covers the slice.
    pub estimated: bool,
}

fn int(v: u64, column: &'static str) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt(column))
}

fn u64_col(v: i64, column: &'static str) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt(column))
}

fn u32_col(v: i64, column: &'static str) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::Corrupt(column))
}

/// Appends one slice. The principal (key or device), account, project, `kind` and `template_id` come from the job's
/// own row (H2 §5.6). The ledger's key (`UNIQUE (job_id, attempt, slice_start)`, one last slice per attempt) refuses
/// a slice written twice.
pub async fn insert_slice(conn: &mut Conn, s: &NewSlice) -> Result<(), StoreError> {
    let done = sqlx::query(
        "INSERT INTO usage_records (job_id, attempt, lease_id, node_id, key_id, device_id, account_id, project_id, \
         kind, template_id, started_at, ended_at, slice_start, slice_end, last_slice, charge_day, reserved_cpu_ms, \
         reserved_gpu_ms, used_cpu_ms, max_rss_mb, units, estimated) \
         SELECT ?1, ?2, ?3, ?4, j.key_id, j.device_id, j.account_id, j.project_id, j.kind, j.template_id, ?5, ?7, \
                ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15 \
         FROM jobs j WHERE j.job_id = ?1",
    )
    .bind(s.job_id.to_string())
    .bind(i64::from(s.attempt))
    .bind(s.lease_id.to_string())
    .bind(s.node_id.to_string())
    .bind(s.started_at)
    .bind(s.slice_start)
    .bind(s.slice_end)
    .bind(s.last_slice)
    .bind(s.charge_day)
    .bind(int(s.amounts.reserved_cpu_ms, "usage_records.reserved_cpu_ms")?)
    .bind(int(s.amounts.reserved_gpu_ms, "usage_records.reserved_gpu_ms")?)
    .bind(int(s.used_cpu_ms, "usage_records.used_cpu_ms")?)
    .bind(int(s.max_rss_mb, "usage_records.max_rss_mb")?)
    .bind(int(s.amounts.units.milli(), "usage_records.units")?)
    .bind(s.estimated)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if done == 1 {
        Ok(())
    } else {
        Err(StoreError::Corrupt("usage_records.job_id"))
    }
}

/// The slices an attempt already has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttemptSoFar {
    /// The attempt's start as its first slice recorded it.
    pub started_at: Option<i64>,
    /// The end of its latest slice.
    pub cut_at: Option<i64>,
    /// The CPU time its slices recorded.
    pub used_cpu_ms: u64,
}

/// The slices of attempt `attempt` of `job_id` written so far.
pub async fn attempt_so_far(conn: &mut Conn, job_id: JobId, attempt: u32) -> Result<AttemptSoFar, StoreError> {
    let (started, cut, used): (Option<i64>, Option<i64>, i64) = sqlx::query_as(
        "SELECT MIN(started_at), MAX(slice_end), COALESCE(SUM(used_cpu_ms), 0) FROM usage_records \
         WHERE job_id = ? AND attempt = ?",
    )
    .bind(job_id.to_string())
    .bind(i64::from(attempt))
    .fetch_one(&mut *conn)
    .await?;
    Ok(AttemptSoFar {
        started_at: started,
        cut_at: cut,
        used_cpu_ms: u64_col(used, "usage_records.used_cpu_ms")?,
    })
}

/// The units of `job_id`'s rows charged to `day`.
pub async fn job_units_on_day(conn: &mut Conn, job_id: JobId, day: i64) -> Result<Units, StoreError> {
    let units: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(units), 0) FROM usage_records WHERE job_id = ? AND charge_day = ?")
            .bind(job_id.to_string())
            .bind(day)
            .fetch_one(&mut *conn)
            .await?;
    Ok(Units::from_milli(u64_col(units, "usage_records.units")?))
}

/// Sets a service's day reservation (`Some((day, units))`) or clears it (`None`). Nothing for a job without a
/// `service_state` row (a batch job).
pub async fn set_reservation(
    conn: &mut Conn,
    job_id: JobId,
    reservation: Option<(i64, Units)>,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let units = reservation
        .map(|(_, u)| int(u.milli(), "service_state.cap_reserved_units"))
        .transpose()?;
    sqlx::query("UPDATE service_state SET cap_day = ?, cap_reserved_units = ?, updated_at = ? WHERE job_id = ?")
        .bind(reservation.map(|(d, _)| d))
        .bind(units)
        .bind(ts(now))
        .bind(job_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The running attempt of a metered service.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveAttempt {
    /// Its lease (accepted or running).
    pub lease_id: LeaseId,
    /// The lease's epoch.
    pub epoch: u64,
    /// The attempt.
    pub attempt: u32,
    /// Its node.
    pub node_id: NodeId,
    /// What the lease reserved.
    pub reserved: Reserved,
    /// The attempt's start (Unix seconds): as its first slice recorded it, or the lease's start (or acceptance), as
    /// the ledger counts it (§11).
    pub started_at: i64,
    /// Where its current slice starts: the end of its latest slice, or `started_at`.
    pub cut_at: i64,
    /// The CPU time its slices recorded.
    pub used_cpu_ms: u64,
}

/// A service that is not terminal, with what the metering reads (H2 §12).
#[derive(Debug, Clone, PartialEq)]
pub struct MeteredService {
    /// The job.
    pub job_id: JobId,
    /// Its account.
    pub account_id: AccountId,
    /// Its project.
    pub project_id: ProjectId,
    /// Its principal.
    pub principal: Principal,
    /// `queued`, `assigned` or `running`.
    pub status: JobStatus,
    /// Whether a stop was already requested.
    pub cancel_requested: bool,
    /// `timeout_s`, per attempt.
    pub timeout_s: u32,
    /// The vCPUs it asks for.
    pub cpu: f64,
    /// The GPUs it asks for.
    pub gpu: u32,
    /// The principal's `daily_unit_cap` now.
    pub cap: Option<Units>,
    /// The day of its reservation.
    pub cap_day: Option<i64>,
    /// The milli-units reserved for `cap_day`.
    pub cap_reserved: Option<Units>,
    /// The units of its rows charged to `cap_day`.
    pub rows_on_cap_day: Units,
    /// Its running attempt, if one was accepted.
    pub attempt: Option<ActiveAttempt>,
}

#[derive(sqlx::FromRow)]
struct RawMetered {
    job_id: String,
    account_id: String,
    project_id: String,
    key_id: Option<String>,
    device_id: Option<String>,
    status: String,
    cancel_requested: bool,
    timeout_s: Option<i64>,
    cpu: Option<f64>,
    gpu: Option<i64>,
    cap: Option<i64>,
    cap_day: Option<i64>,
    cap_reserved: Option<i64>,
    rows_on_cap_day: i64,
    lease_id: Option<String>,
    epoch: Option<i64>,
    attempt: Option<i64>,
    node_id: Option<String>,
    reserved: Option<String>,
    lease_start: Option<i64>,
    first_start: Option<i64>,
    cut_at: Option<i64>,
    used_cpu_ms: i64,
}

/// The non-terminal services, with their principal's cap (from `api_keys` or `devices`), their reservation and their
/// accepted or running lease. The ledger subqueries read the attempt's own slices.
macro_rules! select_metered {
    ($tail:literal) => {
        concat!(
            "SELECT j.job_id, j.account_id, j.project_id, j.key_id, j.device_id, j.status, \
                    j.cancel_requested_at IS NOT NULL AS cancel_requested, \
                    json_extract(j.spec_view, '$.timeout_s') AS timeout_s, \
                    json_extract(j.spec_view, '$.resources.cpu') AS cpu, \
                    json_extract(j.spec_view, '$.resources.gpu') AS gpu, \
                    COALESCE(k.daily_unit_cap, d.daily_unit_cap) AS cap, \
                    s.cap_day, s.cap_reserved_units AS cap_reserved, \
                    (SELECT COALESCE(SUM(u.units), 0) FROM usage_records u \
                     WHERE u.job_id = j.job_id AND u.charge_day = s.cap_day) AS rows_on_cap_day, \
                    l.id AS lease_id, l.epoch, l.attempt, l.node_id, l.reserved, \
                    COALESCE(l.started_at, l.accepted_at) AS lease_start, \
                    (SELECT MIN(u.started_at) FROM usage_records u \
                     WHERE u.job_id = j.job_id AND u.attempt = l.attempt) AS first_start, \
                    (SELECT MAX(u.slice_end) FROM usage_records u \
                     WHERE u.job_id = j.job_id AND u.attempt = l.attempt) AS cut_at, \
                    (SELECT COALESCE(SUM(u.used_cpu_ms), 0) FROM usage_records u \
                     WHERE u.job_id = j.job_id AND u.attempt = l.attempt) AS used_cpu_ms \
             FROM jobs j \
             LEFT JOIN service_state s ON s.job_id = j.job_id \
             LEFT JOIN api_keys k ON k.key_id = j.key_id \
             LEFT JOIN devices d ON d.device_id = j.device_id \
             LEFT JOIN leases l ON l.job_id = j.job_id AND l.state IN ('accepted', 'running') \
             WHERE j.kind = 'service' AND j.status IN ('queued', 'assigned', 'running') ",
            $tail
        )
    };
}

fn status(text: &str) -> Result<JobStatus, StoreError> {
    JobStatus::ALL
        .into_iter()
        .find(|s| s.as_str() == text)
        .ok_or(StoreError::Corrupt("jobs.status"))
}

fn units_opt(v: Option<i64>, column: &'static str) -> Result<Option<Units>, StoreError> {
    v.map(|m| u64_col(m, column).map(Units::from_milli)).transpose()
}

fn decode(raw: RawMetered) -> Result<MeteredService, StoreError> {
    let attempt = match (raw.lease_id, raw.epoch, raw.attempt, raw.node_id, raw.reserved) {
        (Some(id), Some(epoch), Some(attempt), Some(node), Some(reserved)) => {
            // A lease that was accepted has a start for the ledger: its acceptance at the latest.
            let started_at = raw
                .first_start
                .or(raw.lease_start)
                .ok_or(StoreError::Corrupt("leases.accepted_at"))?;
            Some(ActiveAttempt {
                lease_id: parse_col(&id, "leases.id")?,
                epoch: u64_col(epoch, "leases.epoch")?,
                attempt: u32_col(attempt, "leases.attempt")?,
                node_id: parse_col(&node, "leases.node_id")?,
                reserved: serde_json::from_str(&reserved).map_err(|_| StoreError::Corrupt("leases.reserved"))?,
                started_at,
                cut_at: raw.cut_at.unwrap_or(started_at).max(started_at),
                used_cpu_ms: u64_col(raw.used_cpu_ms, "usage_records.used_cpu_ms")?,
            })
        }
        _ => None,
    };
    Ok(MeteredService {
        job_id: parse_col(&raw.job_id, "jobs.job_id")?,
        account_id: parse_col(&raw.account_id, "jobs.account_id")?,
        project_id: parse_col(&raw.project_id, "jobs.project_id")?,
        principal: super::jobs::principal_cols(
            raw.key_id.as_deref(),
            raw.device_id.as_deref(),
            "jobs.key_id/device_id",
        )?,
        status: status(&raw.status)?,
        cancel_requested: raw.cancel_requested,
        timeout_s: u32_col(raw.timeout_s.unwrap_or(0), "jobs.spec_view.timeout_s")?,
        cpu: raw.cpu.unwrap_or(0.0),
        gpu: u32_col(raw.gpu.unwrap_or(0), "jobs.spec_view.resources.gpu")?,
        cap: units_opt(raw.cap, "daily_unit_cap")?,
        cap_day: raw.cap_day,
        cap_reserved: units_opt(raw.cap_reserved, "service_state.cap_reserved_units")?,
        rows_on_cap_day: Units::from_milli(u64_col(raw.rows_on_cap_day, "usage_records.units")?),
        attempt,
    })
}

/// Every service that is not terminal, oldest first. A row that does not decode is logged and left out, so one bad
/// row never stops the metering of the others.
pub async fn metered_services(conn: &mut Conn) -> Result<Vec<MeteredService>, StoreError> {
    let rows: Vec<RawMetered> = sqlx::query_as(select_metered!("ORDER BY j.created_at, j.job_id"))
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|raw| {
            let id = raw.job_id.clone();
            decode(raw)
                .map_err(
                    |e| tracing::warn!(error = %e, job_id = %id, "service skipped by the metering: it does not decode"),
                )
                .ok()
        })
        .collect())
}

/// One service, if it is not terminal.
pub async fn metered_service(conn: &mut Conn, job_id: JobId) -> Result<Option<MeteredService>, StoreError> {
    let raw: Option<RawMetered> = sqlx::query_as(select_metered!("AND j.job_id = ?"))
        .bind(job_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    raw.map(decode).transpose()
}

#[cfg(test)]
pub(crate) mod tests {
    //! The metering of services through the scheduler (H2 §12): midnight slices with their reports, the catch-up of a
    //! hub that was down, the slices an attempt's end writes, and the day reservation with `cap_reached`. Time moves
    //! only when a test moves the clock.

    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use p2pc_proto::api::{JobSpec, REASON_CAP_REACHED, UsageGroupBy};
    use p2pc_proto::ids::DeviceId;
    use p2pc_proto::protocol::{AgentMsg, Outcome, RunningLease, ServerMsg, Usage, capability};
    use time::macros::datetime;

    use super::*;
    use crate::scheduler::tests::{Clean, Fx};
    use crate::store::jobs::{self, NewJob};
    use crate::store::leases::{self, UsageQuery};
    use crate::units::{self, DAY_S};

    pub(crate) const GPU_HOUR: Units = Units::from_units(10);
    /// 00:00 UTC of the fixture's first day (`T0` is 10:00 that day).
    const D0: i64 = datetime!(2026-11-05 00:00:00 UTC).unix_timestamp();

    /// One ledger row, as the tests read it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Row {
        pub attempt: i64,
        pub started_at: i64,
        pub slice_start: i64,
        pub slice_end: i64,
        pub last_slice: bool,
        pub charge_day: i64,
        pub units: i64,
        pub used_cpu_ms: i64,
        pub max_rss_mb: i64,
        pub estimated: bool,
    }

    pub(crate) async fn rows(conn: &mut Conn, job: JobId) -> Vec<Row> {
        type Raw = (i64, i64, i64, i64, bool, i64, i64, i64, i64, bool);
        let raw: Vec<Raw> = sqlx::query_as(
            "SELECT attempt, started_at, slice_start, slice_end, last_slice, charge_day, units, used_cpu_ms, \
                    max_rss_mb, estimated FROM usage_records WHERE job_id = ? ORDER BY attempt, slice_start",
        )
        .bind(job.to_string())
        .fetch_all(&mut *conn)
        .await
        .unwrap();
        raw.into_iter()
            .map(|r| Row {
                attempt: r.0,
                started_at: r.1,
                slice_start: r.2,
                slice_end: r.3,
                last_slice: r.4,
                charge_day: r.5,
                units: r.6,
                used_cpu_ms: r.7,
                max_rss_mb: r.8,
                estimated: r.9,
            })
            .collect()
    }

    /// A node whose agent runs services, offering `cpu` vCPUs.
    pub(crate) async fn service_node(fx: &Fx, cpu: f64) -> NodeId {
        let node = fx.node(cpu, 8192, 0).await;
        sqlx::query("UPDATE nodes SET features = ? WHERE id = ?")
            .bind(serde_json::json!([capability::SERVICE_JOBS]).to_string())
            .bind(node.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
        node
    }

    /// The spec of a service of `cpu` vCPUs that may run `timeout_s`.
    pub(crate) fn service_spec(cpu: f64, timeout_s: u32) -> JobSpec {
        serde_json::from_value(serde_json::json!({
            "kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
            "resources": {"cpu": cpu, "memory_mb": 256}, "timeout_s": timeout_s,
            "service": {"ports": [{"port": 8080, "name": "http"}]},
        }))
        .unwrap()
    }

    /// Creates a service of `principal` as `POST /v1/jobs` does: `units_reserved` 0 and, for a capped principal, the
    /// day reservation (`Err` is the `402`).
    pub(crate) async fn create_service(
        fx: &Fx,
        principal: Principal,
        spec: JobSpec,
    ) -> Result<JobId, crate::units::CapExceeded> {
        let mut tx = crate::store::begin_immediate(&fx.db).await.unwrap();
        let now = fx.now();
        let cap: Option<i64> = match principal {
            Principal::Key(k) => sqlx::query_scalar("SELECT daily_unit_cap FROM api_keys WHERE key_id = ?")
                .bind(k.to_string())
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            Principal::Device(d) => sqlx::query_scalar("SELECT daily_unit_cap FROM devices WHERE device_id = ?")
                .bind(d.to_string())
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
        };
        let held = match cap {
            Some(cap) => Some(
                units::reserve_new_service(
                    &mut tx,
                    fx.account,
                    principal,
                    Units::from_milli(u64::try_from(cap).unwrap()),
                    &spec,
                    GPU_HOUR,
                    now,
                )
                .await
                .unwrap()?,
            ),
            None => None,
        };
        let job = NewJob {
            job_id: JobId::generate(),
            account_id: fx.account,
            project_id: fx.project,
            principal,
            units_reserved: Units::ZERO,
            files_meta: p2pc_proto::api::FileMeta::compute_all(&spec).unwrap(),
            spec,
            spec_hash: format!("sha256:{}", "0".repeat(64)),
        };
        let id = jobs::insert(&mut tx, &job, now).await.unwrap().job_id;
        if let Some(held) = held {
            units::hold(&mut tx, id, held, now).await.unwrap();
        }
        tx.commit().await.unwrap();
        Ok(id)
    }

    /// A device of the fixture's project with a cap (milli-units, `None`: uncapped).
    pub(crate) async fn device(fx: &Fx, cap: Option<u64>) -> DeviceId {
        let id = DeviceId::generate();
        sqlx::query(
            "INSERT INTO devices (device_id, account_id, project_id, iroh_node_id, scopes, daily_unit_cap, created_at) \
             VALUES (?, ?, ?, ?, '[\"admin\"]', ?, 0)",
        )
        .bind(id.to_string())
        .bind(fx.account.to_string())
        .bind(fx.project.to_string())
        .bind(format!(
            "{:0<64}",
            data_encoding::HEXLOWER.encode(id.to_string().as_bytes())
        ))
        .bind(cap.map(|c| i64::try_from(c).unwrap()))
        .execute(&fx.db)
        .await
        .unwrap();
        id
    }

    /// Sets the key's cap (milli-units, `None`: uncapped).
    pub(crate) async fn set_key_cap(fx: &Fx, cap: Option<u64>) {
        sqlx::query("UPDATE api_keys SET daily_unit_cap = ? WHERE key_id = ?")
            .bind(cap.map(|c| i64::try_from(c).unwrap()))
            .bind(fx.key.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
    }

    /// A heartbeat of `node` reporting the usage of one service lease.
    pub(crate) async fn report(fx: &Fx, node: NodeId, lease: LeaseId, epoch: u64, used: u64, rss: u64) {
        let running = [RunningLease {
            used_cpu_ms: Some(used),
            max_rss_mb: Some(rss),
            ..RunningLease::new(lease, epoch)
        }];
        fx.sched.on_heartbeat(node, &running).await.unwrap();
    }

    /// `JobFinished` with these usage figures.
    pub(crate) fn finished(lease: LeaseId, epoch: u64, outcome: Outcome, used: u64, rss: u64) -> AgentMsg {
        AgentMsg::JobFinished {
            lease_id: lease,
            epoch,
            outcome,
            exit_code: (outcome == Outcome::Exited).then_some(0),
            error: None,
            usage: Usage {
                wall_ms: 1,
                cpu_used_ms: used,
                max_rss_mb: rss,
            },
            outputs: vec![],
        }
    }

    fn at(t: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(t).unwrap()
    }

    /// Moves the clock to `t` (Unix seconds).
    fn to(fx: &Fx, t: i64) {
        let now = fx.now().unix_timestamp();
        assert!(t >= now, "the clock only moves forward");
        fx.advance(t - now);
    }

    async fn spent(fx: &Fx, principal: Principal, day: i64) -> u64 {
        let mut conn = fx.db.acquire().await.unwrap();
        leases::spent(&mut conn, fx.account, principal, day).await.unwrap()
    }

    async fn reservation(fx: &Fx, job: JobId) -> (Option<i64>, Option<i64>) {
        sqlx::query_as("SELECT cap_day, cap_reserved_units FROM service_state WHERE job_id = ?")
            .bind(job.to_string())
            .fetch_one(&fx.db)
            .await
            .unwrap()
    }

    /// 1 vCPU for `secs` seconds, in milli-units.
    fn one_cpu(secs: i64) -> i64 {
        i64::try_from(units::Rate::new(1.0, 0, GPU_HOUR).units_for(secs).milli()).unwrap()
    }

    #[tokio::test]
    async fn a_service_is_cut_at_every_midnight_it_runs_through() {
        let fx = Fx::new().await;
        let node = service_node(&fx, 4.0).await;
        let job = create_service(&fx, Principal::Key(fx.key), service_spec(1.0, 30 * 86_400))
            .await
            .unwrap();
        let (_, lease, epoch) = fx.running(job).await;
        let start = fx.now().unix_timestamp();
        // An hour in, the agent reports its usage so far.
        fx.advance(3_600);
        report(&fx, node, lease, epoch, 1_000, 100).await;
        // Nothing to cut before midnight.
        fx.sched.tick().await.clean();
        let mut conn = fx.db.acquire().await.unwrap();
        assert_eq!(rows(&mut conn, job).await, vec![]);
        // The first pass after midnight writes the slice of the day that ended, with the report.
        let m1 = D0 + DAY_S;
        to(&fx, m1 + 1);
        fx.sched.tick().await.clean();
        let first = Row {
            attempt: 1,
            started_at: start,
            slice_start: start,
            slice_end: m1,
            last_slice: false,
            charge_day: D0,
            units: one_cpu(m1 - start),
            used_cpu_ms: 1_000,
            max_rss_mb: 100,
            estimated: false,
        };
        assert_eq!(rows(&mut conn, job).await, vec![first.clone()]);
        // A second pass writes nothing more.
        fx.sched.tick().await.clean();
        assert_eq!(rows(&mut conn, job).await.len(), 1);
        // No report during the next day: its slice is the server's estimate, with nothing measured.
        let m2 = m1 + DAY_S;
        to(&fx, m2 + 5);
        fx.sched.tick().await.clean();
        let second = Row {
            slice_start: m1,
            slice_end: m2,
            charge_day: m1,
            units: one_cpu(DAY_S),
            used_cpu_ms: 0,
            max_rss_mb: 0,
            estimated: true,
            ..first.clone()
        };
        assert_eq!(rows(&mut conn, job).await, vec![first.clone(), second.clone()]);
        // The end writes the last slice: the final cumulative figure minus what the earlier slices recorded.
        to(&fx, m2 + 7_200);
        report(&fx, node, lease, epoch, 5_000, 300).await;
        fx.msg(node, finished(lease, epoch, Outcome::Cancelled, 9_000, 400))
            .await;
        let last = Row {
            slice_start: m2,
            slice_end: m2 + 7_200,
            last_slice: true,
            charge_day: m2,
            units: one_cpu(7_200),
            used_cpu_ms: 8_000,
            max_rss_mb: 400,
            estimated: false,
            ..first.clone()
        };
        assert_eq!(rows(&mut conn, job).await, vec![first.clone(), second, last]);
        // The cap counts each slice on the day it lies in.
        let p = Principal::Key(fx.key);
        assert_eq!(spent(&fx, p, D0).await, u64::try_from(one_cpu(m1 - start)).unwrap());
        assert_eq!(spent(&fx, p, m1).await, u64::try_from(one_cpu(DAY_S)).unwrap());
        assert_eq!(spent(&fx, p, m2).await, u64::try_from(one_cpu(7_200)).unwrap());
        // `GET /v1/usage` over the three days: one attempt, one estimated slice.
        let q = UsageQuery {
            from: at(D0),
            to: at(m2 + DAY_S),
            group_by: UsageGroupBy::Job,
            after: None,
            limit: 10,
        };
        let (groups, total) = leases::usage_report(&mut conn, fx.account, fx.project, &q)
            .await
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            (total.attempts, total.estimated_attempts, total.estimated_slices),
            (1, 0, 1)
        );
        assert_eq!(total.used_cpu_ms, 9_000);
        assert_eq!(total.max_rss_mb, 400);
        // The range of the first day alone: its midnight slice adds to the sums, not to `attempts`.
        let q = UsageQuery { to: at(m1 + 1), ..q };
        let (_, day1) = leases::usage_report(&mut conn, fx.account, fx.project, &q)
            .await
            .unwrap();
        assert_eq!(
            (day1.attempts, day1.units.milli()),
            (0, u64::try_from(one_cpu(m1 - start)).unwrap())
        );
    }

    #[tokio::test]
    async fn a_hub_down_at_midnight_writes_the_missed_slices_at_start() {
        let fx = Fx::new().await;
        let node = service_node(&fx, 4.0).await;
        let job = create_service(&fx, Principal::Key(fx.key), service_spec(1.0, 30 * 86_400))
            .await
            .unwrap();
        let (_, lease, epoch) = fx.running(job).await;
        let start = fx.now().unix_timestamp();
        report(&fx, node, lease, epoch, 500, 50).await;
        // The hub is down for three midnights and comes back at 06:00 on the fourth day: a new process, which
        // remembers no report.
        to(&fx, D0 + 3 * DAY_S + 6 * 3_600);
        let restarted = fx.another_scheduler();
        restarted.catch_up().await;
        let mut conn = fx.db.acquire().await.unwrap();
        let got = rows(&mut conn, job).await;
        let cuts: Vec<(i64, i64, i64, bool)> = got
            .iter()
            .map(|r| (r.slice_start, r.slice_end, r.charge_day, r.estimated))
            .collect();
        assert_eq!(
            cuts,
            vec![
                (start, D0 + DAY_S, D0, true),
                (D0 + DAY_S, D0 + 2 * DAY_S, D0 + DAY_S, true),
                (D0 + 2 * DAY_S, D0 + 3 * DAY_S, D0 + 2 * DAY_S, true),
            ]
        );
        assert!(got.iter().all(|r| !r.last_slice && r.started_at == start));
        // Catching up again writes nothing more.
        restarted.catch_up().await;
        assert_eq!(rows(&mut conn, job).await.len(), 3);
        // The agent was never told anything else: the service still runs.
        assert_eq!(fx.status(job).await, JobStatus::Running);
        let _ = lease;
    }

    #[tokio::test]
    async fn an_attempt_that_ends_before_the_pass_writes_its_own_midnight_slices() {
        let fx = Fx::new().await;
        let node = service_node(&fx, 4.0).await;
        let job = create_service(&fx, Principal::Key(fx.key), service_spec(1.0, 30 * 86_400))
            .await
            .unwrap();
        let (_, lease, epoch) = fx.running(job).await;
        let start = fx.now().unix_timestamp();
        // Lost with its node two days later, before any pass: H1's estimate, cut at each midnight.
        let end = D0 + 2 * DAY_S + 600;
        to(&fx, end);
        fx.hello(node, &[]).await;
        let mut conn = fx.db.acquire().await.unwrap();
        let got = rows(&mut conn, job).await;
        let cuts: Vec<(i64, i64, bool, bool)> = got
            .iter()
            .map(|r| (r.slice_start, r.slice_end, r.last_slice, r.estimated))
            .collect();
        assert_eq!(
            cuts,
            vec![
                (start, D0 + DAY_S, false, true),
                (D0 + DAY_S, D0 + 2 * DAY_S, false, true),
                (D0 + 2 * DAY_S, end, true, true),
            ]
        );
        let total: i64 = got.iter().map(|r| r.units).sum();
        assert_eq!(total, one_cpu(D0 + DAY_S - start) + one_cpu(DAY_S) + one_cpu(600));
        let _ = (lease, epoch);
    }

    #[tokio::test]
    async fn a_capped_service_stops_at_its_cap_deadline() {
        let fx = Fx::new().await;
        let node = service_node(&fx, 4.0).await;
        // 10 units a day; the service costs 1 an hour, and starts at 10:00 with 14 hours left in the day.
        set_key_cap(&fx, Some(10_000)).await;
        let p = Principal::Key(fx.key);
        let job = create_service(&fx, p, service_spec(1.0, 30 * 86_400)).await.unwrap();
        assert_eq!(reservation(&fx, job).await, (Some(D0), Some(10_000)));
        // The reservation counts against the day at once, and leaves less than 15 minutes for another service.
        assert_eq!(spent(&fx, p, D0).await, 10_000);
        assert_eq!(
            create_service(&fx, p, service_spec(1.0, 3_600)).await.unwrap_err(),
            crate::units::CapExceeded {
                cap: Units::from_milli(10_000),
                reserved: Units::from_milli(10_000),
                estimate: Units::from_milli(250),
            }
        );
        let (_, lease, epoch) = fx.running(job).await;
        let start = fx.now().unix_timestamp();
        let mut conn = fx.db.acquire().await.unwrap();
        let deadline = units::cap_deadline(&mut conn, job, GPU_HOUR).await.unwrap();
        assert_eq!(deadline, Some(at(start + 10 * 3_600)));
        // One second before the deadline it keeps running.
        to(&fx, start + 10 * 3_600 - 1);
        fx.sched.tick().await.clean();
        assert_eq!(fx.row(job).await.cancel_requested_at, None);
        // At the deadline, the hub asks it to stop with `cap_reached`, and the agent is told why.
        to(&fx, start + 10 * 3_600);
        fx.link.take();
        fx.sched.tick().await.clean();
        let cancels: Vec<String> = fx
            .link
            .take()
            .into_iter()
            .filter_map(|(_, m)| match m {
                ServerMsg::Cancel { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(cancels, vec![REASON_CAP_REACHED.to_string()]);
        fx.msg(node, finished(lease, epoch, Outcome::Cancelled, 10, 10)).await;
        let row = fx.row(job).await;
        assert_eq!(
            (row.status, row.reason.as_deref()),
            (JobStatus::Cancelled, Some(REASON_CAP_REACHED))
        );
        // What it held is in the ledger, and the day counts the row, not the row and the reservation both.
        let got = rows(&mut conn, job).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].units, 10_000);
        assert_eq!(spent(&fx, p, D0).await, 10_000);
    }

    #[tokio::test]
    async fn the_midnight_renews_the_reservation_and_stops_a_service_left_under_15_minutes() {
        let fx = Fx::new().await;
        let _node = service_node(&fx, 4.0).await;
        let dev = device(&fx, Some(30_000)).await;
        let p = Principal::Device(dev);
        let job = create_service(&fx, p, service_spec(1.0, 30 * 86_400)).await.unwrap();
        // Created at 10:00: 14 hours of the day.
        assert_eq!(reservation(&fx, job).await, (Some(D0), Some(14_000)));
        fx.running(job).await;
        // At midnight the day's slice is written and the next day reserved, in one step: the first day counts its
        // row only, the second its reservation only.
        let m1 = D0 + DAY_S;
        to(&fx, m1);
        fx.sched.tick().await.clean();
        assert_eq!(reservation(&fx, job).await, (Some(m1), Some(24_000)));
        assert_eq!(spent(&fx, p, D0).await, 14_000);
        assert_eq!(spent(&fx, p, m1).await, 24_000);
        // The device's cap drops to 0.2 units: the next midnight gives 12 minutes, under 15, and stops it.
        sqlx::query("UPDATE devices SET daily_unit_cap = 200 WHERE device_id = ?")
            .bind(dev.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
        let m2 = m1 + DAY_S;
        to(&fx, m2);
        fx.sched.tick().await.clean();
        assert_eq!(reservation(&fx, job).await, (Some(m2), Some(200)));
        let row = fx.row(job).await;
        assert!(row.cancel_requested_at.is_some());
        assert_eq!(row.reason.as_deref(), Some(REASON_CAP_REACHED));
    }

    #[tokio::test]
    async fn a_queued_service_left_under_15_minutes_is_cancelled_at_midnight() {
        let fx = Fx::new().await;
        // No node: it stays queued.
        set_key_cap(&fx, Some(30_000)).await;
        let job = create_service(&fx, Principal::Key(fx.key), service_spec(1.0, 30 * 86_400))
            .await
            .unwrap();
        set_key_cap(&fx, Some(100)).await;
        to(&fx, D0 + DAY_S + 1);
        fx.sched.tick().await.clean();
        let row = fx.row(job).await;
        assert_eq!(
            (row.status, row.reason.as_deref()),
            (JobStatus::Cancelled, Some(REASON_CAP_REACHED))
        );
        // A terminal service holds nothing.
        assert_eq!(spent(&fx, Principal::Key(fx.key), D0 + DAY_S).await, 0);
    }

    #[tokio::test]
    async fn usage_groups_rows_by_principal_kind_and_template_and_never_by_null() {
        let fx = Fx::new().await;
        let _node = service_node(&fx, 4.0).await;
        // A key's batch job, and a device's service that crosses a midnight.
        let batch = fx.job(1.0, 512, 0).await;
        let (bn, bl, be) = fx.running(batch).await;
        fx.advance(60);
        fx.finish(bn, bl, be, Outcome::Exited, Some(0)).await;
        let dev = device(&fx, None).await;
        let svc = create_service(&fx, Principal::Device(dev), service_spec(1.0, 30 * 86_400))
            .await
            .unwrap();
        let (sn, sl, se) = fx.running(svc).await;
        to(&fx, D0 + DAY_S + 60);
        fx.sched.tick().await.clean();
        fx.msg(sn, finished(sl, se, Outcome::Cancelled, 10, 10)).await;
        let mut conn = fx.db.acquire().await.unwrap();
        let report = async |conn: &mut Conn, group_by| {
            let q = UsageQuery {
                from: at(D0),
                to: at(D0 + 2 * DAY_S),
                group_by,
                after: None,
                limit: 10,
            };
            leases::usage_report(conn, fx.account, fx.project, &q).await.unwrap()
        };
        let keys = |groups: &[leases::UsageTotalsRow]| groups.iter().map(|g| g.key.clone()).collect::<Vec<_>>();
        let (groups, total) = report(&mut conn, UsageGroupBy::Key).await;
        // Device rows are left out of the key groups; the total still covers every row.
        assert_eq!(keys(&groups), vec![fx.key.to_string()]);
        assert_eq!(groups[0].attempts, 1);
        assert_eq!((total.attempts, rows(&mut conn, svc).await.len()), (2, 2));
        assert!(groups[0].units < total.units);
        let (groups, _) = report(&mut conn, UsageGroupBy::Device).await;
        assert_eq!(keys(&groups), vec![dev.to_string()]);
        assert_eq!(
            groups[0].attempts, 1,
            "a service that crossed a midnight is one attempt"
        );
        let (groups, _) = report(&mut conn, UsageGroupBy::Principal).await;
        assert_eq!(keys(&groups), vec![format!("device:{dev}"), format!("key:{}", fx.key)]);
        assert_eq!(
            groups.iter().map(|g| g.units).fold(Units::ZERO, Units::saturating_add),
            total.units
        );
        let (groups, _) = report(&mut conn, UsageGroupBy::Kind).await;
        assert_eq!(keys(&groups), vec!["batch".to_string(), "service".to_string()]);
        // No job came from a template: no group, never a null one.
        let (groups, _) = report(&mut conn, UsageGroupBy::Template).await;
        assert_eq!(groups, vec![]);
        let (groups, _) = report(&mut conn, UsageGroupBy::Job).await;
        assert_eq!(groups.len(), 2);
        // The service's midnight slice was estimated (no report came): only `estimated_slices` counts it.
        assert_eq!((total.estimated_attempts, total.estimated_slices), (0, 1));
    }

    #[tokio::test]
    async fn heartbeat_reports_count_only_for_the_current_lease_of_a_running_service() {
        let fx = Fx::new().await;
        let a = service_node(&fx, 4.0).await;
        let b = service_node(&fx, 4.0).await;
        let job = create_service(&fx, Principal::Key(fx.key), service_spec(1.0, 30 * 86_400))
            .await
            .unwrap();
        let (node, lease, epoch) = fx.running(job).await;
        let other = if node == a { b } else { a };
        // Another node, a stale epoch and an unknown lease report big numbers; only the real one counts.
        report(&fx, other, lease, epoch, 9_999_999, 9_999).await;
        report(&fx, node, lease, epoch + 1, 9_999_999, 9_999).await;
        report(&fx, node, LeaseId::generate(), 1, 9_999_999, 9_999).await;
        report(&fx, node, lease, epoch, 700, 70).await;
        to(&fx, D0 + DAY_S);
        fx.sched.tick().await.clean();
        let mut conn = fx.db.acquire().await.unwrap();
        let got = rows(&mut conn, job).await;
        assert_eq!(
            (got[0].used_cpu_ms, got[0].max_rss_mb, got[0].estimated),
            (700, 70, false)
        );
    }
}
