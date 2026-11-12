// SPDX-License-Identifier: AGPL-3.0-only

//! Compute units, the daily cap and the metering of services (spec §11, H2 §12).
//!
//! A batch job reserves `estimate_units(resources, timeout_s, gpu_hour_units)` milli-units when it is created. A
//! principal's `daily_unit_cap` is checked against what it has spent in the current UTC day, **plus** the new
//! estimate: exactly at the cap is allowed, one milli-unit more is not.
//!
//! [`spent_today`] is the one place that answers "how much has this principal spent today": `spent(P, D)` of H2 §12
//! ([`store::leases::spent`]), the ledger rows charged to the day plus the open reservations, never both for the
//! same unit.
//!
//! # Services (H2 §12)
//!
//! A service may run for 30 days, more than any daily cap, so it is metered and capped **one UTC day at a time**:
//! - **Slices.** Its attempt is cut at every 00:00 UTC it runs through: [`meter`] writes the row of the slice that
//!   just ended (reserved time exact, `used_cpu_ms` from the latest cumulative `Heartbeat` value minus what earlier
//!   slices recorded, `max_rss_mb` the attempt's peak so far), and the attempt's end writes its last slice
//!   ([`store::leases::insert_usage`]). A hub that was down at midnight writes the missed slices at start
//!   ([`meter`] again, before it serves requests), one per UTC day. A slice with no report is `estimated`.
//! - **The daily reservation.** For a principal with a cap, the service holds a reservation for one UTC day
//!   (`service_state.cap_day`, `cap_reserved_units`): its reserved rate × the runtime left in the day, bounded by what
//!   is left of `timeout_s` and by the cap minus `spent(P, D)` ([`day_reservation`]). It is set at creation
//!   ([`reserve_new_service`], `402 cap_exceeded` under 15 minutes of runtime) and again at each midnight, in the
//!   transaction that writes the slice of the day that ended, so no instant counts the slice and the reservation
//!   both, or neither. A new attempt (after a node loss) takes it again too, from its own start and with its whole
//!   `timeout_s` ([`attempt_began`]): the reservation of the lost attempt may be bounded by that attempt's timeout.
//! - **`cap_reached`.** While it runs, its `cap_deadline` is when its rows for the day plus its current slice at the
//!   reserved rate reach the reservation ([`cap_deadline_at`]). When the cap is what bounds the reservation, the hub
//!   asks it to stop one stop grace before that ([`STOP_GRACE_S`]), and at a midnight or a new attempt whose
//!   reservation is under 15 minutes: `cancelled`, `reason: "cap_reached"`. A reservation bounded by the day or by
//!   `timeout_s` never stops it: the midnight renews it, or the attempt ends `timed_out`.
//! - **Reports.** A heartbeat's `used_cpu_ms` above what the lease can have used is refused
//!   ([`plausible_cpu_ms`]), and what a slice records saturates, so no agent can keep a slice from being written.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use p2pc_proto::api::{JobSpec, JobStatus, Principal, REASON_CAP_REACHED, Resources};
use p2pc_proto::ids::{AccountId, JobId, LeaseId, NodeId};
use p2pc_proto::protocol::RunningLease;
use p2pc_proto::units::Units;
use time::OffsetDateTime;

use crate::config::Config;
use crate::scheduler::fit::{Reserved, cpu_milli};
use crate::store::usage::{self, MeteredService, NewSlice};
use crate::store::{self, Conn, Db, StoreError, leases};

/// Seconds in a UTC day.
pub const DAY_S: i64 = 86_400;

/// A service's day reservation must buy at least this much runtime (H2 §12), unless the day or its `timeout_s`
/// leaves less.
pub const MIN_CAP_RUNTIME_S: i64 = 15 * 60;

/// How long an agent may take to stop a job it is told to cancel (spec §9: SIGTERM, 10 s of grace, SIGKILL). The hub
/// asks a service to stop for its cap this long before its cap deadline, so that an agent that takes the whole grace
/// still ends within the day's reservation.
pub const STOP_GRACE_S: i64 = 10;

/// Milliseconds in an hour: units are per hour, amounts per millisecond.
const HOUR_MS: u128 = 3_600_000;

/// The `[start, end)` Unix seconds of the UTC day that contains `now`.
#[must_use]
pub fn utc_day(now: OffsetDateTime) -> (i64, i64) {
    let start = day_of(now.unix_timestamp());
    (start, start + DAY_S)
}

/// 00:00 UTC of the day that contains `t` (Unix seconds).
#[must_use]
pub const fn day_of(t: i64) -> i64 {
    t - t.rem_euclid(DAY_S)
}

/// The midnights (00:00 UTC) `m` with `after < m <= upto`, in order: where an attempt whose slices end at `after`
/// is cut up to `upto`.
pub fn midnights(after: i64, upto: i64) -> impl Iterator<Item = i64> {
    let first = day_of(after) + DAY_S;
    (0..)
        .map(move |k: i64| first.saturating_add(k.saturating_mul(DAY_S)))
        .take_while(move |m| *m <= upto)
}

/// The value of one GPU-hour on this server, from `server.toml` (`gpu_hour_units`, default 10).
#[must_use]
pub fn gpu_hour_units(config: &Config) -> Units {
    Units::from_units(u64::from(config.gpu_hour_units))
}

/// What one span of reserved time comes to in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Amounts {
    /// Reserved vCPU-milliseconds.
    pub reserved_cpu_ms: u64,
    /// Reserved GPU-milliseconds.
    pub reserved_gpu_ms: u64,
    /// Milli-units, rounded up.
    pub units: Units,
}

/// A reserved rate: what a lease (or a spec) holds, charged per unit of time exactly as the estimate and the ledger
/// charge it (spec §11): milli-vCPUs plus GPUs at `gpu_hour_units`, and only the time fraction rounds up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    cpu_milli: u64,
    gpus: u64,
    gpu_hour_milli: u64,
}

impl Rate {
    /// `cpu` vCPUs and `gpus` GPUs, with a GPU-hour worth `gpu_hour`.
    #[must_use]
    pub fn new(cpu: f64, gpus: u32, gpu_hour: Units) -> Self {
        Self {
            cpu_milli: cpu_milli(cpu),
            gpus: u64::from(gpus),
            gpu_hour_milli: gpu_hour.milli(),
        }
    }

    /// The rate of a job's resources.
    #[must_use]
    pub fn of_resources(resources: &Resources, gpu_hour: Units) -> Self {
        Self::new(resources.cpu, resources.gpu, gpu_hour)
    }

    /// The rate of what a lease reserved on its node (one GPU at most).
    #[must_use]
    pub fn of_reserved(reserved: &Reserved, gpu_hour: Units) -> Self {
        Self::new(reserved.cpu, u32::from(reserved.gpu_uuid.is_some()), gpu_hour)
    }

    /// Milli-units per hour.
    fn per_hour(self) -> u128 {
        u128::from(self.cpu_milli) + u128::from(self.gpus) * u128::from(self.gpu_hour_milli)
    }

    /// What `wall_ms` milliseconds of this rate come to.
    #[must_use]
    pub fn amounts(self, wall_ms: u64) -> Amounts {
        let wall = u128::from(wall_ms);
        let to_u64 = |v: u128| u64::try_from(v).unwrap_or(u64::MAX);
        Amounts {
            reserved_cpu_ms: to_u64(u128::from(self.cpu_milli) * wall / 1000),
            reserved_gpu_ms: to_u64(u128::from(self.gpus) * wall),
            units: Units::from_milli(to_u64((self.per_hour() * wall).div_ceil(HOUR_MS))),
        }
    }

    /// The units of `secs` seconds (0 for a negative span).
    #[must_use]
    pub fn units_for(self, secs: i64) -> Units {
        self.amounts(secs_ms(secs)).units
    }

    /// The longest whole number of seconds that `units` pay for (`units_for(s) <= units`); `None` for a rate of zero,
    /// which any time costs nothing.
    #[must_use]
    pub fn seconds_for(self, units: Units) -> Option<i64> {
        let per_hour = self.per_hour();
        if per_hour == 0 {
            return None;
        }
        Some(i64::try_from(u128::from(units.milli()) * 3600 / per_hour).unwrap_or(i64::MAX))
    }
}

/// `secs` seconds in milliseconds; a negative span is empty.
fn secs_ms(secs: i64) -> u64 {
    u64::try_from(secs).unwrap_or(0).saturating_mul(1000)
}

/// A service's reservation for one UTC day (H2 §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DayReservation {
    /// Milli-units reserved.
    pub units: Units,
    /// Whether it buys the runtime the cap must allow: 15 minutes, or all that is left of the day and of `timeout_s`
    /// when that is less. Creation is refused (`402`) and a running service stopped (`cap_reached`) when it does not.
    pub enough: bool,
}

/// The reservation of a service at `rate` whose runtime is counted from `from` (Unix seconds): the rate × the runtime
/// left in the day (to `day_end`), bounded by `timeout_left_s` and by `cap − spent` (`spent`: `spent(P, D)` without
/// this reservation).
#[must_use]
pub fn day_reservation(
    rate: Rate,
    from: i64,
    day_end: i64,
    timeout_left_s: i64,
    cap: Units,
    spent: Units,
) -> DayReservation {
    let runtime = (day_end - from).min(timeout_left_s).max(0);
    let units = rate.units_for(runtime).min(cap.saturating_sub(spent));
    DayReservation {
        units,
        enough: units >= rate.units_for(runtime.min(MIN_CAP_RUNTIME_S)),
    }
}

/// When a running service's day reservation runs out (Unix seconds): its rows for the day (`rows`) plus its current
/// slice, from `slice_start` at `rate`, reach `reserved`. `None` for a rate of zero.
#[must_use]
pub fn cap_deadline_at(rate: Rate, slice_start: i64, reserved: Units, rows: Units) -> Option<i64> {
    rate.seconds_for(reserved.saturating_sub(rows))
        .map(|s| slice_start.saturating_add(s))
}

/// Milli-units `principal` (an API key or a device) has spent in the UTC day of `now`: `spent(P, D)` (H2 §12).
pub async fn spent_today(
    conn: &mut Conn,
    account_id: AccountId,
    principal: Principal,
    now: OffsetDateTime,
) -> Result<Units, StoreError> {
    let milli = leases::spent(conn, account_id, principal, day_of(now.unix_timestamp())).await?;
    Ok(Units::from_milli(milli))
}

// --- The daily reservation at creation ----------------------------------------------------------------------------

/// The reservation a new service takes for the current UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DayHold {
    /// 00:00 UTC of the day.
    pub day: i64,
    /// Milli-units reserved.
    pub units: Units,
}

/// The day reservation of a new service of a principal with a `cap` (H2 §12 "Caps for services"), or the
/// [`CapExceeded`] of `402 cap_exceeded` when it buys under 15 minutes of runtime (`estimate` is what the minimum
/// runtime would cost). Call it in the creation transaction, then [`hold`] after inserting the job.
pub async fn reserve_new_service(
    conn: &mut Conn,
    account_id: AccountId,
    principal: Principal,
    cap: Units,
    spec: &JobSpec,
    gpu_hour: Units,
    now: OffsetDateTime,
) -> Result<Result<DayHold, CapExceeded>, StoreError> {
    let now_s = now.unix_timestamp();
    let day = day_of(now_s);
    let spent = Units::from_milli(leases::spent(conn, account_id, principal, day).await?);
    let rate = Rate::of_resources(&spec.resources, gpu_hour);
    let timeout = i64::from(spec.timeout_s);
    let r = day_reservation(rate, now_s, day + DAY_S, timeout, cap, spent);
    if r.enough {
        return Ok(Ok(DayHold { day, units: r.units }));
    }
    let minimum = (day + DAY_S - now_s).min(timeout).min(MIN_CAP_RUNTIME_S);
    Ok(Err(CapExceeded {
        cap,
        reserved: spent,
        estimate: rate.units_for(minimum),
    }))
}

/// Writes a new service's day reservation, in the transaction that inserted it.
pub async fn hold(conn: &mut Conn, job_id: JobId, hold: DayHold, now: OffsetDateTime) -> Result<(), StoreError> {
    usage::set_reservation(conn, job_id, Some((hold.day, hold.units)), now).await
}

/// `cap_deadline` of `GET /v1/jobs/{id}` (H2 §7.2): when the running service's reservation for the day runs out;
/// `None` for an uncapped principal, a service with no attempt running, or one that holds no reservation.
pub async fn cap_deadline(
    conn: &mut Conn,
    job_id: JobId,
    gpu_hour: Units,
) -> Result<Option<OffsetDateTime>, StoreError> {
    let Some(s) = usage::metered_service(conn, job_id).await? else {
        return Ok(None);
    };
    Ok(deadline_of(&s, gpu_hour).and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok()))
}

/// Whether the cap stops `s` at `now` (H2 §12): its reservation is bounded by the cap, and its cap deadline is one
/// stop grace away or closer ([`STOP_GRACE_S`]).
///
/// The reservation is bounded by the cap when what is left of it is less than the attempt could use until the end of
/// the day or of its `timeout_s`. Otherwise it runs out when the day or the attempt does: the midnight renews it, or
/// the attempt ends `timed_out`, as H1 ends it, never `cap_reached`.
fn cap_reached(s: &MeteredService, now: i64, gpu_hour: Units) -> bool {
    let (Some(a), Some(day), Some(reserved)) = (s.attempt.as_ref(), s.cap_day, s.cap_reserved) else {
        return false;
    };
    let rate = Rate::of_reserved(&a.reserved, gpu_hour);
    let left = reserved.saturating_sub(s.rows_on_cap_day);
    let uncapped = (day + DAY_S - a.cut_at).min(a.timeout_left(s.timeout_s)).max(0);
    if s.cap.is_none() || s.cancel_requested || left >= rate.units_for(uncapped) {
        return false;
    }
    cap_deadline_at(rate, a.cut_at, reserved, s.rows_on_cap_day).is_some_and(|d| d.saturating_sub(STOP_GRACE_S) <= now)
}

/// The cap deadline of a metered service, if it has one (see [`cap_deadline`]).
fn deadline_of(s: &MeteredService, gpu_hour: Units) -> Option<i64> {
    let a = s.attempt.as_ref()?;
    s.cap?;
    let reserved = s.cap_reserved?;
    cap_deadline_at(
        Rate::of_reserved(&a.reserved, gpu_hour),
        a.cut_at,
        reserved,
        s.rows_on_cap_day,
    )
}

// --- Reports from heartbeats --------------------------------------------------------------------------------------

/// The latest cumulative usage an agent reported for a running service lease (`Heartbeat.running[]`, H2 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageReport {
    /// The lease's epoch.
    pub epoch: u64,
    /// CPU time used by the attempt so far.
    pub used_cpu_ms: u64,
    /// The attempt's peak resident memory so far.
    pub max_rss_mb: u64,
    /// When the hub received it (Unix seconds).
    pub at: i64,
}

/// The slack of [`plausible_cpu_ms`], in seconds of wall time: reports come at most once a minute, and the hub
/// learns of an attempt's start a little after the agent.
pub const CPU_REPORT_MARGIN_S: i64 = 60;

/// The most CPU time (milliseconds) an attempt that reserved `cpu` vCPUs can have used `elapsed_s` seconds after its
/// start: the reserved vCPUs for the whole time, plus [`CPU_REPORT_MARGIN_S`] of slack. The sandbox limits the
/// attempt to its reserved CPU (hard rule 3), so a report above this is wrong or hostile.
#[must_use]
pub fn plausible_cpu_ms(elapsed_s: i64, cpu: f64) -> u64 {
    let wall = u64::try_from(elapsed_s.max(0).saturating_add(CPU_REPORT_MARGIN_S)).unwrap_or(0);
    // `cpu_milli` milliseconds of CPU per second of wall time.
    wall.saturating_mul(cpu_milli(cpu))
}

/// The latest usage report of each running service lease, kept in memory: a midnight slice reads it (H2 §12). A hub
/// restart forgets them, and a slice with no report is `estimated`, as the spec says. Only the current lease of a
/// running service is ever recorded ([`record_heartbeat`]), and ended leases are dropped at every [`meter`], so its
/// size is bounded by the running services, never by what agents send. Cheap to clone; clones share the map.
#[derive(Debug, Clone, Default)]
pub struct ServiceReports(Arc<Mutex<HashMap<LeaseId, UsageReport>>>, Arc<Mutex<HashSet<LeaseId>>>);

impl ServiceReports {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<LeaseId, UsageReport>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether this is the first implausible report of `lease_id`: the caller logs it once per lease, so an agent
    /// cannot fill the log by repeating it. The set holds only current leases of running services, like the reports.
    fn first_refusal(&self, lease_id: LeaseId) -> bool {
        self.1.lock().unwrap_or_else(PoisonError::into_inner).insert(lease_id)
    }

    /// The latest report of `(lease_id, epoch)`.
    #[must_use]
    pub fn get(&self, lease_id: LeaseId, epoch: u64) -> Option<UsageReport> {
        self.map().get(&lease_id).copied().filter(|r| r.epoch == epoch)
    }

    /// Records a report. Both values are cumulative over the attempt, so a report that arrives out of order never
    /// lowers them.
    pub fn record(&self, lease_id: LeaseId, report: UsageReport) {
        let mut map = self.map();
        let entry = map.entry(lease_id).or_insert(report);
        if entry.epoch == report.epoch {
            entry.used_cpu_ms = entry.used_cpu_ms.max(report.used_cpu_ms);
            entry.max_rss_mb = entry.max_rss_mb.max(report.max_rss_mb);
            entry.at = entry.at.max(report.at);
        } else {
            *entry = report;
        }
    }

    /// Keeps only the reports (and the refusals) of `active` leases.
    fn retain(&self, active: &HashSet<LeaseId>) {
        self.map().retain(|id, _| active.contains(id));
        self.1
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id| active.contains(id));
    }

    fn is_empty(&self) -> bool {
        self.map().is_empty() && self.1.lock().unwrap_or_else(PoisonError::into_inner).is_empty()
    }
}

/// Records the `used_cpu_ms` and `max_rss_mb` a `Heartbeat` of `node_id` carries for its running service leases. An
/// entry is kept only for the job's current lease, held by `node_id`, of a service that runs: a report for any other
/// lease changes nothing (the H1 paths fence it).
///
/// A report whose `used_cpu_ms` is above [`plausible_cpu_ms`] for the attempt's age and reserved vCPUs is refused
/// whole (and logged once per lease): the ledger never records CPU time a lease cannot have used, and the slice it
/// would have fed is the server's estimate instead.
pub async fn record_heartbeat(
    db: &Db,
    reports: &ServiceReports,
    node_id: NodeId,
    running: &[RunningLease],
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    let reported: Vec<&RunningLease> = running
        .iter()
        .filter(|r| r.used_cpu_ms.is_some() || r.max_rss_mb.is_some())
        .collect();
    if reported.is_empty() {
        return Ok(());
    }
    let mut conn = db.acquire().await?;
    for r in reported {
        let Some(lease) = leases::get(&mut conn, r.lease_id).await? else {
            continue;
        };
        if lease.node_id != node_id
            || lease.epoch != r.epoch
            || !lease.is_current()
            || lease.job_kind != p2pc_proto::api::JobKind::Service
            || lease.state != leases::LeaseState::Running
        {
            continue;
        }
        let elapsed = lease.started_at.map_or(0, |at| (now - at).whole_seconds());
        let limit = plausible_cpu_ms(elapsed, lease.reserved.cpu);
        if r.used_cpu_ms.is_some_and(|used| used > limit) {
            if reports.first_refusal(r.lease_id) {
                tracing::warn!(lease_id = %r.lease_id, %node_id, limit,
                    "usage report refused: more CPU time than the lease can have used");
            }
            continue;
        }
        let previous = reports.get(r.lease_id, r.epoch);
        reports.record(
            r.lease_id,
            UsageReport {
                epoch: r.epoch,
                used_cpu_ms: r.used_cpu_ms.or(previous.map(|p| p.used_cpu_ms)).unwrap_or(0),
                max_rss_mb: r.max_rss_mb.or(previous.map(|p| p.max_rss_mb)).unwrap_or(0),
                at: now.unix_timestamp(),
            },
        );
    }
    Ok(())
}

// --- Retries --------------------------------------------------------------------------------------------------------

/// Runs `step` until it succeeds, at most `tries` times, waiting `backoff` before the second try and twice as long
/// before each one after. The last failure is returned; the earlier ones are logged with `what`.
pub async fn retry<T, E: std::fmt::Display>(
    tries: u32,
    backoff: std::time::Duration,
    what: &str,
    mut step: impl AsyncFnMut() -> Result<T, E>,
) -> Result<T, E> {
    let mut pause = backoff;
    let mut tried = 1;
    loop {
        match step().await {
            Ok(v) => return Ok(v),
            Err(e) if tried >= tries => return Err(e),
            Err(e) => tracing::warn!(error = %e, tried, tries, "{what} failed; trying again"),
        }
        if !pause.is_zero() {
            tokio::time::sleep(pause).await;
        }
        pause = pause.saturating_mul(2);
        tried += 1;
    }
}

// --- The midnight step and the cap ---------------------------------------------------------------------------------

/// What one [`meter`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MeterReport {
    /// Midnight slices written.
    pub slices: usize,
    /// Services stopped for their cap (`cap_reached`).
    pub stopped: usize,
    /// Services whose step failed (logged and rolled back; the next pass retries).
    pub errors: usize,
}

/// Whether `s` needs a metering step at `now`: an uncut midnight, a reservation to set, renew or clear, or a cap
/// deadline reached.
fn due(s: &MeteredService, now: i64, gpu_hour: Units) -> bool {
    let today = day_of(now);
    if s.attempt
        .as_ref()
        .is_some_and(|a| midnights(a.cut_at, now).next().is_some())
    {
        return true;
    }
    match s.cap {
        None => s.cap_day.is_some(),
        Some(_) if s.cap_day != Some(today) => true,
        Some(_) => cap_reached(s, now, gpu_hour),
    }
}

/// The metering of services at `now` (H2 §12), the scheduler's pass and the catch-up at start: for every service that
/// is not terminal, write the slices of the midnights its running attempt crossed, renew its day reservation (or set
/// or clear it as its principal's cap says), and stop it with `cap_reached` when the reservation is under 15 minutes
/// or its cap deadline is reached. One `BEGIN IMMEDIATE` transaction per service; a read-only pass first, so a pass
/// with nothing due takes no write lock. A failed service is logged, counted and retried at the next pass.
pub async fn meter(
    db: &Db,
    now: OffsetDateTime,
    gpu_hour: Units,
    reports: &ServiceReports,
) -> Result<MeterReport, StoreError> {
    let now_s = now.unix_timestamp();
    let services = {
        let mut conn = db.acquire().await?;
        usage::metered_services(&mut conn).await?
    };
    if !reports.is_empty() {
        let active = services
            .iter()
            .filter_map(|s| s.attempt.as_ref().map(|a| a.lease_id))
            .collect();
        reports.retain(&active);
    }
    let mut out = MeterReport::default();
    for s in services.iter().filter(|s| due(s, now_s, gpu_hour)) {
        match meter_one(db, s.job_id, now, gpu_hour, reports).await {
            Ok((slices, stopped)) => {
                out.slices += slices;
                out.stopped += usize::from(stopped);
            }
            Err(e) => {
                out.errors += 1;
                tracing::warn!(error = %e, job_id = %s.job_id, "metering step failed; retried at the next pass");
            }
        }
    }
    Ok(out)
}

/// The metering step of one service, in its own transaction (see [`meter`]). Returns the slices written and whether
/// it was stopped.
async fn meter_one(
    db: &Db,
    job_id: JobId,
    now: OffsetDateTime,
    gpu_hour: Units,
    reports: &ServiceReports,
) -> Result<(usize, bool), StoreError> {
    let mut tx = store::begin_immediate(db).await?;
    // Re-read inside the transaction: the attempt may have ended, or another pass done this step, meanwhile.
    let Some(mut s) = usage::metered_service(&mut tx, job_id).await? else {
        return Ok((0, false));
    };
    let now_s = now.unix_timestamp();
    let today = day_of(now_s);
    // 1. The slices of the midnights the running attempt crossed, each charged to the day it lies in.
    let mut slices = 0;
    if let Some(a) = s.attempt.as_mut() {
        let rate = Rate::of_reserved(&a.reserved, gpu_hour);
        for m in midnights(a.cut_at, now_s).collect::<Vec<_>>() {
            // A report counts for this slice only if it came during it: the cumulative value minus what the earlier
            // slices recorded. With none, the slice is the server's estimate (H2 §12).
            let report = reports.get(a.lease_id, a.epoch).filter(|r| r.at >= a.cut_at);
            let used = report.map_or(0, |r| r.used_cpu_ms.saturating_sub(a.used_cpu_ms));
            usage::insert_slice(
                &mut tx,
                &NewSlice {
                    job_id,
                    attempt: a.attempt,
                    lease_id: a.lease_id,
                    node_id: a.node_id,
                    started_at: a.started_at,
                    slice_start: a.cut_at,
                    slice_end: m,
                    last_slice: false,
                    charge_day: m - DAY_S,
                    amounts: rate.amounts(secs_ms(m - a.cut_at)),
                    used_cpu_ms: used,
                    max_rss_mb: report.map_or(0, |r| r.max_rss_mb),
                    estimated: report.is_none(),
                },
            )
            .await?;
            a.used_cpu_ms = a.used_cpu_ms.saturating_add(used);
            a.cut_at = m;
            slices += 1;
        }
    }
    // 2. The day's reservation: renewed at the first step of each UTC day, after the slice of the day that ended.
    let mut stop = false;
    match s.cap {
        None if s.cap_day.is_some() => usage::set_reservation(&mut tx, job_id, None, now).await?,
        Some(cap) if s.cap_day != Some(today) => {
            stop = !take_reservation(&mut tx, &mut s, cap, now, gpu_hour).await?;
            if stop {
                tracing::info!(job_id = %job_id, "the day's cap reservation is under 15 minutes: the service stops");
            }
        }
        _ => {}
    }
    // 3. The cap deadline.
    if !stop && s.cap_day == Some(today) && cap_reached(&s, now_s, gpu_hour) {
        tracing::info!(job_id = %job_id, "the service reached its daily cap");
        stop = true;
    }
    let stopped = stop && stop_for_cap(&mut tx, &s, now).await?;
    tx.commit().await?;
    Ok((slices, stopped))
}

/// Takes the reservation of `s` for the UTC day of `now` (H2 §12), at a midnight and again when an attempt starts:
/// what the service's rows already charged to the day, plus its rate × the runtime left in the day, counted from the
/// start of its current slice (now, for a queued service) and bounded by what is left of the attempt's `timeout_s`
/// and by `cap − spent(P, D)` without this reservation. Returns whether it is enough ([`DayReservation::enough`]).
///
/// The rows are part of the reservation because a slice written against a day's reservation uses it up (`spent`'s
/// term 3): what is still reserved is always `cap_reserved_units − rows`.
async fn take_reservation(
    tx: &mut Conn,
    s: &mut MeteredService,
    cap: Units,
    now: OffsetDateTime,
    gpu_hour: Units,
) -> Result<bool, StoreError> {
    let now_s = now.unix_timestamp();
    let today = day_of(now_s);
    // `spent(P, D)` without this reservation: what it still holds for the day, if it is for this day, is taken off.
    let own = match (s.cap_day, s.cap_reserved) {
        (Some(day), Some(reserved)) if day == today => reserved.saturating_sub(s.rows_on_cap_day),
        _ => Units::ZERO,
    };
    let spent = Units::from_milli(leases::spent(tx, s.account_id, s.principal, today).await?).saturating_sub(own);
    let rows = usage::job_units_on_day(tx, s.job_id, today).await?;
    let (rate, from, timeout_left) = match &s.attempt {
        Some(a) => (
            Rate::of_reserved(&a.reserved, gpu_hour),
            a.cut_at,
            a.timeout_left(s.timeout_s),
        ),
        None => (Rate::new(s.cpu, s.gpu, gpu_hour), now_s, i64::from(s.timeout_s)),
    };
    let r = day_reservation(rate, from, today + DAY_S, timeout_left, cap, spent);
    let reserved = rows.saturating_add(r.units);
    usage::set_reservation(tx, s.job_id, Some((today, reserved)), now).await?;
    s.cap_day = Some(today);
    s.cap_reserved = Some(reserved);
    s.rows_on_cap_day = rows;
    Ok(r.enough)
}

/// An attempt of a service was accepted or started (H2 §12): it has its whole `timeout_s` again and its own start,
/// so a capped principal's service takes the day's reservation again, as at a midnight. Without this, an attempt
/// requeued after a node loss would keep the reservation its lost attempt took, which may be bounded by that
/// attempt's `timeout_s`, and would be stopped for a cap it has not reached. A reservation under 15 minutes stops the
/// service with `cap_reached`, as at a midnight. Call it in the transaction that accepts or starts the lease.
///
/// Nothing for a batch job, an uncapped principal, or an attempt with a midnight still to cut: the next
/// [`meter`] pass cuts it and takes the new day's reservation.
pub async fn attempt_began(
    tx: &mut Conn,
    job_id: JobId,
    now: OffsetDateTime,
    gpu_hour: Units,
) -> Result<(), StoreError> {
    let Some(mut s) = usage::metered_service(tx, job_id).await? else {
        return Ok(());
    };
    let (Some(cap), Some(cut_at)) = (s.cap, s.attempt.as_ref().map(|a| a.cut_at)) else {
        return Ok(());
    };
    if midnights(cut_at, now.unix_timestamp()).next().is_some() {
        return Ok(());
    }
    if !take_reservation(tx, &mut s, cap, now, gpu_hour).await? {
        tracing::info!(job_id = %job_id, "the cap leaves a new attempt under 15 minutes: the service stops");
        stop_for_cap(tx, &s, now).await?;
    }
    Ok(())
}

/// Stops a service for its principal's daily cap: a queued one is `cancelled` at once, an assigned or running one
/// gets a cancel request that the scheduler delivers (H2 §7.2), both with `reason: "cap_reached"`. Whether it changed
/// anything.
async fn stop_for_cap(tx: &mut Conn, s: &MeteredService, now: OffsetDateTime) -> Result<bool, StoreError> {
    match s.status {
        JobStatus::Queued => {
            let Some(job) = store::jobs::get(tx, s.account_id, s.project_id, s.job_id).await? else {
                return Ok(false);
            };
            store::job_state::transition(tx, &job, JobStatus::Cancelled, REASON_CAP_REACHED, now)
                .await
                .map_err(|e| match e {
                    store::job_state::TransitionError::Store(e) => e,
                    _ => StoreError::Corrupt("jobs.status"),
                })?;
            leases::set_cancelled_reason(tx, s.job_id, REASON_CAP_REACHED).await?;
            Ok(true)
        }
        JobStatus::Assigned | JobStatus::Running if !s.cancel_requested => {
            leases::request_stop(tx, s.job_id, REASON_CAP_REACHED, now).await
        }
        _ => Ok(false),
    }
}

/// A job that does not fit under a key's daily cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapExceeded {
    /// The key's daily cap.
    pub cap: Units,
    /// Already reserved today.
    pub reserved: Units,
    /// What the new job would reserve.
    pub estimate: Units,
}

/// Checks `reserved + estimate <= cap`, saturating, so exactly at the cap passes and one milli-unit over fails.
pub fn check_cap(cap: Units, reserved: Units, estimate: Units) -> Result<(), CapExceeded> {
    if reserved.saturating_add(estimate) <= cap {
        Ok(())
    } else {
        Err(CapExceeded {
            cap,
            reserved,
            estimate,
        })
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn the_utc_day_is_midnight_to_midnight() {
        let (from, to) = utc_day(datetime!(2026-11-05 10:30:15 UTC));
        assert_eq!(from, datetime!(2026-11-05 00:00:00 UTC).unix_timestamp());
        assert_eq!(to, datetime!(2026-11-06 00:00:00 UTC).unix_timestamp());
        // The first and the last second of a day belong to it; the next second does not.
        let first = datetime!(2026-11-05 00:00:00 UTC);
        let last = datetime!(2026-11-05 23:59:59 UTC);
        assert_eq!(utc_day(first), utc_day(last));
        assert_ne!(utc_day(last), utc_day(datetime!(2026-11-06 00:00:00 UTC)));
        // A time zone offset does not move the day: it is the UTC day.
        assert_eq!(
            utc_day(datetime!(2026-11-05 23:30:00 -5)),
            utc_day(datetime!(2026-11-06 04:30:00 UTC))
        );
    }

    #[test]
    fn the_cap_boundary_is_exact_to_the_milli_unit() {
        let cap = Units::from_milli(1500);
        let at =
            |reserved: u64, estimate: u64| check_cap(cap, Units::from_milli(reserved), Units::from_milli(estimate));
        assert!(at(0, 1500).is_ok(), "exactly at the cap");
        assert!(at(1000, 500).is_ok());
        assert_eq!(
            at(1000, 501),
            Err(CapExceeded {
                cap,
                reserved: Units::from_milli(1000),
                estimate: Units::from_milli(501)
            })
        );
        assert!(at(0, 1501).is_err(), "one milli-unit over");
        assert!(at(1500, 1).is_err());
        // A cap of zero allows nothing but a zero estimate.
        assert!(check_cap(Units::ZERO, Units::ZERO, Units::ZERO).is_ok());
        assert!(check_cap(Units::ZERO, Units::ZERO, Units::from_milli(1)).is_err());
        // Saturation: a huge reservation never wraps around to "fits".
        assert!(check_cap(cap, Units::from_milli(u64::MAX), Units::from_milli(2)).is_err());
    }

    const GPU_HOUR: Units = Units::from_units(10);

    fn rate(cpu: f64, gpu: u32) -> Rate {
        Rate::new(cpu, gpu, GPU_HOUR)
    }

    #[test]
    fn a_rate_charges_like_the_estimate_and_the_ledger() {
        let one = rate(1.0, 0);
        // 1 vCPU-hour is 1 unit; a GPU-hour is `gpu_hour_units` more.
        assert_eq!(one.amounts(3_600_000).units, Units::from_units(1));
        assert_eq!(rate(1.0, 1).amounts(3_600_000).units, Units::from_units(11));
        let a = rate(1.5, 1).amounts(1_000);
        assert_eq!((a.reserved_cpu_ms, a.reserved_gpu_ms), (1_500, 1_000));
        // The real fraction rounds up to the next milli-unit, as `estimate_units` does.
        assert_eq!(one.amounts(1).units, Units::from_milli(1));
        assert_eq!(one.amounts(0).units, Units::ZERO);
        let res: p2pc_proto::api::Resources =
            serde_json::from_value(serde_json::json!({"cpu": 1.5, "memory_mb": 512, "gpu": 1})).unwrap();
        assert_eq!(Rate::of_resources(&res, GPU_HOUR), rate(1.5, 1));
        for secs in [1_i64, 59, 3_600, 86_400, 30 * 86_400] {
            let estimate = p2pc_proto::units::estimate_units(&res, u32::try_from(secs).unwrap(), GPU_HOUR);
            assert_eq!(rate(1.5, 1).units_for(secs), estimate, "{secs} s");
        }
    }

    #[test]
    fn the_time_a_rate_buys_never_costs_more_than_the_units() {
        for r in [rate(0.5, 0), rate(1.0, 0), rate(1.5, 1), rate(3.0, 0)] {
            for milli in [0_u64, 1, 999, 1_000, 12_345, 1_500_000] {
                let u = Units::from_milli(milli);
                let secs = r.seconds_for(u).unwrap();
                assert!(r.units_for(secs) <= u, "{r:?} {milli}");
                assert!(
                    r.units_for(secs + 1) > u,
                    "{r:?} {milli}: the floor is the largest such time"
                );
            }
        }
        // Nothing reserved costs nothing: a zero rate buys unbounded time.
        assert_eq!(rate(0.0, 0).seconds_for(Units::from_units(1)), None);
    }

    #[test]
    fn midnights_are_listed_between_two_instants() {
        let m = datetime!(2026-11-06 00:00:00 UTC).unix_timestamp();
        let t = datetime!(2026-11-05 10:00:00 UTC).unix_timestamp();
        assert_eq!(day_of(t), m - DAY_S);
        assert_eq!(day_of(m), m);
        assert_eq!(midnights(t, t + 3_600).collect::<Vec<_>>(), Vec::<i64>::new());
        assert_eq!(midnights(t, m).collect::<Vec<_>>(), vec![m]);
        assert_eq!(
            midnights(t, m + 2 * DAY_S + 5).collect::<Vec<_>>(),
            vec![m, m + DAY_S, m + 2 * DAY_S]
        );
        // A cut at a midnight is not cut again.
        assert_eq!(midnights(m, m + DAY_S - 1).collect::<Vec<_>>(), Vec::<i64>::new());
        assert_eq!(midnights(m, m + DAY_S).collect::<Vec<_>>(), vec![m + DAY_S]);
    }

    #[test]
    fn a_day_reservation_is_bounded_by_the_day_the_timeout_and_the_cap() {
        let r = rate(1.0, 0); // 1 unit an hour
        let day = datetime!(2026-11-05 00:00:00 UTC).unix_timestamp();
        let end = day + DAY_S;
        let cap = Units::from_units(100);
        // From midnight, a whole day: 24 units.
        let got = day_reservation(r, day, end, 30 * DAY_S, cap, Units::ZERO);
        assert_eq!(
            got,
            DayReservation {
                units: Units::from_units(24),
                enough: true
            }
        );
        // From 18:00, what is left of the day.
        let got = day_reservation(r, day + 18 * 3_600, end, 30 * DAY_S, cap, Units::ZERO);
        assert_eq!(got.units, Units::from_units(6));
        // What is left of `timeout_s`.
        let got = day_reservation(r, day, end, 2 * 3_600, cap, Units::ZERO);
        assert_eq!(got.units, Units::from_units(2));
        // The cap minus what the principal spent already.
        let got = day_reservation(r, day, end, 30 * DAY_S, Units::from_units(10), Units::from_units(7));
        assert_eq!(
            got,
            DayReservation {
                units: Units::from_units(3),
                enough: true
            }
        );
        // Under 15 minutes of runtime: not enough (exactly 15 minutes is).
        let quarter = Units::from_milli(250);
        let got = day_reservation(r, day, end, 30 * DAY_S, Units::from_units(1), Units::from_milli(750));
        assert_eq!(
            got,
            DayReservation {
                units: quarter,
                enough: true
            }
        );
        let got = day_reservation(r, day, end, 30 * DAY_S, Units::from_units(1), Units::from_milli(751));
        assert_eq!(
            got,
            DayReservation {
                units: Units::from_milli(249),
                enough: false
            }
        );
        let got = day_reservation(r, day, end, 30 * DAY_S, cap, Units::from_units(500));
        assert_eq!(
            got,
            DayReservation {
                units: Units::ZERO,
                enough: false
            }
        );
        // When the day or the timeout itself leaves under 15 minutes, the cap need only cover that (Spec questions).
        let got = day_reservation(r, end - 600, end, 30 * DAY_S, cap, Units::ZERO);
        assert_eq!(got.units, r.units_for(600));
        assert!(got.enough);
        let got = day_reservation(r, day, end, 300, cap, Units::ZERO);
        assert_eq!((got.units, got.enough), (r.units_for(300), true));
    }

    #[tokio::test]
    async fn a_retry_tries_again_and_gives_up_after_its_tries() {
        let none = std::time::Duration::ZERO;
        // Two failures, then a success: three calls.
        let mut calls = 0;
        let got: Result<u32, String> = retry(4, none, "a step", async || {
            calls += 1;
            if calls < 3 {
                Err(format!("failure {calls}"))
            } else {
                Ok(calls)
            }
        })
        .await;
        assert_eq!(got, Ok(3));
        // Never a success: every try is made, no more, and the last failure comes back.
        let mut calls = 0;
        let got: Result<(), String> = retry(4, none, "a step", async || {
            calls += 1;
            Err(format!("failure {calls}"))
        })
        .await;
        assert_eq!((got, calls), (Err("failure 4".to_string()), 4));
        // One try means no retry.
        let mut calls = 0;
        let got: Result<(), &str> = retry(1, none, "a step", async || {
            calls += 1;
            Err("no")
        })
        .await;
        assert_eq!((got, calls), (Err("no"), 1));
    }

    #[test]
    fn the_cap_deadline_is_when_the_rows_and_the_current_slice_reach_the_reservation() {
        let r = rate(2.0, 0); // 2 units an hour
        let start = datetime!(2026-11-05 08:00:00 UTC).unix_timestamp();
        assert_eq!(
            cap_deadline_at(r, start, Units::from_units(4), Units::ZERO),
            Some(start + 2 * 3_600)
        );
        // The rows already written for the day use the reservation up first.
        assert_eq!(
            cap_deadline_at(r, start, Units::from_units(4), Units::from_units(3)),
            Some(start + 1_800)
        );
        assert_eq!(
            cap_deadline_at(r, start, Units::from_units(4), Units::from_units(5)),
            Some(start)
        );
        assert_eq!(cap_deadline_at(rate(0.0, 0), start, Units::ZERO, Units::ZERO), None);
    }
}
