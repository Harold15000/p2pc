// SPDX-License-Identifier: Apache-2.0

//! The WSL2 distro's boot status (T14a2 real run, carry-over 9).
//!
//! `p2pc-boot` is the distro's `[boot] command`. WSL runs it asynchronously at every start, and it can take about
//! 10 s (it runs `nvidia-smi -L` and may regenerate the CDI spec). It then writes one JSON line to
//! [`BOOT_STATUS_FILE`]: `time`, `cdi`, `cdi_regenerated`, `errors` and `notes` (see `deploy/wsl/p2pc-boot`).
//!
//! So on WSL2 with `/dev/dxg`, before it reports GPU inventory, the agent waits up to [`BOOT_STATUS_WAIT`] for a
//! **fresh** status. A missing or stale file means "not ready yet", never "no GPU".
//!
//! **Fresh by identity** (T14b2 review). Since image 0.2.0, `p2pc-boot` records `init_starttime`: the raw start
//! ticks of this distro's init (field 22 of `/proc/1/stat`). A status is fresh only when that number **equals** the
//! current one: it was written during this start of the distro, whatever the clocks say. `"init_starttime": null`
//! (`p2pc-boot` could not read it) is never fresh.
//!
//! **Fallback by time**, only for a status without the field (an older image), logged once: fresh when its `time`
//! is not earlier than the distro's start, `btime` from `/proc/stat` plus that same field 22 in seconds (`btime`
//! alone is the start of the whole WSL VM, shared by every distro).
//!
//! - A fresh status with `cdi = "nvidia_smi_failed"` or any `errors`: the GPUs are **not offerable**, and `doctor`
//!   shows why.
//! - No fresh status after the wait: the GPUs are not offerable either ("not ready yet"), and the next detection
//!   reads the file again.
//!
//! The wait has one deadline per agent process, 30 s after the first wait (it lives in the [`Host`]), so the
//! periodic re-detection never stalls 30 s again when `p2pc-boot` did not run at all.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::time::Instant;

use super::{Blocking, blocking_until, clean};
use crate::host::Host;

/// Where `p2pc-boot` writes its status.
pub const BOOT_STATUS_FILE: &str = "/var/lib/p2pc/boot-status.json";
/// The longest the agent waits for a fresh status, in total, over the life of the process.
pub const BOOT_STATUS_WAIT: Duration = Duration::from_secs(30);
/// How often the file is read again while waiting.
pub const BOOT_STATUS_POLL: Duration = Duration::from_secs(1);
/// Single-flight key of the boot status read.
pub const FLIGHT_BOOT_STATUS: &str = "boot status";
/// Deadline of one read of the boot status and of `/proc`.
const READ_DEADLINE: Duration = Duration::from_secs(2);
/// Most errors kept from the file.
const MAX_ERRORS: usize = 16;

/// What the boot status says about the GPUs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BootStatus {
    /// A fresh status without errors.
    Ok {
        /// The CDI state (`fresh`, `regenerated`, `no_nvidia_gpu`, `skipped`).
        cdi: String,
    },
    /// A fresh status that reports a failure: the GPUs are not offerable.
    Failed {
        /// The CDI state, for example `nvidia_smi_failed`.
        cdi: String,
        /// The reasons `p2pc-boot` gave.
        errors: Vec<String>,
    },
    /// No fresh status (yet): the GPUs are not offerable.
    NotReady {
        /// Why.
        reason: String,
    },
}

impl BootStatus {
    /// Why the GPUs are not offerable, or `None` when the status allows them.
    #[must_use]
    pub fn blocks_gpus(&self) -> Option<String> {
        match self {
            BootStatus::Ok { .. } => None,
            BootStatus::Failed { cdi, errors } if errors.is_empty() => Some(format!("the boot check reports {cdi}")),
            BootStatus::Failed { cdi, errors } => Some(format!("the boot check reports {cdi}: {}", errors.join("; "))),
            BootStatus::NotReady { reason } => Some(reason.clone()),
        }
    }
}

/// The file's JSON line. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
struct Raw {
    time: String,
    /// Absent (an image before 0.2.0): `None`. `null`: `Some(None)`. A number: `Some(Some(ticks))`.
    #[serde(default, deserialize_with = "present")]
    init_starttime: Option<Option<u64>>,
    cdi: String,
    #[serde(default)]
    errors: Vec<String>,
}

/// Tells a present `null` from an absent field.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<u64>>, D::Error> {
    Option::<u64>::deserialize(d).map(Some)
}

/// Whether the "freshness by time" fallback was already logged by this process.
static TIME_FALLBACK_LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Field 22 of `/proc/<pid>/stat` (`starttime`): the raw clock ticks after boot. The command name (field 2) is in
/// parentheses and may hold spaces and parentheses, so fields count from the last `)`.
#[must_use]
pub fn init_starttime(init_stat: &str) -> Option<u64> {
    let (_, rest) = init_stat.rsplit_once(')')?;
    rest.split_whitespace().nth(22 - 3)?.parse().ok()
}

/// The start of the distro's init, in whole Unix seconds (rounded down), from `/proc/stat` and `/proc/1/stat`.
#[must_use]
pub fn distro_start(proc_stat: &str, init_stat: &str, ticks_per_second: u64) -> Option<i64> {
    let btime: i64 = proc_stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    let start_ticks = init_starttime(init_stat)?;
    let secs = i64::try_from(start_ticks / ticks_per_second.max(1)).ok()?;
    btime.checked_add(secs)
}

/// This start of the distro, as [`read_once`] needs it.
#[derive(Debug, Clone, Copy, Default)]
struct DistroStart {
    /// The init's `starttime` ticks: the identity.
    ticks: Option<u64>,
    /// The init's start in Unix seconds: the fallback.
    unix: Option<i64>,
}

/// Reads the status once: `Ok(status)` when it is fresh, `Err(reason)` when it is missing, unreadable or from
/// another start of the distro.
fn read_once(host: &Host, now: DistroStart) -> Result<BootStatus, String> {
    let text = host
        .read(BOOT_STATUS_FILE)
        .map_err(|_| format!("no boot status yet ({BOOT_STATUS_FILE} is missing)"))?;
    let raw: Raw = serde_json::from_str(text.trim())
        .map_err(|_| format!("the boot status {BOOT_STATUS_FILE} is not valid JSON"))?;
    let earlier =
        || "the boot status is from an earlier start of the distro; p2pc-boot has not finished yet".to_string();
    match raw.init_starttime {
        Some(Some(recorded)) => {
            let current = now
                .ticks
                .ok_or_else(|| "the distro's init start cannot be read from /proc/1/stat".to_string())?;
            if recorded != current {
                return Err(earlier());
            }
        }
        Some(None) => {
            return Err(
                "the boot status has no init start (p2pc-boot could not read /proc/1/stat); it is never taken as fresh"
                    .into(),
            );
        }
        None => {
            if !TIME_FALLBACK_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::info!(
                    "the boot status has no init_starttime (an image before 0.2.0): judging its freshness by time"
                );
            }
            let time = OffsetDateTime::parse(&raw.time, &Rfc3339)
                .map_err(|_| format!("the boot status {BOOT_STATUS_FILE} has no valid time"))?;
            let start = now
                .unix
                .ok_or_else(|| "the distro's start time cannot be read from /proc".to_string())?;
            if time.unix_timestamp() < start {
                return Err(earlier());
            }
        }
    }
    let cdi = clean(&raw.cdi);
    let errors: Vec<String> = raw.errors.iter().take(MAX_ERRORS).map(|e| clean(e)).collect();
    if cdi == "nvidia_smi_failed" || !errors.is_empty() {
        Ok(BootStatus::Failed { cdi, errors })
    } else {
        Ok(BootStatus::Ok { cdi })
    }
}

/// Waits for a fresh boot status, polling every [`BOOT_STATUS_POLL`], until the process's deadline
/// ([`Host::boot_wait_deadline`], [`BOOT_STATUS_WAIT`] after the first wait).
pub async fn wait(host: &Host) -> BootStatus {
    let ticks = rustix::param::clock_ticks_per_second();
    let read = || {
        let flights = host.clone();
        let h = host.clone();
        async move {
            let read = move || {
                let init = h.read("/proc/1/stat").ok();
                let now = DistroStart {
                    ticks: init.as_deref().and_then(init_starttime),
                    unix: match (h.read("/proc/stat"), init.as_deref()) {
                        (Ok(stat), Some(init)) => distro_start(&stat, init, ticks),
                        _ => None,
                    },
                };
                read_once(&h, now)
            };
            match blocking_until(&flights, FLIGHT_BOOT_STATUS, Instant::now() + READ_DEADLINE, read).await {
                Blocking::Done(r) => r,
                Blocking::Late | Blocking::Busy => Err("reading the boot status does not answer".to_string()),
            }
        }
    };
    wait_until(host.boot_wait_deadline(), read).await
}

/// Reads the status with `read` until it is fresh, polling every [`BOOT_STATUS_POLL`], and gives up at `deadline`
/// (a real deadline: time spent reading counts too, T05b review P3). It always reads once, even past the deadline,
/// so a later detection still picks up a status that arrived since.
pub async fn wait_until<F, Fut>(deadline: Instant, mut read: F) -> BootStatus
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<BootStatus, String>>,
{
    loop {
        let last = match read().await {
            Ok(status) => return status,
            Err(reason) => reason,
        };
        let now = Instant::now();
        if now >= deadline {
            return BootStatus::NotReady {
                reason: format!(
                    "{last}; waited {}s for it. GPUs are not offered until a fresh status arrives (the next \
                     detection reads it again)",
                    BOOT_STATUS_WAIT.as_secs()
                ),
            };
        }
        tokio::time::sleep(BOOT_STATUS_POLL.min(deadline - now)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_distro_start_is_btime_plus_the_init_start() {
        let stat = "cpu  1 2 3\nbtime 1700000000\nprocesses 9\n";
        // pid (comm with spaces) state ppid ...: field 22 is 2500 ticks.
        let init = "1 (init (x) y) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 2500 2000000 100\n";
        assert_eq!(distro_start(stat, init, 100), Some(1_700_000_025));
        assert_eq!(distro_start(stat, init, 250), Some(1_700_000_010));
        assert_eq!(distro_start("cpu 1\n", init, 100), None);
        assert_eq!(distro_start(stat, "garbage", 100), None);
    }

    /// The 30 s is a real deadline: reads that take time count against it (T05b review P3). Each read here takes
    /// 2 s; counting 1 s steps instead would wait 30 × 3 s.
    #[tokio::test(start_paused = true)]
    async fn the_wait_is_a_real_deadline_even_when_reads_are_slow() {
        let started = Instant::now();
        let mut reads = 0u32;
        let status = wait_until(started + BOOT_STATUS_WAIT, || {
            reads += 1;
            async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Err("no boot status yet".to_string())
            }
        })
        .await;
        let took = started.elapsed();
        assert!(
            took >= BOOT_STATUS_WAIT && took <= BOOT_STATUS_WAIT + Duration::from_secs(2),
            "{took:?}"
        );
        assert!(reads <= 11, "{reads}");
        assert!(matches!(status, BootStatus::NotReady { reason } if reason.contains("no boot status yet")));
        // Past the deadline: one read, no wait.
        let again = Instant::now();
        let mut once = 0;
        let _ = wait_until(started, || {
            once += 1;
            async { Err::<BootStatus, String>("x".into()) }
        })
        .await;
        assert_eq!((once, again.elapsed()), (1, Duration::ZERO));
        // A fresh status ends the wait at once.
        let ok = wait_until(Instant::now() + BOOT_STATUS_WAIT, || async {
            Ok(BootStatus::Ok { cdi: "fresh".into() })
        })
        .await;
        assert_eq!(ok, BootStatus::Ok { cdi: "fresh".into() });
    }

    /// T14b2 review: fresh by identity. A status that records `init_starttime` is fresh only when it equals the
    /// current init's, whatever its time says; `null` is never fresh; a status without the field (an older image)
    /// falls back to the time rule.
    #[test]
    fn a_status_is_fresh_by_the_inits_identity_and_by_time_only_without_it() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::with_root(dir.path());
        let file = dir.path().join(BOOT_STATUS_FILE.trim_start_matches('/'));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let write = |json: &str| std::fs::write(&file, format!("{json}\n")).unwrap();
        let now = DistroStart {
            ticks: Some(2500),
            unix: Some(1_700_000_025),
        };
        // Identity: equal ticks are fresh, even with a time from long ago (a clock that was wrong).
        write(r#"{"time":"2001-01-01T00:00:00Z","init_starttime":2500,"cdi":"fresh","errors":[]}"#);
        assert_eq!(read_once(&host, now), Ok(BootStatus::Ok { cdi: "fresh".into() }));
        // Other ticks are an earlier start of the distro, even with a time after this start.
        write(r#"{"time":"2030-01-01T00:00:00Z","init_starttime":2499,"cdi":"fresh","errors":[]}"#);
        assert!(read_once(&host, now).unwrap_err().contains("earlier start"));
        // Unknown current ticks: not fresh.
        write(r#"{"time":"2030-01-01T00:00:00Z","init_starttime":2500,"cdi":"fresh","errors":[]}"#);
        let unknown = DistroStart { ticks: None, ..now };
        assert!(read_once(&host, unknown).unwrap_err().contains("/proc/1/stat"));
        // null: never fresh.
        write(r#"{"time":"2030-01-01T00:00:00Z","init_starttime":null,"cdi":"fresh","errors":[]}"#);
        assert!(read_once(&host, now).unwrap_err().contains("never taken as fresh"));
        // No field (an older image): the time rule.
        write(r#"{"time":"2023-11-14T22:13:45Z","cdi":"regenerated","errors":[]}"#);
        assert_eq!(
            read_once(&host, now),
            Ok(BootStatus::Ok {
                cdi: "regenerated".into()
            })
        );
        write(r#"{"time":"2023-11-14T22:13:44Z","cdi":"regenerated","errors":[]}"#);
        assert!(read_once(&host, now).unwrap_err().contains("earlier start"));
        assert!(
            TIME_FALLBACK_LOGGED.load(std::sync::atomic::Ordering::Relaxed),
            "the fallback was logged"
        );
        // The identity is field 22 of /proc/1/stat.
        let init = "1 (init (x) y) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 2500 2000000 100\n";
        assert_eq!(init_starttime(init), Some(2500));
        assert_eq!(init_starttime("garbage"), None);
    }

    #[test]
    fn failures_block_the_gpus_with_their_reason() {
        let ok = BootStatus::Ok { cdi: "fresh".into() };
        assert_eq!(ok.blocks_gpus(), None);
        let failed = BootStatus::Failed {
            cdi: "nvidia_smi_failed".into(),
            errors: vec!["nvidia-smi -L failed".into()],
        };
        assert_eq!(
            failed.blocks_gpus().as_deref(),
            Some("the boot check reports nvidia_smi_failed: nvidia-smi -L failed")
        );
        let late = BootStatus::NotReady {
            reason: "no boot status yet".into(),
        };
        assert_eq!(late.blocks_gpus().as_deref(), Some("no boot status yet"));
    }
}
