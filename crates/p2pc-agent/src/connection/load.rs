// SPDX-License-Identifier: Apache-2.0

//! The `load` of every `Heartbeat` (§6): CPU use from the deltas of `/proc/stat`, memory in use from
//! `/proc/meminfo` (`MemTotal - MemAvailable`). GPU utilisation is optional and not measured in v0.1.
//!
//! The reads go through [`Host`] on the blocking pool, single-flight and with a short deadline, like the inventory's:
//! a hung `/proc` must never delay a heartbeat. Anything unreadable is reported as 0.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use p2pc_proto::protocol::Load;

use super::BoxFuture;
use crate::host::Host;

/// Deadline of one load sample.
pub const LOAD_DEADLINE: Duration = Duration::from_secs(1);
/// Single-flight key of the load reads.
pub const FLIGHT_LOAD: &str = "load (/proc/stat, /proc/meminfo)";

/// Where heartbeats get their `load`.
pub trait LoadSource: Send + Sync + std::fmt::Debug + 'static {
    /// The load now.
    fn sample(&self) -> BoxFuture<'_, Load>;
}

/// Total and idle jiffies of the `cpu` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTimes {
    /// All the time fields summed (guest time is already inside user and nice, so it is left out).
    pub total: u64,
    /// `idle + iowait`.
    pub idle: u64,
}

/// Parses the aggregate `cpu` line of `/proc/stat`.
#[must_use]
pub fn cpu_times(proc_stat: &str) -> Option<CpuTimes> {
    let line = proc_stat.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(|f| f.parse().unwrap_or(0))
        .collect();
    if v.len() < 4 {
        return None;
    }
    // user nice system idle iowait irq softirq steal [guest guest_nice]
    let total = v.iter().take(8).fold(0u64, |a, x| a.saturating_add(*x));
    let idle = v[3].saturating_add(v.get(4).copied().unwrap_or(0));
    Some(CpuTimes { total, idle })
}

/// CPU use between two samples, 0-100.
#[must_use]
pub fn cpu_pct(before: CpuTimes, after: CpuTimes) -> u32 {
    let total = after.total.saturating_sub(before.total);
    let idle = after.idle.saturating_sub(before.idle).min(total);
    if total == 0 {
        return 0;
    }
    u32::try_from((total - idle).saturating_mul(100) / total)
        .unwrap_or(100)
        .min(100)
}

/// `MemTotal - MemAvailable`, in MiB.
#[must_use]
pub fn mem_used_mb(meminfo: &str) -> Option<u64> {
    let field = |name: &str| -> Option<u64> {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(name))?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()
    };
    let total = field("MemTotal:")?;
    let available = field("MemAvailable:")?;
    Some(total.saturating_sub(available) / 1024)
}

/// The real load, read from the host's `/proc`.
#[derive(Debug)]
pub struct LoadMeter {
    host: Host,
    previous: Arc<Mutex<Option<CpuTimes>>>,
}

impl LoadMeter {
    /// A meter for `host`. The first sample has no previous CPU times, so it reports 0 % CPU.
    #[must_use]
    pub fn new(host: Host) -> Self {
        Self {
            host,
            previous: Arc::new(Mutex::new(None)),
        }
    }
}

impl LoadSource for LoadMeter {
    fn sample(&self) -> BoxFuture<'_, Load> {
        Box::pin(async move {
            let unknown = Load {
                cpu_pct: 0,
                mem_used_mb: 0,
                gpu_util_pct: None,
            };
            let Some(token) = self.host.flights().start(FLIGHT_LOAD) else {
                return unknown;
            };
            let host = self.host.clone();
            let read = tokio::task::spawn_blocking(move || {
                let r = (host.read("/proc/stat").ok(), host.read("/proc/meminfo").ok());
                drop(token);
                r
            });
            let Ok(Ok((stat, meminfo))) = tokio::time::timeout(LOAD_DEADLINE, read).await else {
                return unknown;
            };
            let now = stat.as_deref().and_then(cpu_times);
            let cpu = {
                let mut prev = self.previous.lock().unwrap_or_else(PoisonError::into_inner);
                let pct = match (*prev, now) {
                    (Some(a), Some(b)) => cpu_pct(a, b),
                    _ => 0,
                };
                if now.is_some() {
                    *prev = now;
                }
                pct
            };
            Load {
                cpu_pct: cpu,
                mem_used_mb: meminfo.as_deref().and_then(mem_used_mb).unwrap_or(0),
                gpu_util_pct: None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_percent_from_deltas() {
        let a = cpu_times("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        let b = cpu_times("cpu  200 0 200 1400 200 0 0 0 0 0\n").unwrap();
        assert_eq!(a, CpuTimes { total: 1000, idle: 800 });
        // 1000 more jiffies, 800 of them idle or iowait: 20 % busy.
        assert_eq!(cpu_pct(a, b), 20);
        assert_eq!(cpu_pct(a, a), 0, "no time passed");
        assert_eq!(cpu_pct(b, a), 0, "counters going back (a reset) never panic");
        assert_eq!(cpu_times("intr 1 2\n"), None);
        assert_eq!(cpu_times("cpu  1 2\n"), None);
    }

    #[test]
    fn memory_in_use() {
        let meminfo = "MemTotal:       32782336 kB\nMemFree:  100 kB\nMemAvailable:   16391168 kB\n";
        assert_eq!(mem_used_mb(meminfo), Some(16_007));
        assert_eq!(mem_used_mb("MemTotal: 1 kB\n"), None);
    }

    #[tokio::test]
    async fn the_meter_reads_the_hosts_proc() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("proc")).unwrap();
        let write_stat = |t: &str| std::fs::write(dir.path().join("proc/stat"), t).unwrap();
        write_stat("cpu  100 0 100 800 0 0 0 0\n");
        std::fs::write(
            dir.path().join("proc/meminfo"),
            "MemTotal: 2097152 kB\nMemAvailable: 1048576 kB\n",
        )
        .unwrap();
        let meter = LoadMeter::new(Host::with_root(dir.path()));
        let first = meter.sample().await;
        assert_eq!((first.cpu_pct, first.mem_used_mb, first.gpu_util_pct), (0, 1024, None));
        write_stat("cpu  600 0 100 1300 0 0 0 0\n");
        assert_eq!(meter.sample().await.cpu_pct, 50);
        // Nothing readable: zeros, never an error.
        let empty = LoadMeter::new(Host::with_root(dir.path().join("missing")));
        assert_eq!(empty.sample().await.mem_used_mb, 0);
    }
}
