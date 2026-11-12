// SPDX-License-Identifier: Apache-2.0

//! Service health (H2 §7.2, §11.2): the check a service declares, the probe that runs it, and the state machine the
//! driver feeds with its results.
//!
//! - **States.** `starting` from `JobStarted` until the first passing check; `healthy`; `unhealthy` once the last
//!   `failure_threshold` checks failed. Every change is reported (`ServiceHealth`, H2 §6.1).
//! - **The agent stops the service** (the H1 cancel sequence; the attempt ends `error="health_check_failed"`) when it
//!   is still `starting` after `start_period_s`, or when `failure_threshold` consecutive checks failed after it was
//!   `healthy`. A failed check during the start period does not count.
//! - **Without a `health` block** the service is `healthy` as soon as a connection to its first port succeeds (H2
//!   §7.1). It is then checked no more, and it is never stopped for its health: it has no `failure_threshold`. Its
//!   `starting` is still bounded (H2 §7.2: `starting` lasts at most `start_period_s`, and a service still `starting`
//!   after it is stopped): by the default start period of §7.1, 300 s. Without that bound a service whose first port
//!   never took a connection would stay `starting` until its `timeout_s` (up to 30 days), and the hub's idle timeout,
//!   which counts from the first `healthy`, would never end it.
//! - **The probe** ([`HealthProbe`]) is the ingress bridge's (§11.2, T2-21): the agent opens a bridged connection and
//!   reads only the status line. The driver bounds each check by `timeout_s`. A node without a probe refuses service
//!   leases (`invalid_job`): a service it could never check would only be stopped at the end of its start period.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use p2pc_proto::api::ServiceSpec;
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::HealthState;

use crate::connection::BoxFuture;

/// Longest `detail` the agent reports with a health change, in bytes (the protocol allows 1 KiB).
pub const MAX_DETAIL_LEN: usize = 256;

/// One check of a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthCheck {
    /// `GET <path>` through the bridge; a 2xx or 3xx status line passes.
    Http {
        /// The port, one of the service's.
        port: u16,
        /// An absolute path (validated, H2 §7.1).
        path: String,
    },
    /// A connection through the bridge; the shim's status byte 0 passes.
    Tcp {
        /// The port, one of the service's.
        port: u16,
    },
}

/// How a service may fail its health (H2 §7.1, §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthLimits {
    /// How long it may stay `starting`: `start_period_s`, or its default (300 s) without a `health` block.
    pub start_period: Duration,
    /// Consecutive failed checks after `healthy` that make it `unhealthy` and stop it. `None` without a `health`
    /// block: once healthy it is checked no more.
    pub failure_threshold: Option<u32>,
}

/// What the driver runs for a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPolicy {
    /// The check.
    pub check: HealthCheck,
    /// Time between two checks; the first one comes one interval after the start.
    pub interval: Duration,
    /// Longest one check may take before it counts as failed.
    pub timeout: Duration,
    /// How long it may stay `starting`, and how many failures after `healthy` stop it.
    pub limits: HealthLimits,
}

/// A port of a validated JobSpec (1-65 535); anything else is refused as an invalid job.
fn port(p: u32) -> Option<u16> {
    u16::try_from(p).ok().filter(|p| *p != 0)
}

impl HealthPolicy {
    /// The policy of a validated `service` block: its `health` block, or a TCP check of its first port with the
    /// default interval, timeout and start period and no failure threshold. `None` if the block is not valid (no
    /// port, or a port out of range).
    #[must_use]
    pub fn of(service: &ServiceSpec) -> Option<Self> {
        use p2pc_proto::api::{DEFAULT_HEALTH_INTERVAL_S, DEFAULT_HEALTH_START_PERIOD_S, DEFAULT_HEALTH_TIMEOUT_S};
        let secs = |s: u32| Duration::from_secs(u64::from(s));
        match &service.health {
            Some(h) => {
                let port = port(h.port)?;
                let check = match &h.http_get {
                    Some(path) => HealthCheck::Http {
                        port,
                        path: path.clone(),
                    },
                    None => HealthCheck::Tcp { port },
                };
                Some(Self {
                    check,
                    interval: secs(h.interval_s.max(1)),
                    timeout: secs(h.timeout_s.max(1)),
                    limits: HealthLimits {
                        start_period: secs(h.start_period_s),
                        failure_threshold: Some(h.failure_threshold.max(1)),
                    },
                })
            }
            None => Some(Self {
                check: HealthCheck::Tcp {
                    port: port(service.ports.first()?.port)?,
                },
                interval: secs(DEFAULT_HEALTH_INTERVAL_S),
                timeout: secs(DEFAULT_HEALTH_TIMEOUT_S),
                limits: HealthLimits {
                    start_period: secs(DEFAULT_HEALTH_START_PERIOD_S),
                    failure_threshold: None,
                },
            }),
        }
    }
}

/// Where a check goes: the lease, and its job directory (which holds the bridge's socket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    /// The lease.
    pub lease_id: LeaseId,
    /// `<data_dir>/jobs/<lease_id>`.
    pub job_dir: PathBuf,
}

/// Runs one health check of a running service (H2 §11.2). T2-21's ingress bridge implements it.
///
/// `Ok` passes; `Err` carries a short detail (for example the status line's code). The answer comes from an
/// untrusted container: the probe reads at most the status line, 1 KiB (SI-H2-7), and the detail is shortened and
/// stripped of control characters before it is reported. The driver bounds the call with the check's `timeout_s`.
pub trait HealthProbe: Send + Sync + fmt::Debug + 'static {
    /// One check.
    fn check<'a>(&'a self, target: &'a ProbeTarget, check: &'a HealthCheck) -> BoxFuture<'a, Result<(), String>>;
}

/// What the driver does after a check, or after the start period ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nothing changes.
    Stay,
    /// The state changed: report it.
    Report(HealthState, Option<String>),
    /// Report this state (when it changed), then stop the service (`health_check_failed`).
    Stop(Option<HealthState>, String),
}

/// The health of one service attempt.
#[derive(Debug, Clone)]
pub struct HealthMachine {
    limits: HealthLimits,
    state: HealthState,
    /// Consecutive failed checks since the last pass.
    failures: u32,
    start_period_over: bool,
    stopped: bool,
}

/// A detail fit to report: at most [`MAX_DETAIL_LEN`] bytes, control characters replaced.
#[must_use]
pub fn clean_detail(detail: &str) -> String {
    let mut out = String::new();
    for c in detail.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > MAX_DETAIL_LEN {
            break;
        }
        out.push(c);
    }
    out
}

impl HealthMachine {
    /// A service that just started: `starting`.
    #[must_use]
    pub fn new(limits: HealthLimits) -> Self {
        Self {
            limits,
            state: HealthState::Starting,
            failures: 0,
            start_period_over: false,
            stopped: false,
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> HealthState {
        self.state
    }

    /// Whether the driver should keep checking: not after a stop, and not once a service without a `health` block
    /// is healthy.
    #[must_use]
    pub fn wants_checks(&self) -> bool {
        !self.stopped && (self.limits.failure_threshold.is_some() || self.state == HealthState::Starting)
    }

    /// The start period is over. A service still `starting` is checked once more at once (the driver does that when
    /// this returns true): that check decides, so even `start_period_s = 0` gets one.
    pub fn start_period_ended(&mut self) -> bool {
        self.start_period_over = true;
        self.state == HealthState::Starting && !self.stopped
    }

    /// The result of one check.
    pub fn record(&mut self, result: Result<(), String>) -> Step {
        if self.stopped {
            return Step::Stay;
        }
        match result {
            Ok(()) => {
                self.failures = 0;
                if self.state == HealthState::Healthy {
                    Step::Stay
                } else {
                    self.state = HealthState::Healthy;
                    Step::Report(HealthState::Healthy, None)
                }
            }
            Err(detail) => {
                let detail = clean_detail(&detail);
                match self.state {
                    // Every service, with or without a `health` block (H2 §7.2).
                    HealthState::Starting if self.start_period_over => {
                        self.stopped = true;
                        Step::Stop(
                            None,
                            clean_detail(&format!("still starting after the start period: {detail}")),
                        )
                    }
                    // A failure in the start period does not count.
                    HealthState::Starting => Step::Stay,
                    HealthState::Healthy | HealthState::Unhealthy => {
                        // No `health` block: once healthy it is never stopped for its health.
                        let Some(threshold) = self.limits.failure_threshold else {
                            return Step::Stay;
                        };
                        self.failures = self.failures.saturating_add(1);
                        if self.failures < threshold {
                            return Step::Stay;
                        }
                        self.stopped = true;
                        self.state = HealthState::Unhealthy;
                        Step::Stop(
                            Some(HealthState::Unhealthy),
                            clean_detail(&format!("{} consecutive checks failed: {detail}", self.failures)),
                        )
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use p2pc_proto::api::{HealthCheck as SpecHealth, ServicePort};

    use super::*;

    fn limits(start_period_s: u64, failure_threshold: u32) -> HealthLimits {
        HealthLimits {
            start_period: Duration::from_secs(start_period_s),
            failure_threshold: Some(failure_threshold),
        }
    }

    /// A service without a `health` block: the default start period, no threshold.
    fn no_block() -> HealthLimits {
        HealthLimits {
            start_period: Duration::from_secs(300),
            failure_threshold: None,
        }
    }

    fn fail(d: &str) -> Result<(), String> {
        Err(d.into())
    }

    #[test]
    fn starting_becomes_healthy_at_the_first_pass_and_start_period_failures_do_not_count() {
        let mut m = HealthMachine::new(limits(300, 3));
        assert_eq!(m.state(), HealthState::Starting);
        for _ in 0..10 {
            assert_eq!(m.record(fail("refused")), Step::Stay);
        }
        assert_eq!(m.state(), HealthState::Starting);
        assert_eq!(m.record(Ok(())), Step::Report(HealthState::Healthy, None));
        assert_eq!(m.record(Ok(())), Step::Stay, "no change, no report");
        assert!(m.wants_checks());
    }

    #[test]
    fn still_starting_after_the_start_period_stops_at_the_next_failed_check() {
        let mut m = HealthMachine::new(limits(300, 3));
        assert_eq!(m.record(fail("refused")), Step::Stay);
        assert!(m.start_period_ended(), "check once more at once");
        let Step::Stop(None, detail) = m.record(fail("HTTP 503")) else {
            panic!("not stopped")
        };
        assert!(detail.contains("HTTP 503"), "{detail}");
        assert!(!m.wants_checks());
        assert_eq!(m.record(Ok(())), Step::Stay, "nothing after the stop");
    }

    #[test]
    fn a_pass_after_the_start_period_still_counts() {
        let mut m = HealthMachine::new(limits(0, 3));
        assert!(m.start_period_ended());
        assert_eq!(m.record(Ok(())), Step::Report(HealthState::Healthy, None));
        // A healthy service at the end of its start period is not checked early.
        let mut m = HealthMachine::new(limits(10, 3));
        m.record(Ok(()));
        assert!(!m.start_period_ended());
    }

    #[test]
    fn failure_threshold_consecutive_failures_after_healthy_stop_it_as_unhealthy() {
        let mut m = HealthMachine::new(limits(300, 3));
        m.record(Ok(()));
        assert_eq!(m.record(fail("a")), Step::Stay);
        assert_eq!(m.record(fail("b")), Step::Stay);
        // A pass resets the count.
        assert_eq!(m.record(Ok(())), Step::Stay);
        assert_eq!(m.record(fail("c")), Step::Stay);
        assert_eq!(m.record(fail("d")), Step::Stay);
        let Step::Stop(Some(HealthState::Unhealthy), detail) = m.record(fail("timed out")) else {
            panic!("not stopped as unhealthy")
        };
        assert!(detail.starts_with("3 consecutive checks failed"), "{detail}");
        assert_eq!(m.state(), HealthState::Unhealthy);
        assert!(!m.wants_checks());
        // A threshold of 1 stops at the first failure.
        let mut m = HealthMachine::new(limits(300, 1));
        m.record(Ok(()));
        assert!(matches!(
            m.record(fail("x")),
            Step::Stop(Some(HealthState::Unhealthy), _)
        ));
    }

    #[test]
    fn without_a_health_block_it_is_healthy_at_the_first_connection_and_never_stopped_after() {
        let mut m = HealthMachine::new(no_block());
        for _ in 0..100 {
            assert_eq!(
                m.record(fail("refused")),
                Step::Stay,
                "the start period does not count failures"
            );
        }
        assert_eq!(m.record(Ok(())), Step::Report(HealthState::Healthy, None));
        assert!(!m.wants_checks(), "checked no more once healthy");
        assert!(
            !m.start_period_ended(),
            "healthy at the end of the start period: nothing to decide"
        );
        assert_eq!(
            m.record(fail("refused")),
            Step::Stay,
            "never stopped for its health once healthy"
        );
        assert_eq!(m.state(), HealthState::Healthy);
    }

    /// H2 §7.2: `starting` lasts at most `start_period_s` (default 300 s, §7.1) for every service. One without a
    /// `health` block whose first port never took a connection is stopped like any other (`health_check_failed`),
    /// instead of staying `starting` until its `timeout_s`.
    #[test]
    fn without_a_health_block_still_starting_after_the_start_period_is_stopped() {
        let mut m = HealthMachine::new(no_block());
        assert_eq!(m.record(fail("refused")), Step::Stay);
        assert!(m.start_period_ended(), "check once more at once");
        let Step::Stop(None, detail) = m.record(fail("connection refused")) else {
            panic!("not stopped")
        };
        assert!(detail.contains("still starting after the start period"), "{detail}");
        assert!(!m.wants_checks());
        assert_eq!(m.state(), HealthState::Starting);
        // A first connection that succeeds at the deciding check still counts.
        let mut m = HealthMachine::new(no_block());
        assert!(m.start_period_ended());
        assert_eq!(m.record(Ok(())), Step::Report(HealthState::Healthy, None));
    }

    #[test]
    fn details_are_short_and_have_no_control_characters() {
        let d = clean_detail(&format!("HTTP/1.1 500\r\n{}", "é".repeat(1000)));
        assert!(d.len() <= MAX_DETAIL_LEN);
        assert!(!d.chars().any(char::is_control));
        assert!(d.starts_with("HTTP/1.1 500  "));
        let mut m = HealthMachine::new(limits(0, 1));
        m.start_period_ended();
        let Step::Stop(_, detail) = m.record(Err("\u{1b}[31m".repeat(500))) else {
            panic!()
        };
        assert!(detail.len() <= MAX_DETAIL_LEN && !detail.chars().any(char::is_control));
    }

    fn service(health: Option<SpecHealth>) -> ServiceSpec {
        ServiceSpec {
            ports: vec![ServicePort {
                port: 11434,
                name: "api".into(),
            }],
            health,
            idle_timeout_s: Some(3600),
            restart: p2pc_proto::api::RestartPolicy::OnNodeLoss,
        }
    }

    #[test]
    fn the_policy_follows_the_service_block() {
        let p = HealthPolicy::of(&service(None)).unwrap();
        assert_eq!(p.check, HealthCheck::Tcp { port: 11434 });
        assert_eq!(
            (p.interval, p.timeout, p.limits),
            (Duration::from_secs(10), Duration::from_secs(3), no_block()),
            "no block: the default start period of H2 §7.1, and no threshold"
        );
        let h = SpecHealth {
            http_get: Some("/api/version".into()),
            tcp: false,
            port: 11434,
            interval_s: 10,
            timeout_s: 3,
            start_period_s: 600,
            failure_threshold: 3,
        };
        let p = HealthPolicy::of(&service(Some(h.clone()))).unwrap();
        assert_eq!(
            p.check,
            HealthCheck::Http {
                port: 11434,
                path: "/api/version".into()
            }
        );
        assert_eq!(p.limits, limits(600, 3));
        let tcp = SpecHealth {
            http_get: None,
            tcp: true,
            ..h.clone()
        };
        assert_eq!(
            HealthPolicy::of(&service(Some(tcp))).unwrap().check,
            HealthCheck::Tcp { port: 11434 }
        );
        let bad = SpecHealth { port: 70_000, ..h };
        assert_eq!(HealthPolicy::of(&service(Some(bad))), None);
        let mut none = service(None);
        none.ports.clear();
        assert_eq!(HealthPolicy::of(&none), None);
    }
}
