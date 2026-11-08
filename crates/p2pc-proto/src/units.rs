// SPDX-License-Identifier: Apache-2.0

//! Compute units (spec §11).
//!
//! 1 unit is 1 vCPU-hour reserved. 1 GPU-hour is worth `gpu_hour_units` units (10 by default, configurable on the
//! server). Memory is recorded but not billed in v0.1. Units are integers in **milli-units** everywhere, so ledger
//! totals add up exactly.

use std::fmt;
use std::ops::Add;

use serde::{Deserialize, Serialize};

use crate::api::Resources;

/// Seconds in one hour.
const HOUR_S: u128 = 3600;

/// An amount of compute, in milli-units (1 unit = 1 000 milli-units = 1 vCPU-hour reserved).
///
/// Serialized as a JSON integer of milli-units.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema), schema(value_type = u64))]
#[serde(transparent)]
pub struct Units(u64);

/// Default value of one GPU-hour: 10 units.
pub const DEFAULT_GPU_HOUR_UNITS: Units = Units::from_units(10);

impl Units {
    /// Zero units.
    pub const ZERO: Units = Units(0);

    /// From a count of milli-units.
    #[must_use]
    pub const fn from_milli(milli: u64) -> Self {
        Self(milli)
    }

    /// From a count of whole units (saturating).
    #[must_use]
    pub const fn from_units(units: u64) -> Self {
        Self(units.saturating_mul(1000))
    }

    /// The amount in milli-units.
    #[must_use]
    pub const fn milli(self) -> u64 {
        self.0
    }

    /// Saturating addition.
    #[must_use]
    pub const fn saturating_add(self, other: Units) -> Units {
        Units(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction (never below zero).
    #[must_use]
    pub const fn saturating_sub(self, other: Units) -> Units {
        Units(self.0.saturating_sub(other.0))
    }
}

impl Add for Units {
    type Output = Units;

    /// Saturating: a ledger total never wraps around.
    fn add(self, rhs: Units) -> Units {
        self.saturating_add(rhs)
    }
}

impl fmt::Display for Units {
    /// Whole units with three decimals, for example `2.500`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:03}", self.0 / 1000, self.0 % 1000)
    }
}

/// Converts a CPU count to milli-vCPUs, rounding to the **nearest** (§7: `resources.cpu` is a multiple of 0.001,
/// so this only removes float noise such as `4.03 × 1000 = 4030.000000000001`; `ceil` would bill one milli-vCPU
/// too many). Negative or non-finite values count as zero.
fn cpu_milli(cpu: f64) -> u128 {
    if cpu.is_finite() && cpu > 0.0 {
        // `as` saturates for out-of-range floats.
        (cpu * 1000.0).round() as u128
    } else {
        0
    }
}

/// Estimates the units a job reserves: `(cpu + gpu × gpu_hour_units) × timeout_s / 3600`.
///
/// This is the figure checked against a key's `daily_unit_cap` when a job is created (§11). The CPU is first rounded
/// to the nearest milli-vCPU (it is a multiple of 0.001 once validated), and the computation is then exact in
/// integers. Only the real time fraction (milli-vCPU-seconds / 3600) rounds **up** to the next milli-unit, so the
/// estimate never under-counts and float error never over-counts. Call it on a validated [`Resources`]; out-of-range
/// input (negative or non-finite CPU) counts as zero, and the result saturates instead of overflowing.
#[must_use]
pub fn estimate_units(resources: &Resources, timeout_s: u32, gpu_hour_units: Units) -> Units {
    let seconds = u128::from(timeout_s);
    let cpu = cpu_milli(resources.cpu).saturating_mul(seconds);
    let gpu = u128::from(resources.gpu)
        .saturating_mul(u128::from(gpu_hour_units.milli()))
        .saturating_mul(seconds);
    let total = cpu.saturating_add(gpu).div_ceil(HOUR_S);
    Units(u64::try_from(total).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(cpu: f64, gpu: u32) -> Resources {
        Resources {
            cpu,
            memory_mb: 1024,
            gpu,
            disk_mb: 10_240,
        }
    }

    #[test]
    fn one_vcpu_hour_is_one_unit() {
        assert_eq!(
            estimate_units(&res(1.0, 0), 3600, DEFAULT_GPU_HOUR_UNITS),
            Units::from_units(1)
        );
        assert_eq!(
            estimate_units(&res(2.0, 0), 3600, DEFAULT_GPU_HOUR_UNITS),
            Units::from_units(2)
        );
        assert_eq!(
            estimate_units(&res(0.25, 0), 3600, DEFAULT_GPU_HOUR_UNITS),
            Units::from_milli(250)
        );
    }

    #[test]
    fn a_gpu_hour_costs_gpu_hour_units() {
        assert_eq!(
            estimate_units(&res(1.0, 1), 3600, DEFAULT_GPU_HOUR_UNITS),
            Units::from_units(11)
        );
        assert_eq!(
            estimate_units(&res(1.0, 1), 3600, Units::from_units(4)),
            Units::from_units(5)
        );
        assert_eq!(
            estimate_units(&res(0.0, 1), 1800, DEFAULT_GPU_HOUR_UNITS),
            Units::from_units(5)
        );
    }

    #[test]
    fn estimates_round_up_to_the_next_milli_unit() {
        // 1 vCPU for 1 s is 1/3.6 milli-units: rounds up to 1.
        assert_eq!(
            estimate_units(&res(1.0, 0), 1, DEFAULT_GPU_HOUR_UNITS),
            Units::from_milli(1)
        );
        // The CPU is rounded to the nearest milli-vCPU (validation only lets multiples of 0.001 through), so
        // 0.3333 counts as 333 milli-vCPU: float noise never adds a milli-unit.
        assert_eq!(
            estimate_units(&res(0.3333, 0), 3600, DEFAULT_GPU_HOUR_UNITS),
            Units::from_milli(333)
        );
        assert_eq!(estimate_units(&res(2.0, 0), 0, DEFAULT_GPU_HOUR_UNITS), Units::ZERO);
    }

    /// Review P3 (spec §7 `resources.cpu`, 908b42c): no two-decimal CPU value from 0.25 to 256 over-counts. The
    /// float `k / 100` is often a hair above `k / 100` (for example `0.29` is `0.29000000000000004`), which the old
    /// `ceil` turned into an extra milli-vCPU. The expectation is computed in integers.
    #[test]
    fn no_two_decimal_cpu_value_over_counts() {
        for k in 25u64..=25_600 {
            let cpu = k as f64 / 100.0;
            for timeout_s in [1u32, 7, 60, 3600, 86_400] {
                let milli_cpu_seconds = u128::from(k * 10) * u128::from(timeout_s);
                let expected = milli_cpu_seconds.div_ceil(3600);
                assert_eq!(
                    estimate_units(&res(cpu, 0), timeout_s, DEFAULT_GPU_HOUR_UNITS).milli(),
                    u64::try_from(expected).unwrap(),
                    "cpu {cpu} for {timeout_s} s"
                );
            }
        }
    }

    #[test]
    fn the_largest_valid_job_does_not_overflow() {
        let u = estimate_units(&res(256.0, 1), 86_400, DEFAULT_GPU_HOUR_UNITS);
        assert_eq!(u, Units::from_units(256 * 24 + 10 * 24));
    }

    #[test]
    fn garbage_input_does_not_panic() {
        assert_eq!(
            estimate_units(&res(f64::NAN, 0), 3600, DEFAULT_GPU_HOUR_UNITS),
            Units::ZERO
        );
        assert_eq!(estimate_units(&res(-3.0, 0), 3600, DEFAULT_GPU_HOUR_UNITS), Units::ZERO);
        let huge = estimate_units(&res(f64::MAX, u32::MAX), u32::MAX, Units::from_milli(u64::MAX));
        assert_eq!(huge, Units::from_milli(u64::MAX));
    }

    #[test]
    fn units_display_and_serialize_as_milli() {
        assert_eq!(Units::from_milli(2500).to_string(), "2.500");
        assert_eq!(Units::from_milli(7).to_string(), "0.007");
        assert_eq!(serde_json::to_string(&Units::from_milli(2500)).unwrap(), "2500");
        assert_eq!(serde_json::from_str::<Units>("42").unwrap(), Units::from_milli(42));
        assert!(serde_json::from_str::<Units>("-1").is_err());
        assert_eq!(
            Units::from_milli(u64::MAX) + Units::from_milli(1),
            Units::from_milli(u64::MAX)
        );
        assert_eq!(Units::from_milli(1).saturating_sub(Units::from_milli(5)), Units::ZERO);
    }
}
