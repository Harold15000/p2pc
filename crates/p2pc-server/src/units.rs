// SPDX-License-Identifier: AGPL-3.0-only

//! Compute units and the daily cap (spec §11).
//!
//! A job reserves `estimate_units(resources, timeout_s, gpu_hour_units)` milli-units when it is created. A key's
//! `daily_unit_cap` is checked against what that key has spent in the current UTC day, **plus** the new estimate:
//! exactly at the cap is allowed, one milli-unit more is not.
//!
//! [`spent_today`] is the one place that answers "how much has this key spent today" (T06): **reserved and used**.
//! For each job the key created today:
//! - a finished job with usage records counts what its attempts **used** (the ledger, §11): its reservation is
//!   replaced by the real figure;
//! - a job cancelled before it ever ran counts nothing ("never ran" is sticky: no `running` event, T04 review);
//! - any other job counts its **reservation**: it is queued or running, or it ended with no report.

use p2pc_proto::api::Principal;
use p2pc_proto::ids::AccountId;
use p2pc_proto::units::Units;
use time::OffsetDateTime;

use crate::config::Config;
use crate::store::{self, Conn, StoreError};

/// Seconds in a UTC day.
const DAY_S: i64 = 86_400;

/// The `[start, end)` Unix seconds of the UTC day that contains `now`.
#[must_use]
pub fn utc_day(now: OffsetDateTime) -> (i64, i64) {
    let t = now.unix_timestamp();
    let start = t - t.rem_euclid(DAY_S);
    (start, start + DAY_S)
}

/// The value of one GPU-hour on this server, from `server.toml` (`gpu_hour_units`, default 10).
#[must_use]
pub fn gpu_hour_units(config: &Config) -> Units {
    Units::from_units(u64::from(config.gpu_hour_units))
}

/// Milli-units `principal` (an API key or a device) has spent on jobs created in the UTC day of `now`: used by
/// finished jobs, reserved by the others (see the module docs).
pub async fn spent_today(
    conn: &mut Conn,
    account_id: AccountId,
    principal: Principal,
    now: OffsetDateTime,
) -> Result<Units, StoreError> {
    let (from, to) = utc_day(now);
    let milli = store::leases::spent_between(conn, account_id, principal, from, to).await?;
    Ok(Units::from_milli(milli))
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
}
