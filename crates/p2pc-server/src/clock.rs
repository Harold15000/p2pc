// SPDX-License-Identifier: AGPL-3.0-only

//! An injectable clock, so that expiry and throttling are tested without sleeping.

use std::fmt;
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

/// A source of the current time.
pub trait Clock: Send + Sync + fmt::Debug + 'static {
    /// The current time, in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock that only moves when told to. For tests.
#[derive(Debug)]
pub struct ManualClock(Mutex<OffsetDateTime>);

impl ManualClock {
    /// A clock stopped at `now`.
    #[must_use]
    pub fn new(now: OffsetDateTime) -> Self {
        Self(Mutex::new(now))
    }

    /// Sets the time.
    pub fn set(&self, now: OffsetDateTime) {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = now;
    }

    /// Moves the time forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut t = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *t += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn manual_clock_moves_only_when_told() {
        let c = ManualClock::new(datetime!(2026-11-05 10:00:00 UTC));
        assert_eq!(c.now(), datetime!(2026-11-05 10:00:00 UTC));
        c.advance(Duration::minutes(1));
        assert_eq!(c.now(), datetime!(2026-11-05 10:01:00 UTC));
        c.set(datetime!(2027-01-01 00:00:00 UTC));
        assert_eq!(c.now(), datetime!(2027-01-01 00:00:00 UTC));
    }
}
