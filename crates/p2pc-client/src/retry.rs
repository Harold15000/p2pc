// SPDX-License-Identifier: Apache-2.0

//! Retry policy (spec §7 "CLI conventions"): connection errors and `502`/`503`/`504`, up to 3 times, with
//! exponential backoff and full jitter.
//!
//! Only requests that are safe to repeat use it: every `GET`, and `POST /v1/jobs`, which always carries an idempotency
//! key. Other `POST`s and every `DELETE` are sent once.

use std::time::Duration;

/// How many times, and how patiently, a repeatable request is retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retries after the first attempt (so the request is sent at most `max_retries + 1` times). Default 3.
    pub max_retries: u32,
    /// The backoff ceiling of the first retry. It doubles at every retry. Default 250 ms.
    pub base_delay: Duration,
    /// The longest backoff ceiling. Default 4 s.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(4),
        }
    }
}

impl RetryPolicy {
    /// Never retry.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }

    /// Retry `max_retries` times with no waiting. For tests.
    #[must_use]
    pub fn immediate(max_retries: u32) -> Self {
        Self {
            max_retries,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    /// The upper bound of the wait before retry number `retry` (0 for the first retry).
    #[must_use]
    pub fn ceiling(&self, retry: u32) -> Duration {
        let factor = 1u32.checked_shl(retry.min(16)).unwrap_or(u32::MAX);
        self.base_delay.saturating_mul(factor).min(self.max_delay)
    }

    /// The wait before retry number `retry`: a random time between zero and [`RetryPolicy::ceiling`] ("full jitter"),
    /// so clients that failed together do not come back together.
    #[must_use]
    pub fn delay(&self, retry: u32) -> Duration {
        let ceiling = self.ceiling(retry);
        if ceiling.is_zero() {
            return Duration::ZERO;
        }
        let ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX).max(1);
        Duration::from_millis(rand::random_range(0..=ms))
    }
}

/// Whether an HTTP status is a transient gateway failure worth retrying.
#[must_use]
pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 502..=504)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_doubles_up_to_the_maximum() {
        let p = RetryPolicy::default();
        assert_eq!(p.ceiling(0), Duration::from_millis(250));
        assert_eq!(p.ceiling(1), Duration::from_millis(500));
        assert_eq!(p.ceiling(2), Duration::from_millis(1000));
        assert_eq!(p.ceiling(10), Duration::from_secs(4));
        assert_eq!(p.ceiling(u32::MAX), Duration::from_secs(4));
    }

    #[test]
    fn delay_never_exceeds_the_ceiling() {
        let p = RetryPolicy::default();
        for retry in 0..6 {
            for _ in 0..50 {
                assert!(p.delay(retry) <= p.ceiling(retry));
            }
        }
    }

    #[test]
    fn immediate_policy_never_waits() {
        assert_eq!(RetryPolicy::immediate(3).delay(2), Duration::ZERO);
    }

    #[test]
    fn only_gateway_statuses_are_retryable() {
        for s in [502, 503, 504] {
            assert!(is_retryable_status(s));
        }
        for s in [200, 400, 401, 404, 409, 429, 500, 501, 505] {
            assert!(!is_retryable_status(s));
        }
    }
}
