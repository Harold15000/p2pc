// SPDX-License-Identifier: Apache-2.0

//! Reconnect delays (§6 "Reconnects" and "Liveness on both sides").
//!
//! Exponential backoff with jitter: the base delay starts at 1 s and doubles at each failed attempt, up to 30 s, or
//! up to **5 s** while the supervisor reports running leases (so a reconnect lands well inside the 45 s agent-side
//! lease timer). The delay is drawn uniformly from `[base / 2, base]` ("equal jitter"): never zero, so a fleet of
//! agents does not reconnect in lockstep after a server restart. A `Welcome` resets it. The RNG is seeded, so tests
//! see a fixed sequence.

use std::time::Duration;

use rand::rngs::StdRng;
use rand::{RngExt as _, SeedableRng as _};

/// The first base delay.
pub const BACKOFF_START: Duration = Duration::from_secs(1);
/// The largest base delay.
pub const BACKOFF_CAP: Duration = Duration::from_secs(30);
/// The largest base delay while leases are running (§6).
pub const BACKOFF_CAP_WITH_LEASES: Duration = Duration::from_secs(5);

/// The backoff state of the reconnect loop.
#[derive(Debug)]
pub struct Backoff {
    attempt: u32,
    rng: StdRng,
}

impl Backoff {
    /// A backoff whose jitter comes from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            attempt: 0,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// The base delay of the next attempt (before jitter).
    #[must_use]
    pub fn base(&self, leases_running: bool) -> Duration {
        let cap = if leases_running {
            BACKOFF_CAP_WITH_LEASES
        } else {
            BACKOFF_CAP
        };
        let factor = 1u32.checked_shl(self.attempt.min(16)).unwrap_or(u32::MAX);
        BACKOFF_START.saturating_mul(factor).min(cap)
    }

    /// The delay before the next attempt, then counts the attempt.
    pub fn next_delay(&mut self, leases_running: bool) -> Duration {
        let base = self.base(leases_running);
        self.attempt = self.attempt.saturating_add(1);
        let half = base / 2;
        let ms = u64::try_from(half.as_millis()).unwrap_or(u64::MAX);
        half + Duration::from_millis(self.rng.random_range(0..=ms))
    }

    /// After a `Welcome`: the next failure starts again from [`BACKOFF_START`].
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base_doubles_from_1_s_to_30_s() {
        let mut b = Backoff::new(7);
        let bases: Vec<u64> = (0..8)
            .map(|_| {
                let base = b.base(false).as_secs();
                b.next_delay(false);
                base
            })
            .collect();
        assert_eq!(bases, [1, 2, 4, 8, 16, 30, 30, 30]);
        // Very many failures never overflow.
        for _ in 0..10_000 {
            assert!(b.next_delay(false) <= BACKOFF_CAP);
        }
    }

    #[test]
    fn jitter_stays_within_half_to_full_base() {
        for seed in 0..50 {
            let mut b = Backoff::new(seed);
            for _ in 0..12 {
                let base = b.base(false);
                let d = b.next_delay(false);
                assert!(
                    d >= base / 2 && d <= base,
                    "seed {seed}: {d:?} outside [{:?}, {base:?}]",
                    base / 2
                );
            }
        }
        // Not a constant: different seeds give different delays.
        let firsts: std::collections::BTreeSet<Duration> = (0..20).map(|s| Backoff::new(s).next_delay(false)).collect();
        assert!(firsts.len() > 10, "{firsts:?}");
    }

    #[test]
    fn the_sequence_is_fixed_by_the_seed() {
        let run = |seed| {
            let mut b = Backoff::new(seed);
            (0..6).map(|_| b.next_delay(false)).collect::<Vec<_>>()
        };
        assert_eq!(run(42), run(42));
        assert_ne!(run(42), run(43));
    }

    #[test]
    fn running_leases_cap_the_base_at_5_s() {
        let mut b = Backoff::new(1);
        for _ in 0..10 {
            b.next_delay(false);
        }
        assert_eq!(b.base(false), BACKOFF_CAP);
        assert_eq!(b.base(true), BACKOFF_CAP_WITH_LEASES);
        for _ in 0..100 {
            assert!(b.next_delay(true) <= BACKOFF_CAP_WITH_LEASES);
        }
        // Early attempts are below the cap anyway.
        let fresh = Backoff::new(1);
        assert_eq!(fresh.base(true), BACKOFF_START);
    }

    #[test]
    fn reset_starts_again_from_1_s() {
        let mut b = Backoff::new(3);
        for _ in 0..6 {
            b.next_delay(false);
        }
        b.reset();
        assert_eq!(b.base(false), BACKOFF_START);
        assert!(b.next_delay(false) <= BACKOFF_START);
    }
}
