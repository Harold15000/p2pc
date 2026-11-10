// SPDX-License-Identifier: Apache-2.0

//! The device protocol, ALPN `p2pc/device/1` (H2 spec §6.3): constants and limits.
//!
//! The protocol has no messages of its own: each bidirectional stream carries one HTTP/1.1 connection to the hub's
//! REST API, served in-process with the device principal attached, so a device gets every endpoint its scopes allow
//! through the one OpenAPI document. This module holds what both ends must agree on: the close code for a NodeId that
//! is not a live device, the error code for a request that carries its own `Authorization`, and the limits of §6.3 with
//! the relations the hub checks at start ([`DeviceStreamBudget::validate`]).

use std::time::Duration;

/// QUIC application close code of a `p2pc/device/1` connection from a NodeId that is not a live device (never
/// paired, revoked, expired or belonging to nothing: one answer for all, §5.5). Sent with the reason
/// [`NOT_PAIRED`]. The codes 0 and 1 are H1's (closed by the agent, closed by the server).
pub const CLOSE_NOT_PAIRED: u32 = 2;
/// The close reason that comes with [`CLOSE_NOT_PAIRED`] (§5.5 "Unknown or revoked device").
pub const NOT_PAIRED: &str = "not_paired";
/// Error `code` of `400` for a request on a device stream that carries an `Authorization` header: mixing two
/// principals on one request is refused (§6.3).
pub const UNEXPECTED_AUTHORIZATION: &str = "unexpected_authorization";

/// Most `p2pc/device/1` connections per device NodeId (§6.3).
pub const MAX_CONNECTIONS_PER_DEVICE: usize = 2;
/// Default of `device_streams_per_device`: concurrent streams per device across its connections (§6.3). A stream is
/// one HTTP/1.1 connection, so an upgraded port connection or a log follow holds one for its life.
pub const DEFAULT_STREAMS_PER_DEVICE: usize = 16;
/// Default of `device_stream_budget`: device streams in total, separate from H1's REST connection cap (§6.3).
pub const DEFAULT_STREAM_BUDGET: usize = 96;
/// Default of `device_stream_admin_reserve`: streams of the budget usable only by devices with the `admin` scope, so
/// paired phones can never take the slots of the hub PC's app (§6.3).
pub const DEFAULT_STREAM_ADMIN_RESERVE: usize = 32;
/// Most connections at once that have not passed the device check, counted apart from the other ALPNs (§6.3).
pub const MAX_UNCHECKED_CONNECTIONS: usize = 32;
/// A connection must pass the device check within this time (§6.3: 5 s).
pub const DEVICE_CHECK_DEADLINE: Duration = Duration::from_secs(5);
/// `not_paired` closes a minute per NodeId; beyond it the NodeId is closed at connect without the lookup (§6.3).
pub const NOT_PAIRED_PER_NODE_PER_MINUTE: u32 = 10;
/// Default `port_idle_s`: an upgraded port connection on `p2pc/device/1` closes after this long with no byte in
/// either direction (§6.3, §7.4: 600 s).
pub const DEFAULT_PORT_IDLE: Duration = Duration::from_secs(600);
/// The hub's liveness sweep re-reads the revocation and expiry of the devices with live connections this often
/// (§5.5: every 2 s).
pub const LIVENESS_SWEEP_INTERVAL: Duration = Duration::from_secs(2);
/// A revoked or expired device's connections and service streams are closed within this time (§5.5, SI-H2-4: 5 s).
pub const REVOCATION_CLOSE_DEADLINE: Duration = Duration::from_secs(5);

// The sweep is what makes an offline revocation and an expiry meet SI-H2-4.
const _: () = assert!(LIVENESS_SWEEP_INTERVAL.as_secs() < REVOCATION_CLOSE_DEADLINE.as_secs());

/// The device stream budget of §6.3, as the hub's configuration sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStreamBudget {
    /// `device_streams_per_device`.
    pub streams_per_device: usize,
    /// `device_stream_budget`.
    pub budget: usize,
    /// `device_stream_admin_reserve`.
    pub admin_reserve: usize,
}

impl Default for DeviceStreamBudget {
    fn default() -> Self {
        Self {
            streams_per_device: DEFAULT_STREAMS_PER_DEVICE,
            budget: DEFAULT_STREAM_BUDGET,
            admin_reserve: DEFAULT_STREAM_ADMIN_RESERVE,
        }
    }
}

/// A [`DeviceStreamBudget`] that breaks a relation of §6.3. The hub refuses to start with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// `device_streams_per_device` is 0.
    #[error("device_streams_per_device must be at least 1")]
    NoStreamsPerDevice,
    /// `device_stream_admin_reserve` is below `device_streams_per_device`, so one `admin` device could not use its
    /// whole share from the reserve.
    #[error("device_stream_admin_reserve must be at least device_streams_per_device")]
    ReserveBelowPerDevice,
    /// `device_stream_admin_reserve` is not below `device_stream_budget`, so no non-`admin` device could open a stream.
    #[error("device_stream_admin_reserve must be below device_stream_budget")]
    ReserveNotBelowBudget,
}

impl DeviceStreamBudget {
    /// Checks the relations of §6.3: at least one stream per device, a reserve of at least one device's streams and
    /// below the budget.
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.streams_per_device == 0 {
            return Err(BudgetError::NoStreamsPerDevice);
        }
        if self.admin_reserve < self.streams_per_device {
            return Err(BudgetError::ReserveBelowPerDevice);
        }
        if self.admin_reserve >= self.budget {
            return Err(BudgetError::ReserveNotBelowBudget);
        }
        Ok(())
    }

    /// Streams that devices without the `admin` scope hold together at most: the budget minus the reserve (64 by
    /// default).
    #[must_use]
    pub const fn non_admin_streams(&self) -> usize {
        self.budget.saturating_sub(self.admin_reserve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_match_the_spec() {
        assert_eq!(MAX_CONNECTIONS_PER_DEVICE, 2);
        assert_eq!(
            (
                DEFAULT_STREAMS_PER_DEVICE,
                DEFAULT_STREAM_BUDGET,
                DEFAULT_STREAM_ADMIN_RESERVE
            ),
            (16, 96, 32)
        );
        assert_eq!(MAX_UNCHECKED_CONNECTIONS, 32);
        assert_eq!(DEVICE_CHECK_DEADLINE, Duration::from_secs(5));
        assert_eq!(NOT_PAIRED_PER_NODE_PER_MINUTE, 10);
        assert_eq!(DEFAULT_PORT_IDLE, Duration::from_secs(600));
        assert_eq!(LIVENESS_SWEEP_INTERVAL, Duration::from_secs(2));
        assert_eq!(REVOCATION_CLOSE_DEADLINE, Duration::from_secs(5));
        assert_eq!(NOT_PAIRED, "not_paired");
        assert_eq!(UNEXPECTED_AUTHORIZATION, "unexpected_authorization");
    }

    #[test]
    fn the_default_budget_is_valid_and_leaves_64_streams_to_phones() {
        let b = DeviceStreamBudget::default();
        assert_eq!(b.validate(), Ok(()));
        assert_eq!(b.non_admin_streams(), 64);
    }

    #[test]
    fn budgets_that_break_a_relation_are_refused() {
        let with = |streams_per_device, budget, admin_reserve| {
            DeviceStreamBudget {
                streams_per_device,
                budget,
                admin_reserve,
            }
            .validate()
        };
        assert_eq!(with(0, 96, 32), Err(BudgetError::NoStreamsPerDevice));
        assert_eq!(with(16, 96, 15), Err(BudgetError::ReserveBelowPerDevice));
        assert_eq!(with(16, 96, 96), Err(BudgetError::ReserveNotBelowBudget));
        assert_eq!(with(16, 16, 16), Err(BudgetError::ReserveNotBelowBudget));
        // The edges that hold.
        assert_eq!(with(16, 17, 16), Ok(()));
        assert_eq!(with(1, 2, 1), Ok(()));
        assert_eq!(
            DeviceStreamBudget {
                streams_per_device: 1,
                budget: 0,
                admin_reserve: 5
            }
            .non_admin_streams(),
            0
        );
    }

    /// Clients key on the number: it never changes, and it is not one of H1's (0 is "closed by the agent", 1 is
    /// "closed by the server").
    #[test]
    fn the_not_paired_close_code_is_stable() {
        assert_eq!(CLOSE_NOT_PAIRED, 2);
    }
}
