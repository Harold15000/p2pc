// SPDX-License-Identifier: AGPL-3.0-only

//! The gateway's limits (spec §6 "Before `Join`", §10; H2 §5.3, §6.3), a fixed-window rate limiter and the device
//! stream budget.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration as StdDuration;

use p2pc_proto::device::{self, DeviceStreamBudget};
use p2pc_proto::ids::DeviceId;
use p2pc_proto::pair;
use time::{Duration, OffsetDateTime};

/// Every limit of the gateway. [`GatewayLimits::default`] is the spec; tests shorten the timeouts.
#[derive(Debug, Clone)]
pub struct GatewayLimits {
    /// Connections from NodeIds that are not enrolled, at once (§6: 64).
    pub max_unknown_connections: usize,
    /// `Join`s being processed at once (§6: 16).
    pub max_pending_joins: usize,
    /// Time for the first message of a connection (`Join` or `Hello`) to arrive (§6: 10 s for `Join`).
    pub first_message_timeout: StdDuration,
    /// `p2pc/agent/1` connections at once per enrolled node; a further one is closed with no detail. Only one of
    /// them is the node's session (a newer one replaces it), so this bounds what one NodeId can hold open.
    pub max_connections_per_node: usize,
    /// Failed `Join`s per NodeId per minute (§6: 10).
    pub join_failures_per_node_per_minute: u32,
    /// Failed `Join`s per minute in total (§6: 60). Beyond it failures get no detailed answer, but the token is still
    /// looked up, so a valid one enrolls (H2 §6.1, T2-17).
    pub join_failures_per_minute: u32,
    /// Frames decoded at once, across all connections: bounds serde's decode amplification (T02 review).
    pub max_concurrent_decodes: usize,
    /// QUIC handshakes in progress at once.
    pub max_handshakes: usize,
    /// Time for a QUIC handshake.
    pub handshake_timeout: StdDuration,
    /// `p2pc/http/1` streams at once per connection (64).
    pub http_streams_per_connection: usize,
    /// `p2pc/http/1` streams at once in total: `iroh.tunnel_max_streams` (§10 "Tunnel budget", 128 by default).
    pub http_streams_total: usize,
    /// `p2pc/http/1` connections at once in total (NodeIds cost nothing to make, so the per-NodeId rate alone
    /// does not bound them).
    pub http_connections_total: usize,
    /// `p2pc/http/1` connections at once per NodeId (8). A `p2pc proxy` or a CLI uses one; the cap keeps one peer
    /// from holding every slot of `http_connections_total` (T05 review).
    pub http_connections_per_node: usize,
    /// New `p2pc/http/1` connections per NodeId per minute.
    pub http_connections_per_node_per_minute: u32,
    /// `last_seen` is written to SQLite at most this often per node (and on disconnect).
    pub last_seen_flush: Duration,
    /// How long the server waits for the peer to read a final message (an `Error`) before closing.
    pub final_message_grace: StdDuration,
    /// How often the liveness sweep runs.
    pub sweep_interval: StdDuration,
    /// Output upload streams (§6 "Uploads", T10b): 2 per node and 8 in total at once, 30 s idle, 64 KiB/s after
    /// the first 10 s.
    pub uploads: crate::outputs::UploadLimits,
    /// `p2pc/pair/1` connections at once, counted apart from the other ALPNs (H2 §5.3: 32).
    pub pair_max_connections: usize,
    /// `Pair`s being checked at once (H2 §5.3: 8).
    pub pair_max_pending: usize,
    /// Time for the one `Pair` of a connection to arrive, counted from the handshake (H2 §5.3: 10 s).
    pub pair_deadline: StdDuration,
    /// Failed pairings per NodeId per minute; a NodeId over it is refused when it connects (H2 §5.3: 10).
    pub pair_failures_per_node_per_minute: u32,
    /// Failed pairings per ticket-hash prefix per minute; beyond it a failing attempt in that prefix is closed with
    /// no detail, and a valid ticket still pairs (H2 §5.3: 10).
    pub pair_failures_per_prefix_per_minute: u32,
    /// The aggregate failure cap of `p2pc/pair/1` and of the device check of `p2pc/device/1`, each counted on its own
    /// (H2 §5.3: 60 a minute). Beyond it a failure gets no detailed answer and is not logged one by one; the
    /// credential is still looked up, so a valid one succeeds. `p2pc/agent/1` has `join_failures_per_minute`.
    pub aggregate_failures_per_minute: u32,
    /// `p2pc/device/1` connections at once that have not passed the device check (H2 §6.3: 32).
    pub device_max_unchecked_connections: usize,
    /// Time for the device check of a connection, counted from the handshake (H2 §6.3: 5 s).
    pub device_check_deadline: StdDuration,
    /// `not_paired` closes per NodeId per minute; a NodeId over it is closed at connect without the lookup (H2 §6.3:
    /// 10).
    pub device_not_paired_per_node_per_minute: u32,
    /// `p2pc/device/1` connections at once per device (H2 §6.3: 2).
    pub device_connections_per_device: usize,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            max_unknown_connections: 64,
            max_pending_joins: 16,
            first_message_timeout: StdDuration::from_secs(10),
            max_connections_per_node: 4,
            join_failures_per_node_per_minute: 10,
            join_failures_per_minute: 60,
            max_concurrent_decodes: 8,
            max_handshakes: 256,
            handshake_timeout: StdDuration::from_secs(10),
            http_streams_per_connection: 64,
            http_streams_total: crate::config::DEFAULT_TUNNEL_MAX_STREAMS as usize,
            http_connections_total: 256,
            http_connections_per_node: 8,
            http_connections_per_node_per_minute: 60,
            last_seen_flush: Duration::seconds(15),
            final_message_grace: StdDuration::from_secs(2),
            sweep_interval: StdDuration::from_secs(1),
            uploads: crate::outputs::UploadLimits::default(),
            pair_max_connections: pair::PAIR_MAX_CONNECTIONS,
            pair_max_pending: pair::PAIR_MAX_PENDING,
            pair_deadline: pair::PAIR_DEADLINE,
            pair_failures_per_node_per_minute: pair::PAIR_FAILURES_PER_NODE_PER_MINUTE,
            pair_failures_per_prefix_per_minute: pair::PAIR_FAILURES_PER_PREFIX_PER_MINUTE,
            aggregate_failures_per_minute: pair::AGGREGATE_FAILURE_CAP_PER_MINUTE,
            device_max_unchecked_connections: device::MAX_UNCHECKED_CONNECTIONS,
            device_check_deadline: device::DEVICE_CHECK_DEADLINE,
            device_not_paired_per_node_per_minute: device::NOT_PAIRED_PER_NODE_PER_MINUTE,
            device_connections_per_device: device::MAX_CONNECTIONS_PER_DEVICE,
        }
    }
}

/// The device stream budget (H2 §6.3), counted apart from the REST connection cap and the tunnel budget: device
/// streams never take a TCP slot and TCP connections never take a device slot.
///
/// A stream is one HTTP/1.1 connection of a `p2pc/device/1` connection; it holds its [`StreamSlot`] for its whole
/// life, an upgraded port connection or a log follow included. Three caps apply to a new stream:
/// - **per device:** `streams_per_device` across the device's connections;
/// - **in total:** `budget`;
/// - **the `admin` reserve:** devices without the `admin` scope hold together at most `budget - admin_reserve`, so
///   the hub PC's app, which is how a device gets revoked, always finds a slot whatever paired phones do.
#[derive(Debug)]
pub struct DeviceBudget {
    limits: DeviceStreamBudget,
    used: Arc<Mutex<BudgetUse>>,
}

#[derive(Debug, Default)]
struct BudgetUse {
    total: usize,
    non_admin: usize,
    per_device: HashMap<DeviceId, usize>,
}

/// One device stream of the budget. Dropping it gives the slot back.
#[derive(Debug)]
pub struct StreamSlot {
    used: Arc<Mutex<BudgetUse>>,
    device_id: DeviceId,
    admin: bool,
}

impl DeviceBudget {
    /// An unused budget with `limits`.
    #[must_use]
    pub fn new(limits: DeviceStreamBudget) -> Self {
        Self {
            limits,
            used: Arc::default(),
        }
    }

    /// The limits this budget enforces.
    #[must_use]
    pub fn limits(&self) -> DeviceStreamBudget {
        self.limits
    }

    /// A slot for one more stream of `device_id`, or `None` when the device, the non-`admin` share or the whole
    /// budget is full. `admin` says whether the device has the `admin` scope.
    #[must_use]
    pub fn try_acquire(&self, device_id: DeviceId, admin: bool) -> Option<StreamSlot> {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        if used.total >= self.limits.budget
            || used.per_device.get(&device_id).copied().unwrap_or(0) >= self.limits.streams_per_device
            || (!admin && used.non_admin >= self.limits.non_admin_streams())
        {
            return None;
        }
        used.total += 1;
        if !admin {
            used.non_admin += 1;
        }
        *used.per_device.entry(device_id).or_insert(0) += 1;
        Some(StreamSlot {
            used: self.used.clone(),
            device_id,
            admin,
        })
    }

    /// Streams open now, in total.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.used.lock().unwrap_or_else(PoisonError::into_inner).total
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        used.total = used.total.saturating_sub(1);
        if !self.admin {
            used.non_admin = used.non_admin.saturating_sub(1);
        }
        if let Some(count) = used.per_device.get_mut(&self.device_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                used.per_device.remove(&self.device_id);
            }
        }
    }
}

/// Caps how many frames are decoded at once, across all connections (T02 review: serde's tagged-enum buffering can
/// cost ×16-30 a frame's size while it decodes). Reading the bytes happens before, outside the cap, so a slow peer
/// never holds a slot.
#[derive(Debug)]
pub struct DecodeGate {
    permits: tokio::sync::Semaphore,
}

impl DecodeGate {
    /// A gate letting `max` decodes run at once.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            permits: tokio::sync::Semaphore::new(max),
        }
    }

    /// Waits for a slot, then decodes `body` as `T` and releases the slot. `None` if the gate is closed.
    pub async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        body: &[u8],
    ) -> Option<Result<T, p2pc_proto::protocol::FrameError>> {
        let _permit = self.permits.acquire().await.ok()?;
        Some(p2pc_proto::protocol::decode_frame(body))
    }

    /// Slots free right now.
    #[must_use]
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// Most keys a [`MinuteLimiter`] tracks. Beyond it, a new key evicts the oldest one (T05 review): keys such as
/// NodeIds cost nothing to make, and failing closed would let anyone lock everyone out for the rest of the minute.
const MAX_KEYS: usize = 4096;

/// Counts events per key in fixed one-minute windows of the injected clock, with a per-key and a total cap.
///
/// The table holds at most [`MAX_KEYS`] keys; a new key evicts the one that was seen first in the window. An
/// attacker who cycles through that many keys can reset one key's count, but never the total cap, and never refuse
/// others.
#[derive(Debug)]
pub struct MinuteLimiter {
    per_key: u32,
    total: u32,
    window: i64,
    counts: HashMap<String, u32>,
    /// The keys of `counts`, oldest first.
    order: VecDeque<String>,
    sum: u32,
}

impl MinuteLimiter {
    /// A limiter allowing `per_key` events per key and `total` events overall per minute.
    #[must_use]
    pub fn new(per_key: u32, total: u32) -> Self {
        Self {
            per_key,
            total,
            window: i64::MIN,
            counts: HashMap::new(),
            order: VecDeque::new(),
            sum: 0,
        }
    }

    fn roll(&mut self, now: OffsetDateTime) {
        let window = now.unix_timestamp().div_euclid(60);
        if window != self.window {
            self.window = window;
            self.counts.clear();
            self.order.clear();
            self.sum = 0;
        }
    }

    /// Whether another event for `key` would still be within both caps at `now`.
    pub fn allows(&mut self, key: &str, now: OffsetDateTime) -> bool {
        self.key_allows(key, now) && self.total_allows(now)
    }

    /// Whether another event for `key` would still be within the per-key cap at `now`, whatever the total.
    pub fn key_allows(&mut self, key: &str, now: OffsetDateTime) -> bool {
        self.roll(now);
        self.counts.get(key).copied().unwrap_or(0) < self.per_key
    }

    /// Whether another event would still be within the total cap at `now`, whatever its key.
    pub fn total_allows(&mut self, now: OffsetDateTime) -> bool {
        self.roll(now);
        self.sum < self.total
    }

    /// Counts an event for `key` at `now`, and returns whether it was within the total cap (before it was counted).
    /// A new key in a full table evicts the oldest key.
    pub fn record(&mut self, key: &str, now: OffsetDateTime) -> bool {
        self.roll(now);
        let within_total = self.sum < self.total;
        if let Some(count) = self.counts.get_mut(key) {
            *count = count.saturating_add(1);
        } else {
            while self.counts.len() >= MAX_KEYS {
                let Some(oldest) = self.order.pop_front() else { break };
                self.counts.remove(&oldest);
            }
            self.counts.insert(key.to_string(), 1);
            self.order.push_back(key.to_string());
        }
        self.sum = self.sum.saturating_add(1);
        within_total
    }

    /// How many keys the table holds now.
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.counts.len()
    }

    /// [`MinuteLimiter::allows`], then [`MinuteLimiter::record`] when allowed.
    pub fn try_take(&mut self, key: &str, now: OffsetDateTime) -> bool {
        let ok = self.allows(key, now);
        if ok {
            self.record(key, now);
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const T: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);

    /// The gate never lets more than `max` decodes run: with every slot taken, a decode waits (it is polled by
    /// hand, so nothing depends on timing), and it runs once a slot frees.
    #[test]
    fn the_decode_gate_caps_concurrent_decodes() {
        use std::future::Future as _;
        use std::task::{Context, Poll, Waker};

        let gate = DecodeGate::new(8);
        assert_eq!(gate.available(), 8);
        // Take every slot, as eight decodes in progress would.
        let held: Vec<_> = (0..8).map(|_| gate.permits.try_acquire().unwrap()).collect();
        assert_eq!(gate.available(), 0);
        let body = br#"{"type":"heartbeat_ack","seq":7}"#;
        let mut ninth = Box::pin(gate.decode::<p2pc_proto::protocol::ServerMsg>(body));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..3 {
            assert!(ninth.as_mut().poll(&mut cx).is_pending(), "a ninth decode must wait");
        }
        drop(held);
        match ninth.as_mut().poll(&mut cx) {
            Poll::Ready(Some(Ok(p2pc_proto::protocol::ServerMsg::HeartbeatAck { seq: 7 }))) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(gate.available(), 8, "the slot is released after the decode");
    }

    fn budget(streams_per_device: usize, budget: usize, admin_reserve: usize) -> DeviceBudget {
        let limits = DeviceStreamBudget {
            streams_per_device,
            budget,
            admin_reserve,
        };
        assert_eq!(limits.validate(), Ok(()));
        DeviceBudget::new(limits)
    }

    /// H2 §6.3: the pre-auth limits of `p2pc/pair/1` and of the device check are the spec's.
    #[test]
    fn the_h2_defaults_are_the_specs() {
        let l = GatewayLimits::default();
        assert_eq!((l.pair_max_connections, l.pair_max_pending), (32, 8));
        assert_eq!(l.pair_deadline, StdDuration::from_secs(10));
        assert_eq!(
            (
                l.pair_failures_per_node_per_minute,
                l.pair_failures_per_prefix_per_minute,
                l.aggregate_failures_per_minute
            ),
            (10, 10, 60)
        );
        assert_eq!(l.device_max_unchecked_connections, 32);
        assert_eq!(l.device_check_deadline, StdDuration::from_secs(5));
        assert_eq!(l.device_not_paired_per_node_per_minute, 10);
        assert_eq!(l.device_connections_per_device, 2);
    }

    /// H2 §6.3 "Per device": a device holds at most `streams_per_device` streams, and a slot it gives back is usable
    /// again.
    #[test]
    fn a_device_is_capped_at_its_own_streams() {
        let b = budget(2, 8, 2);
        let phone = DeviceId::generate();
        let first = b.try_acquire(phone, false).unwrap();
        let _second = b.try_acquire(phone, false).unwrap();
        assert!(b.try_acquire(phone, false).is_none(), "a third stream of one device");
        // Another device is not affected.
        let _other = b.try_acquire(DeviceId::generate(), false).unwrap();
        assert_eq!(b.in_use(), 3);
        drop(first);
        assert_eq!(b.in_use(), 2);
        assert!(b.try_acquire(phone, false).is_some());
    }

    /// H2 §6.3 "Reserved for `admin`", SI-H2-4: phones hold together at most the budget minus the reserve, whatever
    /// their number, and an `admin` device still opens its own share from the reserve.
    #[test]
    fn non_admin_devices_never_take_the_admin_reserve() {
        let b = budget(2, 6, 2);
        let mut held = Vec::new();
        // Four phone streams: the whole non-admin share (6 - 2).
        for _ in 0..2 {
            let phone = DeviceId::generate();
            held.push(b.try_acquire(phone, false).unwrap());
            held.push(b.try_acquire(phone, false).unwrap());
        }
        let late_phone = DeviceId::generate();
        assert!(
            b.try_acquire(late_phone, false).is_none(),
            "the non-admin share is full"
        );
        // The owner's app still gets its whole per-device share.
        let app = DeviceId::generate();
        held.push(b.try_acquire(app, true).unwrap());
        held.push(b.try_acquire(app, true).unwrap());
        assert_eq!(b.in_use(), 6);
        // The whole budget is in use: nobody gets a stream, `admin` or not.
        assert!(b.try_acquire(DeviceId::generate(), true).is_none());
        assert!(b.try_acquire(late_phone, false).is_none());
        // A phone slot given back goes to a phone again.
        held.remove(0);
        assert!(b.try_acquire(late_phone, false).is_some());
    }

    /// `admin` devices may use the whole budget; the phones then wait, and the total is never exceeded.
    #[test]
    fn the_total_budget_bounds_admin_devices_too() {
        let b = budget(2, 5, 2);
        let mut held = Vec::new();
        for _ in 0..2 {
            let app = DeviceId::generate();
            held.push(b.try_acquire(app, true).unwrap());
            held.push(b.try_acquire(app, true).unwrap());
        }
        let phone = DeviceId::generate();
        held.push(b.try_acquire(phone, false).unwrap());
        assert_eq!(b.in_use(), 5);
        assert!(b.try_acquire(phone, false).is_none());
        assert!(b.try_acquire(DeviceId::generate(), true).is_none());
        held.clear();
        assert_eq!(b.in_use(), 0);
    }

    #[test]
    fn per_key_and_total_caps_reset_each_minute() {
        let mut l = MinuteLimiter::new(10, 60);
        for _ in 0..10 {
            assert!(l.allows("a", T));
            l.record("a", T);
        }
        assert!(!l.allows("a", T + Duration::seconds(59)));
        assert!(l.allows("b", T));
        for i in 0..50 {
            assert!(l.try_take(&format!("k{}", i % 5), T), "{i}");
        }
        assert!(!l.allows("fresh", T), "60 in total this minute");
        // The next minute starts empty.
        assert!(l.allows("a", T + Duration::seconds(60)));
        assert!(l.allows("fresh", T + Duration::seconds(60)));
    }

    /// H2 §6.1 (T2-17): the per-key and the total caps are told apart, so a caller can refuse a key over its own cap
    /// and still serve a fresh key once only the total is reached. `record` says whether the event fit in the total,
    /// and keeps counting per key beyond it.
    #[test]
    fn the_per_key_and_total_caps_are_reported_apart() {
        let mut l = MinuteLimiter::new(2, 3);
        assert!(l.record("a", T), "1 of 3");
        assert!(l.record("b", T), "2 of 3");
        assert!(l.record("c", T), "3 of 3");
        assert!(!l.total_allows(T));
        assert!(!l.allows("fresh", T), "the combined check still refuses");
        assert!(l.key_allows("fresh", T), "a fresh key is within its own cap");
        assert!(l.key_allows("a", T));
        assert!(!l.record("a", T), "beyond the total");
        assert!(!l.key_allows("a", T), "counted per key beyond the total too");
        assert!(l.key_allows("b", T));
        // The next minute starts empty.
        assert!(l.total_allows(T + Duration::seconds(60)));
        assert!(l.key_allows("a", T + Duration::seconds(60)));
    }

    /// T05 review: NodeIds cost nothing, so a full table must not lock out new keys. The oldest key is evicted
    /// instead, and the table never grows past its bound.
    #[test]
    fn a_full_limiter_evicts_the_oldest_key_instead_of_failing_closed() {
        let mut l = MinuteLimiter::new(2, u32::MAX);
        assert!(l.try_take("first", T));
        assert!(l.try_take("first", T));
        assert!(!l.allows("first", T), "first is at its cap");
        for i in 0..MAX_KEYS - 1 {
            assert!(l.try_take(&format!("k{i}"), T), "{i}");
        }
        assert_eq!(l.tracked_keys(), MAX_KEYS);
        // The table is full: a brand-new key is still allowed, and it evicts the oldest one ("first").
        assert!(l.allows("newcomer", T));
        assert!(l.try_take("newcomer", T));
        assert_eq!(l.tracked_keys(), MAX_KEYS);
        assert!(
            l.allows("first", T),
            "the oldest key was evicted, so its count starts over"
        );
        // A key that is still tracked keeps its count.
        assert!(l.try_take("k5", T));
        assert!(!l.allows("k5", T));
    }
}
