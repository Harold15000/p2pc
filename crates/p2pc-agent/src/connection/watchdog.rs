// SPDX-License-Identifier: Apache-2.0

//! The agent-side lease timer (§6 "Liveness on both sides", SI-13).
//!
//! Epochs fence the *reports* of a partitioned node; they do not stop its *execution*. So the agent tracks, on a
//! monotonic clock (tokio's), the last time **any** server message arrived. When nothing has arrived for
//! `agent_lease_ttl_s` (default 45), it calls [`LeaseSupervisor::stop_all`] with [`LEASE_LOST`], once, and then waits
//! for the next server message before it can fire again.
//!
//! It runs on its own task, independent of the connection: it keeps counting while the agent is disconnected and
//! while it backs off between reconnect attempts. Because `agent_lease_ttl_s + 10 <= lease_ttl_s`, a partitioned
//! agent stops its jobs before the server requeues them.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::lease::{LEASE_LOST, LeaseSupervisor};

#[derive(Debug)]
struct State {
    last_heard: Instant,
    ttl: Duration,
    fired: bool,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    changed: Notify,
}

/// A handle on the lease timer. Clones share it.
#[derive(Debug, Clone)]
pub struct Watchdog {
    inner: Arc<Inner>,
}

impl Watchdog {
    /// A timer of `ttl`, counting from now (the agent's start counts as the last contact).
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    last_heard: Instant::now(),
                    ttl,
                    fired: false,
                }),
                changed: Notify::new(),
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A server message arrived: the timer starts again.
    pub fn heard(&self) {
        {
            let mut s = self.state();
            s.last_heard = Instant::now();
            s.fired = false;
        }
        self.inner.changed.notify_one();
    }

    /// Sets the timer's length (the `Welcome` may lower it).
    pub fn set_ttl(&self, ttl: Duration) {
        self.state().ttl = ttl;
        self.inner.changed.notify_one();
    }

    /// The timer's length now.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.state().ttl
    }

    /// Starts the timer's task: it calls `supervisor.stop_all(LEASE_LOST)` each time the timer expires. Abort the
    /// handle to stop it.
    #[must_use]
    pub fn spawn(&self, supervisor: Arc<dyn LeaseSupervisor>) -> JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move { me.run(supervisor).await })
    }

    async fn run(self, supervisor: Arc<dyn LeaseSupervisor>) {
        loop {
            let deadline = {
                let s = self.state();
                (!s.fired).then(|| s.last_heard + s.ttl)
            };
            match deadline {
                // Fired: wait for the next server message (or a TTL change).
                None => self.inner.changed.notified().await,
                Some(deadline) => {
                    tokio::select! {
                        () = tokio::time::sleep_until(deadline) => {
                            let expired = {
                                let mut s = self.state();
                                let expired = !s.fired && Instant::now() >= s.last_heard + s.ttl;
                                s.fired |= expired;
                                expired
                            };
                            if expired {
                                tracing::error!(
                                    ttl_s = self.ttl().as_secs(),
                                    "no message from the server for agent_lease_ttl_s: stopping every running job \
                                     (lease_lost, SI-13)"
                                );
                                supervisor.stop_all(LEASE_LOST).await;
                            }
                        }
                        () = self.inner.changed.notified() => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use p2pc_proto::protocol::RunningLease;

    use super::*;
    use crate::connection::BoxFuture;

    #[derive(Debug, Default)]
    struct Stops(AtomicUsize);

    impl LeaseSupervisor for Stops {
        fn running(&self) -> Vec<RunningLease> {
            Vec::new()
        }
        fn stop_all(&self, reason: &'static str) -> BoxFuture<'_, ()> {
            assert_eq!(reason, LEASE_LOST);
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
        fn drain(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
        fn resume(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    fn start(ttl_s: u64) -> (Watchdog, Arc<Stops>, JoinHandle<()>) {
        let stops = Arc::new(Stops::default());
        let w = Watchdog::new(Duration::from_secs(ttl_s));
        let task = w.spawn(stops.clone());
        (w, stops, task)
    }

    async fn wait(s: u64) {
        tokio::time::sleep(Duration::from_secs(s)).await;
    }

    /// SI-13: 45 s with nothing: `stop_all("lease_lost")`, exactly once.
    #[tokio::test(start_paused = true)]
    async fn fires_once_after_45_s_of_silence() {
        let (_w, stops, task) = start(45);
        wait(44).await;
        assert_eq!(stops.0.load(Ordering::SeqCst), 0);
        wait(1).await;
        tokio::task::yield_now().await;
        assert_eq!(stops.0.load(Ordering::SeqCst), 1);
        wait(3600).await;
        assert_eq!(stops.0.load(Ordering::SeqCst), 1, "exactly once");
        task.abort();
    }

    /// SI-13: a message at 44 s starts the timer again; it fires 45 s after that message.
    #[tokio::test(start_paused = true)]
    async fn a_message_at_44_s_resets_the_timer() {
        let (w, stops, task) = start(45);
        wait(44).await;
        w.heard();
        wait(44).await;
        assert_eq!(
            stops.0.load(Ordering::SeqCst),
            0,
            "88 s after start, 44 s after the message"
        );
        wait(1).await;
        tokio::task::yield_now().await;
        assert_eq!(stops.0.load(Ordering::SeqCst), 1);
        // After firing, a new message re-arms it.
        w.heard();
        wait(46).await;
        assert_eq!(stops.0.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_lowered_ttl_applies_at_once() {
        let (w, stops, task) = start(45);
        wait(20).await;
        w.set_ttl(Duration::from_secs(30));
        assert_eq!(w.ttl(), Duration::from_secs(30));
        wait(9).await;
        assert_eq!(stops.0.load(Ordering::SeqCst), 0);
        wait(2).await;
        tokio::task::yield_now().await;
        assert_eq!(stops.0.load(Ordering::SeqCst), 1, "30 s after the last contact, not 45");
        task.abort();
    }
}
