// SPDX-License-Identifier: Apache-2.0

//! The one `tracing` capture of the lib's test binary: a **global** subscriber that keeps the `warn` (and worse)
//! events that carry a `lease_id`, so a test can check what the agent logged for its own lease.
//!
//! A thread-local `set_default` is not enough. Tracing's callsite interest cache and maximum level are process-wide,
//! and the other tests of this binary reach the same `warn!` with no subscriber of their own, so whether a scoped
//! subscriber saw its event depended on timing (T10n review: `a_failed_phase_logs_its_cause_at_warn` failed once in a
//! full run). It is the same flake as PR #18's (`tests/iroh_fake_server.rs`) and has the same cure: one global
//! subscriber, installed once. Each test reads only the lines of its own lease, so tests running in parallel do not see
//! each other's.
//!
//! The store is bounded: only events with a `lease_id`, only `warn` and above, and at most [`MAX_EVENTS`] of them.

use std::fmt::Write as _;
use std::sync::{Mutex, OnceLock, PoisonError};

use p2pc_proto::ids::LeaseId;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, registry};

/// The most events kept; the rest are dropped.
const MAX_EVENTS: usize = 4096;

/// `(lease_id, "LEVEL message field=value …")`.
static EVENTS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

struct Capture;

/// Collects an event's message and fields as text, and its `lease_id` apart.
#[derive(Default)]
struct Fields {
    lease_id: Option<String>,
    text: String,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "lease_id" {
            self.lease_id = Some(format!("{value:?}"));
        } else if field.name() == "message" {
            let _ = write!(self.text, " {value:?}");
        } else {
            let _ = write!(self.text, " {}={value:?}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let Some(lease_id) = fields.lease_id else {
            return;
        };
        let mut events = EVENTS.lock().unwrap_or_else(PoisonError::into_inner);
        if events.len() < MAX_EVENTS {
            events.push((lease_id, format!("{}{}", event.metadata().level(), fields.text)));
        }
    }
}

/// Installs the global subscriber, once. Call it first in every test that reads [`warnings`].
pub(crate) fn install() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let subscriber = registry().with(Capture.with_filter(LevelFilter::from_level(Level::WARN)));
        tracing::subscriber::set_global_default(subscriber)
            .expect("the lib's test binary has no other global subscriber");
    });
}

/// The `warn` (and worse) events logged for `lease_id` so far, as `"WARN message field=value …"`.
pub(crate) fn warnings(lease_id: &LeaseId) -> Vec<String> {
    let id = lease_id.to_string();
    EVENTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(lease, _)| *lease == id)
        .map(|(_, text)| text.clone())
        .collect()
}
