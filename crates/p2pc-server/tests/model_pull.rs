// SPDX-License-Identifier: AGPL-3.0-only

//! The hub's own model pull and `service.setup` (H2 spec §7.2, §7.6; SI-H2-18 "The hub's own model pull"), against
//! a **fake Ollama**: the service behind a fake agent's port, which answers `POST /api/pull` with a few bounded
//! NDJSON lines and records every byte the hub sends it. No registry is ever contacted.
//!
//! The server runs as `serve` wires it, over loopback iroh with relays disabled. The clock is injected: the 2 h
//! deadline and the idle timeout pass by moving it. Nothing sleeps to synchronise: a test waits for what the hub or
//! the fake service does, under `WAIT`.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::http::{Method, StatusCode};
use common::assert_problem;
use common::ports::{Act, CHAT_PORT, World, eventually, plain_service, template_service};
use p2pc_proto::ids::JobId;
use p2pc_proto::protocol::{HealthState, ServerMsg};
use p2pc_server::clock::Clock;
use p2pc_server::model_pull::{ModelPuller, PullLimits, pull_request};
use p2pc_server::store;
use serde_json::{Value, json};
use time::Duration;
use tokio::sync::Semaphore;

const MODEL: &str = "qwen3:1.7b";
const MIB: u64 = 1024 * 1024;

const HEAD: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n";
/// The end of a chunked answer.
const END: &str = "0\r\n\r\n";
const PULLING: &str = "{\"status\":\"pulling manifest\"}\n";
const SUCCESS: &str = "{\"status\":\"success\"}\n";

/// `line` as one chunk of a chunked answer.
fn chunk(line: &str) -> String {
    format!("{:x}\r\n{line}\r\n", line.len())
}

/// A progress line of a model layer, as Ollama sends it.
fn layer(name: &str, completed_mb: u64, total_mb: u64) -> String {
    format!(
        "{{\"status\":\"pulling {name}\",\"digest\":\"sha256:{name}\",\"total\":{},\"completed\":{}}}\n",
        total_mb * MIB,
        completed_mb * MIB
    )
}

/// A whole answer: the head, each line as a chunk, and the end.
fn answer(lines: &[&str]) -> Vec<u8> {
    let mut out = HEAD.to_string();
    for line in lines {
        out.push_str(&chunk(line));
    }
    out.push_str(END);
    out.into_bytes()
}

/// The private chat as its launch stores it: a template service whose `template.pull` is `MODEL`.
fn chat() -> Value {
    let mut spec = template_service("private-chat");
    spec["template"]["pull"] = json!(MODEL);
    spec["service"]["idle_timeout_s"] = json!(300);
    spec
}

/// The hub with a node, and a puller whose waits are short.
async fn world() -> World {
    let w = World::start().await;
    w.app().state.puller.set_limits(short_limits());
    w
}

fn short_limits() -> PullLimits {
    PullLimits {
        poll: StdDuration::from_millis(10),
        progress_interval: StdDuration::ZERO,
        ..PullLimits::default()
    }
}

/// One pass of the puller, as the hub makes once a second: how many pull sessions it started.
async fn scan(w: &World) -> usize {
    let state = &w.app().state;
    state.puller.scan(state).await.unwrap()
}

async fn setup(w: &World, job: JobId) -> Value {
    w.job(job).await["service"]["setup"].clone()
}

/// Waits until `service.setup` of `job` passes `ready`, and returns it.
async fn setup_when(w: &World, job: JobId, what: &str, ready: impl Fn(&Value) -> bool) -> Value {
    eventually(what, || async {
        let s = setup(w, job).await;
        ready(&s).then_some(s)
    })
    .await
}

/// Waits until the fake service has been asked for `n` connections.
async fn opens(w: &World, n: usize) {
    let service = w.node.service.clone();
    eventually(&format!("{n} PortOpen(s) at the service"), || {
        let service = service.clone();
        async move { (service.opens().len() >= n).then_some(()) }
    })
    .await;
    assert_eq!(w.node.service.opens().len(), n);
}

fn http(first: Vec<u8>, second: Vec<u8>, gate: Option<Arc<Semaphore>>) -> Act {
    Act::Http { first, second, gate }
}

#[tokio::test]
async fn a_healthy_attempt_gets_one_pull_of_the_stored_model_and_a_final_success_sets_done() {
    let mut w = world().await;
    let gate = Arc::new(Semaphore::new(0));
    let first = format!("{HEAD}{}{}", chunk(PULLING), chunk(&layer("aaa", 1500, 2000)));
    let second = format!("{}{}{END}", chunk(&layer("aaa", 2000, 2000)), chunk(SUCCESS));
    w.node
        .service
        .set(http(first.into_bytes(), second.into_bytes(), Some(gate.clone())));

    // The attempt runs but is not healthy yet: a fresh setup, and no pull.
    let job = w.store_job(w.owner(), chat()).await;
    let (lease_id, epoch) = w.node.start_next_unready(&w.fleet).await;
    assert_eq!(
        setup(&w, job).await,
        json!({"state": "pulling", "completed_mb": 0, "total_mb": null, "tries": 0, "reason": null})
    );
    assert_eq!(scan(&w).await, 0);
    assert!(w.node.service.opens().is_empty());

    // Healthy: one `POST /api/pull`, and its progress is `service.setup`.
    w.node.health(&w.fleet, lease_id, epoch, HealthState::Healthy).await;
    assert_eq!(scan(&w).await, 1);
    let s = setup_when(&w, job, "the progress of the pull", |s| s["completed_mb"] == 1500).await;
    assert_eq!(
        s,
        json!({"state": "pulling", "completed_mb": 1500, "total_mb": 2000, "tries": 1, "reason": null})
    );
    // The pull is an open connection of the service (H2 §7.4), and the only pull: scanning again starts nothing.
    assert_eq!(w.job(job).await["service"]["open_connections"], 1);
    assert_eq!(scan(&w).await, 0);
    assert!(w.app().state.puller.is_pulling(job));

    gate.add_permits(1);
    let s = setup_when(&w, job, "the pull to be done", |s| s["state"] == "done").await;
    assert_eq!(
        s,
        json!({"state": "done", "completed_mb": 2000, "total_mb": 2000, "tries": 1, "reason": null})
    );
    // What reached the service: exactly one request, for the model stored with the job, ended cleanly.
    let seen = w.node.seen().await;
    assert_eq!(seen.bytes, pull_request(MODEL, CHAT_PORT));
    assert_eq!(
        String::from_utf8(seen.bytes).unwrap().split_once("\r\n\r\n").unwrap().1,
        r#"{"model":"qwen3:1.7b","stream":true}"#
    );
    assert!(seen.clean);
    assert_eq!(
        (seen.open.lease_id, seen.open.epoch, seen.open.port),
        (lease_id, epoch, CHAT_PORT)
    );
    // Done is final for the attempt: nothing pulls again, and the connection is gone.
    eventually("the pull session to end", || async {
        (!w.app().state.puller.is_pulling(job)).then_some(())
    })
    .await;
    assert_eq!(scan(&w).await, 0);
    assert_eq!(w.node.service.opens().len(), 1);
    assert_eq!(w.job(job).await["service"]["open_connections"], 0);
}

/// Each way a try fails: the hub retries once at once, the fake sees exactly two pulls, and the setup is `failed`
/// with that reason. The hub does not pull again in that attempt.
#[tokio::test]
async fn a_failed_try_is_retried_once_and_then_the_setup_is_failed_with_its_reason() {
    let long = format!("{{\"status\":\"{}\"}}\n", "x".repeat(4096));
    let cut_short = format!("{HEAD}{}", chunk(PULLING)).into_bytes();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // A line with `error`.
        (
            "error_line",
            answer(&[PULLING, "{\"error\":\"pull model manifest: file does not exist\"}\n"]),
        ),
        // The answer ends, completely, without the final success line.
        ("eof", answer(&[PULLING, &layer("aaa", 10, 10)])),
        // The service ends the stream in the middle of the answer.
        ("eof", cut_short),
        // A line over 4 KiB.
        ("bad_line", answer(&[PULLING, &long, SUCCESS])),
        // A malformed line.
        ("bad_line", answer(&[PULLING, "{\"status\": pulling}\n", SUCCESS])),
    ];
    for (reason, bytes) in cases {
        let mut w = world().await;
        w.node.service.set(http(bytes, Vec::new(), None));
        let (job, ..) = w.running(w.owner(), chat()).await;
        assert_eq!(scan(&w).await, 1, "{reason}");
        let s = setup_when(&w, job, "the setup to fail", |s| s["state"] == "failed").await;
        assert_eq!(s["reason"], reason);
        assert_eq!(s["tries"], 2, "{reason}: one automatic retry");
        // Exactly one retry reached the service, and both tries asked for the same model.
        opens(&w, 2).await;
        for _ in 0..2 {
            assert_eq!(w.node.seen().await.bytes, pull_request(MODEL, CHAT_PORT), "{reason}");
        }
        // Not again in this attempt, however often the hub looks.
        eventually("the pull session to end", || async {
            (!w.app().state.puller.is_pulling(job)).then_some(())
        })
        .await;
        assert_eq!(scan(&w).await, 0, "{reason}");
        assert_eq!(w.node.service.opens().len(), 2, "{reason}");
        // The service keeps running: the chat UI shows the reason and offers "Restart".
        assert_eq!(w.job(job).await["status"], "running");
    }
}

#[tokio::test]
async fn a_stream_the_service_breaks_is_stream_broken() {
    let mut w = world().await;
    w.node
        .service
        .set(Act::Reset(format!("{HEAD}{}", chunk(PULLING)).into_bytes()));
    let (job, ..) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    let s = setup_when(&w, job, "the setup to fail", |s| s["state"] == "failed").await;
    assert_eq!(
        (s["reason"].as_str(), s["tries"].as_u64()),
        (Some("stream_broken"), Some(2))
    );
    opens(&w, 2).await;
    // A node that refuses the connection is the same failure (`node_unreachable`).
    let mut w = world().await;
    w.node.service.set(Act::Refuse("connect_failed"));
    let (job, ..) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    let s = setup_when(&w, job, "the setup to fail", |s| s["state"] == "failed").await;
    assert_eq!(
        (s["reason"].as_str(), s["tries"].as_u64()),
        (Some("stream_broken"), Some(2))
    );
    opens(&w, 2).await;
    let _ = w.node.seen().await;
}

/// The agent's connection breaks during the first try and comes back with the lease still running: the try is
/// `stream_broken`, and the one retry reaches the service once the node is connected again.
#[tokio::test]
async fn an_agent_disconnect_breaks_the_try_and_the_retry_reaches_the_service_when_the_node_is_back() {
    let mut w = world().await;
    let gate = Arc::new(Semaphore::new(0));
    w.node.service.set(http(
        format!("{HEAD}{}", chunk(PULLING)).into_bytes(),
        Vec::new(),
        Some(gate),
    ));
    let (job, lease_id, epoch) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    opens(&w, 1).await;
    setup_when(&w, job, "the first try", |s| s["tries"] == 1).await;

    // The retry will find a service that answers.
    w.node.service.set(http(answer(&[PULLING, SUCCESS]), Vec::new(), None));
    let World { fleet, rest, node } = w;
    let node = node.reconnect(&fleet, &[(lease_id, epoch)]).await;
    let w = World { fleet, rest, node };
    // The first try broke with the connection. Whether its session saw the node back in time or not, the next look
    // of the hub makes sure the retry runs, and there is exactly one.
    eventually(
        "the first try to be recorded as broken, or the retry to start",
        || async {
            let s = setup(&w, job).await;
            (s["tries"] == 2 || !w.app().state.puller.is_pulling(job)).then_some(())
        },
    )
    .await;
    scan(&w).await;
    let s = setup_when(&w, job, "the retry to be done", |s| s["state"] == "done").await;
    assert_eq!(s["tries"], 2);
    opens(&w, 2).await;
    assert_eq!(
        w.job(job).await["status"],
        "running",
        "the attempt survived the reconnect"
    );
}

/// The 2 h deadline, on the injected clock.
#[tokio::test]
async fn a_try_that_runs_for_two_hours_fails_with_deadline() {
    let mut w = world().await;
    // A service that starts answering and then says nothing more.
    let never = Arc::new(Semaphore::new(0));
    w.node.service.set(http(
        format!("{HEAD}{}", chunk(&layer("aaa", 1, 2000))).into_bytes(),
        Vec::new(),
        Some(never.clone()),
    ));
    let (job, ..) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    opens(&w, 1).await;
    setup_when(&w, job, "the first try to read", |s| {
        s["tries"] == 1 && s["total_mb"] == 2000
    })
    .await;

    // One second short of two hours the try is still the first one.
    w.app().clock.advance(Duration::hours(2) - Duration::seconds(1));
    assert_eq!(setup(&w, job).await["state"], "pulling");
    assert_eq!(w.node.service.opens().len(), 1);
    // Two hours after it started the try fails, and the retry starts at once with its own two hours.
    w.app().clock.advance(Duration::seconds(1));
    opens(&w, 2).await;
    let s = setup_when(&w, job, "the retry", |s| s["tries"] == 2).await;
    assert_eq!(s["state"], "pulling");
    setup_when(&w, job, "the retry to read", |s| s["total_mb"] == 2000).await;
    w.app().clock.advance(Duration::hours(2));
    let s = setup_when(&w, job, "the setup to fail", |s| s["state"] == "failed").await;
    assert_eq!((s["reason"].as_str(), s["tries"].as_u64()), (Some("deadline"), Some(2)));
    assert_eq!(w.node.service.opens().len(), 2, "exactly one automatic retry");
    // Both streams were reset by the hub: the service, let go of its wait, finds the hub gone.
    never.add_permits(2);
    for _ in 0..2 {
        assert!(!w.node.seen().await.clean);
    }
}

/// A hub restart during the first try: the pull is sent again, with the model stored with the job.
#[tokio::test]
async fn a_hub_restart_during_the_first_try_sends_the_pull_again_with_the_stored_model() {
    let mut w = world().await;
    let never = Arc::new(Semaphore::new(0));
    w.node.service.set(http(
        format!("{HEAD}{}", chunk(PULLING)).into_bytes(),
        Vec::new(),
        Some(never.clone()),
    ));
    let (job, ..) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    opens(&w, 1).await;
    setup_when(&w, job, "the first try", |s| s["tries"] == 1).await;

    // The hub stops: its pull goes with it, and the database still has the try running.
    let state = w.app().state.clone();
    state.puller.shutdown();
    never.add_permits(1);
    assert!(!w.node.seen().await.clean, "the stream of the stopped hub was reset");
    assert_eq!(
        setup(&w, job).await,
        json!({"state": "pulling", "completed_mb": 0, "total_mb": null, "tries": 1, "reason": null})
    );

    // The hub starts again, with nothing in memory. It looks at every running attempt: the try that was running
    // counts as failed (`stream_broken`), and the retry asks for the stored model.
    w.node.service.set(http(answer(&[PULLING, SUCCESS]), Vec::new(), None));
    let restarted = ModelPuller::new(short_limits());
    assert_eq!(restarted.scan(&state).await.unwrap(), 1);
    let s = setup_when(&w, job, "the pull to be done", |s| s["state"] == "done").await;
    assert_eq!(s["tries"], 2);
    opens(&w, 2).await;
    assert_eq!(w.node.seen().await.bytes, pull_request(MODEL, CHAT_PORT));

    // A restart during the second try leaves nothing to retry: `failed`, `stream_broken`, and no third pull.
    let mut w = world().await;
    let never = Arc::new(Semaphore::new(0));
    w.node.service.set(http(
        format!("{HEAD}{}", chunk(PULLING)).into_bytes(),
        Vec::new(),
        Some(never),
    ));
    let (job, ..) = w.running(w.owner(), chat()).await;
    let state = w.app().state.clone();
    assert_eq!(scan(&w).await, 1);
    opens(&w, 1).await;
    setup_when(&w, job, "the first try", |s| s["tries"] == 1).await;
    state.puller.shutdown();
    let second = ModelPuller::new(short_limits());
    assert_eq!(second.scan(&state).await.unwrap(), 1);
    opens(&w, 2).await;
    setup_when(&w, job, "the second try", |s| s["tries"] == 2).await;
    second.shutdown();
    let third = ModelPuller::new(short_limits());
    assert_eq!(
        third.scan(&state).await.unwrap(),
        1,
        "it looks at the attempt once more"
    );
    let s = setup_when(&w, job, "the setup to fail", |s| s["state"] == "failed").await;
    assert_eq!(
        (s["reason"].as_str(), s["tries"].as_u64()),
        (Some("stream_broken"), Some(2))
    );
    assert_eq!(third.scan(&state).await.unwrap(), 0);
    assert_eq!(w.node.service.opens().len(), 2, "no third pull");
}

/// A new attempt after a node loss starts with a fresh setup and pulls again, with the stored model.
#[tokio::test]
async fn a_new_attempt_after_a_node_loss_pulls_again_with_a_fresh_setup() {
    let mut w = world().await;
    w.node.service.set(http(answer(&[PULLING, SUCCESS]), Vec::new(), None));
    let (job, ..) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    setup_when(&w, job, "the pull to be done", |s| s["state"] == "done").await;
    opens(&w, 1).await;
    let _ = w.node.seen().await;
    // What a pull of the first attempt would write into, for the fencing check below.
    let old = {
        let mut conn = w.app().db.acquire().await.unwrap();
        store::setup::targets(&mut conn).await.unwrap().remove(0)
    };

    // The node is lost: its agent comes back without the lease, and the service is requeued (`on_node_loss`).
    let World { fleet, rest, node } = w;
    let node = node.restart(&fleet).await;
    let mut w = World { fleet, rest, node };
    let v = w.job(job).await;
    assert_eq!(v["status"], "queued");
    assert_eq!(v["service"]["setup"], Value::Null, "no attempt runs: no setup");

    let (lease_id, epoch) = w.node.start_next(&w.fleet).await;
    assert_ne!((lease_id, epoch), (old.lease_id, old.epoch));
    assert_eq!(
        setup(&w, job).await,
        json!({"state": "pulling", "completed_mb": 0, "total_mb": null, "tries": 0, "reason": null}),
        "a new attempt starts with a fresh setup, not with the `done` of the last one"
    );
    // A pull of the lost attempt can write nothing into this one: every write is fenced by its lease.
    {
        let mut tx = store::begin_immediate(&w.app().db).await.unwrap();
        let now = w.app().clock.now();
        assert!(!store::setup::begin_try(&mut tx, &old, 2, now).await.unwrap());
        assert!(!store::setup::progress(&mut tx, &old, 5, Some(9), now).await.unwrap());
        assert!(!store::setup::done(&mut tx, &old, now).await.unwrap());
        let broken = p2pc_proto::api::SetupFailure::StreamBroken;
        assert!(
            !store::setup::try_failed(&mut tx, &old, broken, true, now)
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
    }
    assert_eq!(setup(&w, job).await["tries"], 0);

    assert_eq!(scan(&w).await, 1);
    let s = setup_when(&w, job, "the pull to be done again", |s| s["state"] == "done").await;
    assert_eq!(s["tries"], 1);
    opens(&w, 2).await;
    let seen = w.node.seen().await;
    assert_eq!(seen.bytes, pull_request(MODEL, CHAT_PORT));
    assert_eq!((seen.open.lease_id, seen.open.epoch), (lease_id, epoch));
}

/// H2 §7.4 "Idle accounting", with the injected clock: a pull that runs past `idle_timeout_s` with no client
/// connection is not cancelled as `idle_timeout`, and the timeout counts from the end of the pull.
#[tokio::test]
async fn a_pull_that_runs_past_the_idle_timeout_is_not_an_idle_service() {
    let mut w = world().await;
    let gate = Arc::new(Semaphore::new(0));
    w.node.service.set(http(
        format!("{HEAD}{}", chunk(PULLING)).into_bytes(),
        format!("{}{END}", chunk(SUCCESS)).into_bytes(),
        Some(gate.clone()),
    ));
    // `idle_timeout_s` is 300; the attempt became healthy now.
    let (job, ..) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    opens(&w, 1).await;
    setup_when(&w, job, "the first try", |s| s["tries"] == 1).await;

    // Well past the idle timeout, with no client connection at all.
    w.app().clock.advance(Duration::seconds(1000));
    assert_eq!(w.fleet.scheduler.tick().await.errors, 0);
    let v = w.job(job).await;
    assert_eq!(v["status"], "running");
    assert_eq!(
        v["cancel_requested_at"],
        Value::Null,
        "not cancelled as idle: the hub is pulling"
    );
    assert_eq!(v["service"]["open_connections"], 1);
    assert_eq!(v["service"]["idle_deadline"], Value::Null);

    // The pull ends. Its end is the service's last activity: the idle timeout starts counting now.
    gate.add_permits(1);
    setup_when(&w, job, "the pull to be done", |s| s["state"] == "done").await;
    eventually("the pull session to end", || async {
        (!w.app().state.puller.is_pulling(job)).then_some(())
    })
    .await;
    let done_at = w.app().clock.now();
    assert_eq!(w.fleet.scheduler.tick().await.errors, 0);
    let v = w.job(job).await;
    assert_eq!(
        v["cancel_requested_at"],
        Value::Null,
        "the user gets the whole idle timeout after the download"
    );
    assert_eq!(v["service"]["open_connections"], 0);
    let rfc3339 = |t: time::OffsetDateTime| t.format(&time::format_description::well_known::Rfc3339).unwrap();
    assert_eq!(v["service"]["last_activity_at"], rfc3339(done_at));
    assert_eq!(v["service"]["idle_deadline"], rfc3339(done_at + Duration::seconds(300)));
    // And then it is an idle service like any other.
    w.app().clock.advance(Duration::seconds(300));
    assert_eq!(w.fleet.scheduler.tick().await.errors, 0);
    let sent = w.node.agent.sync().await;
    assert!(
        sent.iter()
            .any(|m| matches!(m, ServerMsg::Cancel { reason, .. } if reason == "idle_timeout")),
        "{sent:?}"
    );
}

#[tokio::test]
async fn only_a_running_template_service_with_a_model_is_pulled() {
    let mut w = world().await;
    // A service from no template, a template service without a model, and a chat that is being stopped.
    let (plain, ..) = w.running(w.owner(), plain_service()).await;
    let (notes, ..) = w.running(w.owner(), template_service("notes")).await;
    let (stopping, ..) = w.running(w.owner(), chat()).await;
    let app = w.app();
    let r = app
        .call(
            Method::POST,
            &format!("/v1/jobs/{stopping}/cancel"),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(scan(&w).await, 0);
    assert!(w.node.service.opens().is_empty());
    for job in [plain, notes] {
        assert_eq!(
            setup(&w, job).await,
            Value::Null,
            "`null` for a job without a model pull"
        );
    }
}

/// End to end: a launch of the shipped `private-chat` template is what the hub then pulls for, and a second launch
/// with another model names the running one (SI-H2-18).
#[tokio::test]
async fn a_launched_private_chat_gets_its_default_model_pulled() {
    const LAUNCH: &str = "/v1/templates/private-chat/launch";
    let World { fleet, rest, node } = world().await;
    // The template has a volume, so its node declares `volumes` too.
    let node = node.with_features(&fleet, &["service_jobs", "volumes"]).await;
    let mut w = World { fleet, rest, node };
    w.node.service.set(http(answer(&[PULLING, SUCCESS]), Vec::new(), None));
    let app = w.app();
    let r = app.call(Method::POST, LAUNCH, Some(&app.admin), Some(json!({}))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let launched = r.json();
    assert_eq!(launched["spec"]["template"]["pull"], "qwen3:4b-instruct");
    let job: JobId = launched["id"].as_str().unwrap().parse().unwrap();

    let (lease_id, epoch) = w.node.start_next(&w.fleet).await;
    assert_eq!(scan(&w).await, 1);
    let s = setup_when(&w, job, "the pull to be done", |s| s["state"] == "done").await;
    assert_eq!(s["tries"], 1);
    let seen = w.node.seen().await;
    assert_eq!(seen.bytes, pull_request("qwen3:4b-instruct", CHAT_PORT));
    assert_eq!(
        (seen.open.lease_id, seen.open.epoch, seen.open.port),
        (lease_id, epoch, CHAT_PORT)
    );

    let app = w.app();
    let other = json!({"params": {"model": "qwen3:1.7b"}});
    let r = app.call(Method::POST, LAUNCH, Some(&app.admin), Some(other)).await;
    let problem = assert_problem(&r, StatusCode::CONFLICT, "singleton_running");
    let detail = problem["detail"].as_str().unwrap();
    assert!(
        detail.contains("qwen3:4b-instruct") && detail.contains(&job.to_string()),
        "{detail}"
    );
    // The running instance keeps its model: nothing new was pulled.
    assert_eq!(scan(&w).await, 0);
    assert_eq!(w.node.service.opens().len(), 1);
}

/// `service.setup` once the job has ended: what its last attempt came to, never a pull that no longer runs.
#[tokio::test]
async fn the_setup_of_an_ended_job_is_what_its_last_attempt_came_to() {
    // The pull is done, then the service exits: `done` stays.
    let mut w = world().await;
    w.node.service.set(http(answer(&[PULLING, SUCCESS]), Vec::new(), None));
    let (job, lease_id, epoch) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    setup_when(&w, job, "the pull to be done", |s| s["state"] == "done").await;
    w.node.agent.finished(lease_id, epoch, 0, vec![]).await;
    let v = w.job(job).await;
    assert_eq!(v["status"], "succeeded");
    assert_eq!(v["service"]["setup"]["state"], "done");

    // The service exits in the middle of a pull: the job has no pull any more, and the hub's session ends with it.
    let mut w = world().await;
    let never = Arc::new(Semaphore::new(0));
    w.node.service.set(http(
        format!("{HEAD}{}", chunk(PULLING)).into_bytes(),
        Vec::new(),
        Some(never),
    ));
    let (job, lease_id, epoch) = w.running(w.owner(), chat()).await;
    assert_eq!(scan(&w).await, 1);
    opens(&w, 1).await;
    setup_when(&w, job, "the first try", |s| s["tries"] == 1).await;
    w.node.agent.finished(lease_id, epoch, 0, vec![]).await;
    let v = w.job(job).await;
    assert_eq!(v["status"], "succeeded");
    assert_eq!(v["service"]["setup"], Value::Null);
    assert_eq!(scan(&w).await, 0);
    assert!(!w.app().state.puller.is_pulling(job));
    eventually("the ended pull to give its connection back", || async {
        (w.job(job).await["service"]["open_connections"] == 0).then_some(())
    })
    .await;
}
