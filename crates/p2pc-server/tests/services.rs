// SPDX-License-Identifier: AGPL-3.0-only

//! Service jobs end to end (H2 spec §6.1, §7.1, §7.2, §7.4): `POST /v1/jobs` with `kind = "service"`, the `service`
//! member of `GET /v1/jobs/{id}`, the `kind` filter, the stop reason, and the server as `serve` wires it with a fake
//! agent over a real iroh connection on loopback (relays disabled): capabilities in placement, `ServiceHealth`
//! through the gateway, the idle cancel on the injected clock and the restart on node loss.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::fleet::{FakeAgent, Fleet, NowForTests};
use common::{TestApp, assert_problem};
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{AgentMsg, HealthState, Outcome, RunningLease, ServerMsg, ServiceHealth, Usage};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// A timestamp as the API writes it.
fn ts(t: OffsetDateTime) -> Value {
    json!(t.format(&Rfc3339).unwrap())
}

fn service(extra: Value) -> Value {
    let mut block = json!({"ports": [{"port": 8080, "name": "http"}]});
    block
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json!({"kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
        "resources": {"cpu": 1, "memory_mb": 256}, "service": block})
}

async fn job(app: &TestApp, id: &str) -> Value {
    let r = app.get(&format!("/v1/jobs/{id}"), &app.admin).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.json()
}

/// An agent that joined and then said `Hello` with the H2 capabilities (a `Join` carries none).
async fn h2_agent(fleet: &Fleet) -> FakeAgent {
    let agent = fleet.agent().await;
    fleet.restart_with(agent, &["service_jobs"]).await
}

/// The next lease of `agent`, accepted and started.
async fn start_next(fleet: &Fleet, agent: &mut FakeAgent) -> (LeaseId, u64) {
    assert_eq!(fleet.scheduler.tick().await.errors, 0);
    let (lease_id, epoch) = agent.next_lease().await;
    agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    agent
        .send(&AgentMsg::JobStarted {
            lease_id,
            epoch,
            started_at: fleet.app.clock.now_for_tests(),
        })
        .await;
    agent.sync().await;
    (lease_id, epoch)
}

async fn health(fleet: &Fleet, agent: &mut FakeAgent, lease_id: LeaseId, epoch: u64, state: HealthState) {
    agent
        .send(&AgentMsg::ServiceHealth(ServiceHealth {
            lease_id,
            epoch,
            state,
            since: fleet.app.clock.now_for_tests(),
            detail: None,
        }))
        .await;
    agent.sync().await;
}

fn cancels(msgs: &[ServerMsg]) -> Vec<(LeaseId, String)> {
    msgs.iter()
        .filter_map(|m| match m {
            ServerMsg::Cancel { lease_id, reason, .. } => Some((*lease_id, reason.clone())),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_service_is_accepted_with_its_defaults_and_a_batch_job_keeps_the_h1_rules() {
    let app = TestApp::new().await;
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&app.admin), Some(service(json!({}))))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let v = r.json();
    // H2 §7.1: 30 days and 3 attempts by default for a service; a 1 h idle timeout; restart on node loss.
    assert_eq!(v["spec"]["kind"], "service");
    assert_eq!(v["spec"]["timeout_s"], 2_592_000);
    assert_eq!(v["spec"]["retry"]["max_attempts"], 3);
    assert_eq!(v["spec"]["service"]["idle_timeout_s"], 3600);
    assert_eq!(v["spec"]["service"]["restart"], "on_node_loss");
    assert!(
        v.get("service").is_none(),
        "only `GET /v1/jobs/{{id}}` adds the service view"
    );
    let id = v["id"].as_str().unwrap().to_string();
    // Queued: no health, no deadline, nothing to count the idle timeout from.
    let v = job(&app, &id).await;
    assert_eq!(
        v["service"],
        json!({"health": null, "health_since": null, "ports": [{"port": 8080, "name": "http"}],
            "open_connections": 0, "last_activity_at": null, "idle_deadline": null, "deadline": null,
            "cap_deadline": null, "restarts_24h": 0, "setup": null, "traffic": null})
    );
    // A batch job has no `service` member, and the H1 rules still hold for it.
    let batch = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256}});
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&app.admin), Some(batch.clone()))
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let batch_id = r.json()["id"].as_str().unwrap().to_string();
    assert!(job(&app, &batch_id).await.get("service").is_none());
    let mut with_block = batch.clone();
    with_block["service"] = json!({"ports": [{"port": 80, "name": "http"}]});
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&app.admin), Some(with_block))
        .await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    // A service out of its `timeout_s` range is refused, never clamped.
    let mut long = service(json!({}));
    long["timeout_s"] = json!(2_592_001);
    let r = app.call(Method::POST, "/v1/jobs", Some(&app.admin), Some(long)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.body);
    // A batch job has no volumes (they are for services and template launches, T2-15), and a blob input must be a
    // blob of the account (T2-14).
    let mut with_volume = batch.clone();
    with_volume["volumes"] = json!([{"name": "data", "mount": "/volumes/data", "max_mb": 64}]);
    let mut with_blob = batch;
    with_blob["inputs"] = json!([{"path": "/inputs/a", "blob": format!("sha256:{}", "0".repeat(64))}]);
    for body in [with_volume, with_blob] {
        let r = app.call(Method::POST, "/v1/jobs", Some(&app.admin), Some(body)).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{:?}", r.body);
    }
    // The `kind` filter.
    let r = app.get("/v1/jobs?kind=service", &app.admin).await;
    let items = r.json()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], id.as_str());
    let r = app.get("/v1/jobs?kind=batch", &app.admin).await;
    assert_eq!(r.json()["items"][0]["id"], batch_id.as_str());
    // Stopping a queued service: `cancelled`, `reason: "stopped"`; a batch job keeps H1's empty reason.
    let r = app
        .call(Method::POST, &format!("/v1/jobs/{id}/cancel"), Some(&app.admin), None)
        .await;
    let v = r.json();
    assert_eq!(
        (v["status"].as_str(), v["reason"].as_str()),
        (Some("cancelled"), Some("stopped"))
    );
    let r = app
        .call(
            Method::POST,
            &format!("/v1/jobs/{batch_id}/cancel"),
            Some(&app.admin),
            None,
        )
        .await;
    let v = r.json();
    assert_eq!((v["status"].as_str(), v["reason"].as_str()), (Some("cancelled"), None));
}

#[tokio::test]
async fn a_service_runs_only_on_an_agent_with_service_jobs_and_reports_its_health() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    // An agent that declared no capability (as after a `Join`) gets batch jobs, never the service.
    let mut h1 = fleet.agent().await;
    let id = fleet.submit(service(json!({"idle_timeout_s": 300}))).await;
    let report = fleet.scheduler.tick().await;
    assert_eq!((report.errors, report.offered), (0, 0));
    assert!(h1.sync().await.is_empty(), "nothing was offered");
    let v = job(app, &id).await;
    assert_eq!(v["status"], "queued");
    assert!(v["reason"].as_str().unwrap().contains("`service_jobs`"), "{v}");
    // It says `Hello` with `service_jobs`: the lease goes out, with the service block.
    let mut agent = fleet.restart_with(h1, &["service_jobs", "approval"]).await;
    let (lease, epoch) = start_next(&fleet, &mut agent).await;
    let started = app.clock.now_for_tests();
    let v = job(app, &id).await;
    assert_eq!((v["status"].as_str(), v["reason"].as_str()), (Some("running"), None));
    assert_eq!(v["service"]["health"], "starting");
    assert_eq!(v["service"]["idle_deadline"], Value::Null);
    let deadline = started + Duration::days(30);
    assert_eq!(v["service"]["deadline"], ts(deadline));
    // `ServiceHealth` through the real gateway: stored by the scheduler, shown by the API.
    app.clock.advance(Duration::seconds(30));
    health(&fleet, &mut agent, lease, epoch, HealthState::Healthy).await;
    let healthy_at = app.clock.now_for_tests();
    let v = job(app, &id).await;
    assert_eq!(v["service"]["health"], "healthy");
    assert_eq!(v["service"]["health_since"], ts(healthy_at));
    assert_eq!(v["service"]["last_activity_at"], ts(healthy_at));
    assert_eq!(v["service"]["idle_deadline"], ts(healthy_at + Duration::seconds(300)));
    // An open port connection: no idle deadline, and no idle cancel however long it lasts.
    fleet.scheduler.connections().opened(id.parse().unwrap());
    app.clock.advance(Duration::seconds(1000));
    assert_eq!(fleet.scheduler.tick().await.errors, 0);
    let v = job(app, &id).await;
    assert_eq!(
        (
            v["service"]["open_connections"].as_u64(),
            &v["service"]["idle_deadline"]
        ),
        (Some(1), &Value::Null)
    );
    assert!(cancels(&agent.sync().await).is_empty());
    // A health repeat in a heartbeat is fenced like the message: a stale epoch changes nothing.
    agent
        .send(&AgentMsg::Heartbeat {
            seq: 10_000,
            load: serde_json::from_value(json!({"cpu_pct": 1, "mem_used_mb": 1})).unwrap(),
            running: vec![RunningLease {
                health: Some(HealthState::Unhealthy),
                ..RunningLease::new(lease, epoch + 1)
            }],
        })
        .await;
    agent.sync().await;
    assert_eq!(job(app, &id).await["service"]["health"], "healthy");
    // The connection closes; the idle timeout has long passed: the next pass sends `Cancel{idle_timeout}`.
    fleet.scheduler.connections().closed(id.parse().unwrap());
    assert_eq!(fleet.scheduler.tick().await.errors, 0);
    assert_eq!(cancels(&agent.sync().await), vec![(lease, "idle_timeout".to_string())]);
    let v = job(app, &id).await;
    assert_eq!(
        (v["status"].as_str(), v["reason"].as_str()),
        (Some("running"), Some("idle_timeout"))
    );
    agent
        .send(&AgentMsg::JobFinished {
            lease_id: lease,
            epoch,
            outcome: Outcome::Cancelled,
            exit_code: None,
            error: None,
            usage: Usage {
                wall_ms: 1000,
                cpu_used_ms: 10,
                max_rss_mb: 1,
            },
            outputs: vec![],
        })
        .await;
    agent.sync().await;
    let v = job(app, &id).await;
    assert_eq!(
        (v["status"].as_str(), v["reason"].as_str()),
        (Some("cancelled"), Some("idle_timeout"))
    );
    assert_eq!(v["service"]["health"], Value::Null, "no attempt runs");
}

#[tokio::test]
async fn a_service_is_restarted_on_node_loss_and_stopped_with_its_reason() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let mut agent = h2_agent(&fleet).await;
    let id = fleet.submit(service(json!({}))).await;
    let (lease, epoch) = start_next(&fleet, &mut agent).await;
    let never = fleet.submit(service(json!({"restart": "never"}))).await;
    let (never_lease, never_epoch) = start_next(&fleet, &mut agent).await;
    health(&fleet, &mut agent, lease, epoch, HealthState::Healthy).await;
    health(&fleet, &mut agent, never_lease, never_epoch, HealthState::Healthy).await;
    // The agent restarts: its `Hello` lists no lease, so both attempts are lost at once.
    let mut agent = fleet.restart_with(agent, &["service_jobs"]).await;
    let v = job(app, &never).await;
    assert_eq!(
        (v["status"].as_str(), v["error"].as_str()),
        (Some("lost"), None),
        "restart: never"
    );
    let v = job(app, &id).await;
    assert_eq!((v["status"].as_str(), v["attempt"].as_u64()), (Some("queued"), Some(2)));
    assert_eq!(v["service"]["restarts_24h"], 1);
    assert_eq!(v["service"]["health"], Value::Null);
    // The second attempt, stopped by its owner: `Cancel{stopped}`, then `cancelled` with `reason: "stopped"`.
    let (lease, epoch) = start_next(&fleet, &mut agent).await;
    assert_eq!(job(app, &id).await["service"]["health"], "starting");
    let r = app
        .call(Method::POST, &format!("/v1/jobs/{id}/cancel"), Some(&app.admin), None)
        .await;
    let v = r.json();
    assert_eq!(
        (v["status"].as_str(), v["reason"].as_str()),
        (Some("running"), Some("stopped"))
    );
    assert!(v["cancel_requested_at"].is_string());
    assert_eq!(fleet.scheduler.tick().await.errors, 0);
    assert_eq!(cancels(&agent.sync().await), vec![(lease, "stopped".to_string())]);
    agent
        .send(&AgentMsg::JobFinished {
            lease_id: lease,
            epoch,
            outcome: Outcome::Cancelled,
            exit_code: None,
            error: None,
            usage: Usage {
                wall_ms: 1000,
                cpu_used_ms: 10,
                max_rss_mb: 1,
            },
            outputs: vec![],
        })
        .await;
    agent.sync().await;
    let v = job(app, &id).await;
    assert_eq!(
        (v["status"].as_str(), v["reason"].as_str()),
        (Some("cancelled"), Some("stopped"))
    );
    assert_eq!(v["attempts"].as_array().unwrap().len(), 2);
}
