// SPDX-License-Identifier: AGPL-3.0-only

//! Service jobs and node approval in the scheduler (H2 spec §5.5, §6.1, §7.2, §7.4; SI-H2-19): no lease to a
//! `pending_approval` node, capabilities in placement, the restart policy with its cap of 5 restarts in 24 h, health
//! from the agents, the idle cancel, the stop reasons and the wait for the node that holds a volume. Time moves only
//! when a test moves the clock.

use p2pc_proto::api::{
    ERROR_RESTART_LIMIT, REASON_IDLE_TIMEOUT, REASON_STOPPED, RestartPolicy, ServiceHealth as Health,
};
use p2pc_proto::protocol::{HealthState, ServiceHealth, capability};

use super::*;
use crate::scheduler::service::{OpenConnections, on_node_loss};
use crate::store::leases::ServiceState;

const H2_AGENT: [&str; 3] = [capability::SERVICE_JOBS, capability::VOLUMES, capability::BLOB_INPUTS];

impl Fx {
    /// [`Fx::node`] whose agent declared the H2 capabilities.
    async fn h2_node(&self, cpu: f64, mem: u64) -> NodeId {
        let id = self.node(cpu, mem, 0).await;
        self.set_features(id, &H2_AGENT).await;
        id
    }

    async fn set_features(&self, node: NodeId, features: &[&str]) {
        sqlx::query("UPDATE nodes SET features = ? WHERE id = ?")
            .bind(serde_json::to_string(features).unwrap())
            .bind(node.to_string())
            .execute(&self.db)
            .await
            .unwrap();
    }

    /// Sets the node's approval straight in its row. No API moves an approved node back to `pending_approval`.
    pub(crate) async fn set_approval(&self, node: NodeId, approved: bool) {
        sqlx::query("UPDATE nodes SET approval = ? WHERE id = ?")
            .bind(if approved { "approved" } else { "pending_approval" })
            .bind(node.to_string())
            .execute(&self.db)
            .await
            .unwrap();
    }

    /// A service of 1 vCPU and 512 MiB with one port, and `extra` merged into its `service` block and its spec.
    async fn service(&self, service: serde_json::Value, spec: serde_json::Value) -> JobId {
        let mut block = serde_json::json!({"ports": [{"port": 8080, "name": "http"}]});
        block
            .as_object_mut()
            .unwrap()
            .extend(service.as_object().unwrap().clone());
        let mut body = serde_json::json!({
            "kind": "service",
            "image": "docker.io/library/nginx:1.27",
            "command": ["nginx"],
            "resources": {"cpu": 1, "memory_mb": 512},
            "service": block,
        });
        body.as_object_mut().unwrap().extend(spec.as_object().unwrap().clone());
        self.job_with(body).await
    }

    async fn health(&self, node: NodeId, lease: LeaseId, epoch: u64, state: HealthState) {
        let since = self.now();
        self.msg(
            node,
            AgentMsg::ServiceHealth(ServiceHealth {
                lease_id: lease,
                epoch,
                state,
                since,
                detail: None,
            }),
        )
        .await;
    }

    /// A heartbeat of `node` whose `running` lists `lease` with `health`.
    async fn heartbeat_health(&self, node: NodeId, lease: LeaseId, epoch: u64, health: HealthState) {
        let running = [RunningLease {
            health: Some(health),
            ..RunningLease::new(lease, epoch)
        }];
        self.sched.on_heartbeat(node, &running).await.unwrap();
    }

    async fn state(&self, job: JobId) -> ServiceState {
        let mut conn = self.db.acquire().await.unwrap();
        leases::service_state(&mut conn, job).await.unwrap()
    }

    /// The node's agent restarted: its `Hello` lists no lease, so its leases are lost at once (§6 "Reconnects").
    async fn lose(&self, node: NodeId) {
        self.hello(node, &[]).await;
        self.link.take();
    }

    async fn error(&self, job: JobId) -> Option<String> {
        self.row(job).await.error
    }
}

// --- Node approval (SI-H2-19) ------------------------------------------------------------------------------------

mt_test!(a_pending_node_gets_no_lease_until_it_is_approved, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    fx.set_approval(node, false).await;
    let job = fx.job(1.0, 1024, 0).await;
    for _ in 0..3 {
        let r = fx.sched.tick().await.clean();
        assert_eq!((r.offered, r.placements_tried), (0, 0));
        fx.advance(30);
    }
    assert!(fx.link.take().is_empty(), "nothing is sent to a pending node");
    let row = fx.row(job).await;
    assert_eq!(row.status, JobStatus::Queued);
    assert_eq!(row.reason.as_deref(), Some(REASON_WAITING_FOR_APPROVAL));
    assert_eq!(fx.offer_count(job).await, 0, "waiting is not a failed offer");
    // Approved (what `POST /v1/nodes/{id}/approve` does): the next pass offers it, and the reason is gone.
    let mut conn = fx.db.acquire().await.unwrap();
    assert_eq!(nodes::approve(&mut conn, fx.account, node).await.unwrap(), Some(true));
    drop(conn);
    assert_eq!(fx.sched.tick().await.clean().offered, 1);
    assert_eq!(fx.sent().leases[0].0, node);
    assert_eq!(fx.row(job).await.reason, None);
});

mt_test!(
    an_approved_node_is_chosen_and_the_pending_one_is_never_a_candidate,
    async {
        let fx = Fx::new().await;
        // The pending node is the better fit; it still gets nothing.
        let pending = fx.node(1.0, 1024, 0).await;
        fx.set_approval(pending, false).await;
        let approved = fx.node(8.0, 16_384, 0).await;
        for _ in 0..4 {
            fx.job(1.0, 1024, 0).await;
        }
        fx.sched.tick().await.clean();
        let sent = fx.sent().leases;
        assert_eq!(sent.len(), 4);
        assert!(sent.iter().all(|(n, _, _)| *n == approved));
        // A job that only waits for room on the approved node shows no approval reason.
        let waiting = fx.job(8.0, 1024, 0).await;
        fx.sched.tick().await.clean();
        assert_eq!(fx.row(waiting).await.reason, None);
        assert_eq!(fx.held(pending).await, 0);
    }
);

mt_test!(an_offer_is_not_accepted_from_a_node_that_is_pending, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    // The offer is in flight when the node stops being approved.
    fx.set_approval(node, false).await;
    fx.accept(node, lease, epoch).await;
    let l = fx.lease(lease).await;
    assert_eq!(l.state, LeaseState::Revoked);
    assert!(!l.holds(), "it never started");
    let row = fx.row(job).await;
    assert_eq!((row.status, row.attempt, row.node_id), (JobStatus::Queued, 1, None));
    assert_eq!(fx.offer_count(job).await, 0, "not the job's fault");
    let cancels = fx.sent().cancels;
    assert_eq!(cancels, vec![(node, lease, epoch, code::PENDING_APPROVAL.to_string())]);
    // `JobStarted` and `JobFinished` on that offer do not get it in either.
    let other = fx.job(1.0, 1024, 0).await;
    fx.set_approval(node, true).await;
    fx.sched.tick().await.clean();
    let offers = fx.sent().leases;
    fx.set_approval(node, false).await;
    for (_, lease, epoch) in &offers {
        fx.start(node, *lease, *epoch).await;
        fx.msg(node, finished(*lease, *epoch, Outcome::Exited, Some(0))).await;
        assert_eq!(fx.lease(*lease).await.state, LeaseState::Revoked);
    }
    assert_eq!(fx.status(job).await, JobStatus::Queued);
    assert_eq!(fx.status(other).await, JobStatus::Queued);
    assert_eq!(fx.usage_rows().await, 0);
    // A `Hello` listing an offer does not accept it either.
    fx.set_approval(node, true).await;
    fx.advance(61);
    fx.sched.tick().await.clean();
    let offers = fx.sent().leases;
    assert!(!offers.is_empty());
    fx.set_approval(node, false).await;
    let listed: Vec<(LeaseId, u64)> = offers.iter().map(|(_, l, e)| (*l, *e)).collect();
    fx.hello(node, &listed).await;
    for (_, lease, _) in offers {
        assert_eq!(fx.lease(lease).await.state, LeaseState::Revoked);
    }
});

mt_test!(
    a_lease_found_on_a_pending_node_is_revoked_and_its_job_goes_on_elsewhere,
    async {
        let fx = Fx::new().await;
        let first = fx.node(4.0, 8192, 0).await;
        let job = fx.job(1.0, 1024, 0).await;
        let (node, lease, epoch) = fx.running(job).await;
        assert_eq!(node, first);
        let offered = fx.job(1.0, 1024, 0).await;
        fx.sched.tick().await.clean();
        let (_, offer, offer_epoch) = fx.sent().leases[0];
        let other = fx.node(4.0, 8192, 0).await;
        // The node is found pending while it holds a running lease and an offer.
        fx.set_approval(first, false).await;
        fx.advance(5);
        fx.sched.tick().await.clean();
        let sent = fx.sent();
        let l = fx.lease(lease).await;
        assert_eq!(l.state, LeaseState::Revoked);
        assert!(l.holds(), "its execution may still run: the reservation is held");
        assert_eq!(fx.lease(offer).await.state, LeaseState::Revoked);
        let reasons: BTreeSet<(LeaseId, u64, String)> = sent
            .cancels
            .iter()
            .filter(|(n, ..)| *n == first)
            .map(|(_, l, e, r)| (*l, *e, r.clone()))
            .collect();
        assert_eq!(
            reasons,
            BTreeSet::from([
                (lease, epoch, code::PENDING_APPROVAL.to_string()),
                (offer, offer_epoch, code::PENDING_APPROVAL.to_string()),
            ])
        );
        // Both jobs go to the approved node, in the same pass; the running one as a new attempt.
        assert_eq!(sent.leases.len(), 2);
        assert!(sent.leases.iter().all(|(n, _, _)| *n == other));
        let row = fx.row(job).await;
        assert_eq!((row.status, row.attempt), (JobStatus::Queued, 2));
        assert_eq!(fx.row(offered).await.attempt, 1, "an offer is not an attempt");
        assert_eq!(
            fx.usage_rows().await,
            1,
            "the revoked attempt is billed with an estimate"
        );
        // Its `Cancel` is sent again until the node confirms the end; then the reservation is released.
        fx.advance(5);
        fx.sched.tick().await.clean();
        assert!(
            fx.sent()
                .cancels
                .contains(&(first, lease, epoch, code::PENDING_APPROVAL.to_string()))
        );
        fx.msg(first, finished(lease, epoch, Outcome::Cancelled, None)).await;
        assert!(!fx.lease(lease).await.holds());
        assert_eq!(fx.held(first).await, 0);
        // A late report from the pending node changes nothing of the job.
        assert_eq!(fx.row(job).await.status, JobStatus::Queued);
    }
);

// --- Capabilities (H2 §6.1) --------------------------------------------------------------------------------------

mt_test!(a_service_goes_only_to_an_agent_that_declared_service_jobs, async {
    let fx = Fx::new().await;
    let h1 = fx.node(4.0, 8192, 0).await;
    let service = fx.service(serde_json::json!({}), serde_json::json!({})).await;
    let batch = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(
        fx.jobs_of(&sent).await,
        vec![batch],
        "the H1 agent still gets batch jobs"
    );
    let reason = fx.row(service).await.reason.unwrap();
    assert!(reason.contains("`service_jobs`"), "{reason}");
    // An agent that declares it gets the lease, with the service block in the job.
    let h2 = fx.h2_node(4.0, 8192).await;
    fx.sched.tick().await.clean();
    let msgs = fx.link.take();
    assert_eq!(msgs.len(), 1);
    let (to, ServerMsg::Lease { job: lj, .. }) = &msgs[0] else {
        panic!("{msgs:?}")
    };
    assert_eq!(*to, h2);
    assert_eq!(lj.as_object()["kind"], "service");
    assert_eq!(lj.as_object()["service"]["ports"][0]["port"], 8080);
    assert_eq!(fx.row(service).await.reason, None);
    let _ = h1;
});

mt_test!(volumes_and_blob_inputs_need_their_own_capabilities, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    fx.set_features(node, &[capability::SERVICE_JOBS]).await;
    let with_volume = fx
        .service(
            serde_json::json!({}),
            serde_json::json!({"volumes": [{"name": "data", "mount": "/volumes/data", "max_mb": 64}]}),
        )
        .await;
    let digest = "0".repeat(64);
    let with_blob = fx
        .job_with(serde_json::json!({
            "image": "docker.io/library/alpine:3", "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 512},
            "inputs": [{"path": "/inputs/a", "blob": format!("sha256:{digest}")}],
        }))
        .await;
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty());
    assert!(fx.row(with_volume).await.reason.unwrap().contains("`volumes`"));
    assert!(fx.row(with_blob).await.reason.unwrap().contains("`blob_inputs`"));
    fx.set_features(node, &H2_AGENT).await;
    fx.sched.tick().await.clean();
    assert_eq!(fx.sent().leases.len(), 2);
});

// --- Restart on node loss (H2 §7.2) ------------------------------------------------------------------------------

#[test]
fn the_restart_policy_counts_unhealthy_attempts_and_caps_restarts_per_24_h() {
    let state = |unhealthy, restarts: &[i64]| ServiceState {
        unhealthy_attempts: unhealthy,
        node_loss_restarts: restarts
            .iter()
            .map(|s| (T0 + Duration::seconds(*s)).unix_timestamp())
            .collect(),
        ..ServiceState::default()
    };
    let now = T0 + Duration::hours(30);
    let on = RestartPolicy::OnNodeLoss;
    // `never`: the first node loss ends it.
    let r = on_node_loss(RestartPolicy::Never, 3, &state(0, &[]), true, now);
    assert_eq!((r.requeue, r.error), (false, None));
    // An attempt that never became healthy counts; the third ends the job.
    let r = on_node_loss(on, 3, &state(0, &[]), false, now);
    assert_eq!((r.requeue, r.unhealthy_attempts), (true, 1));
    let r = on_node_loss(on, 3, &state(1, &[]), false, now);
    assert_eq!((r.requeue, r.unhealthy_attempts), (true, 2));
    let r = on_node_loss(on, 3, &state(2, &[]), false, now);
    assert_eq!((r.requeue, r.unhealthy_attempts, r.error), (false, 3, None));
    // One that became healthy does not count.
    let r = on_node_loss(on, 3, &state(2, &[]), true, now);
    assert_eq!((r.requeue, r.unhealthy_attempts), (true, 2));
    assert!(!on_node_loss(on, 1, &state(0, &[]), false, now).requeue);
    // Five restarts in the last 24 h: the sixth node loss ends the job, whatever the count.
    let hours = |h: &[i64]| h.iter().map(|h| h * 3600).collect::<Vec<i64>>();
    let five = hours(&[7, 10, 15, 20, 29]);
    let r = on_node_loss(on, 5, &state(0, &five), true, now);
    assert_eq!((r.requeue, r.error), (false, Some(ERROR_RESTART_LIMIT)));
    assert_eq!(r.node_loss_restarts.len(), 5);
    // The oldest is exactly 24 h old: no longer within 24 hours.
    let aged = hours(&[6, 10, 15, 20, 29]);
    let r = on_node_loss(on, 5, &state(0, &aged), true, now);
    assert!(r.requeue);
    assert_eq!(r.node_loss_restarts.len(), 5, "the old one is dropped, this one added");
    assert_eq!(*r.node_loss_restarts.last().unwrap(), now.unix_timestamp());
    // Four: the fifth restart is allowed.
    let r = on_node_loss(on, 5, &state(0, &five[1..]), true, now);
    assert_eq!((r.requeue, r.node_loss_restarts.len()), (true, 5));
}

mt_test!(restart_never_ends_the_service_at_its_first_node_loss, async {
    let fx = Fx::new().await;
    let node = fx.h2_node(4.0, 8192).await;
    let job = fx
        .service(serde_json::json!({"restart": "never"}), serde_json::json!({}))
        .await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.health(node, lease, epoch, HealthState::Healthy).await;
    fx.lose(node).await;
    let row = fx.row(job).await;
    assert_eq!((row.status, row.attempt, row.error), (JobStatus::Lost, 1, None));
    // A batch job on the same node keeps H1's rule: requeued.
    let batch = fx.job(1.0, 1024, 0).await;
    fx.running(batch).await;
    fx.lose(node).await;
    assert_eq!(fx.status(batch).await, JobStatus::Queued);
});

mt_test!(a_service_that_never_becomes_healthy_stops_after_max_attempts, async {
    let fx = Fx::new().await;
    let node = fx.h2_node(4.0, 8192).await;
    // The default: `on_node_loss`, 3 attempts.
    let job = fx.service(serde_json::json!({}), serde_json::json!({})).await;
    assert_eq!(fx.row(job).await.max_attempts, 3);
    for attempt in 1..=3u32 {
        let (_, lease, epoch) = fx.running(job).await;
        assert_eq!(fx.state(job).await.health, Some(Health::Starting));
        // It reports `starting`, even `unhealthy`: never `healthy`.
        fx.health(node, lease, epoch, HealthState::Unhealthy).await;
        fx.lose(node).await;
        let row = fx.row(job).await;
        if attempt < 3 {
            assert_eq!((row.status, row.attempt), (JobStatus::Queued, attempt + 1));
        } else {
            assert_eq!((row.status, row.attempt, row.error), (JobStatus::Lost, 3, None));
        }
        let st = fx.state(job).await;
        assert_eq!(st.unhealthy_attempts, attempt);
        assert_eq!(st.health, None, "no attempt runs");
    }
});

mt_test!(ten_minutes_of_health_reset_the_count_and_less_does_not, async {
    let fx = Fx::new().await;
    let node = fx.h2_node(4.0, 8192).await;
    let job = fx.service(serde_json::json!({}), serde_json::json!({})).await;
    // Two attempts that never became healthy.
    for _ in 0..2 {
        fx.running(job).await;
        fx.lose(node).await;
        fx.advance(1);
    }
    assert_eq!(fx.state(job).await.unhealthy_attempts, 2);
    // The third is healthy for 9 min 59 s: it counts neither way.
    let (_, lease, epoch) = fx.running(job).await;
    fx.health(node, lease, epoch, HealthState::Healthy).await;
    fx.advance(599);
    fx.heartbeat_health(node, lease, epoch, HealthState::Healthy).await;
    assert_eq!(fx.state(job).await.unhealthy_attempts, 2);
    fx.lose(node).await;
    assert_eq!(fx.row(job).await.status, JobStatus::Queued);
    assert_eq!(fx.state(job).await.unhealthy_attempts, 2);
    // The fourth is healthy for 10 minutes, as its heartbeats say: the count starts over.
    let (_, lease, epoch) = fx.running(job).await;
    fx.health(node, lease, epoch, HealthState::Healthy).await;
    fx.advance(600);
    fx.heartbeat_health(node, lease, epoch, HealthState::Healthy).await;
    assert_eq!(fx.state(job).await.unhealthy_attempts, 0);
    fx.lose(node).await;
    assert_eq!(fx.row(job).await.status, JobStatus::Queued);
    // So three more unhealthy attempts are needed to end it (a day later: the 24-hour cap is another rule).
    fx.advance(25 * 3600);
    for attempt in 1..=3u32 {
        fx.advance(1);
        fx.running(job).await;
        fx.lose(node).await;
        assert_eq!(fx.state(job).await.unhealthy_attempts, attempt);
    }
    assert_eq!(fx.row(job).await.status, JobStatus::Lost);
    assert_eq!(
        fx.row(job).await.attempt,
        7,
        "attempts go on past max_attempts for a service"
    );
});

mt_test!(
    a_healthy_period_that_ends_before_the_report_still_resets_the_count,
    async {
        let fx = Fx::new().await;
        let node = fx.h2_node(4.0, 8192).await;
        let job = fx.service(serde_json::json!({}), serde_json::json!({})).await;
        fx.running(job).await;
        fx.lose(node).await;
        assert_eq!(fx.state(job).await.unhealthy_attempts, 1);
        let (_, lease, epoch) = fx.running(job).await;
        fx.health(node, lease, epoch, HealthState::Healthy).await;
        fx.advance(700);
        // No heartbeat came in between: the change away from `healthy` is the evidence of the 10 minutes.
        fx.health(node, lease, epoch, HealthState::Unhealthy).await;
        let st = fx.state(job).await;
        assert_eq!((st.unhealthy_attempts, st.health), (0, Some(Health::Unhealthy)));
        assert_eq!(st.healthy_since, None);
    }
);

mt_test!(
    the_sixth_node_loss_within_24_hours_ends_the_service_with_restart_limit,
    async {
        let fx = Fx::new().await;
        let node = fx.h2_node(4.0, 8192).await;
        let job = fx.service(serde_json::json!({}), serde_json::json!({})).await;
        // A node that flaps every 4 hours, with the service healthy each time: the attempt count never ends it.
        for restart in 1..=5 {
            let (_, lease, epoch) = fx.running(job).await;
            fx.health(node, lease, epoch, HealthState::Healthy).await;
            fx.advance(4 * 3600);
            fx.lose(node).await;
            let row = fx.row(job).await;
            assert_eq!((row.status, row.attempt), (JobStatus::Queued, restart + 1));
            assert_eq!(fx.state(job).await.node_loss_restarts.len(), restart as usize);
        }
        let (_, lease, epoch) = fx.running(job).await;
        fx.health(node, lease, epoch, HealthState::Healthy).await;
        fx.advance(3600);
        fx.lose(node).await;
        let row = fx.row(job).await;
        assert_eq!(row.status, JobStatus::Lost);
        assert_eq!(row.error.as_deref(), Some(ERROR_RESTART_LIMIT));
        assert_eq!(row.attempt, 6);
    }
);

mt_test!(a_nightly_sleep_stays_under_the_restart_cap, async {
    let fx = Fx::new().await;
    let node = fx.h2_node(4.0, 8192).await;
    let job = fx.service(serde_json::json!({}), serde_json::json!({})).await;
    // One node loss a day, for 8 days: restarts older than 24 h no longer count.
    for day in 1..=8u32 {
        let (_, lease, epoch) = fx.running(job).await;
        fx.health(node, lease, epoch, HealthState::Healthy).await;
        fx.advance(24 * 3600);
        fx.lose(node).await;
        assert_eq!(fx.row(job).await.status, JobStatus::Queued, "day {day}");
        assert_eq!(fx.state(job).await.node_loss_restarts.len(), 1);
    }
    assert_eq!(fx.error(job).await, None);
});

mt_test!(a_ttl_node_loss_follows_the_restart_policy_too, async {
    let fx = Fx::new().await;
    let node = fx.h2_node(4.0, 8192).await;
    let job = fx
        .service(serde_json::json!({}), serde_json::json!({"retry": {"max_attempts": 1}}))
        .await;
    fx.running(job).await;
    let last = fx.now();
    fx.advance(60);
    fx.node_went_offline(node, last).await;
    let row = fx.row(job).await;
    assert_eq!(
        (row.status, row.error),
        (JobStatus::Lost, None),
        "one unhealthy attempt allowed"
    );
    assert_eq!(fx.usage_rows().await, 1);
});

// --- Health from the agents (H2 §6.1) ----------------------------------------------------------------------------

mt_test!(
    service_health_is_stored_fenced_and_cleared_when_the_attempt_ends,
    async {
        let fx = Fx::new().await;
        let node = fx.h2_node(4.0, 8192).await;
        let other = fx.h2_node(4.0, 8192).await;
        let job = fx.service(serde_json::json!({}), serde_json::json!({})).await;
        let (node, lease, epoch) = {
            let (n, l, e) = fx.running(job).await;
            assert!(n == node || n == other);
            (n, l, e)
        };
        let started = fx.now();
        let st = fx.state(job).await;
        assert_eq!((st.health, st.health_since), (Some(Health::Starting), Some(started)));
        assert_eq!(st.last_activity_at, None, "nothing to count the idle timeout from yet");
        fx.advance(20);
        fx.health(node, lease, epoch, HealthState::Healthy).await;
        let healthy_at = fx.now();
        let st = fx.state(job).await;
        assert_eq!((st.health, st.health_since), (Some(Health::Healthy), Some(healthy_at)));
        assert_eq!(st.healthy_since, Some(healthy_at));
        assert_eq!(st.last_activity_at, Some(healthy_at));
        // A repeat in a heartbeat changes nothing; a change in one is caught up.
        fx.advance(10);
        fx.heartbeat_health(node, lease, epoch, HealthState::Healthy).await;
        assert_eq!(fx.state(job).await.health_since, Some(healthy_at));
        fx.heartbeat_health(node, lease, epoch, HealthState::Unhealthy).await;
        let st = fx.state(job).await;
        assert_eq!((st.health, st.health_since), (Some(Health::Unhealthy), Some(fx.now())));
        assert_eq!(
            st.last_activity_at,
            Some(healthy_at),
            "the idle clock is not moved by health"
        );
        // SI-8: a stale epoch, another node and an unknown lease are fenced and change nothing.
        let wrong = if node == other {
            fx.h2_node(1.0, 512).await
        } else {
            other
        };
        fx.sent();
        fx.health(node, lease, epoch + 1, HealthState::Healthy).await;
        fx.health(wrong, lease, epoch, HealthState::Healthy).await;
        let ghost = LeaseId::generate();
        fx.health(node, ghost, 1, HealthState::Healthy).await;
        assert_eq!(
            fx.sent().cancels,
            vec![
                (node, lease, epoch + 1, code::STALE_EPOCH.to_string()),
                (wrong, lease, epoch, code::UNKNOWN_LEASE.to_string()),
                (node, ghost, 1, code::UNKNOWN_LEASE.to_string()),
            ]
        );
        fx.heartbeat_health(wrong, lease, epoch, HealthState::Healthy).await;
        fx.heartbeat_health(node, lease, epoch + 1, HealthState::Healthy).await;
        assert_eq!(fx.state(job).await.health, Some(Health::Unhealthy));
        // The agent's `since` is kept within the attempt: never before its start, never in the future.
        let before = started - Duration::hours(1);
        for (since, want) in [(before, started), (fx.now() + Duration::hours(1), fx.now())] {
            let msg = ServiceHealth {
                lease_id: lease,
                epoch,
                state: if want == started {
                    HealthState::Starting
                } else {
                    HealthState::Healthy
                },
                since,
                detail: Some("HTTP/1.1 503".into()),
            };
            fx.msg(node, AgentMsg::ServiceHealth(msg)).await;
            assert_eq!(fx.state(job).await.health_since, Some(want));
        }
        // The agent stops a service whose health check failed: `failed`, `error: "health_check_failed"`, no health left.
        fx.msg(
            node,
            AgentMsg::JobFinished {
                lease_id: lease,
                epoch,
                outcome: Outcome::Error,
                exit_code: None,
                error: Some(p2pc_proto::api::ERROR_HEALTH_CHECK_FAILED.into()),
                usage: Usage {
                    wall_ms: 1000,
                    cpu_used_ms: 1,
                    max_rss_mb: 1,
                },
                outputs: vec![],
            },
        )
        .await;
        let row = fx.row(job).await;
        assert_eq!(row.status, JobStatus::Failed);
        assert_eq!(row.error.as_deref(), Some("health_check_failed"));
        assert_eq!(fx.state(job).await.health, None);
        // A report after the end is fenced.
        fx.sent();
        fx.health(node, lease, epoch, HealthState::Healthy).await;
        assert_eq!(fx.sent().cancels.len(), 1);
        assert_eq!(fx.state(job).await.health, None);
    }
);

mt_test!(a_health_report_for_a_batch_lease_changes_nothing, async {
    let fx = Fx::new().await;
    let node = fx.h2_node(4.0, 8192).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.health(node, lease, epoch, HealthState::Healthy).await;
    fx.heartbeat_health(node, lease, epoch, HealthState::Healthy).await;
    assert_eq!(fx.state(job).await, ServiceState::default());
    assert!(fx.sent().cancels.is_empty(), "the lease is current: not fenced");
    assert_eq!(fx.status(job).await, JobStatus::Running);
});

// --- Idle cancel and stop reasons (H2 §7.2, §7.4) ----------------------------------------------------------------

mt_test!(an_idle_service_is_cancelled_after_idle_timeout_s, async {
    let fx = Fx::new().await;
    let node = fx.h2_node(4.0, 8192).await;
    let job = fx
        .service(serde_json::json!({"idle_timeout_s": 300}), serde_json::json!({}))
        .await;
    let (_, lease, epoch) = fx.running(job).await;
    // Still `starting`: the idle timeout has nothing to count from, however long the start takes.
    fx.advance(1000);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty());
    fx.health(node, lease, epoch, HealthState::Healthy).await;
    fx.advance(299);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty(), "one second short");
    assert_eq!(fx.row(job).await.cancel_requested_at, None);
    fx.advance(1);
    fx.sched.tick().await.clean();
    assert_eq!(
        fx.sent().cancels,
        vec![(node, lease, epoch, REASON_IDLE_TIMEOUT.to_string())]
    );
    let row = fx.row(job).await;
    assert_eq!(
        (row.status, row.cancel_requested_at),
        (JobStatus::Running, Some(fx.now()))
    );
    assert_eq!(row.reason.as_deref(), Some(REASON_IDLE_TIMEOUT));
    // Sent again until the node reports, with the same reason.
    fx.advance(5);
    fx.sched.tick().await.clean();
    assert_eq!(fx.sent().cancels[0].3, REASON_IDLE_TIMEOUT);
    fx.finish(node, lease, epoch, Outcome::Cancelled, None).await;
    let row = fx.row(job).await;
    assert_eq!(row.status, JobStatus::Cancelled);
    assert_eq!(row.reason.as_deref(), Some(REASON_IDLE_TIMEOUT));
});

mt_test!(
    connections_traffic_a_model_pull_and_null_keep_a_service_from_the_idle_cancel,
    async {
        let fx = Fx::new().await;
        let node = fx.h2_node(8.0, 16_384).await;
        let busy = fx
            .service(serde_json::json!({"idle_timeout_s": 300}), serde_json::json!({}))
            .await;
        let never = fx
            .service(serde_json::json!({"idle_timeout_s": null}), serde_json::json!({}))
            .await;
        let (_, lease, epoch) = fx.running(busy).await;
        let (_, never_lease, never_epoch) = fx.running(never).await;
        fx.health(node, lease, epoch, HealthState::Healthy).await;
        fx.health(node, never_lease, never_epoch, HealthState::Healthy).await;
        // An open port connection (the port relay counts it): never idle, however long.
        let open: &OpenConnections = fx.sched.connections();
        open.opened(busy);
        open.opened(busy);
        fx.advance(10_000);
        fx.sched.tick().await.clean();
        assert!(fx.sent().cancels.is_empty());
        open.closed(busy);
        fx.sched.tick().await.clean();
        assert!(fx.sent().cancels.is_empty(), "one is still open");
        assert_eq!(open.count(busy), 1);
        // Traffic moved the last activity (the relay writes it): the timeout counts from there.
        sqlx::query("UPDATE service_state SET last_activity_at = ? WHERE job_id = ?")
            .bind(store::ts(fx.now()))
            .bind(busy.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
        open.closed(busy);
        assert_eq!(open.count(busy), 0);
        fx.advance(299);
        fx.sched.tick().await.clean();
        assert!(fx.sent().cancels.is_empty());
        // The hub's model pull is running: the idle cancel waits for it.
        sqlx::query("UPDATE service_state SET setup_state = 'pulling' WHERE job_id = ?")
            .bind(busy.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
        fx.advance(5000);
        fx.sched.tick().await.clean();
        assert!(fx.sent().cancels.is_empty());
        sqlx::query("UPDATE service_state SET setup_state = 'done' WHERE job_id = ?")
            .bind(busy.to_string())
            .execute(&fx.db)
            .await
            .unwrap();
        fx.sched.tick().await.clean();
        let cancels = fx.sent().cancels;
        assert_eq!(cancels, vec![(node, lease, epoch, REASON_IDLE_TIMEOUT.to_string())]);
        // `idle_timeout_s: null` never stops; its wall-clock limit still applies.
        assert_eq!(fx.row(never).await.cancel_requested_at, None);
        assert_eq!(fx.status(never).await, JobStatus::Running);
    }
);

mt_test!(
    an_idle_service_on_an_unreachable_node_ends_cancelled_with_its_reason,
    async {
        let fx = Fx::new().await;
        let node = fx.h2_node(4.0, 8192).await;
        let job = fx
            .service(serde_json::json!({"idle_timeout_s": 300}), serde_json::json!({}))
            .await;
        let (_, lease, epoch) = fx.running(job).await;
        fx.health(node, lease, epoch, HealthState::Healthy).await;
        fx.link.disconnect(node);
        fx.advance(300);
        fx.sched.tick().await.clean();
        let row = fx.row(job).await;
        assert_eq!(row.status, JobStatus::Cancelled);
        assert_eq!(row.reason.as_deref(), Some(REASON_IDLE_TIMEOUT));
        assert!(fx.lease(lease).await.holds(), "held until the node confirms");
        assert_eq!(fx.state(job).await.health, None);
    }
);

mt_test!(
    a_stopped_service_ends_cancelled_with_reason_stopped_and_a_batch_job_keeps_h1,
    async {
        let fx = Fx::new().await;
        let node = fx.h2_node(4.0, 8192).await;
        let service = fx.service(serde_json::json!({}), serde_json::json!({})).await;
        let batch = fx.job(1.0, 1024, 0).await;
        let (_, lease, epoch) = fx.running(service).await;
        let (_, batch_lease, batch_epoch) = fx.running(batch).await;
        // What `POST /v1/jobs/{id}/cancel` does for each kind.
        let mut tx = store::begin_immediate(&fx.db).await.unwrap();
        assert!(
            leases::request_stop(&mut tx, service, REASON_STOPPED, fx.now())
                .await
                .unwrap()
        );
        assert!(
            jobs::request_cancel(&mut tx, fx.account, fx.project, batch, fx.now())
                .await
                .unwrap()
        );
        // Asking again changes neither the time nor the reason.
        assert!(
            !leases::request_stop(&mut tx, service, REASON_IDLE_TIMEOUT, fx.now())
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        fx.sched.tick().await.clean();
        let cancels: BTreeSet<(LeaseId, String)> = fx.sent().cancels.into_iter().map(|(_, l, _, r)| (l, r)).collect();
        assert_eq!(
            cancels,
            BTreeSet::from([
                (lease, REASON_STOPPED.to_string()),
                (batch_lease, code::USER.to_string())
            ])
        );
        // A reconnect delivers the pending cancels again, with the same reasons.
        let replies = fx.hello(node, &[(lease, epoch), (batch_lease, batch_epoch)]).await;
        let reasons: BTreeSet<String> = replies
            .into_iter()
            .filter_map(|m| match m {
                ServerMsg::Cancel { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(
            reasons,
            BTreeSet::from([REASON_STOPPED.to_string(), code::USER.to_string()])
        );
        fx.finish_held(node, lease, epoch, Outcome::Cancelled, None).await;
        fx.finish_held(node, batch_lease, batch_epoch, Outcome::Cancelled, None)
            .await;
        let row = fx.row(service).await;
        assert_eq!(
            (row.status, row.reason.as_deref()),
            (JobStatus::Cancelled, Some(REASON_STOPPED))
        );
        let row = fx.row(batch).await;
        assert_eq!((row.status, row.reason), (JobStatus::Cancelled, None), "H1: no reason");
    }
);

mt_test!(
    a_stopped_service_whose_node_is_lost_ends_cancelled_not_requeued,
    async {
        let fx = Fx::new().await;
        let node = fx.h2_node(4.0, 8192).await;
        let job = fx.service(serde_json::json!({}), serde_json::json!({})).await;
        fx.running(job).await;
        let mut tx = store::begin_immediate(&fx.db).await.unwrap();
        leases::request_stop(&mut tx, job, REASON_STOPPED, fx.now())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        fx.lose(node).await;
        let row = fx.row(job).await;
        assert_eq!(
            (row.status, row.reason.as_deref()),
            (JobStatus::Cancelled, Some(REASON_STOPPED))
        );
        assert_eq!(
            fx.state(job).await.node_loss_restarts,
            Vec::<i64>::new(),
            "not a restart"
        );
    }
);

// --- Waiting for the node that holds the volume (H2 §7.2) --------------------------------------------------------

/// A service with a volume, running on `holder` and then lost with it. Returns the job.
async fn lost_service_with_volume(fx: &Fx, holder: NodeId) -> JobId {
    let job = fx
        .service(
            serde_json::json!({}),
            serde_json::json!({"volumes": [{"name": "models", "mount": "/volumes/models", "max_mb": 1024}]}),
        )
        .await;
    let (node, lease, epoch) = fx.running(job).await;
    assert_eq!(node, holder);
    fx.health(node, lease, epoch, HealthState::Healthy).await;
    let last = fx.now();
    fx.advance(60);
    fx.node_went_offline(holder, last).await;
    assert_eq!(fx.status(job).await, JobStatus::Queued);
    fx.link.take();
    job
}

mt_test!(a_requeued_service_waits_for_the_node_that_holds_its_volume, async {
    let fx = Fx::new().await;
    let holder = fx.h2_node(4.0, 8192).await;
    let job = lost_service_with_volume(&fx, holder).await;
    let requeued_at = fx.now();
    // Another node has room, but the volume is on the holder, which is offline: the job waits and says so.
    let other = fx.h2_node(4.0, 8192).await;
    fx.advance(899);
    let r = fx.sched.tick().await.clean();
    assert_eq!((r.offered, r.placements_tried), (0, 0));
    let reason = fx.row(job).await.reason.unwrap();
    assert!(
        reason.contains(&holder.to_string()) && reason.contains("900 s"),
        "{reason}"
    );
    // The holder comes back within the wait: the job goes back to it, not to the idle node.
    fx.hello(holder, &[]).await;
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, holder);
    assert_eq!(fx.row(job).await.reason, None);
    let _ = (other, requeued_at);
});

mt_test!(after_volume_affinity_wait_s_the_service_is_placed_elsewhere, async {
    let fx = Fx::new().await;
    let holder = fx.h2_node(4.0, 8192).await;
    let job = lost_service_with_volume(&fx, holder).await;
    let other = fx.h2_node(4.0, 8192).await;
    fx.advance(899);
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty());
    fx.advance(1);
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].0, other,
        "900 s after the requeue: elsewhere, with an empty volume"
    );
    assert_eq!(fx.row(job).await.reason, None);
});

mt_test!(a_busy_holder_is_waited_for_and_an_ineligible_one_is_not, async {
    let fx = Fx::new().await;
    let holder = fx.h2_node(1.0, 1024).await;
    let job = fx
        .service(
            serde_json::json!({}),
            serde_json::json!({"volumes": [{"name": "models", "mount": "/volumes/models", "max_mb": 1024}]}),
        )
        .await;
    fx.running(job).await;
    // The agent restarts (the lease is lost at once) and stays connected; a batch job takes its room first.
    let batch = fx.job(1.0, 512, 0).await;
    sqlx::query("UPDATE jobs SET created_at = created_at - 10 WHERE job_id = ?")
        .bind(batch.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
    fx.lose(holder).await;
    let other = fx.h2_node(4.0, 8192).await;
    sqlx::query("UPDATE jobs SET spec_view = json_set(spec_view, '$.placement.node_id', ?) WHERE job_id = ?")
        .bind(holder.to_string())
        .bind(batch.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(
        fx.jobs_of(&sent).await,
        vec![batch],
        "the service waits for its busy holder"
    );
    assert!(fx.row(job).await.reason.is_some());
    // The holder is deleted: nothing to wait for, so the service goes elsewhere at once.
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::soft_delete(&mut conn, fx.account, holder, fx.now())
        .await
        .unwrap();
    drop(conn);
    fx.link.disconnect(holder);
    fx.sched.node_offline(holder, OfflineReason::Deleted).await.unwrap();
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].0, fx.jobs_of(&sent).await), (other, vec![job]));
});

mt_test!(a_service_without_a_volume_and_a_batch_job_do_not_wait, async {
    let fx = Fx::new().await;
    let first = fx.h2_node(4.0, 8192).await;
    let service = fx.service(serde_json::json!({}), serde_json::json!({})).await;
    let batch = fx.job(1.0, 512, 0).await;
    fx.running(service).await;
    fx.running(batch).await;
    let last = fx.now();
    fx.advance(60);
    fx.node_went_offline(first, last).await;
    fx.link.take();
    let other = fx.h2_node(4.0, 8192).await;
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(n, _, _)| *n == other));
    assert_eq!(fx.row(service).await.reason, None);
});
