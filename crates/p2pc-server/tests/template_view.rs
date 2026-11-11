// SPDX-License-Identifier: AGPL-3.0-only

//! The template view of the job routes and the cancel rule (H2 spec §5.5, §7.2, SI-H2-18): what a principal with
//! `templates:launch` and no `jobs:read` or `jobs:write` reaches, pinned by a negative test per route.
//!
//! The project holds a developer batch job, a developer service (`p2pc service run`), another device's `transcribe`
//! job, a `private-chat` instance launched by the owner, and the phone's own `transcribe` job. Template launches come
//! with T2-15, so the template jobs are stored here as a launch stores them: a job with `template` set and the
//! launcher as its principal.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::{Method, StatusCode};
use common::{DeviceLimits, Resp, TestApp, assert_problem};
use p2pc_proto::api::{FileMeta, JobSpec, PHONE_PROFILE, Principal, Scope};
use p2pc_proto::ids::{DeviceId, JobId};
use p2pc_proto::units::Units;
use p2pc_server::app::router;
use p2pc_server::clock::Clock;
use p2pc_server::jobs_api::{JobRoute, TemplateCatalog, visible_job};
use p2pc_server::store::{self, jobs};
use serde_json::{Value, json};

/// The bundle of the tests: `private-chat` is a singleton, `transcribe` is not.
#[derive(Debug)]
struct Bundle;

impl TemplateCatalog for Bundle {
    fn singleton_ids(&self) -> Vec<String> {
        vec!["private-chat".to_string()]
    }
}

struct World {
    app: TestApp,
    phone: DeviceId,
    other: DeviceId,
    dev_batch: JobId,
    dev_service: JobId,
    others_transcribe: JobId,
    chat: JobId,
    own_transcribe: JobId,
}

async fn store_job(app: &TestApp, by: Principal, spec: Value) -> JobId {
    let spec: JobSpec = serde_json::from_value(spec).unwrap();
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let new = jobs::NewJob {
        job_id: JobId::generate(),
        account_id: app.account_id,
        project_id: app.project_id,
        principal: by,
        files_meta: FileMeta::compute_all(&spec).unwrap(),
        spec,
        spec_hash: format!("sha256:{}", "0".repeat(64)),
        units_reserved: Units::from_units(1),
    };
    let row = jobs::insert(&mut tx, &new, app.clock.now()).await.unwrap();
    tx.commit().await.unwrap();
    row.job_id
}

fn transcribe() -> Value {
    json!({"image": "docker.io/library/alpine:3", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 512},
           "template": {"id": "transcribe", "version": 1}})
}

fn service(template: Option<&str>) -> Value {
    let mut spec = json!({"kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
        "resources": {"cpu": 1, "memory_mb": 512}, "service": {"ports": [{"port": 11434, "name": "api"}]}});
    if let Some(id) = template {
        spec["template"] = json!({"id": id, "version": 1, "pull": "small-model"});
    }
    spec
}

async fn world() -> World {
    let mut app = TestApp::new().await;
    app.state.templates = Arc::new(Bundle);
    app.router = router(app.state.clone());
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let other = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let owner = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let developer = Principal::Key(app.admin_key.key_id());
    let batch = json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 512}, "env": {"TOKEN": "developer-secret"}}); // gitleaks:allow (fake)
    let dev_batch = store_job(&app, developer, batch).await;
    let dev_service = store_job(&app, developer, service(None)).await;
    let others_transcribe = store_job(&app, Principal::Device(other), transcribe()).await;
    let chat = store_job(&app, Principal::Device(owner), service(Some("private-chat"))).await;
    let own_transcribe = store_job(&app, Principal::Device(phone), transcribe()).await;
    World {
        app,
        phone,
        other,
        dev_batch,
        dev_service,
        others_transcribe,
        chat,
        own_transcribe,
    }
}

fn ids(r: &Resp) -> BTreeSet<String> {
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["id"].as_str().unwrap().to_string())
        .collect()
}

fn set(jobs: &[JobId]) -> BTreeSet<String> {
    jobs.iter().map(ToString::to_string).collect()
}

async fn status(app: &TestApp, job: JobId) -> String {
    sqlx::query_scalar("SELECT status FROM jobs WHERE job_id = ?")
        .bind(job.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_phone_lists_only_its_own_template_jobs_and_the_singleton_instance() {
    let w = world().await;
    let app = &w.app;
    let r = app.device_call(w.phone, Method::GET, "/v1/jobs", None).await;
    assert_eq!(ids(&r), set(&[w.own_transcribe, w.chat]));
    // The developer's env names never reach it either: the jobs are simply not there.
    assert!(!String::from_utf8_lossy(&r.body).contains("TOKEN"));
    // The other phone sees its own job and the same shared instance.
    let r = app.device_call(w.other, Method::GET, "/v1/jobs", None).await;
    assert_eq!(ids(&r), set(&[w.others_transcribe, w.chat]));
    // Filters and pages work inside the view: a hidden job takes no place in a page and moves no cursor.
    let r = app
        .device_call(w.phone, Method::GET, "/v1/jobs?kind=service", None)
        .await;
    assert_eq!(ids(&r), set(&[w.chat]));
    let r = app
        .device_call(w.phone, Method::GET, "/v1/jobs?kind=batch&status=queued", None)
        .await;
    assert_eq!(ids(&r), set(&[w.own_transcribe]));
    let mut seen = BTreeSet::new();
    let mut uri = "/v1/jobs?limit=1".to_string();
    for _ in 0..2 {
        let r = app.device_call(w.phone, Method::GET, &uri, None).await;
        let page = ids(&r);
        assert_eq!(page.len(), 1);
        seen.extend(page);
        match r.json()["next_cursor"].as_str() {
            Some(c) => uri = format!("/v1/jobs?limit=1&cursor={c}"),
            None => break,
        }
    }
    assert_eq!(seen, set(&[w.own_transcribe, w.chat]));
    let r = app.device_call(w.phone, Method::GET, &uri, None).await;
    assert!(ids(&r).is_subset(&seen), "no page ever holds a hidden job");
    // With `jobs:read` the listing is H1's: every job of the project.
    let all = set(&[
        w.dev_batch,
        w.dev_service,
        w.others_transcribe,
        w.chat,
        w.own_transcribe,
    ]);
    let r = app.get("/v1/jobs", &app.admin).await;
    assert_eq!(ids(&r), all);
    let mut scopes = PHONE_PROFILE.to_vec();
    scopes.push(Scope::JobsRead);
    let reader = app.add_device(&scopes, DeviceLimits::default()).await;
    let r = app.device_call(reader, Method::GET, "/v1/jobs", None).await;
    assert_eq!(
        ids(&r),
        all,
        "the template view only adds: it never narrows `jobs:read`"
    );
    let r = app.get("/v1/jobs?kind=service", &app.admin).await;
    assert_eq!(ids(&r), set(&[w.dev_service, w.chat]));
    let r = app.get("/v1/jobs?kind=batch", &app.admin).await;
    assert_eq!(ids(&r), set(&[w.dev_batch, w.others_transcribe, w.own_transcribe]));
    let r = app.get("/v1/jobs?kind=cron", &app.admin).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

/// SI-H2-18: every job route on a job outside the view answers `404`, byte for byte as for an unknown id.
#[tokio::test]
async fn every_job_route_hides_what_is_outside_the_template_view() {
    let w = world().await;
    let app = &w.app;
    let unknown = JobId::generate();
    let get = async |uri: String| app.device_call(w.phone, Method::GET, &uri, None).await;
    let missing = get(format!("/v1/jobs/{unknown}")).await;
    assert_problem(&missing, StatusCode::NOT_FOUND, "not_found");
    for hidden in [w.dev_batch, w.dev_service, w.others_transcribe] {
        for route in ["", "/logs", "/logs?follow=true", "/outputs", "/outputs/result.txt"] {
            let r = get(format!("/v1/jobs/{hidden}{route}")).await;
            assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
            assert_eq!(
                r.body, missing.body,
                "{hidden}{route}: the same answer as an unknown id"
            );
        }
        let r = app
            .device_call(w.phone, Method::POST, &format!("/v1/jobs/{hidden}/cancel"), None)
            .await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
        assert_eq!(r.body, missing.body);
        assert_eq!(status(app, hidden).await, "queued", "nothing was cancelled");
    }
    // The owner's singleton instance: its state is visible, its logs and outputs are not.
    let r = get(format!("/v1/jobs/{}", w.chat)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v = r.json();
    assert_eq!(v["spec"]["template"]["id"], "private-chat");
    assert_eq!(v["service"]["ports"], json!([{"port": 11434, "name": "api"}]));
    for route in ["/logs", "/outputs", "/outputs/result.txt"] {
        let r = get(format!("/v1/jobs/{}{route}", w.chat)).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
        assert_eq!(r.body, missing.body);
    }
    // Its own template job: state, logs and outputs.
    let own = w.own_transcribe;
    assert_eq!(get(format!("/v1/jobs/{own}")).await.status, StatusCode::OK);
    let r = get(format!("/v1/jobs/{own}/logs")).await;
    assert_eq!((r.status, r.body.len()), (StatusCode::OK, 0), "no log yet");
    let r = get(format!("/v1/jobs/{own}/outputs")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["items"], json!([]));
    // What only `jobs:write` and `jobs:read` give stays `403`.
    let job = json!({"image": "python:3.12-slim", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 512}});
    let r = app.device_call(w.phone, Method::POST, "/v1/jobs", Some(job)).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(jobs, 5);
}

/// A principal with neither the H1 scope nor `templates:launch` gets `403` on every job route, whatever it names.
#[tokio::test]
async fn without_templates_launch_the_job_routes_keep_their_h1_scopes() {
    let w = world().await;
    let app = &w.app;
    let nodes_only = app.add_device(&[Scope::NodesRead], DeviceLimits::default()).await;
    let key = app.key_with(&[Scope::NodesRead]).await;
    for job in [
        w.own_transcribe.to_string(),
        JobId::generate().to_string(),
        "nope".into(),
    ] {
        for (method, route) in [
            (Method::GET, ""),
            (Method::GET, "/logs"),
            (Method::GET, "/outputs"),
            (Method::GET, "/outputs/a.txt"),
            (Method::POST, "/cancel"),
        ] {
            let uri = format!("/v1/jobs/{job}{route}");
            let r = app.device_call(nodes_only, method.clone(), &uri, None).await;
            assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
            let r = app.call(method, &uri, Some(&key), None).await;
            assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
        }
    }
    let r = app.device_call(nodes_only, Method::GET, "/v1/jobs", None).await;
    let v = assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    assert!(v["detail"].as_str().unwrap().contains("`jobs:read`"), "{v}");
    // `jobs:write` alone cancels (H1) and still reads nothing.
    let writer = app.key_with(&[Scope::JobsWrite]).await;
    let r = app.get(&format!("/v1/jobs/{}", w.dev_batch), &writer).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = app
        .call(
            Method::POST,
            &format!("/v1/jobs/{}/cancel", w.dev_batch),
            Some(&writer),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

/// H2 §7.2 "Who can stop a service": H1's rule for `jobs:write`; the template view for `templates:launch`.
#[tokio::test]
async fn the_cancel_rule_is_h1s_for_jobs_write_and_the_template_view_for_templates_launch() {
    let w = world().await;
    let app = &w.app;
    let cancel = async |by: DeviceId, job: JobId| {
        app.device_call(by, Method::POST, &format!("/v1/jobs/{job}/cancel"), None)
            .await
    };
    // The phone stops its own template job: a batch job keeps H1's empty reason.
    let r = cancel(w.phone, w.own_transcribe).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.json()["status"], "cancelled");
    assert_eq!(r.json()["reason"], Value::Null);
    // Any launcher may stop the shared singleton instance, though the owner launched it; a service says `stopped`.
    let r = cancel(w.other, w.chat).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v = r.json();
    assert_eq!(
        (v["status"].as_str(), v["reason"].as_str()),
        (Some("cancelled"), Some("stopped"))
    );
    // Idempotent, and still inside the view.
    let r = cancel(w.phone, w.chat).await;
    assert_eq!(r.json()["reason"], "stopped");
    // Another device's template job and the developer's jobs: not there.
    for hidden in [w.others_transcribe, w.dev_batch, w.dev_service] {
        let r = cancel(w.phone, hidden).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
        assert_eq!(status(app, hidden).await, "queued");
    }
    // With `jobs:write`, H1's project-wide cancel still works, template view or not: on another device's template
    // job and on the developer's jobs.
    let mut scopes = PHONE_PROFILE.to_vec();
    scopes.push(Scope::JobsWrite);
    let writer = app.add_device(&scopes, DeviceLimits::default()).await;
    for job in [w.others_transcribe, w.dev_batch, w.dev_service] {
        let r = cancel(writer, job).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        assert_eq!(r.json()["status"], "cancelled");
    }
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>("SELECT reason FROM jobs WHERE job_id = ?")
            .bind(w.dev_service.to_string())
            .fetch_one(&app.db)
            .await
            .unwrap()
            .as_deref(),
        Some("stopped"),
        "the developer's service was stopped"
    );
}

/// The view follows the principal, key or device, and the bundle: with no bundle loaded nothing is a singleton.
#[tokio::test]
async fn the_view_is_per_principal_and_knows_singletons_only_from_the_bundle() {
    let mut w = world().await;
    let key = w.app.key_with(&[Scope::TemplatesLaunch]).await;
    let key_id = key[8..20].parse().unwrap();
    let launched = store_job(&w.app, Principal::Key(key_id), transcribe()).await;
    let r = w.app.get("/v1/jobs", &key).await;
    assert_eq!(ids(&r), set(&[launched, w.chat]));
    let r = w.app.get(&format!("/v1/jobs/{}/logs", launched), &key).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = w.app.get(&format!("/v1/jobs/{}", w.own_transcribe), &key).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    // No bundle (the state before T2-15 loads one): the chat instance is just another principal's template job.
    w.app.state.templates = Arc::new(p2pc_server::jobs_api::NoTemplates);
    w.app.router = router(w.app.state.clone());
    let r = w.app.device_call(w.phone, Method::GET, "/v1/jobs", None).await;
    assert_eq!(ids(&r), set(&[w.own_transcribe]));
    let r = w
        .app
        .device_call(w.phone, Method::GET, &format!("/v1/jobs/{}", w.chat), None)
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    let r = w
        .app
        .device_call(w.phone, Method::POST, &format!("/v1/jobs/{}/cancel", w.chat), None)
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    assert_eq!(status(&w.app, w.chat).await, "queued");
}

/// The access rule for the port route, which T2-13 adds (H2 §5.5 "Ports", §7.4): through the template view, only a
/// visible template **service**; with `services:connect`, any job of the project.
#[tokio::test]
async fn a_port_is_reachable_through_the_view_only_on_a_visible_template_service() {
    let w = world().await;
    let app = &w.app;
    let developer = app
        .add_device(&p2pc_proto::api::DEVELOPER_DEVICE_PROFILE, DeviceLimits::default())
        .await;
    let nodes_only = app.add_device(&[Scope::NodesRead], DeviceLimits::default()).await;
    let mut conn = app.db.acquire().await.unwrap();
    let mut principal = async |d: DeviceId| {
        p2pc_server::auth::reload(&mut conn, app.account_id, Principal::Device(d), app.clock.now())
            .await
            .unwrap()
            .unwrap()
    };
    let (phone, developer, nodes_only) = (
        principal(w.phone).await,
        principal(developer).await,
        principal(nodes_only).await,
    );
    let mut conn = app.db.acquire().await.unwrap();
    let mut port = async |p: &p2pc_server::auth::Principal, job: JobId| {
        visible_job(&mut conn, &app.state, p, JobRoute::Port, job)
            .await
            .map(|row| row.job_id)
            .map_err(|e| e.status())
    };
    assert_eq!(port(&phone, w.chat).await, Ok(w.chat));
    for hidden in [w.own_transcribe, w.others_transcribe, w.dev_service, w.dev_batch] {
        assert_eq!(port(&phone, hidden).await, Err(StatusCode::NOT_FOUND), "{hidden}");
    }
    // `services:connect` keeps the project-wide rule (the port route itself answers for a job that is no service).
    for job in [w.chat, w.dev_service, w.others_transcribe] {
        assert_eq!(port(&developer, job).await, Ok(job));
    }
    assert_eq!(port(&nodes_only, w.chat).await, Err(StatusCode::FORBIDDEN));
}
