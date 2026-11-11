// SPDX-License-Identifier: AGPL-3.0-only

//! Devices and pairing tickets (H2 spec §5.2, §5.3, §5.5): the ticket REST endpoints with their no-escalation rule,
//! the pairing transaction (SI-H2-2), the device principal and its router (SI-H2-3), device listing filtered for
//! non-`admin` devices, revocation with `last_admin_device`, the closing of live connections on revocation and by the
//! liveness sweep (SI-H2-4, the store and registry side), and the offline `init --owner-device`, `devices add` and
//! `devices revoke`.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::{DeviceLimits, T0, TestApp, assert_problem, node_key};
use p2pc_proto::api::{PHONE_PROFILE, Principal, Scope};
use p2pc_proto::auth::SecretHash;
use p2pc_proto::ids::DeviceId;
use p2pc_proto::pair::PairingTicket;
use p2pc_proto::units::Units;
use p2pc_server::auth::DeviceConnection;
use p2pc_server::clock::Clock;
use p2pc_server::devices_api::sweep_once;
use p2pc_server::store::{self, devices::PairOutcome};
use serde_json::{Value, json};
use time::Duration;

const ORIGIN: &str = "https://app.example.invalid";

async fn new_app() -> TestApp {
    TestApp::with_config(|c| c.devices.web_app_origin = Some(ORIGIN.into())).await
}

/// Creates a ticket with the admin key; returns the ticket and the response body.
async fn ticket(app: &TestApp, body: Value) -> (PairingTicket, Value) {
    let r = app
        .call(
            Method::POST,
            "/v1/devices/pairing-tickets",
            Some(&app.admin),
            Some(body),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    let v = r.json();
    (PairingTicket::decode(v["ticket"].as_str().unwrap()).unwrap(), v)
}

/// Runs the pairing transaction (what `p2pc/pair/1` will do, T2-11) and commits it when it paired.
async fn pair(app: &TestApp, code: &SecretHash, node: &str) -> PairOutcome {
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let out = store::devices::pair(
        &mut tx,
        code,
        &app.state.dummy_digest,
        node,
        Some("phone".into()),
        "iOS Safari",
        app.clock.now(),
    )
    .await
    .unwrap();
    if matches!(out, PairOutcome::Paired(_)) {
        tx.commit().await.unwrap();
    }
    out
}

fn paired(out: PairOutcome) -> DeviceId {
    match out {
        PairOutcome::Paired(d) => d.device_id,
        other => panic!("not paired: {other:?}"),
    }
}

async fn device_rows(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&app.db)
        .await
        .unwrap()
}

async fn audit_kinds(app: &TestApp) -> Vec<String> {
    sqlx::query_scalar("SELECT kind FROM audit_events ORDER BY seq")
        .fetch_all(&app.db)
        .await
        .unwrap()
}

// --- Pairing tickets ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_admin_creates_lists_and_revokes_a_pairing_ticket() {
    let app = new_app().await;
    let (t, v) = ticket(&app, json!({"label": "phone"})).await;
    let text = v["ticket"].as_str().unwrap();
    assert!(text.starts_with("p2pc_pair_"));
    // The QR link carries the ticket in the fragment, which browsers never send to the static host.
    assert_eq!(v["url"], format!("{ORIGIN}/pair#{text}"));
    assert_eq!(t.hub.to_string(), app.state.server.node_id().to_string());
    // The hub stores only the code's hash.
    let stored: String = sqlx::query_scalar("SELECT code_digest FROM pairing_tickets")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(stored, t.code_hash().to_stored());
    let r = app.get("/v1/devices/pairing-tickets", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    let list = r.json();
    let item = &list["items"][0];
    assert_eq!(item["id"], v["id"]);
    assert_eq!(item["scopes"], json!(PHONE_PROFILE), "the default is the phone profile");
    assert_eq!(
        item["created_by"],
        json!({"kind": "key", "id": app.admin_key.key_id().to_string()})
    );
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert!(!body.contains("p2pc_pair_"), "a listing never shows a ticket");
    // Revoke: idempotent; an unknown ID is 404.
    let path = format!("/v1/devices/pairing-tickets/{}", v["id"].as_str().unwrap());
    for _ in 0..2 {
        let r = app.call(Method::DELETE, &path, Some(&app.admin), None).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
    }
    let r = app
        .call(
            Method::DELETE,
            "/v1/devices/pairing-tickets/ptk_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            Some(&app.admin),
            None,
        )
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    let kinds = audit_kinds(&app).await;
    assert_eq!(kinds.iter().filter(|k| *k == "pairing_ticket_created").count(), 1);
    assert_eq!(kinds.iter().filter(|k| *k == "pairing_ticket_revoked").count(), 1);
    let audit: Vec<String> = sqlx::query_scalar("SELECT detail FROM audit_events")
        .fetch_all(&app.db)
        .await
        .unwrap();
    assert!(
        audit.iter().all(|d| !d.contains("p2pc_pair_")),
        "SI-H2-1: no ticket in the audit log"
    );
    // A revoked ticket pairs nothing.
    assert_eq!(pair(&app, &t.code_hash(), &node_key()).await, PairOutcome::Invalid);
}

#[tokio::test]
async fn pairing_needs_admin_a_web_app_origin_and_a_valid_body() {
    let app = new_app().await;
    let reader = app.key_with(&[Scope::JobsRead]).await;
    let r = app
        .call(
            Method::POST,
            "/v1/devices/pairing-tickets",
            Some(&reader),
            Some(json!({})),
        )
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = app.get("/v1/devices/pairing-tickets", &reader).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    // A phone-profile device creates no ticket (only `admin` principals do, SI-H2-18).
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let r = app
        .device_call(phone, Method::POST, "/v1/devices/pairing-tickets", Some(json!({})))
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    for (body, field) in [
        (json!({"expires_in_s": 0}), "expires_in_s"),
        (json!({"expires_in_s": 3601}), "expires_in_s"),
        (json!({"device_expires_in_s": 0}), "device_expires_in_s"),
        (json!({"device_expires_in_s": 600}), "device_expires_in_s"),
        (
            json!({"expires_in_s": 60, "device_expires_in_s": 60}),
            "device_expires_in_s",
        ),
        (json!({"device_expires_in_s": u64::MAX}), "device_expires_in_s"),
    ] {
        let r = app
            .call(
                Method::POST,
                "/v1/devices/pairing-tickets",
                Some(&app.admin),
                Some(body.clone()),
            )
            .await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        assert_eq!(v["errors"][0]["field"], field, "{body}");
        assert_eq!(v["errors"][0]["code"], "out_of_range", "{body}");
    }
    // Without `[devices] web_app_origin` no link can be built.
    let bare = TestApp::new().await;
    let r = bare
        .call(
            Method::POST,
            "/v1/devices/pairing-tickets",
            Some(&bare.admin),
            Some(json!({})),
        )
        .await;
    assert_problem(&r, StatusCode::SERVICE_UNAVAILABLE, "web_app_origin_unset");
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_tickets")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// SI-H2-18: a ticket carries a subset of its creator's power.
#[tokio::test]
async fn a_ticket_never_has_more_power_than_its_creator() {
    let app = new_app().await;
    let expiry = T0 + Duration::days(30);
    let (capped, _) = app
        .create_key(json!({
            "scopes": ["admin"],
            "daily_unit_cap": 1000,
            "allowed_images": ["docker.io/library/python:*"],
            "expires_at": "2026-12-05T10:00:00Z",
        }))
        .await;
    let in_30_days = (expiry - T0).whole_seconds();
    let ok = json!({
        "daily_unit_cap": 1000,
        "allowed_images": ["docker.io/library/python:*"],
        "device_expires_in_s": in_30_days,
    });
    for (patch, field) in [
        (json!({"daily_unit_cap": null}), "daily_unit_cap"),
        (json!({"daily_unit_cap": 1001}), "daily_unit_cap"),
        (json!({"allowed_images": null}), "allowed_images"),
        (json!({"allowed_images": ["ghcr.io/**"]}), "allowed_images"),
        (json!({"device_expires_in_s": null}), "expires_at"),
        (json!({"device_expires_in_s": in_30_days + 1}), "expires_at"),
    ] {
        let mut body = ok.clone();
        for (k, v) in patch.as_object().unwrap() {
            if v.is_null() {
                body.as_object_mut().unwrap().remove(k);
            } else {
                body[k] = v.clone();
            }
        }
        let r = app
            .call(
                Method::POST,
                "/v1/devices/pairing-tickets",
                Some(&capped),
                Some(body.clone()),
            )
            .await;
        let v = assert_problem(&r, StatusCode::FORBIDDEN, "escalation_denied");
        let fields: Vec<&str> = v["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["field"].as_str().unwrap())
            .collect();
        assert!(fields.contains(&field), "{body}: {fields:?}");
    }
    let r = app
        .call(
            Method::POST,
            "/v1/devices/pairing-tickets",
            Some(&capped),
            Some(ok.clone()),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    // The device it pairs is bound by the same limits, as its own principal.
    let t = PairingTicket::decode(r.json()["ticket"].as_str().unwrap()).unwrap();
    let device = paired(pair(&app, &t.code_hash(), &node_key()).await);
    let row = store::devices::get(&mut app.db.acquire().await.unwrap(), app.account_id, device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.daily_unit_cap, Some(Units::from_milli(1000)));
    assert_eq!(row.allowed_images, Some(vec!["docker.io/library/python:*".to_string()]));
    assert_eq!(row.expires_at, Some(expiry));
    assert_eq!(row.paired_by, Some(Principal::Key(capped[8..20].parse().unwrap())));
    // A blob quota: an admin device with one cannot create a ticket without one, or with a larger one.
    let quota = app
        .add_device(
            &[Scope::Admin],
            DeviceLimits {
                blobs_quota_mb: Some(100),
                ..DeviceLimits::default()
            },
        )
        .await;
    for body in [json!({}), json!({"blobs_quota_mb": 101})] {
        let r = app
            .device_call(quota, Method::POST, "/v1/devices/pairing-tickets", Some(body))
            .await;
        let v = assert_problem(&r, StatusCode::FORBIDDEN, "escalation_denied");
        assert_eq!(v["errors"][0]["field"], "blobs_quota_mb");
    }
    let r = app
        .device_call(
            quota,
            Method::POST,
            "/v1/devices/pairing-tickets",
            Some(json!({"blobs_quota_mb": 100})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

// --- The pairing transaction (SI-H2-2) ----------------------------------------------------------------------------

#[tokio::test]
async fn a_ticket_pairs_once_retries_are_idempotent_and_never_revive_a_revoked_device() {
    let app = new_app().await;
    let (t, _) = ticket(&app, json!({"scopes": ["nodes:read"], "label": "kitchen"})).await;
    let code = t.code_hash();
    let phone = node_key();
    let first = paired(pair(&app, &code, &phone).await);
    // The same NodeId gets the same answer again, and nothing new is created.
    match pair(&app, &code, &phone).await {
        PairOutcome::Again(d) => assert_eq!(d.device_id, first),
        other => panic!("{other:?}"),
    }
    assert_eq!(device_rows(&app).await, 1);
    // Any other NodeId gets the one `invalid_ticket` answer.
    assert_eq!(pair(&app, &code, &node_key()).await, PairOutcome::Invalid);
    // The device has the ticket's project, scopes and label, and its creator as `paired_by`.
    let r = app.get(&format!("/v1/devices/{first}"), &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["scopes"], json!(["nodes:read"]));
    assert_eq!(v["label"], "phone", "the label the device sent wins over the ticket's");
    assert_eq!(v["platform"], "iOS Safari");
    assert_eq!(
        v["paired_by"],
        json!({"kind": "key", "id": app.admin_key.key_id().to_string()})
    );
    let r = app.get("/v1/devices/pairing-tickets", &app.admin).await;
    assert_eq!(r.json()["items"][0]["device_id"], first.to_string());
    // Revoked by an admin: the retry from the same NodeId is refused and creates nothing.
    let r = app
        .call(Method::DELETE, &format!("/v1/devices/{first}"), Some(&app.admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(pair(&app, &code, &phone).await, PairOutcome::Invalid);
    assert_eq!(device_rows(&app).await, 1);
    let kinds = audit_kinds(&app).await;
    assert!(kinds.contains(&"device_revoked".to_string()));

    // Revoked by the device itself ("Forget this cloud"): the same.
    let (t, _) = ticket(&app, json!({})).await;
    let other = node_key();
    let second = paired(pair(&app, &t.code_hash(), &other).await);
    let r = app
        .device_call(second, Method::DELETE, &format!("/v1/devices/{second}"), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(pair(&app, &t.code_hash(), &other).await, PairOutcome::Invalid);
    // A revoked device's NodeId may pair again with a new ticket, as a new device.
    let (t, _) = ticket(&app, json!({})).await;
    let third = paired(pair(&app, &t.code_hash(), &other).await);
    assert_ne!(third, second);
}

#[tokio::test]
async fn expired_unknown_and_already_paired_node_ids_get_invalid_ticket() {
    let app = new_app().await;
    let (t, _) = ticket(&app, json!({"expires_in_s": 60})).await;
    // Unknown code.
    let unknown = PairingTicket::generate(t.hub, vec![], Duration::seconds(60), T0).unwrap();
    assert_eq!(
        pair(&app, &unknown.code_hash(), &node_key()).await,
        PairOutcome::Invalid
    );
    // A NodeId that is already a live device pairs nothing new.
    let live = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let live_node: String = sqlx::query_scalar("SELECT iroh_node_id FROM devices WHERE device_id = ?")
        .bind(live.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(pair(&app, &t.code_hash(), &live_node).await, PairOutcome::Invalid);
    // The row's expiry decides, an expiry equal to now included.
    app.clock.advance(Duration::seconds(60));
    assert_eq!(pair(&app, &t.code_hash(), &node_key()).await, PairOutcome::Invalid);
    assert_eq!(device_rows(&app).await, 1);
}

#[tokio::test]
async fn two_concurrent_pairs_for_one_ticket_create_exactly_one_device() {
    let app = new_app().await;
    for _ in 0..5 {
        let (t, _) = ticket(&app, json!({})).await;
        let code = t.code_hash();
        let before = device_rows(&app).await;
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let db = app.db.clone();
            let dummy = app.state.dummy_digest;
            let now = app.clock.now();
            tasks.push(tokio::spawn(async move {
                let mut tx = store::begin_immediate(&db).await.unwrap();
                let out = store::devices::pair(&mut tx, &code, &dummy, &node_key(), None, "", now)
                    .await
                    .unwrap();
                if matches!(out, PairOutcome::Paired(_)) {
                    tx.commit().await.unwrap();
                }
                out
            }));
        }
        let mut wins = 0;
        for t in tasks {
            if matches!(t.await.unwrap(), PairOutcome::Paired(_)) {
                wins += 1;
            }
        }
        assert_eq!(wins, 1);
        assert_eq!(device_rows(&app).await, before + 1);
    }
}

// --- The device principal (SI-H2-3) -------------------------------------------------------------------------------

#[tokio::test]
async fn a_device_principal_exists_only_on_the_device_router() {
    let app = new_app().await;
    let device = app.add_device(&[Scope::NodesRead], DeviceLimits::default()).await;
    // whoami names the device; `key_id` is null.
    let r = app.device_call(device, Method::GET, "/v1/whoami", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v = r.json();
    assert_eq!(v["principal"], json!({"kind": "device", "id": device.to_string()}));
    assert_eq!(v["key_id"], Value::Null);
    assert_eq!(v["scopes"], json!(["nodes:read"]));
    assert_eq!(v["project_id"], app.project_id.to_string());
    // A device request with an Authorization header is refused, even with a valid key.
    let mut req = Request::builder()
        .uri("/v1/whoami")
        .header(header::AUTHORIZATION, format!("Bearer {}", app.admin))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(DeviceConnection { device_id: device });
    let r = app
        .send_on(p2pc_server::app::device_router(app.state.clone()), req)
        .await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "unexpected_authorization");
    // The TCP router ignores the extension: no API key, no principal.
    let mut req = Request::builder().uri("/v1/whoami").body(Body::empty()).unwrap();
    req.extensions_mut().insert(DeviceConnection { device_id: device });
    let r = app.send(req).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    // No header can name a device on the TCP router either.
    for (name, value) in [
        ("x-p2pc-device", device.to_string()),
        ("authorization", format!("Device {device}")),
    ] {
        let req = Request::builder()
            .uri("/v1/whoami")
            .header(name, value)
            .body(Body::empty())
            .unwrap();
        assert_problem(&app.send(req).await, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    // The device router without the extension: 401.
    let req = Request::builder().uri("/v1/whoami").body(Body::empty()).unwrap();
    let r = app
        .send_on(p2pc_server::app::device_router(app.state.clone()), req)
        .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[tokio::test]
async fn a_revoked_or_expired_device_is_refused_on_its_next_request_and_last_seen_is_written() {
    let app = new_app().await;
    let expiring = app
        .add_device(
            &[Scope::NodesRead],
            DeviceLimits {
                expires_at: Some(T0 + Duration::minutes(10)),
                ..DeviceLimits::default()
            },
        )
        .await;
    let r = app.device_call(expiring, Method::GET, "/v1/nodes", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let seen: Option<i64> = sqlx::query_scalar("SELECT last_seen_at FROM devices WHERE device_id = ?")
        .bind(expiring.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(seen, Some(T0.unix_timestamp()));
    app.clock.advance(Duration::minutes(10));
    let r = app.device_call(expiring, Method::GET, "/v1/nodes", None).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    let revoked = app.add_device(&[Scope::NodesRead], DeviceLimits::default()).await;
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/devices/{revoked}"),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = app.device_call(revoked, Method::GET, "/v1/nodes", None).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    // An unknown device ID gets the same answer.
    let r = app
        .device_call(DeviceId::generate(), Method::GET, "/v1/nodes", None)
        .await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
}

// --- Listing and revoking devices ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_non_admin_device_sees_only_itself() {
    let app = new_app().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let other = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let r = app.get("/v1/devices", &app.admin).await;
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 2);
    let r = app.device_call(phone, Method::GET, "/v1/devices", None).await;
    assert_eq!(r.status, StatusCode::OK);
    let items = r.json()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], phone.to_string());
    let r = app
        .device_call(phone, Method::GET, &format!("/v1/devices/{phone}"), None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    for uri in [
        format!("/v1/devices/{other}"),
        format!("/v1/devices/{}", DeviceId::generate()),
    ] {
        let r = app.device_call(phone, Method::GET, &uri, None).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
        let r = app.device_call(phone, Method::DELETE, &uri, None).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
    // A non-admin API key may not list devices at all.
    let reader = app.key_with(&[Scope::NodesRead]).await;
    let r = app.get("/v1/devices", &reader).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = app.get(&format!("/v1/devices/{phone}"), &reader).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    // The other device was not touched.
    let r = app.device_call(other, Method::GET, "/v1/whoami", None).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn revocation_follows_no_escalation_and_keeps_the_last_unrestricted_admin() {
    let app = new_app().await;
    let owner = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let restricted = app
        .add_device(
            &[Scope::Admin],
            DeviceLimits {
                daily_unit_cap: Some(Units::from_units(5)),
                ..DeviceLimits::default()
            },
        )
        .await;
    // A restricted admin could not have created the unrestricted owner device.
    let r = app
        .device_call(restricted, Method::DELETE, &format!("/v1/devices/{owner}"), None)
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "escalation_denied");
    // With the owner device unrestricted, the init key is no longer the last unrestricted admin principal.
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/keys/{}", app.admin_key.key_id()),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    // Now the owner device is: revoking it, even by itself, gets 409 last_admin_device.
    let r = app
        .device_call(owner, Method::DELETE, &format!("/v1/devices/{owner}"), None)
        .await;
    assert_problem(&r, StatusCode::CONFLICT, "last_admin_device");
    // A restricted one is revoked normally.
    let r = app
        .device_call(owner, Method::DELETE, &format!("/v1/devices/{restricted}"), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // And a key is kept by the same rule the other way round.
    let app = new_app().await;
    let device = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let r = app
        .call(Method::DELETE, &format!("/v1/devices/{device}"), Some(&app.admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/keys/{}", app.admin_key.key_id()),
            Some(&app.admin),
            None,
        )
        .await;
    assert_problem(&r, StatusCode::CONFLICT, "last_admin_key");
}

/// SI-H2-4 (registry side): a revocation closes every registered connection of the device at once, and the 2 s sweep
/// closes those of a device revoked by another process or past its expiry. The transport (T2-11) ties its streams
/// to these registrations.
#[tokio::test]
async fn revocation_and_the_liveness_sweep_close_live_device_connections() {
    let app = new_app().await;
    let online = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let offline = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let expiring = app
        .add_device(
            &PHONE_PROFILE,
            DeviceLimits {
                expires_at: Some(T0 + Duration::seconds(30)),
                ..DeviceLimits::default()
            },
        )
        .await;
    let bystander = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let sessions = &app.state.devices;
    let (a1, a2) = (sessions.register(online), sessions.register(online));
    let streams = a1.subscribe();
    let b = sessions.register(offline);
    let c = sessions.register(expiring);
    let d = sessions.register(bystander);
    assert_eq!(sessions.count(online), 2);
    // `DELETE /v1/devices/{id}` closes both connections of the device, and the streams watching them.
    let r = app
        .call(Method::DELETE, &format!("/v1/devices/{online}"), Some(&app.admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(a1.is_closed() && a2.is_closed() && *streams.borrow());
    assert_eq!(sessions.count(online), 0);
    // Revoked offline by `p2pc-server devices revoke`, while the hub runs: the next sweep closes it.
    assert!(sweep_once(&app.state).await.unwrap().is_empty());
    p2pc_server::recover::devices_revoke(&app.data_dir(), offline, app.clock.as_ref())
        .await
        .unwrap();
    assert!(!b.is_closed());
    assert_eq!(sweep_once(&app.state).await.unwrap(), vec![offline]);
    assert!(b.is_closed());
    // Expiry: at `expires_at` the sweep closes it (an injected clock, no sleep).
    app.clock.advance(Duration::seconds(29));
    assert!(sweep_once(&app.state).await.unwrap().is_empty());
    app.clock.advance(Duration::seconds(1));
    assert_eq!(sweep_once(&app.state).await.unwrap(), vec![expiring]);
    assert!(c.is_closed());
    assert!(!d.is_closed(), "the other device is unaffected");
    drop(d);
    assert_eq!(sessions.count(bystander), 0, "a dropped connection unregisters itself");
}

// --- Offline commands (H2 §5.3) -----------------------------------------------------------------------------------

#[tokio::test]
async fn init_owner_device_registers_an_admin_device_and_no_key() {
    let dir = tempfile::tempdir().unwrap();
    let clock = p2pc_server::clock::ManualClock::new(T0);
    let node = node_key();
    let options = p2pc_server::init::OwnerDeviceOptions {
        bind: None,
        node_id: node.clone(),
        label: Some("hub PC".into()),
    };
    let out = p2pc_server::init::init_owner_device(&dir.path().join("data"), &options, &clock)
        .await
        .unwrap();
    let db = store::open(&out.data_dir.join("p2pc.db"), store::OpenMode::Existing)
        .await
        .unwrap();
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(keys, 0, "no API key is created");
    let mut conn = db.acquire().await.unwrap();
    let row = store::devices::get(&mut conn, out.account_id, out.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.iroh_node_id, node);
    assert!(row.is_unrestricted_admin());
    assert_eq!(row.project_id, out.project_id);
    assert_eq!(row.label.as_deref(), Some("hub PC"));
    // It cannot be revoked: it is the last unrestricted admin principal.
    drop(conn);
    db.close().await;
    let err = p2pc_server::recover::devices_revoke(&out.data_dir, out.device_id, &clock)
        .await
        .unwrap_err();
    assert!(
        matches!(err, p2pc_server::recover::DeviceCommandError::LastAdmin),
        "{err}"
    );
    // Twice, or with a bad NodeId, init refuses.
    assert!(
        p2pc_server::init::init_owner_device(&out.data_dir, &options, &clock)
            .await
            .is_err()
    );
    let other = tempfile::tempdir().unwrap();
    for bad in ["nope".to_string(), "AB".repeat(32), common::not_a_point()] {
        let options = p2pc_server::init::OwnerDeviceOptions {
            bind: None,
            node_id: bad.clone(),
            label: None,
        };
        let err = p2pc_server::init::init_owner_device(other.path(), &options, &clock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, p2pc_server::init::InitError::InvalidDevice(_)),
            "{bad}: {err}"
        );
    }
}

#[tokio::test]
async fn devices_add_and_revoke_work_offline_and_are_audited() {
    let app = new_app().await;
    let node = node_key();
    let add = p2pc_server::recover::AddDevice {
        node_id: node.clone(),
        scopes: vec![Scope::Admin],
        label: Some("laptop".into()),
        project_id: None,
    };
    let row = p2pc_server::recover::devices_add(&app.data_dir(), &add, app.clock.as_ref())
        .await
        .unwrap();
    assert_eq!(row.project_id, app.project_id);
    // The running hub serves it at once.
    let r = app.device_call(row.device_id, Method::GET, "/v1/whoami", None).await;
    assert_eq!(r.status, StatusCode::OK);
    // The same NodeId again is refused while it is live; bad input is refused before the database.
    let err = p2pc_server::recover::devices_add(&app.data_dir(), &add, app.clock.as_ref())
        .await
        .unwrap_err();
    assert!(
        matches!(err, p2pc_server::recover::DeviceCommandError::NodeIdInUse),
        "{err}"
    );
    for bad in [
        p2pc_server::recover::AddDevice {
            scopes: vec![],
            node_id: node_key(),
            ..add.clone()
        },
        p2pc_server::recover::AddDevice {
            scopes: vec![Scope::NodesRead, Scope::NodesRead],
            node_id: node_key(),
            ..add.clone()
        },
        p2pc_server::recover::AddDevice {
            node_id: common::not_a_point(),
            ..add.clone()
        },
        p2pc_server::recover::AddDevice {
            label: Some(String::new()),
            node_id: node_key(),
            ..add.clone()
        },
        p2pc_server::recover::AddDevice {
            project_id: Some(p2pc_proto::ids::ProjectId::generate()),
            node_id: node_key(),
            ..add.clone()
        },
    ] {
        assert!(
            p2pc_server::recover::devices_add(&app.data_dir(), &bad, app.clock.as_ref())
                .await
                .is_err()
        );
    }
    p2pc_server::recover::devices_revoke(&app.data_dir(), row.device_id, app.clock.as_ref())
        .await
        .unwrap();
    // Idempotent; an unknown device is an error.
    p2pc_server::recover::devices_revoke(&app.data_dir(), row.device_id, app.clock.as_ref())
        .await
        .unwrap();
    assert!(
        p2pc_server::recover::devices_revoke(&app.data_dir(), DeviceId::generate(), app.clock.as_ref())
            .await
            .is_err()
    );
    let r = app.device_call(row.device_id, Method::GET, "/v1/whoami", None).await;
    assert_problem(&r, StatusCode::UNAUTHORIZED, "unauthenticated");
    let kinds = audit_kinds(&app).await;
    assert_eq!(kinds.iter().filter(|k| *k == "device_added_offline").count(), 1);
    assert_eq!(kinds.iter().filter(|k| *k == "device_revoked_offline").count(), 1);
}

/// §5.3, §10.5: the hub serves `p2pc/pair/1` only while a pairing ticket is open. The gateway (T2-11) asks the store;
/// a ticket stops counting once it is consumed, revoked or expired.
#[tokio::test]
async fn a_ticket_is_open_only_until_it_is_consumed_revoked_or_expired() {
    let app = new_app().await;
    let open = |app: &TestApp| {
        let (db, now) = (app.db.clone(), app.clock.now());
        async move {
            let mut conn = db.acquire().await.unwrap();
            store::devices::any_open_ticket(&mut conn, now).await.unwrap()
        }
    };
    assert!(!open(&app).await);
    let (t, _) = ticket(&app, json!({})).await;
    assert!(open(&app).await);
    paired(pair(&app, &t.code_hash(), &node_key()).await);
    assert!(!open(&app).await, "consumed");
    let (_, v) = ticket(&app, json!({})).await;
    let path = format!("/v1/devices/pairing-tickets/{}", v["id"].as_str().unwrap());
    assert_eq!(
        app.call(Method::DELETE, &path, Some(&app.admin), None).await.status,
        StatusCode::NO_CONTENT
    );
    assert!(!open(&app).await, "revoked");
    ticket(&app, json!({"expires_in_s": 30})).await;
    app.clock.advance(Duration::seconds(29));
    assert!(open(&app).await);
    app.clock.advance(Duration::seconds(1));
    assert!(!open(&app).await, "expired at its expiry");
}

/// SI-H2-18: an `admin` with a blob quota could not have created a device without one, so it cannot revoke it.
#[tokio::test]
async fn an_admin_with_a_blob_quota_cannot_revoke_a_device_without_one() {
    let app = new_app().await;
    let quota = app
        .add_device(
            &[Scope::Admin],
            DeviceLimits {
                blobs_quota_mb: Some(100),
                ..DeviceLimits::default()
            },
        )
        .await;
    let unbound = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let within = app
        .add_device(
            &PHONE_PROFILE,
            DeviceLimits {
                blobs_quota_mb: Some(50),
                ..DeviceLimits::default()
            },
        )
        .await;
    let r = app
        .device_call(quota, Method::DELETE, &format!("/v1/devices/{unbound}"), None)
        .await;
    let v = assert_problem(&r, StatusCode::FORBIDDEN, "escalation_denied");
    assert_eq!(v["errors"][0]["field"], "blobs_quota_mb");
    let r = app
        .device_call(quota, Method::DELETE, &format!("/v1/devices/{within}"), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    // The device that was refused is still live.
    let r = app.device_call(unbound, Method::GET, "/v1/whoami", None).await;
    assert_eq!(r.status, StatusCode::OK);
}

/// SI-H2-18, SI-H2-19: the default phone profile is exactly four scopes, with no `nodes:join`, and a phone-profile
/// device reaches none of the developer or admin routes. The template view of the job routes has its negative test
/// per route in `template_view.rs`; the blob routes get theirs with T2-14.
#[tokio::test]
async fn the_phone_profile_reaches_only_what_its_scopes_allow() {
    assert_eq!(
        PHONE_PROFILE,
        [
            Scope::NodesRead,
            Scope::TemplatesLaunch,
            Scope::BlobsWrite,
            Scope::NodesInvite
        ]
    );
    let app = new_app().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let other = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let node = p2pc_proto::ids::NodeId::generate();
    let key = app.admin_key.key_id();
    let job = json!({"image": "python:3.12-slim", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 512}});
    let forbidden: Vec<(Method, String, Option<Value>)> = vec![
        (Method::POST, "/v1/jobs".into(), Some(job.clone())),
        (Method::POST, "/v1/estimate".into(), Some(job)),
        (
            Method::GET,
            "/v1/usage?from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z".into(),
            None,
        ),
        (Method::POST, "/v1/nodes/join-tokens".into(), Some(json!({}))),
        (Method::GET, "/v1/nodes/join-tokens".into(), None),
        (Method::POST, "/v1/devices/pairing-tickets".into(), Some(json!({}))),
        (Method::GET, "/v1/devices/pairing-tickets".into(), None),
        (Method::POST, format!("/v1/nodes/{node}/drain"), None),
        (Method::POST, format!("/v1/nodes/{node}/resume"), None),
        (Method::POST, format!("/v1/nodes/{node}/approve"), None),
        (Method::DELETE, format!("/v1/nodes/{node}"), None),
        (Method::GET, "/v1/keys".into(), None),
        (Method::POST, "/v1/keys".into(), Some(json!({"scopes": ["admin"]}))),
        (Method::DELETE, format!("/v1/keys/{key}"), None),
        (Method::GET, "/v1/audit".into(), None),
        (
            Method::POST,
            "/v1/nodes/join-requests/jrq_01ARZ3NDEKTSV4RRFFQ69G5FAV/approve".into(),
            None,
        ),
    ];
    for (method, uri, body) in forbidden {
        let r = app.device_call(phone, method.clone(), &uri, body).await;
        assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    // Another device is as invisible as an unknown one.
    for method in [Method::GET, Method::DELETE] {
        let r = app
            .device_call(phone, method, &format!("/v1/devices/{other}"), None)
            .await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
    // What it may do: see the PCs, see itself, open a join request (tested in `join_requests.rs`).
    for uri in [
        "/v1/nodes",
        "/v1/whoami",
        "/v1/devices",
        "/v1/server",
        "/v1/nodes/join-requests",
    ] {
        let r = app.device_call(phone, Method::GET, uri, None).await;
        assert_eq!(r.status, StatusCode::OK, "{uri}: {:?}", r.body);
    }
    // Nothing was created or removed by the refused calls.
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM jobs), (SELECT COUNT(*) FROM join_tokens), \
                (SELECT COUNT(*) FROM pairing_tickets), (SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL)",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(counts, (0, 0, 0, 1));
}

/// H1 §5 "Re-checked at the point of use", for pairing: the device takes its power from the ticket's creator, which is
/// reloaded inside the pairing transaction. A ticket whose creator, key or device, was revoked since pairs nothing and
/// gets the one `invalid_ticket` answer; the ticket stays unused.
#[tokio::test]
async fn a_ticket_of_a_revoked_creator_pairs_nothing() {
    let app = new_app().await;
    let (key, key_json) = app.create_key(json!({"scopes": ["admin"]})).await;
    let device = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let r = app
        .call(Method::POST, "/v1/devices/pairing-tickets", Some(&key), Some(json!({})))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let by_key = PairingTicket::decode(r.json()["ticket"].as_str().unwrap()).unwrap();
    let r = app
        .device_call(device, Method::POST, "/v1/devices/pairing-tickets", Some(json!({})))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let by_device = PairingTicket::decode(r.json()["ticket"].as_str().unwrap()).unwrap();
    // Both creators are revoked while their tickets are still open.
    let path = format!("/v1/keys/{}", key_json["id"].as_str().unwrap());
    assert_eq!(
        app.call(Method::DELETE, &path, Some(&app.admin), None).await.status,
        StatusCode::NO_CONTENT
    );
    let path = format!("/v1/devices/{device}");
    assert_eq!(
        app.call(Method::DELETE, &path, Some(&app.admin), None).await.status,
        StatusCode::NO_CONTENT
    );
    let before = device_rows(&app).await;
    for t in [&by_key, &by_device] {
        assert_eq!(pair(&app, &t.code_hash(), &node_key()).await, PairOutcome::Invalid);
    }
    assert_eq!(device_rows(&app).await, before, "no device was created");
    let consumed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_tickets WHERE consumed_at IS NOT NULL")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(consumed, 0, "the tickets stay unused");
    // A ticket of a live creator still pairs.
    let (t, _) = ticket(&app, json!({})).await;
    paired(pair(&app, &t.code_hash(), &node_key()).await);
}

/// A NodeId whose device has expired without being revoked may be registered again: the dead row is revoked, and that
/// revocation is audited as `device_revoked` with `{"reason": "expired_replaced"}`, in the same transaction.
#[tokio::test]
async fn replacing_an_expired_device_audits_its_revocation() {
    let app = new_app().await;
    let node = node_key();
    let device = |expires_at| store::devices::NewDevice {
        device_id: DeviceId::generate(),
        project_id: app.project_id,
        iroh_node_id: node.clone(),
        label: None,
        platform: String::new(),
        scopes: PHONE_PROFILE.to_vec(),
        daily_unit_cap: None,
        allowed_images: None,
        blobs_quota_mb: None,
        expires_at,
        paired_by: None,
    };
    /// `(subject_id, actor_key_id, actor_device_id, detail)` of a `device_revoked` event.
    type Revoked = (Option<String>, Option<String>, Option<String>, String);
    let replaced = |app: &TestApp| {
        let db = app.db.clone();
        async move {
            let rows: Vec<Revoked> = sqlx::query_as(
                "SELECT subject_id, actor_key_id, actor_device_id, detail FROM audit_events \
                 WHERE kind = 'device_revoked' ORDER BY seq",
            )
            .fetch_all(&db)
            .await
            .unwrap();
            rows
        }
    };
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let old = store::devices::insert(
        &mut tx,
        app.account_id,
        &device(Some(T0 + Duration::minutes(5))),
        app.clock.now(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // While it is live, the NodeId is taken, and nothing is audited.
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let err = store::devices::insert(&mut tx, app.account_id, &device(None), app.clock.now())
        .await
        .unwrap_err();
    assert!(matches!(err, store::devices::InsertError::NodeIdInUse), "{err}");
    drop(tx);
    assert!(replaced(&app).await.is_empty());

    // Expired: a rolled-back replacement leaves no trace, a committed one revokes and audits together.
    app.clock.advance(Duration::minutes(5));
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    store::devices::insert(&mut tx, app.account_id, &device(None), app.clock.now())
        .await
        .unwrap();
    drop(tx);
    assert!(
        replaced(&app).await.is_empty(),
        "the event is in the caller's transaction"
    );
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let new = store::devices::insert(&mut tx, app.account_id, &device(None), app.clock.now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_ne!(new.device_id, old.device_id);
    let events = replaced(&app).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let (subject, actor_key, actor_device, detail) = &events[0];
    assert_eq!(subject.as_deref(), Some(old.device_id.to_string().as_str()));
    assert_eq!((actor_key, actor_device), (&None, &None), "no principal did it");
    assert_eq!(
        serde_json::from_str::<Value>(detail).unwrap(),
        json!({"reason": "expired_replaced"})
    );
    let mut conn = app.db.acquire().await.unwrap();
    let old = store::devices::get(&mut conn, app.account_id, old.device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.revoked_at, Some(app.clock.now()));
    // The admin sees it in the audit log.
    let r = app.get("/v1/audit?kind=device_revoked", &app.admin).await;
    assert_eq!(r.json()["items"][0]["detail"], json!({"reason": "expired_replaced"}));
}
