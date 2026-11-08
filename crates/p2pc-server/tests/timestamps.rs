// SPDX-License-Identifier: AGPL-3.0-only

//! T04 carry-over from the T03 review: a handler uses the one `now` it reads **after** it holds the write lock, for
//! the re-check, the stored timestamps and the audit event alike; and `expires_at` is whole seconds. Also
//! `GET /v1/whoami` returning the caller key's limits (spec §7).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::http::{Method, StatusCode};
use common::{T0, TestApp, assert_problem};
use p2pc_server::app::router;
use p2pc_server::clock::Clock;
use serde_json::json;
use time::{Duration, OffsetDateTime};

/// A clock that moves one second on every reading, so each reading is distinct and the last one is known.
#[derive(Debug)]
struct TickingClock(AtomicI64);

impl TickingClock {
    fn new() -> Self {
        Self(AtomicI64::new(T0.unix_timestamp()))
    }

    /// The most recent time handed out.
    fn last(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst) - 1).unwrap()
    }
}

impl Clock for TickingClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.fetch_add(1, Ordering::SeqCst)).unwrap()
    }
}

/// A test app whose clock ticks on every reading.
async fn ticking_app() -> (TestApp, Arc<TickingClock>) {
    let mut app = TestApp::new().await;
    let clock = Arc::new(TickingClock::new());
    app.state.clock = clock.clone();
    app.router = router(app.state.clone());
    (app, clock)
}

#[tokio::test]
async fn key_creation_stamps_the_time_read_after_the_lock() {
    let (app, clock) = ticking_app().await;
    let r = app
        .call(
            Method::POST,
            "/v1/keys",
            Some(&app.admin),
            Some(json!({"scopes": ["jobs:read"]})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    // Nothing reads the clock after the last reading of the handler, and that reading is the one the key and the
    // audit event are stamped with.
    let last = clock.last();
    let created = OffsetDateTime::parse(
        r.json()["created_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(created, last);
    let audit = app.get("/v1/audit?kind=key_created", &app.admin).await.json();
    let at = audit["items"][0]["at"].as_str().unwrap().to_string();
    assert_eq!(
        OffsetDateTime::parse(&at, &time::format_description::well_known::Rfc3339).unwrap(),
        last
    );
}

#[tokio::test]
async fn key_revocation_stamps_the_time_read_after_the_lock() {
    let (app, clock) = ticking_app().await;
    let (_, created) = app.create_key(json!({"scopes": ["jobs:read"]})).await;
    let id = created["id"].as_str().unwrap().to_string();
    let r = app
        .call(Method::DELETE, &format!("/v1/keys/{id}"), Some(&app.admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let last = clock.last();
    let list = app.get("/v1/keys?limit=100", &app.admin).await.json();
    let revoked = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == id)
        .unwrap()["revoked_at"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        OffsetDateTime::parse(&revoked, &time::format_description::well_known::Rfc3339).unwrap(),
        last
    );
}

/// `expires_at` is stored as whole Unix seconds, so a fraction would be silently truncated (and, truncated, could
/// even compare differently against the creator's own expiry). It is refused instead.
#[tokio::test]
async fn expires_at_with_a_fraction_of_a_second_is_refused() {
    let app = TestApp::new().await;
    for bad in ["2026-12-01T00:00:00.5Z", "2026-12-01T00:00:00.000000001Z"] {
        let r = app
            .call(
                Method::POST,
                "/v1/keys",
                Some(&app.admin),
                Some(json!({"scopes": ["jobs:read"], "expires_at": bad})),
            )
            .await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        assert_eq!(v["errors"][0]["field"], "expires_at", "{v}");
        assert_eq!(v["errors"][0]["code"], "invalid_format", "{v}");
    }
    // A zero fraction is whole seconds: accepted, and stored exactly.
    let (_, v) = app
        .create_key(json!({"scopes": ["jobs:read"], "expires_at": "2026-12-01T00:00:00.000Z"}))
        .await;
    assert_eq!(v["expires_at"], "2026-12-01T00:00:00Z");
    // Nothing was created by the refused requests: init's key and this one.
    let list = app.get("/v1/keys?limit=100", &app.admin).await.json();
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn whoami_returns_the_callers_limits_and_never_a_secret() {
    let app = TestApp::new().await;
    let (key, created) = app
        .create_key(json!({
            "label": "agent", "scopes": ["jobs:read", "jobs:write"], "daily_unit_cap": 5000,
            "allowed_images": ["docker.io/library/python:*"],
            "expires_at": (T0 + Duration::days(30)).format(&time::format_description::well_known::Rfc3339).unwrap(),
        }))
        .await;
    let r = app.get("/v1/whoami", &key).await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["account_id"], app.account_id.to_string());
    assert_eq!(v["project_id"], app.project_id.to_string());
    assert_eq!(v["key_id"], created["id"]);
    assert_eq!(v["scopes"], json!(["jobs:read", "jobs:write"]));
    assert_eq!(v["label"], "agent");
    assert_eq!(v["daily_unit_cap"], 5000);
    assert_eq!(v["allowed_images"], json!(["docker.io/library/python:*"]));
    assert_eq!(v["expires_at"], created["expires_at"]);
    let text = String::from_utf8_lossy(&r.body).to_string();
    let secret = &key["p2pc_sk_".len() + 13..];
    assert!(!text.contains(secret), "{text}");
    assert!(!text.contains("sha256:"), "{text}");
    assert!(v.get("key").is_none() && v.get("secret").is_none(), "{v}");

    // init's admin key is unrestricted: the limits are explicit nulls, which is what `p2pc mcp` checks.
    let v = app.get("/v1/whoami", &app.admin).await.json();
    for k in ["daily_unit_cap", "allowed_images", "expires_at"] {
        assert!(v[k].is_null(), "{k}: {v}");
    }
    assert_eq!(v["label"], "admin (init)");
}

/// The contract `p2pc mcp` relies on (§7): for an uncapped key, `GET /v1/whoami` sends `"daily_unit_cap": null`
/// **present** in the raw JSON. `p2pc mcp` tells a `null` cap (uncapped, refused) from an absent member (a server
/// older than the cap fields: "did not report"), so the server must never omit the limit members. `v["x"]` yields
/// `Null` for a missing member too, so this looks at the object's own members.
#[tokio::test]
async fn whoami_always_sends_the_limit_members_even_when_they_are_null() {
    let app = TestApp::new().await;
    let limit_members = ["label", "daily_unit_cap", "allowed_images", "expires_at"];

    // init's admin key is unrestricted: no cap, no image list, no expiry.
    let r = app.get("/v1/whoami", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    let object = v.as_object().unwrap();
    for member in limit_members {
        assert!(object.contains_key(member), "`{member}` is missing from {v}");
    }
    assert_eq!(object.get("daily_unit_cap"), Some(&serde_json::Value::Null), "{v}");
    assert_eq!(object.get("allowed_images"), Some(&serde_json::Value::Null), "{v}");
    assert_eq!(object.get("expires_at"), Some(&serde_json::Value::Null), "{v}");
    // The text of the response says it too, not only the parsed value.
    let text = String::from_utf8_lossy(&r.body);
    assert!(text.contains("\"daily_unit_cap\":null"), "{text}");

    // A key without a label still sends `label`, as `null`.
    let (key, _) = app.create_key(json!({"scopes": ["jobs:read"]})).await;
    let v = app.get("/v1/whoami", &key).await.json();
    let object = v.as_object().unwrap();
    for member in limit_members {
        assert_eq!(object.get(member), Some(&serde_json::Value::Null), "{member} in {v}");
    }

    // A capped key sends the number instead.
    let (capped, _) = app
        .create_key(json!({"scopes": ["jobs:read"], "daily_unit_cap": 5000}))
        .await;
    let v = app.get("/v1/whoami", &capped).await.json();
    assert_eq!(v.get("daily_unit_cap"), Some(&json!(5000)), "{v}");
}
