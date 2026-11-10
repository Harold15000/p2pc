// SPDX-License-Identifier: AGPL-3.0-only

//! The append-only audit log (spec §5, "Audit").
//!
//! This module only appends and reads. It has no function that updates or deletes an event, and the database
//! refuses both with triggers; the one exception is raising the count of an aggregated `auth_failed` row, which
//! [`record_auth_failure`] does (from the writer task in `audit_queue`, off the request path).
//!
//! There is no delete function to call:
//!
//! ```compile_fail
//! async fn try_delete(conn: &mut p2pc_server::store::Conn, account: p2pc_proto::ids::AccountId) {
//!     let _ = p2pc_server::store::audit::delete(conn, account, 1).await;
//! }
//! ```
//!
//! nor an update function:
//!
//! ```compile_fail
//! async fn try_update(conn: &mut p2pc_server::store::Conn, account: p2pc_proto::ids::AccountId) {
//!     let _ = p2pc_server::store::audit::update(conn, account, 1, serde_json::json!({})).await;
//! }
//! ```
//!
//! while reading compiles:
//!
//! ```no_run
//! async fn read(conn: &mut p2pc_server::store::Conn, account: p2pc_proto::ids::AccountId) {
//!     let _ = p2pc_server::store::audit::list(conn, account, None, None, 10).await;
//! }
//! ```
//!
//! Events never contain a secret: callers pass key IDs, never keys, and `detail` holds only metadata.

use p2pc_proto::api::{AuditEvent, AuditKind, Principal, audit_detail_has_secret};
use p2pc_proto::ids::{AccountId, AuditEventId, DeviceId, KeyId};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::{Conn, StoreError, from_ts, parse_col, ts};

/// Subject of an `auth_failed` row when the presented key ID does not exist or the header is malformed.
pub const UNKNOWN_SUBJECT: &str = "unknown";

/// The wire and storage name of a kind (`key_created`, …): its serde name, so it cannot drift from `p2pc-proto`.
#[must_use]
pub fn kind_name(kind: AuditKind) -> String {
    match serde_json::to_value(kind) {
        Ok(Value::String(s)) => s,
        // A unit enum always serializes to a string.
        _ => String::new(),
    }
}

/// Parses a kind name, as given in `GET /v1/audit?kind=`.
#[must_use]
pub fn parse_kind(name: &str) -> Option<AuditKind> {
    serde_json::from_value(Value::String(name.to_string())).ok()
}

/// An event to append.
#[derive(Debug, Clone)]
pub struct NewEvent {
    /// What happened. Not [`AuditKind::AuthFailed`]: use [`record_auth_failure`].
    pub kind: AuditKind,
    /// The key that did it.
    pub actor_key_id: Option<KeyId>,
    /// The device that did it (H2 §5.6). At most one of the two actors is set.
    pub actor_device_id: Option<DeviceId>,
    /// What it happened to.
    pub subject_id: Option<String>,
    /// Non-secret details.
    pub detail: Map<String, Value>,
}

impl NewEvent {
    /// An event acted by `actor` (a key, a device, or nobody for the offline commands and the protocol side).
    #[must_use]
    pub fn new(
        kind: AuditKind,
        actor: Option<Principal>,
        subject_id: Option<String>,
        detail: Map<String, Value>,
    ) -> Self {
        Self {
            kind,
            actor_key_id: actor.and_then(|a| a.key_id()),
            actor_device_id: actor.and_then(|a| a.device_id()),
            subject_id,
            detail,
        }
    }
}

/// An event with its position in the log, which list cursors use.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEvent {
    /// Internal sequence number (newer events have larger numbers).
    pub seq: i64,
    /// The event.
    pub event: AuditEvent,
}

/// Appends an event to `account_id`'s log and returns its ID. Refuses `auth_failed` (see [`record_auth_failure`])
/// and any detail that looks like it holds a key or a join token ([`audit_detail_has_secret`]).
pub async fn append(
    conn: &mut Conn,
    account_id: AccountId,
    event: &NewEvent,
    now: OffsetDateTime,
) -> Result<AuditEventId, StoreError> {
    if event.kind == AuditKind::AuthFailed
        || audit_detail_has_secret(&event.detail)
        || (event.actor_key_id.is_some() && event.actor_device_id.is_some())
    {
        return Err(StoreError::Corrupt("audit_events.kind/detail"));
    }
    let id = AuditEventId::generate();
    sqlx::query(
        "INSERT INTO audit_events (event_id, at, account_id, actor_key_id, actor_device_id, kind, subject_id, \
         detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(ts(now))
    .bind(account_id.to_string())
    .bind(event.actor_key_id.map(|k| k.to_string()))
    .bind(event.actor_device_id.map(|d| d.to_string()))
    .bind(kind_name(event.kind))
    .bind(event.subject_id.clone())
    .bind(Value::Object(event.detail.clone()).to_string())
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

/// The start of the minute `at` falls in, as stored in `auth_failed` rows.
#[must_use]
pub fn minute_of(at: OffsetDateTime) -> i64 {
    ts(at) - ts(at).rem_euclid(60)
}

/// Adds `count` (at least 1) failed authentications to `account_id`'s row for the minute of `at` and `subject`
/// (the presented key ID, or [`UNKNOWN_SUBJECT`]): one row per minute and subject, with the count in
/// `detail.count`. Called by the auth-failure writer task (`audit_queue`), never on the request path.
pub async fn record_auth_failure(
    conn: &mut Conn,
    account_id: AccountId,
    subject: &str,
    at: OffsetDateTime,
    count: u64,
) -> Result<(), StoreError> {
    let count = i64::try_from(count.max(1)).unwrap_or(i64::MAX);
    sqlx::query(
        "INSERT INTO audit_events (event_id, at, account_id, kind, subject_id, detail) \
         VALUES (?1, ?2, ?3, 'auth_failed', ?4, json_object('count', ?5)) \
         ON CONFLICT (account_id, at, subject_id) WHERE kind = 'auth_failed' \
         DO UPDATE SET detail = json_set(detail, '$.count', json_extract(detail, '$.count') + ?5)",
    )
    .bind(AuditEventId::generate().to_string())
    .bind(minute_of(at))
    .bind(account_id.to_string())
    .bind(subject)
    .bind(count)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

type Row = (
    i64,
    String,
    i64,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    String,
);

/// `account_id`'s events, newest first, optionally of one kind, older than sequence number `before`, at most
/// `limit`.
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    kind: Option<AuditKind>,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<StoredEvent>, StoreError> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT seq, event_id, at, actor_key_id, actor_device_id, kind, subject_id, detail FROM audit_events \
         WHERE account_id = ?1 AND (?2 IS NULL OR kind = ?2) AND (?3 IS NULL OR seq < ?3) \
         ORDER BY seq DESC LIMIT ?4",
    )
    .bind(account_id.to_string())
    .bind(kind.map(kind_name))
    .bind(before)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(seq, id, at, actor, device, kind, subject, detail)| {
            let detail = match serde_json::from_str(&detail) {
                Ok(Value::Object(map)) => map,
                _ => return Err(StoreError::Corrupt("audit_events.detail")),
            };
            Ok(StoredEvent {
                seq,
                event: AuditEvent {
                    id: parse_col(&id, "audit_events.event_id")?,
                    at: from_ts(at, "audit_events.at")?,
                    kind: parse_kind(&kind).ok_or(StoreError::Corrupt("audit_events.kind"))?,
                    actor_key_id: actor.map(|a| parse_col(&a, "audit_events.actor_key_id")).transpose()?,
                    actor_device_id: device
                        .map(|d| parse_col(&d, "audit_events.actor_device_id"))
                        .transpose()?,
                    subject_id: subject,
                    detail,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::macros::datetime;

    use super::*;
    use crate::store::{OpenMode, accounts, open};

    const T: OffsetDateTime = datetime!(2026-11-05 10:00:30 UTC);

    async fn db() -> (tempfile::TempDir, crate::store::Db, AccountId) {
        let tmp = tempfile::tempdir().unwrap();
        let db = open(&tmp.path().join("t.db"), OpenMode::Create).await.unwrap();
        let mut conn = db.acquire().await.unwrap();
        let (account, _) = accounts::create_owner(&mut conn, T).await.unwrap();
        drop(conn);
        (tmp, db, account)
    }

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn kind_names_round_trip_and_match_the_schema() {
        let all = [
            AuditKind::KeyCreated,
            AuditKind::KeyRevoked,
            AuditKind::JoinTokenCreated,
            AuditKind::JoinTokenConsumed,
            AuditKind::JoinTokenRevoked,
            AuditKind::NodeEnrolled,
            AuditKind::NodeDeleted,
            AuditKind::AuthFailed,
            AuditKind::KeyRecovered,
            AuditKind::NodeReenrolled,
        ];
        // The latest definition of the table's CHECK (rebuilt when a kind is added): every H1 and H2 kind.
        let schema = include_str!("../../migrations/20261110130000_h2_principals_rebuild.sql");
        for kind in all.into_iter().chain(AuditKind::ALL) {
            let name = kind_name(kind);
            assert_eq!(parse_kind(&name), Some(kind));
            // Every kind is allowed by the table's CHECK.
            assert!(schema.contains(&format!("'{name}'")), "{name}");
        }
        assert_eq!(kind_name(AuditKind::KeyCreated), "key_created");
        assert_eq!(parse_kind("KEY_CREATED"), None);
        assert_eq!(parse_kind(""), None);
    }

    /// The migration that adds `node_reenrolled` rebuilds `audit_events`: the rows keep their `seq` (the list
    /// cursor) and event IDs, new rows go on after them, and the append-only triggers still hold.
    #[tokio::test]
    async fn the_node_reenrolled_rebuild_keeps_rows_cursors_and_the_append_only_triggers() {
        use sqlx::Connection as _;

        const REBUILD: i64 = 20_261_106_130_000;
        let tmp = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(tmp.path().join("t.db"))
            .create_if_missing(true)
            .foreign_keys(true);
        let mut conn = sqlx::SqliteConnection::connect_with(&options).await.unwrap();
        // The database as it was before the rebuild.
        for m in crate::store::MIGRATOR.iter().filter(|m| m.version < REBUILD) {
            sqlx::raw_sql(m.sql.clone()).execute(&mut conn).await.unwrap();
        }
        let (account, _) = accounts::create_owner(&mut conn, T).await.unwrap();
        let event = |kind| NewEvent {
            kind,
            actor_key_id: None,
            actor_device_id: None,
            subject_id: Some("node_x".into()),
            detail: obj(json!({"name": "box"})),
        };
        // The H1 schema of that time, written without the H2 `actor_device_id` column that `append` now writes.
        let h1_append = |kind: &'static str| {
            sqlx::query(
                "INSERT INTO audit_events (event_id, at, account_id, kind, subject_id, detail) \
                 VALUES (?, ?, ?, ?, 'node_x', '{\"name\":\"box\"}')",
            )
            .bind(AuditEventId::generate().to_string())
            .bind(ts(T))
            .bind(account.to_string())
            .bind(kind)
        };
        for kind in ["node_enrolled", "node_deleted"] {
            h1_append(kind).execute(&mut conn).await.unwrap();
        }
        record_auth_failure(&mut conn, account, "unknown", T, 3).await.unwrap();
        let rows = "SELECT seq, event_id, kind, detail FROM audit_events ORDER BY seq";
        let before: Vec<(i64, String, String, String)> = sqlx::query_as(rows).fetch_all(&mut conn).await.unwrap();
        // Before it, the new kind is refused by the table's CHECK.
        assert!(h1_append("node_reenrolled").execute(&mut conn).await.is_err());
        let rebuild = crate::store::MIGRATOR.iter().find(|m| m.version == REBUILD).unwrap();
        sqlx::raw_sql(rebuild.sql.clone()).execute(&mut conn).await.unwrap();
        let after: Vec<(i64, String, String, String)> = sqlx::query_as(rows).fetch_all(&mut conn).await.unwrap();
        assert_eq!(after, before);
        // The later migrations (the H2 rebuild among them, each in a transaction as sqlx runs them), so the current
        // `append` can write.
        for m in crate::store::MIGRATOR.iter().filter(|m| m.version > REBUILD) {
            let mut tx = sqlx::Connection::begin(&mut conn).await.unwrap();
            sqlx::raw_sql(m.sql.clone()).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        }
        let after: Vec<(i64, String, String, String)> = sqlx::query_as(rows).fetch_all(&mut conn).await.unwrap();
        assert_eq!(after, before);
        let added = append(&mut conn, account, &event(AuditKind::NodeReenrolled), T)
            .await
            .unwrap();
        let (last, kind): (i64, String) = sqlx::query_as("SELECT seq, kind FROM audit_events WHERE event_id = ?")
            .bind(added.to_string())
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert!(last > before.iter().map(|r| r.0).max().unwrap());
        assert_eq!(kind, "node_reenrolled");
        assert!(
            sqlx::query("DELETE FROM audit_events")
                .execute(&mut conn)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("UPDATE audit_events SET kind = 'key_created'")
                .execute(&mut conn)
                .await
                .is_err()
        );
        // The aggregated auth_failed row may still have its count raised.
        record_auth_failure(&mut conn, account, "unknown", T, 2).await.unwrap();
        let total: i64 =
            sqlx::query_scalar("SELECT json_extract(detail, '$.count') FROM audit_events WHERE kind = 'auth_failed'")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(total, 5);
    }

    #[tokio::test]
    async fn audit_rows_cannot_be_updated_or_deleted() {
        let (_tmp, db, account) = db().await;
        let mut conn = db.acquire().await.unwrap();
        let event = NewEvent {
            kind: AuditKind::KeyCreated,
            actor_key_id: None,
            actor_device_id: None,
            subject_id: Some("abcdefgh2345".into()),
            detail: obj(json!({"scopes": ["admin"]})),
        };
        let id = append(&mut conn, account, &event, T).await.unwrap();
        record_auth_failure(&mut conn, account, "abcdefgh2345", T, 1)
            .await
            .unwrap();
        // The store API has no update or delete (see the compile_fail examples above). Raw SQL is refused too: the
        // only update allowed is raising an auth_failed row's integer `detail.count`.
        for sql in [
            "DELETE FROM audit_events",
            "DELETE FROM audit_events WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET detail = '{}'",
            "UPDATE audit_events SET subject_id = 'x' WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET detail = json_set(detail, '$.count', 0) WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET detail = json_set(detail, '$.count', 1) WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET detail = json_set(detail, '$.count', 'many') WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET detail = json_set(detail, '$.count', 2.5) WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET detail = json_set(detail, '$.count', json_extract(detail, '$.count') + 1, \
             '$.x', 1) WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET detail = json_set(detail, '$.count', 1) WHERE kind = 'key_created'",
            "UPDATE audit_events SET at = 0 WHERE kind = 'auth_failed'",
            "UPDATE audit_events SET event_id = 'aud_01ARZ3NDEKTSV4RRFFQ69G5FAV' WHERE kind = 'auth_failed'",
        ] {
            let err = sqlx::query(sql).execute(&mut *conn).await.unwrap_err();
            assert!(err.to_string().contains("append-only"), "{sql}: {err}");
        }
        let events = list(&mut conn, account, None, None, 10).await.unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].seq > events[1].seq);
        assert_eq!(events[1].event.id, id);
        assert_eq!(events[1].event.detail, obj(json!({"scopes": ["admin"]})));
        assert_eq!(events[0].event.detail, obj(json!({"count": 1})));
        // Appending an auth_failed directly, or a detail that holds a key or a join token, is refused.
        let key = p2pc_proto::auth::ApiKey::generate().expose();
        for bad in [
            NewEvent {
                kind: AuditKind::AuthFailed,
                ..event.clone()
            },
            NewEvent {
                detail: obj(json!({"oops": key})),
                ..event.clone()
            },
            NewEvent {
                detail: obj(json!({"nested": [{"t": "p2pc_join_abc"}]})),
                ..event.clone()
            },
        ] {
            assert!(append(&mut conn, account, &bad, T).await.is_err());
        }
        assert_eq!(list(&mut conn, account, None, None, 10).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn auth_failures_aggregate_per_minute_and_subject() {
        let (_tmp, db, account) = db().await;
        let mut conn = db.acquire().await.unwrap();
        for (subject, at) in [
            ("k1", T),
            ("k1", datetime!(2026-11-05 10:00:59 UTC)),
            ("k1", datetime!(2026-11-05 10:00:00 UTC)),
            (UNKNOWN_SUBJECT, T),
            ("k1", datetime!(2026-11-05 10:01:00 UTC)),
        ] {
            record_auth_failure(&mut conn, account, subject, at, 1).await.unwrap();
        }
        // A batch adds its whole count at once.
        record_auth_failure(&mut conn, account, UNKNOWN_SUBJECT, T, 5)
            .await
            .unwrap();
        let got: Vec<(OffsetDateTime, Option<String>, Value)> =
            list(&mut conn, account, Some(AuditKind::AuthFailed), None, 10)
                .await
                .unwrap()
                .into_iter()
                .map(|e| (e.event.at, e.event.subject_id, Value::Object(e.event.detail)))
                .collect();
        assert_eq!(
            got,
            vec![
                (
                    datetime!(2026-11-05 10:01:00 UTC),
                    Some("k1".into()),
                    json!({"count": 1})
                ),
                (
                    datetime!(2026-11-05 10:00:00 UTC),
                    Some(UNKNOWN_SUBJECT.into()),
                    json!({"count": 6})
                ),
                (
                    datetime!(2026-11-05 10:00:00 UTC),
                    Some("k1".into()),
                    json!({"count": 3})
                ),
            ]
        );
    }
}
