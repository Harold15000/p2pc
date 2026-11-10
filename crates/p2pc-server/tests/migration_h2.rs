// SPDX-License-Identifier: AGPL-3.0-only

//! The §5.6 rebuild migration (H2 spec §5.6, §12, SI-H2-20), run on a database filled through the H1 migrations:
//! every row and value is copied, `PRAGMA foreign_key_check` is empty, the append-only triggers still refuse
//! `UPDATE` and `DELETE`, and H1's cap and usage numbers are unchanged.

// The helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them (as `common/mod.rs`).
#![allow(clippy::unwrap_used)]

use p2pc_proto::api::{Principal, UsageGroupBy};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{AccountId, JobId, JoinTokenId, KeyId, LeaseId, NodeId, ProjectId};
use p2pc_server::store::leases::{UsageQuery, UsageTotalsRow, spent_between, usage_report};
use p2pc_server::store::{self, MIGRATOR};
use sqlx::{Connection, SqliteConnection};
use time::OffsetDateTime;
use time::macros::datetime;

/// The first H2 migration: everything before it is H1.
const FIRST_H2: i64 = 20_261_110_120_000;
/// 2026-11-05 00:00 UTC.
const DAY: i64 = 1_793_836_800;

async fn open(dir: &tempfile::TempDir) -> SqliteConnection {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(dir.path().join("t.db"))
        .create_if_missing(true)
        .foreign_keys(true);
    SqliteConnection::connect_with(&options).await.unwrap()
}

/// Applies the migrations matching `which`, each in its own transaction, as sqlx does.
async fn migrate(conn: &mut SqliteConnection, which: impl Fn(i64) -> bool) {
    for m in MIGRATOR.iter().filter(|m| which(m.version)) {
        let mut tx = conn.begin().await.unwrap();
        sqlx::raw_sql(m.sql.clone())
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("migration {}: {e}", m.version));
        tx.commit()
            .await
            .unwrap_or_else(|e| panic!("commit {}: {e}", m.version));
    }
}

async fn exec(conn: &mut SqliteConnection, sql: &'static str, binds: &[&str]) {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(&mut *conn).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
}

/// Every H1 column of the four rebuilt tables, as one JSON text per table, in primary-key order.
async fn h1_rows(conn: &mut SqliteConnection) -> Vec<String> {
    let mut out = Vec::new();
    for sql in [
        "SELECT json_group_array(json_array(job_id, account_id, project_id, key_id, name, spec, files_meta, spec_view, \
         spec_hash, status, attempt, max_attempts, idempotency_key, units_reserved, node_id, exit_code, outcome, \
         error, reason, cancel_requested_at, created_at, updated_at, started_at, finished_at, epoch, offer_count, \
         last_lost_node_id)) FROM (SELECT * FROM jobs ORDER BY job_id)",
        "SELECT json_group_array(json_array(id, job_id, attempt, lease_id, node_id, key_id, account_id, project_id, \
         started_at, ended_at, reserved_cpu_ms, reserved_gpu_ms, used_cpu_ms, max_rss_mb, units, estimated)) \
         FROM (SELECT * FROM usage_records ORDER BY id)",
        "SELECT json_group_array(json_array(id, account_id, project_id, code_digest, label, created_by_key_id, \
         created_at, expires_at, consumed_at, consumed_by_node_id, revoked_at)) \
         FROM (SELECT * FROM join_tokens ORDER BY id)",
        "SELECT json_group_array(json_array(seq, event_id, at, account_id, actor_key_id, kind, subject_id, detail)) \
         FROM (SELECT * FROM audit_events ORDER BY seq)",
    ] {
        out.push(sqlx::query_scalar(sql).fetch_one(&mut *conn).await.unwrap());
    }
    out
}

/// H1's `spent_between`, verbatim (before the migration the H2 code cannot run).
async fn h1_spent(conn: &mut SqliteConnection, account: AccountId, key: KeyId, from: i64, to: i64) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(CASE \
             WHEN status IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost') THEN \
                 CASE \
                     WHEN EXISTS (SELECT 1 FROM usage_records u WHERE u.job_id = jobs.job_id) \
                         THEN (SELECT SUM(u.units) FROM usage_records u WHERE u.job_id = jobs.job_id) \
                     WHEN status = 'cancelled' AND NOT EXISTS \
                          (SELECT 1 FROM job_events e WHERE e.job_id = jobs.job_id AND e.to_status = 'running') THEN 0 \
                     ELSE units_reserved END \
             ELSE units_reserved \
                  + COALESCE((SELECT SUM(u.units) FROM usage_records u WHERE u.job_id = jobs.job_id), 0) \
             END), 0) \
         FROM jobs WHERE account_id = ?1 AND key_id = ?2 AND created_at >= ?3 AND created_at < ?4",
    )
    .bind(account.to_string())
    .bind(key.to_string())
    .bind(from)
    .bind(to)
    .fetch_one(&mut *conn)
    .await
    .unwrap()
}

/// H1's `GET /v1/usage` grouping, verbatim: `(group, attempts, units, estimated)`.
async fn h1_usage(conn: &mut SqliteConnection, group: &str, from: i64, to: i64) -> Vec<(String, i64, i64, i64)> {
    sqlx::query_as(
        "SELECT g, COUNT(*), SUM(units), SUM(estimated) \
         FROM (SELECT CASE ?1 WHEN 'job' THEN job_id WHEN 'node' THEN node_id ELSE key_id END AS g, units, estimated \
               FROM usage_records WHERE ended_at >= ?2 AND ended_at < ?3) \
         GROUP BY g ORDER BY g",
    )
    .bind(group)
    .bind(from)
    .bind(to)
    .fetch_all(&mut *conn)
    .await
    .unwrap()
}

fn as_h1(rows: &[UsageTotalsRow]) -> Vec<(String, i64, i64, i64)> {
    rows.iter()
        .map(|r| {
            (
                r.key.clone(),
                i64::try_from(r.attempts).unwrap(),
                i64::try_from(r.units.milli()).unwrap(),
                i64::try_from(r.estimated_attempts).unwrap(),
            )
        })
        .collect()
}

struct Fixture {
    account: AccountId,
    project: ProjectId,
    k1: KeyId,
    k2: KeyId,
}

/// An H1 database with two keys, a node, jobs in every kind of state, leases, ledger rows (one estimated, one of a
/// job created the day before), join tokens and audit events.
async fn fill_h1(conn: &mut SqliteConnection) -> Fixture {
    let created = OffsetDateTime::from_unix_timestamp(DAY + 3600).unwrap();
    let (account, project) = store::accounts::create_owner(conn, created).await.unwrap();
    let (a, p) = (account.to_string(), project.to_string());
    let (k1, k2) = (ApiKey::generate(), ApiKey::generate());
    for (key, scopes, cap) in [
        (&k1, "[\"admin\"]", None),
        (&k2, "[\"jobs:write\",\"jobs:read\"]", Some(5000_i64)),
    ] {
        sqlx::query(
            "INSERT INTO api_keys (key_id, account_id, project_id, secret_digest, scopes, daily_unit_cap, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(key.key_id().to_string())
        .bind(&a)
        .bind(&p)
        .bind(key.hash().to_stored())
        .bind(scopes)
        .bind(cap)
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    let node = NodeId::generate().to_string();
    let (tok_used, tok_open, tok_revoked) = (
        JoinTokenId::generate().to_string(),
        JoinTokenId::generate().to_string(),
        JoinTokenId::generate().to_string(),
    );
    let k1s = k1.key_id().to_string();
    let k2s = k2.key_id().to_string();
    for (i, (id, by)) in [(&tok_used, &k1s), (&tok_open, &k1s), (&tok_revoked, &k2s)]
        .into_iter()
        .enumerate()
    {
        let digest = format!("sha256:{}", format!("{i:x}").repeat(64));
        exec(
            conn,
            "INSERT INTO join_tokens (id, account_id, project_id, code_digest, label, created_by_key_id, created_at, \
             expires_at) VALUES (?, ?, ?, ?, 'box', ?, 100, 1000)",
            &[id, &a, &p, &digest, by],
        )
        .await;
    }
    exec(
        conn,
        "UPDATE join_tokens SET revoked_at = 200 WHERE id = ?",
        &[&tok_revoked],
    )
    .await;
    exec(
        conn,
        "INSERT INTO nodes (id, account_id, project_id, iroh_node_id, name, hostname, inventory, agent_version, state, \
         enrolled_via_token_id, created_at) VALUES (?, ?, ?, ?, 'box', 'box.example.invalid', '{}', '0.1.0', \
         'online', ?, 150)",
        &[&node, &a, &p, &"ab".repeat(32), &tok_used],
    )
    .await;
    exec(
        conn,
        "UPDATE join_tokens SET consumed_at = 150, consumed_by_node_id = ? WHERE id = ?",
        &[&node, &tok_used],
    )
    .await;
    let yesterday = DAY - 60;
    /// `(key, status, units_reserved, created_at, ran, ledger rows as (ended_at, units, estimated))`.
    type FixtureJob<'a> = (&'a str, &'a str, i64, i64, bool, Vec<(i64, i64, i64)>);
    let jobs: [FixtureJob<'_>; 6] = [
        (&k1s, "succeeded", 1000, DAY + 3600, true, vec![(DAY + 7200, 800, 0)]),
        (&k2s, "running", 500, DAY + 3700, true, vec![]),
        (&k2s, "cancelled", 700, DAY + 3800, false, vec![]),
        (&k2s, "failed", 900, DAY + 3900, true, vec![(DAY + 4000, 300, 1)]),
        (&k1s, "lost", 2000, yesterday, true, vec![(DAY + 600, 1500, 1)]),
        (&k2s, "queued", 400, DAY + 5000, false, vec![]),
    ];
    for (i, (key, status, reserved, created_at, ran, rows)) in jobs.iter().enumerate() {
        let job = JobId::generate().to_string();
        let idem = format!("idem-{i}");
        exec(
            conn,
            "INSERT INTO jobs (job_id, account_id, project_id, key_id, name, spec, files_meta, spec_view, spec_hash, \
             status, attempt, max_attempts, idempotency_key, units_reserved, node_id, created_at, updated_at, epoch) \
             VALUES (?, ?, ?, ?, 'j', '{\"image\":\"x\"}', '[]', '{\"image\":\"x\"}', ?, ?, 1, 2, ?, ?, ?, ?, ?, 1)",
            &[
                &job,
                &a,
                &p,
                key,
                &format!("sha256:{}", "c".repeat(64)),
                status,
                &idem,
                &reserved.to_string(),
                &node,
                &created_at.to_string(),
                &created_at.to_string(),
            ],
        )
        .await;
        exec(
            conn,
            "INSERT INTO job_events (job_id, at, from_status, to_status, reason) VALUES (?, ?, NULL, 'queued', 'created')",
            &[&job, &created_at.to_string()],
        )
        .await;
        if *ran {
            exec(
                conn,
                "INSERT INTO job_events (job_id, at, from_status, to_status, reason) VALUES (?, ?, 'assigned', \
                 'running', 'started')",
                &[&job, &created_at.to_string()],
            )
            .await;
        }
        for (ended_at, units, estimated) in rows {
            let lease = LeaseId::generate().to_string();
            exec(
                conn,
                "INSERT INTO leases (id, job_id, node_id, epoch, attempt, state, reserved, offered_at_ms, started_at, \
                 ended_at, confirmed_dead_at) VALUES (?, ?, ?, 1, 1, 'finished', \
                 '{\"cpu\":1,\"memory_mb\":512,\"gpu_uuid\":null}', 0, ?, ?, ?)",
                &[
                    &lease,
                    &job,
                    &node,
                    &created_at.to_string(),
                    &ended_at.to_string(),
                    &ended_at.to_string(),
                ],
            )
            .await;
            exec(
                conn,
                "INSERT INTO usage_records (job_id, attempt, lease_id, node_id, key_id, account_id, project_id, \
                 started_at, ended_at, reserved_cpu_ms, reserved_gpu_ms, used_cpu_ms, max_rss_mb, units, estimated) \
                 VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 1000, 0, 500, 64, ?, ?)",
                &[
                    &job,
                    &lease,
                    &node,
                    key,
                    &a,
                    &p,
                    &created_at.to_string(),
                    &ended_at.to_string(),
                    &units.to_string(),
                    &estimated.to_string(),
                ],
            )
            .await;
        }
    }
    // Audit: a plain event and an aggregated failure.
    let at = created.unix_timestamp().to_string();
    exec(
        conn,
        "INSERT INTO audit_events (event_id, at, account_id, actor_key_id, kind, subject_id, detail) \
         VALUES (?, ?, ?, ?, 'key_created', ?, '{\"scopes\":[\"admin\"]}')",
        &[
            &p2pc_proto::ids::AuditEventId::generate().to_string(),
            &at,
            &a,
            &k1s,
            &k2s,
        ],
    )
    .await;
    store::audit::record_auth_failure(conn, account, "unknown", created, 3)
        .await
        .unwrap();
    Fixture {
        account,
        project,
        k1: k1.key_id(),
        k2: k2.key_id(),
    }
}

#[tokio::test]
async fn the_rebuild_keeps_every_h1_row_value_trigger_and_number() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = open(&dir).await;
    migrate(&mut conn, |v| v < FIRST_H2).await;
    let fx = fill_h1(&mut conn).await;

    // What H1 says, before.
    let rows_before = h1_rows(&mut conn).await;
    let days = [(DAY - 86_400, DAY), (DAY, DAY + 86_400)];
    let mut spent_before = Vec::new();
    for key in [fx.k1, fx.k2] {
        for (from, to) in days {
            spent_before.push(h1_spent(&mut conn, fx.account, key, from, to).await);
        }
    }
    let mut usage_before = Vec::new();
    for group in ["job", "node", "key"] {
        usage_before.push(h1_usage(&mut conn, group, DAY - 86_400, DAY + 86_400).await);
    }
    assert!(spent_before.iter().any(|s| *s > 0), "the fixture must spend something");

    migrate(&mut conn, |v| v >= FIRST_H2).await;

    // Every row and value copied.
    assert_eq!(h1_rows(&mut conn).await, rows_before);
    // The principal columns: the key unchanged, the device NULL, exactly one set.
    for sql in [
        "SELECT COUNT(*) FROM jobs WHERE device_id IS NOT NULL OR key_id IS NULL OR kind <> 'batch' \
         OR template_id IS NOT NULL",
        "SELECT COUNT(*) FROM usage_records WHERE device_id IS NOT NULL OR key_id IS NULL",
        "SELECT COUNT(*) FROM join_tokens WHERE created_by_device_id IS NOT NULL OR created_by_key_id IS NULL \
         OR bound_iroh_node_id IS NOT NULL OR pre_approved <> 0",
        "SELECT COUNT(*) FROM audit_events WHERE actor_device_id IS NOT NULL",
        "SELECT COUNT(*) FROM nodes WHERE approval <> 'approved' OR enrolled_by_key_id IS NOT NULL \
         OR enrolled_by_device_id IS NOT NULL",
    ] {
        let n: i64 = sqlx::query_scalar(sql).fetch_one(&mut conn).await.unwrap();
        assert_eq!(n, 0, "{sql}");
    }
    // Each ledger row is one last slice of a batch attempt, charged to its job's creation day.
    let slices: Vec<(i64, i64, i64, i64, i64, i64, String)> = sqlx::query_as(
        "SELECT u.slice_start, u.started_at, u.slice_end, u.ended_at, u.last_slice, u.charge_day, u.kind \
         FROM usage_records u ORDER BY u.id",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap();
    assert_eq!(slices.len(), 3);
    for (start, started, end, ended, last, _, kind) in &slices {
        assert_eq!((start, end, *last, kind.as_str()), (started, ended, 1, "batch"));
    }
    let days_charged: Vec<i64> = slices.iter().map(|s| s.5).collect();
    // The lost job was created the day before; its row ended today but is charged to its creation day (H1).
    assert_eq!(days_charged, vec![DAY, DAY, DAY - 86_400]);

    // No dangling foreign key.
    let fk: Vec<(String, i64, String, i64)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(&mut conn)
        .await
        .unwrap();
    assert!(fk.is_empty(), "{fk:?}");
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(integrity, "ok");

    // The append-only triggers are in force again.
    for sql in [
        "UPDATE usage_records SET units = 0",
        "DELETE FROM usage_records",
        "DELETE FROM audit_events",
        "UPDATE audit_events SET kind = 'key_revoked' WHERE kind = 'key_created'",
        "UPDATE audit_events SET actor_device_id = 'dev_01ARZ3NDEKTSV4RRFFQ69G5FAV' WHERE kind = 'auth_failed'",
    ] {
        let err = sqlx::query(sql).execute(&mut conn).await.unwrap_err();
        assert!(err.to_string().contains("append-only"), "{sql}: {err}");
    }
    let err = sqlx::query("UPDATE jobs SET status = 'queued' WHERE status = 'succeeded'")
        .execute(&mut conn)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("immutable"), "{err}");
    // The aggregated failure can still be counted up.
    store::audit::record_auth_failure(&mut conn, fx.account, "unknown", datetime!(2026-11-05 01:00:30 UTC), 2)
        .await
        .unwrap();
    // AUTOINCREMENT goes on after the copied rows.
    let max_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM audit_events")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(max_seq, 2);

    // H1's numbers through the H2 code.
    let mut spent_after = Vec::new();
    for key in [fx.k1, fx.k2] {
        for (from, to) in days {
            let milli = spent_between(&mut conn, fx.account, Principal::Key(key), from, to)
                .await
                .unwrap();
            spent_after.push(i64::try_from(milli).unwrap());
        }
    }
    assert_eq!(spent_after, spent_before);
    let from = OffsetDateTime::from_unix_timestamp(DAY - 86_400).unwrap();
    let to = OffsetDateTime::from_unix_timestamp(DAY + 86_400).unwrap();
    for (group_by, before) in [UsageGroupBy::Job, UsageGroupBy::Node, UsageGroupBy::Key]
        .into_iter()
        .zip(&usage_before)
    {
        let q = UsageQuery {
            from,
            to,
            group_by,
            after: None,
            limit: 100,
        };
        let (rows, total) = usage_report(&mut conn, fx.account, fx.project, &q).await.unwrap();
        assert_eq!(&as_h1(&rows), before, "{group_by:?}");
        assert_eq!(total.attempts, 3);
        assert_eq!(total.units.milli(), 800 + 300 + 1500);
    }
}

#[tokio::test]
async fn principal_columns_take_exactly_one_principal() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = open(&dir).await;
    migrate(&mut conn, |_| true).await;
    let (account, project) = store::accounts::create_owner(&mut conn, OffsetDateTime::UNIX_EPOCH)
        .await
        .unwrap();
    let key = ApiKey::generate();
    let (a, p, k) = (account.to_string(), project.to_string(), key.key_id().to_string());
    exec(
        &mut conn,
        "INSERT INTO api_keys (key_id, account_id, project_id, secret_digest, scopes, created_at) \
         VALUES (?, ?, ?, ?, '[\"admin\"]', 0)",
        &[&k, &a, &p, &key.hash().to_stored()],
    )
    .await;
    let device = p2pc_proto::ids::DeviceId::generate().to_string();
    exec(
        &mut conn,
        "INSERT INTO devices (device_id, account_id, project_id, iroh_node_id, scopes, created_at) \
         VALUES (?, ?, ?, ?, '[\"admin\"]', 0)",
        &[&device, &a, &p, &"cd".repeat(32)],
    )
    .await;
    let job = |key: Option<&str>, dev: Option<&str>| {
        let (key, dev) = (key.map(str::to_string), dev.map(str::to_string));
        let (a, p) = (a.clone(), p.clone());
        async move {
            sqlx::query(
                "INSERT INTO jobs (job_id, account_id, project_id, key_id, device_id, spec, files_meta, spec_view, \
                 spec_hash, status, attempt, max_attempts, units_reserved, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, '{}', '[]', '{}', ?, 'queued', 1, 2, 0, 0, 0)",
            )
            .bind(JobId::generate().to_string())
            .bind(a)
            .bind(p)
            .bind(key)
            .bind(dev)
            .bind(format!("sha256:{}", "c".repeat(64)))
        }
    };
    assert!(job(Some(&k), Some(&device)).await.execute(&mut conn).await.is_err());
    assert!(job(None, None).await.execute(&mut conn).await.is_err());
    job(Some(&k), None).await.execute(&mut conn).await.unwrap();
    job(None, Some(&device)).await.execute(&mut conn).await.unwrap();
    for (key, dev) in [(Some(k.as_str()), Some(device.as_str())), (None, None)] {
        let r = sqlx::query(
            "INSERT INTO join_tokens (id, account_id, project_id, code_digest, created_by_key_id, \
             created_by_device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 0, 10)",
        )
        .bind(JoinTokenId::generate().to_string())
        .bind(&a)
        .bind(&p)
        .bind(format!("sha256:{}", "e".repeat(64)))
        .bind(key)
        .bind(dev)
        .execute(&mut conn)
        .await;
        assert!(r.is_err());
    }
    let r = sqlx::query(
        "INSERT INTO audit_events (event_id, at, account_id, actor_key_id, actor_device_id, kind) \
         VALUES (?, 0, ?, ?, ?, 'device_paired')",
    )
    .bind(p2pc_proto::ids::AuditEventId::generate().to_string())
    .bind(&a)
    .bind(&k)
    .bind(&device)
    .execute(&mut conn)
    .await;
    assert!(r.is_err(), "an event has at most one actor");
}
