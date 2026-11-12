// SPDX-License-Identifier: AGPL-3.0-only

//! What the template bundle and the template launch keep in the database (H2 spec §7.6, §13): the anti-rollback
//! high-water mark of the bundle (`template_bundle_state`, one row for the hub) and the running instance of a
//! `singleton` template.

use p2pc_proto::ids::{AccountId, JobId, ProjectId};
use time::OffsetDateTime;

use super::{Conn, StoreError, parse_col, ts};

/// The high-water mark: the highest bundle the hub has ever loaded (H2 §7.6 "High-water mark").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    /// Its `bundle_version`.
    pub bundle_version: u64,
    /// The SHA-256 of its bytes, 64 lowercase hex.
    pub sha256: String,
}

/// The mark, or `None` for a hub that has never loaded a bundle. Hub-wide: the bundle belongs to the hub, not to an
/// account.
pub async fn mark(conn: &mut Conn) -> Result<Option<Mark>, StoreError> {
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT bundle_version, sha256 FROM template_bundle_state WHERE id = 1")
            .fetch_optional(&mut *conn)
            .await?;
    row.map(|(version, sha256)| {
        Ok(Mark {
            bundle_version: u64::try_from(version)
                .map_err(|_| StoreError::Corrupt("template_bundle_state.bundle_version"))?,
            sha256,
        })
    })
    .transpose()
}

/// Raises the mark to `to`. It only ever goes up: a mark at or above `to.bundle_version` stays as it is, with its own
/// SHA-256. Returns whether it was raised.
pub async fn raise_mark(conn: &mut Conn, to: &Mark, now: OffsetDateTime) -> Result<bool, StoreError> {
    let version =
        i64::try_from(to.bundle_version).map_err(|_| StoreError::Corrupt("template_bundle_state.bundle_version"))?;
    let done = sqlx::query(
        "INSERT INTO template_bundle_state (id, bundle_version, sha256, loaded_at) VALUES (1, ?1, ?2, ?3) \
         ON CONFLICT (id) DO UPDATE SET bundle_version = ?1, sha256 = ?2, loaded_at = ?3 \
         WHERE template_bundle_state.bundle_version < ?1",
    )
    .bind(version)
    .bind(&to.sha256)
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// The instance of the `singleton` template `template_id` in `account_id` and `project_id` that is `queued`,
/// `assigned` or `running` (H2 §7.6 "Launch"), whoever launched it: the oldest, if a hub that did not know the
/// template as a singleton left more than one.
pub async fn live_instance(
    conn: &mut Conn,
    account_id: AccountId,
    project_id: ProjectId,
    template_id: &str,
) -> Result<Option<JobId>, StoreError> {
    let id: Option<String> = sqlx::query_scalar(
        "SELECT job_id FROM jobs \
         WHERE account_id = ? AND project_id = ? AND template_id = ? AND status IN ('queued', 'assigned', 'running') \
         ORDER BY created_at, job_id LIMIT 1",
    )
    .bind(account_id.to_string())
    .bind(project_id.to_string())
    .bind(template_id)
    .fetch_optional(&mut *conn)
    .await?;
    id.map(|id| parse_col(&id, "jobs.job_id")).transpose()
}
