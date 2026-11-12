// SPDX-License-Identifier: AGPL-3.0-only

//! The node-local volumes the hub knows of (H2 spec §6.1 `VolumeReport`, §7.3, §11.3): the latest report of each
//! node, in `volume_reports`.
//!
//! A report is the node's whole list, so storing one replaces the node's rows. What the API shows is filtered by the
//! caller's account through the node (SI-7). `max_mb` is not in a report: it is the limit of the job that mounted the
//! volume on that node last, read from the stored JobSpec view.

use p2pc_proto::ids::{AccountId, JobId, LeaseId, NodeId};
use p2pc_proto::protocol;
use time::OffsetDateTime;

use super::{Conn, StoreError, from_ts_opt, parse_col, ts};

/// One volume of a node, as `GET /v1/volumes` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRow {
    /// The node that holds it.
    pub node_id: NodeId,
    /// Its name, as in the JobSpec.
    pub name: String,
    /// Its measured size, in MiB.
    pub size_mb: u64,
    /// The `max_mb` of the job that mounted it on this node last; 0 when the hub knows no such job.
    pub max_mb: u64,
    /// When a lease last used it.
    pub last_used_at: Option<OffsetDateTime>,
    /// The job whose lease holds it now, by the node's last report.
    pub in_use_by: Option<JobId>,
}

/// Position after which a volume list continues: `(node_id, name)` of the last volume returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeCursor {
    /// The node of the last volume.
    pub node_id: NodeId,
    /// Its name.
    pub name: String,
}

impl VolumeCursor {
    /// The cursor after `row`.
    #[must_use]
    pub fn after(row: &VolumeRow) -> Self {
        Self {
            node_id: row.node_id,
            name: row.name.clone(),
        }
    }

    /// The opaque text form, `<node_id>.<name>`. A node ID has no dot, so the first one separates them.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}.{}", self.node_id, self.name)
    }

    /// Parses [`VolumeCursor::encode`]'s output.
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let (node, name) = text.split_once('.')?;
        Some(Self {
            node_id: node.parse().ok()?,
            name: (!name.is_empty()).then(|| name.to_string())?,
        })
    }
}

fn mib(value: i64, column: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(column))
}

/// Replaces the stored report of `node_id` with `volumes` (protocol side: the node is the one iroh authenticated,
/// and the caller checked the names).
///
/// `in_use_by` is kept only when it names a lease of this node: the column references `leases`, and a node says
/// nothing about leases that are not its own.
pub async fn replace_report(
    conn: &mut Conn,
    node_id: NodeId,
    volumes: &[protocol::VolumeInfo],
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM volume_reports WHERE node_id = ?")
        .bind(node_id.to_string())
        .execute(&mut *conn)
        .await?;
    for volume in volumes {
        let holder = match volume.in_use_by {
            Some(lease_id) => own_lease(conn, node_id, lease_id).await?,
            None => None,
        };
        sqlx::query(
            "INSERT INTO volume_reports (node_id, name, size_mb, last_used_at, in_use_by_lease_id, reported_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(node_id.to_string())
        .bind(&volume.name)
        // A size no disk has is stored as the largest the column holds.
        .bind(i64::try_from(volume.size_mb).unwrap_or(i64::MAX))
        .bind(ts(volume.last_used_at))
        .bind(holder)
        .bind(ts(now))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// `lease_id` as text, if it is a lease of `node_id`.
async fn own_lease(conn: &mut Conn, node_id: NodeId, lease_id: LeaseId) -> Result<Option<String>, StoreError> {
    let found: Option<String> = sqlx::query_scalar("SELECT id FROM leases WHERE id = ? AND node_id = ?")
        .bind(lease_id.to_string())
        .bind(node_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    Ok(found)
}

type Raw = (String, String, i64, Option<i64>, Option<String>, Option<i64>);

fn decode(raw: Raw) -> Result<VolumeRow, StoreError> {
    let (node_id, name, size_mb, last_used_at, in_use_by, max_mb) = raw;
    Ok(VolumeRow {
        node_id: parse_col(&node_id, "volume_reports.node_id")?,
        name,
        size_mb: mib(size_mb, "volume_reports.size_mb")?,
        max_mb: mib(max_mb.unwrap_or(0), "jobs.spec_view.volumes.max_mb")?,
        last_used_at: from_ts_opt(last_used_at, "volume_reports.last_used_at")?,
        in_use_by: in_use_by.map(|job| parse_col(&job, "leases.job_id")).transpose()?,
    })
}

/// The columns of a [`VolumeRow`], for `volume_reports r` joined with its node `n`: the holder's job, and the
/// `max_mb` of the latest job of the node's account that mounted a volume of that name on that node. Only a service
/// or a template job can have volumes (H2 §7.1), so only those are looked at.
macro_rules! select_volumes {
    ($tail:literal) => {
        concat!(
            "SELECT r.node_id, r.name, r.size_mb, r.last_used_at, \
                (SELECT l.job_id FROM leases l WHERE l.id = r.in_use_by_lease_id), \
                (SELECT json_extract(v.value, '$.max_mb') \
                   FROM leases l JOIN jobs j ON j.job_id = l.job_id, json_each(j.spec_view, '$.volumes') v \
                  WHERE l.node_id = r.node_id AND j.account_id = n.account_id \
                    AND (j.kind = 'service' OR j.template_id IS NOT NULL) \
                    AND json_extract(v.value, '$.name') = r.name \
                  ORDER BY l.offered_at_ms DESC, l.id DESC LIMIT 1) \
             FROM volume_reports r JOIN nodes n ON n.id = r.node_id ",
            $tail
        )
    };
}

/// The volumes of the live nodes of `account_id`, by node and name, after `after`, at most `limit`.
pub async fn list(
    conn: &mut Conn,
    account_id: AccountId,
    after: Option<&VolumeCursor>,
    limit: u32,
) -> Result<Vec<VolumeRow>, StoreError> {
    let (node, name) = after.map_or((None, None), |c| (Some(c.node_id.to_string()), Some(c.name.clone())));
    let rows: Vec<Raw> = sqlx::query_as(select_volumes!(
        "WHERE n.account_id = ?1 AND n.deleted_at IS NULL \
           AND (?2 IS NULL OR r.node_id > ?2 OR (r.node_id = ?2 AND r.name > ?3)) \
         ORDER BY r.node_id, r.name LIMIT ?4"
    ))
    .bind(account_id.to_string())
    .bind(node)
    .bind(name)
    .bind(i64::from(limit))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(decode).collect()
}

/// The volume `name` of the live node `node_id` of `account_id`, if the node reported it.
pub async fn get(
    conn: &mut Conn,
    account_id: AccountId,
    node_id: NodeId,
    name: &str,
) -> Result<Option<VolumeRow>, StoreError> {
    let row: Option<Raw> = sqlx::query_as(select_volumes!(
        "WHERE n.account_id = ? AND n.deleted_at IS NULL AND r.node_id = ? AND r.name = ?"
    ))
    .bind(account_id.to_string())
    .bind(node_id.to_string())
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(decode).transpose()
}

/// Whether a lease of `node_id` that still holds its execution (offered, accepted or running, or ended and not yet
/// confirmed dead) belongs to a job with a volume `name`: the volume is, or is about to be, mounted, whatever the
/// node's last report says.
pub async fn held_by_lease(conn: &mut Conn, node_id: NodeId, name: &str) -> Result<bool, StoreError> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM leases l JOIN jobs j ON j.job_id = l.job_id, json_each(j.spec_view, '$.volumes') v \
         WHERE l.node_id = ? AND l.confirmed_dead_at IS NULL AND json_extract(v.value, '$.name') = ? LIMIT 1",
    )
    .bind(node_id.to_string())
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.is_some())
}
