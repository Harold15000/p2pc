// SPDX-License-Identifier: AGPL-3.0-only

//! The hub's own settings (H2 spec §7.3, §13): one row of `hub_settings` at most, which the first
//! `PATCH /v1/server` creates. They are the hub's, not a tenant's: `GET /v1/server` shows them to any principal.

use time::OffsetDateTime;

use super::{Conn, StoreError, ts};

/// The hub's display name, if an `admin` set one.
pub async fn hub_name(conn: &mut Conn) -> Result<Option<String>, StoreError> {
    let name: Option<Option<String>> = sqlx::query_scalar("SELECT hub_name FROM hub_settings WHERE id = 1")
        .fetch_optional(&mut *conn)
        .await?;
    Ok(name.flatten())
}

/// Sets the hub's display name (the caller validated it).
pub async fn set_hub_name(conn: &mut Conn, name: &str, now: OffsetDateTime) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO hub_settings (id, hub_name, updated_at) VALUES (1, ?1, ?2) \
         ON CONFLICT (id) DO UPDATE SET hub_name = ?1, updated_at = ?2",
    )
    .bind(name)
    .bind(ts(now))
    .execute(&mut *conn)
    .await?;
    Ok(())
}
