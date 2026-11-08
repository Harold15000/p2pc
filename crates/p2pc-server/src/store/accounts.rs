// SPDX-License-Identifier: AGPL-3.0-only

//! Accounts and projects (spec §5). v0.1 is single-owner: one account, created by `init`, with a `default` project.

use p2pc_proto::ids::{AccountId, ProjectId};
use time::OffsetDateTime;

use super::{Conn, StoreError, parse_col, ts};

/// Name of the project every account starts with.
pub const DEFAULT_PROJECT: &str = "default";

/// Creates the owner account and its `default` project. Fails if an owner already exists.
pub async fn create_owner(conn: &mut Conn, now: OffsetDateTime) -> Result<(AccountId, ProjectId), StoreError> {
    let account = AccountId::generate();
    let project = ProjectId::generate();
    sqlx::query("INSERT INTO accounts (account_id, is_owner, created_at) VALUES (?, 1, ?)")
        .bind(account.to_string())
        .bind(ts(now))
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO projects (project_id, account_id, name, created_at) VALUES (?, ?, ?, ?)")
        .bind(project.to_string())
        .bind(account.to_string())
        .bind(DEFAULT_PROJECT)
        .bind(ts(now))
        .execute(&mut *conn)
        .await?;
    Ok((account, project))
}

/// The project of `account_id` called `name`.
pub async fn project_by_name(
    conn: &mut Conn,
    account_id: AccountId,
    name: &str,
) -> Result<Option<ProjectId>, StoreError> {
    let id: Option<String> = sqlx::query_scalar("SELECT project_id FROM projects WHERE account_id = ? AND name = ?")
        .bind(account_id.to_string())
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
    id.map(|s| parse_col(&s, "projects.project_id")).transpose()
}

/// The server owner's account. Failed authentications with an unknown key ID are recorded there, since no other
/// account can be attributed.
pub async fn owner(conn: &mut Conn) -> Result<Option<AccountId>, StoreError> {
    let id: Option<String> = sqlx::query_scalar("SELECT account_id FROM accounts WHERE is_owner = 1")
        .fetch_optional(&mut *conn)
        .await?;
    id.map(|s| parse_col(&s, "accounts.account_id")).transpose()
}
