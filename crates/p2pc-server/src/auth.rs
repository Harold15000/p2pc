// SPDX-License-Identifier: AGPL-3.0-only

//! API key authentication (spec §5) and scope extractors.
//!
//! The middleware follows the fixed order of §5: parse the `Authorization: Bearer p2pc_sk_…` header with
//! `p2pc-proto`, look the `key_id` up, verify SHA-256 of the secret in constant time, then check `expires_at` and
//! `revoked_at`. Every failure gives the same `401` body. On a lookup miss a dummy constant-time comparison runs, so
//! an unknown key ID costs the same as a wrong secret.
//!
//! There is no bypass of any kind, including for requests from localhost.

use std::marker::PhantomData;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::Scope;
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{AccountId, KeyId, ProjectId};
use p2pc_proto::units::Units;

use crate::app::AppState;
use crate::error::ApiError;
use crate::store::{self, StoreError};

/// The authenticated caller, attached to the request by the middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Account that owns the key. Every store call is filtered by it (SI-7).
    pub account_id: AccountId,
    /// Project the key acts in.
    pub project_id: ProjectId,
    /// The key's public ID.
    pub key_id: KeyId,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Daily cap of the key.
    pub daily_unit_cap: Option<Units>,
    /// Image globs of the key; `None` allows every image.
    pub allowed_images: Option<Vec<String>>,
    /// The key's label, if any (shown by `GET /v1/whoami`).
    pub label: Option<String>,
    /// The key's expiry, if any (shown by `GET /v1/whoami`).
    pub expires_at: Option<time::OffsetDateTime>,
}

impl Principal {
    /// Whether the key has `scope`. `admin` implies every scope.
    #[must_use]
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&Scope::Admin) || self.scopes.contains(&scope)
    }
}

/// What the middleware found. Never carries the presented secret.
enum Outcome {
    Ok(Principal),
    /// No `Authorization` header: not an attempt, so not audited.
    Missing,
    /// A failed attempt, recorded in `account_id`'s audit log under `subject`.
    Failed {
        account_id: Option<AccountId>,
        subject: String,
    },
}

/// Extracts the token from `Authorization: Bearer <token>` (the scheme is case-insensitive).
fn bearer(headers: &HeaderMap) -> Option<Result<&str, ()>> {
    let value: &HeaderValue = headers.get(AUTHORIZATION)?;
    let Ok(text) = value.to_str() else {
        return Some(Err(()));
    };
    let Some((scheme, token)) = text.split_once(' ') else {
        return Some(Err(()));
    };
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Some(Err(()));
    }
    Some(Ok(token))
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Outcome, StoreError> {
    let now = state.clock.now();
    let token = match bearer(headers) {
        None => return Ok(Outcome::Missing),
        Some(Err(())) => None,
        Some(Ok(token)) => Some(token),
    };
    // 1. Parse. A malformed token is refused before a pool connection is taken, so garbage never queues behind
    // the pool.
    let Some(key) = token.and_then(|t| ApiKey::parse(t).ok()) else {
        return Ok(Outcome::Failed {
            account_id: None,
            subject: store::audit::UNKNOWN_SUBJECT.to_string(),
        });
    };
    let mut conn = state.db.acquire().await?;
    // 2. Look up the key ID.
    let row = store::keys::lookup_for_auth(&mut conn, key.key_id()).await?;
    // 3. Verify the secret in constant time; on a miss, compare against a dummy digest so the work is the same.
    let Some(row) = row else {
        std::hint::black_box(key.verify(&state.dummy_digest));
        return Ok(Outcome::Failed {
            account_id: None,
            subject: store::audit::UNKNOWN_SUBJECT.to_string(),
        });
    };
    let secret_ok = key.verify(&row.digest);
    // 4. Expiry and revocation, only after the secret.
    if !secret_ok || row.is_expired(now) || row.revoked_at.is_some() {
        return Ok(Outcome::Failed {
            account_id: Some(row.account_id),
            subject: row.key_id.to_string(),
        });
    }
    // Bookkeeping, best effort: a request that authenticated correctly never fails because this write did.
    if store::keys::last_used_is_stale(row.last_used_at, now)
        && let Err(e) = store::keys::touch_last_used(&mut conn, row.account_id, row.key_id, now).await
    {
        tracing::debug!(error = %e, key_id = %row.key_id, "cannot record last_used_at");
    }
    Ok(Outcome::Ok(Principal {
        account_id: row.account_id,
        project_id: row.project_id,
        key_id: row.key_id,
        scopes: row.scopes,
        daily_unit_cap: row.daily_unit_cap,
        allowed_images: row.allowed_images,
        label: row.label,
        expires_at: row.expires_at,
    }))
}

/// Re-checks the caller at the point of use (spec §5 "Re-checked at the point of use").
///
/// Every operation that grants or removes power (creating or revoking keys today; join tokens in T05, and any
/// later one) calls this **inside its `BEGIN IMMEDIATE` transaction, before changing anything**. It reloads the
/// caller's row: if the key has been revoked or has expired since the middleware authenticated the request, or no
/// longer exists, the answer is the same `401` as every other auth failure, and the caller drops the transaction so
/// nothing changes. A revocation therefore also stops a request that is already in flight.
///
/// Returns the fresh row, so the operation can apply the caller's current limits (for example no-escalation).
///
/// A refusal is also queued as an `auth_failed` audit event of the caller's key, through the same off-path queue as
/// every other failed authentication (it never waits for the database; architect ruling after T03): an attempt made
/// with a key that has just been revoked is exactly what the owner wants to see. `now` is the caller's single
/// post-lock reading, and stamps the event.
pub async fn recheck_caller(
    conn: &mut store::Conn,
    state: &AppState,
    principal: &Principal,
    now: time::OffsetDateTime,
) -> Result<store::keys::KeyRow, ApiError> {
    match store::keys::get(conn, principal.account_id, principal.key_id).await? {
        Some(row) if row.revoked_at.is_none() && !row.is_expired(now) => Ok(row),
        _ => {
            state
                .auth_failures
                .record(principal.account_id, principal.key_id.to_string(), now);
            Err(ApiError::unauthenticated())
        }
    }
}

/// Queues a failed attempt for the audit log, without waiting (see `audit_queue`). Unknown key IDs and malformed
/// headers go to the owner's log, the only account v0.1 has; the owner is cached in the state.
fn audit_failure(state: &AppState, account_id: Option<AccountId>, subject: String) {
    if let Some(account) = account_id.or(state.owner_account) {
        state.auth_failures.record(account, subject, state.clock.now());
    }
}

/// Middleware: authenticates the request and attaches its [`Principal`], or answers `401`.
pub async fn require_api_key(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    match authenticate(&state, req.headers()).await {
        Ok(Outcome::Ok(principal)) => {
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        Ok(Outcome::Missing) => ApiError::unauthenticated().into_response(),
        Ok(Outcome::Failed { account_id, subject }) => {
            audit_failure(&state, account_id, subject);
            ApiError::unauthenticated().into_response()
        }
        Err(e) => ApiError::from(e).into_response(),
    }
}

/// A scope requirement for [`Authorized`].
pub trait RequiredScope: Send + Sync + 'static {
    /// The scope, or `None` for "any valid key".
    const SCOPE: Option<Scope>;
}

/// Any valid key.
#[derive(Debug)]
pub struct AnyScope;
/// The `admin` scope.
#[derive(Debug)]
pub struct AdminScope;
/// The `jobs:read` scope (or `admin`).
#[derive(Debug)]
pub struct JobsReadScope;
/// The `jobs:write` scope (or `admin`).
#[derive(Debug)]
pub struct JobsWriteScope;
/// The `nodes:read` scope (or `admin`).
#[derive(Debug)]
pub struct NodesReadScope;
/// The `nodes:write` scope (or `admin`).
#[derive(Debug)]
pub struct NodesWriteScope;

impl RequiredScope for AnyScope {
    const SCOPE: Option<Scope> = None;
}
impl RequiredScope for AdminScope {
    const SCOPE: Option<Scope> = Some(Scope::Admin);
}
impl RequiredScope for JobsReadScope {
    const SCOPE: Option<Scope> = Some(Scope::JobsRead);
}
impl RequiredScope for JobsWriteScope {
    const SCOPE: Option<Scope> = Some(Scope::JobsWrite);
}
impl RequiredScope for NodesReadScope {
    const SCOPE: Option<Scope> = Some(Scope::NodesRead);
}
impl RequiredScope for NodesWriteScope {
    const SCOPE: Option<Scope> = Some(Scope::NodesWrite);
}

/// Extractor: the request's [`Principal`], which must have scope `S`. `401` without a principal (the route is not
/// behind the middleware), `403 forbidden` without the scope.
#[derive(Debug)]
pub struct Authorized<S> {
    /// The caller.
    pub principal: Principal,
    scope: PhantomData<S>,
}

/// Any authenticated key.
pub type AnyKey = Authorized<AnyScope>;
/// An `admin` key.
pub type AdminKey = Authorized<AdminScope>;
/// A key with `jobs:read` (or `admin`).
pub type JobsReadKey = Authorized<JobsReadScope>;
/// A key with `jobs:write` (or `admin`).
pub type JobsWriteKey = Authorized<JobsWriteScope>;

impl<S: RequiredScope, St: Send + Sync> FromRequestParts<St> for Authorized<S> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Self::Rejection> {
        let principal = parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or_else(ApiError::unauthenticated)?;
        if let Some(scope) = S::SCOPE
            && !principal.has_scope(scope)
        {
            return Err(ApiError::forbidden(scope));
        }
        Ok(Self {
            principal,
            scope: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(v: &[u8]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_bytes(v).unwrap());
        h
    }

    #[test]
    fn bearer_parsing() {
        assert!(bearer(&HeaderMap::new()).is_none());
        assert_eq!(bearer(&headers(b"Bearer abc")), Some(Ok("abc")));
        assert_eq!(bearer(&headers(b"BEARER abc")), Some(Ok("abc")));
        for bad in [
            &b"Bearer"[..],
            b"Bearer ",
            b"Basic abc",
            b"abc",
            b"Bearer\tabc",
            b"Bearer \xff",
        ] {
            assert_eq!(bearer(&headers(bad)), Some(Err(())), "{bad:?}");
        }
        // Extra spaces are kept in the token, which then fails to parse as a key.
        assert_eq!(bearer(&headers(b"Bearer  abc")), Some(Ok(" abc")));
    }
}
