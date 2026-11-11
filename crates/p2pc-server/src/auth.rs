// SPDX-License-Identifier: AGPL-3.0-only

//! Authentication (spec §5, H2 §5.5) and scope extractors.
//!
//! A request is authenticated by an **API key** or by a **paired device**, never both:
//! - on the TCP REST listener and on `p2pc/http/1`, by API key only ([`require_api_key`]). It follows the fixed order
//!   of §5: parse the `Authorization: Bearer p2pc_sk_…` header with `p2pc-proto`, look the `key_id` up, verify SHA-256
//!   of the secret in constant time, then check `expires_at` and `revoked_at`. Every failure gives the same `401`
//!   body. On a lookup miss a dummy constant-time comparison runs, so an unknown key ID costs the same as a wrong
//!   secret;
//! - on `p2pc/device/1` (served in-process by T2-11), by the device whose NodeId iroh authenticated
//!   ([`require_device`]): the transport attaches a [`DeviceConnection`] request extension, which no header can
//!   create (SI-H2-3), and the device's row is re-read on every request. A device request that carries an
//!   `Authorization` header is refused with `400 unexpected_authorization`.
//!
//! There is no bypass of any kind, including for requests from localhost.

use std::marker::PhantomData;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{Principal as PrincipalId, Scope};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::device::UNEXPECTED_AUTHORIZATION;
use p2pc_proto::ids::{AccountId, DeviceId, KeyId, ProjectId};
use p2pc_proto::units::Units;
use p2pc_proto::validate::PrincipalLimits;

use crate::app::AppState;
use crate::error::ApiError;
use crate::store::{self, StoreError};

/// The authenticated caller, attached to the request by the middleware: an API key or a paired device (H2 §5.5).
/// Ownership, scopes, caps and image allowlists come from the principal's own row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Account of the principal. Every store call is filtered by it (SI-7).
    pub account_id: AccountId,
    /// Project the principal acts in.
    pub project_id: ProjectId,
    /// Who it is: `Key{key_id}` or `Device{device_id}`.
    pub id: PrincipalId,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Daily cap.
    pub daily_unit_cap: Option<Units>,
    /// Image globs; `None` allows every image.
    pub allowed_images: Option<Vec<String>>,
    /// The label, if any (shown by `GET /v1/whoami`).
    pub label: Option<String>,
    /// The expiry, if any (shown by `GET /v1/whoami`).
    pub expires_at: Option<time::OffsetDateTime>,
    /// A device's blob quota in MiB (keys have none).
    pub blobs_quota_mb: Option<u64>,
}

impl Principal {
    /// Whether the principal has `scope`. `admin` implies every scope.
    #[must_use]
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&Scope::Admin) || self.scopes.contains(&scope)
    }

    /// Whether the principal has the `admin` scope.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.scopes.contains(&Scope::Admin)
    }

    /// The key, when the principal is an API key.
    #[must_use]
    pub fn key_id(&self) -> Option<KeyId> {
        self.id.key_id()
    }

    /// The device, when the principal is a device.
    #[must_use]
    pub fn device_id(&self) -> Option<DeviceId> {
        self.id.device_id()
    }

    /// Its power, for the no-escalation rule (H1 §5, H2 §5.2).
    #[must_use]
    pub fn limits(&self) -> PrincipalLimits {
        PrincipalLimits {
            scopes: self.scopes.clone(),
            daily_unit_cap: self.daily_unit_cap,
            allowed_images: self.allowed_images.clone(),
            expires_at: self.expires_at,
            blobs_quota_mb: self.blobs_quota_mb,
        }
    }

    /// The principal of an API key row.
    #[must_use]
    pub fn of_key(row: store::keys::KeyRow) -> Self {
        Self {
            account_id: row.account_id,
            project_id: row.project_id,
            id: PrincipalId::Key(row.key_id),
            scopes: row.scopes,
            daily_unit_cap: row.daily_unit_cap,
            allowed_images: row.allowed_images,
            label: row.label,
            expires_at: row.expires_at,
            blobs_quota_mb: None,
        }
    }

    /// The principal of a device row.
    #[must_use]
    pub fn of_device(row: store::devices::DeviceRow) -> Self {
        Self {
            account_id: row.account_id,
            project_id: row.project_id,
            id: PrincipalId::Device(row.device_id),
            scopes: row.scopes,
            daily_unit_cap: row.daily_unit_cap,
            allowed_images: row.allowed_images,
            label: row.label,
            expires_at: row.expires_at,
            blobs_quota_mb: row.blobs_quota_mb,
        }
    }
}

/// The request extension that makes a request a **device** request: attached by the `p2pc/device/1` transport
/// (T2-11) to every request of a stream whose peer passed the device check, after iroh's TLS authenticated its NodeId.
///
/// It is a Rust value, never parsed from the request: no header, query parameter or body can produce one (SI-H2-3).
/// Only the device router ([`crate::app::device_router`]) reads it; the TCP router ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceConnection {
    /// The device whose NodeId the transport authenticated.
    pub device_id: DeviceId,
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
    Ok(Outcome::Ok(Principal::of_key(row)))
}

/// Re-checks the caller at the point of use (spec §5 "Re-checked at the point of use", H2 §5.4).
///
/// Every operation that grants or removes power (keys, join tokens, pairing tickets, devices, join requests)
/// calls this **inside its `BEGIN IMMEDIATE` transaction, before changing anything**. It reloads the caller's row, an
/// API key or a device: if it has been revoked or has expired since the middleware authenticated the request, or no
/// longer exists, the answer is the same `401` as every other auth failure, and the caller drops the transaction so
/// nothing changes. A revocation therefore also stops a request that is already in flight.
///
/// Returns the fresh principal, so the operation can apply the caller's current limits (for example no-escalation).
///
/// A refusal is also queued as an `auth_failed` audit event of the caller, through the same off-path queue as every
/// other failed authentication. `now` is the caller's single post-lock reading, and stamps the event.
pub async fn recheck_caller(
    conn: &mut store::Conn,
    state: &AppState,
    principal: &Principal,
    now: time::OffsetDateTime,
) -> Result<Principal, ApiError> {
    let fresh = reload(conn, principal.account_id, principal.id, now).await?;
    match fresh {
        Some(p) => Ok(p),
        None => {
            state
                .auth_failures
                .record(principal.account_id, subject_of(principal.id), now);
            Err(ApiError::unauthenticated())
        }
    }
}

/// The live principal `id` of `account_id` at `now`, from its row; `None` when it is revoked, expired or gone.
pub async fn reload(
    conn: &mut store::Conn,
    account_id: AccountId,
    id: PrincipalId,
    now: time::OffsetDateTime,
) -> Result<Option<Principal>, StoreError> {
    Ok(match id {
        PrincipalId::Key(k) => store::keys::get(conn, account_id, k)
            .await?
            .filter(|row| row.revoked_at.is_none() && !row.is_expired(now))
            .map(Principal::of_key),
        PrincipalId::Device(d) => store::devices::get(conn, account_id, d)
            .await?
            .filter(|row| row.is_live(now))
            .map(Principal::of_device),
    })
}

/// The `subject_id` of an `auth_failed` row for a principal: its key ID or device ID.
fn subject_of(id: PrincipalId) -> String {
    match id {
        PrincipalId::Key(k) => k.to_string(),
        PrincipalId::Device(d) => d.to_string(),
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

/// Middleware of the device router (H2 §5.5, §6.3): authenticates a request of a `p2pc/device/1` stream by the
/// [`DeviceConnection`] its transport attached, and attaches the device's [`Principal`].
///
/// - A request with an `Authorization` header gets `400 unexpected_authorization`: mixing two principals on one
///   request is refused, so a confused client cannot run as an API key over a device connection.
/// - The device is re-read on every request: a revoked or expired device (or a missing extension) gets `401`, the
///   same answer for every cause. The transport also closes its connections (the liveness sweep, §5.5).
pub async fn require_device(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    if req.headers().contains_key(AUTHORIZATION) {
        return ApiError::bad_request(
            UNEXPECTED_AUTHORIZATION,
            "A device request must not carry an Authorization header.",
        )
        .into_response();
    }
    let Some(conn) = req.extensions().get::<DeviceConnection>().copied() else {
        return ApiError::unauthenticated().into_response();
    };
    match authenticate_device(&state, conn.device_id).await {
        Ok(Some(principal)) => {
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        Ok(None) => ApiError::unauthenticated().into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn authenticate_device(state: &AppState, id: DeviceId) -> Result<Option<Principal>, StoreError> {
    let now = state.clock.now();
    let mut conn = state.db.acquire().await?;
    let Some(row) = store::devices::by_id_for_auth(&mut conn, id).await? else {
        return Ok(None);
    };
    if !row.is_live(now) {
        audit_failure(state, Some(row.account_id), row.device_id.to_string());
        return Ok(None);
    }
    if store::devices::last_seen_is_stale(row.last_seen_at, now)
        && let Err(e) = store::devices::touch_last_seen(&mut conn, row.account_id, row.device_id, now).await
    {
        tracing::debug!(error = %e, device_id = %row.device_id, "cannot record last_seen_at");
    }
    Ok(Some(Principal::of_device(row)))
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
/// The `nodes:invite` scope (or `admin`, H2 §5.4).
#[derive(Debug)]
pub struct NodesInviteScope;

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
impl RequiredScope for NodesInviteScope {
    const SCOPE: Option<Scope> = Some(Scope::NodesInvite);
}

/// Extractor: the request's [`Principal`], which must have scope `S`. `401` without a principal (the route is not
/// behind the middleware), `403 forbidden` without the scope.
#[derive(Debug)]
pub struct Authorized<S> {
    /// The caller.
    pub principal: Principal,
    scope: PhantomData<S>,
}

/// Any authenticated principal.
pub type AnyKey = Authorized<AnyScope>;
/// An `admin` principal.
pub type AdminKey = Authorized<AdminScope>;
/// A principal with `jobs:read` (or `admin`).
pub type JobsReadKey = Authorized<JobsReadScope>;
/// A principal with `jobs:write` (or `admin`).
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
