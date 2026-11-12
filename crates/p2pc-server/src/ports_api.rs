// SPDX-License-Identifier: AGPL-3.0-only

//! Service ports (H2 spec §7.4): `POST /v1/jobs/{id}/ports/{port}/connect`, an HTTP/1.1 upgrade to a connection
//! into a port of a running service.
//!
//! **One code path for every client** (SI-H2-5): devices over `p2pc/device/1`, API keys over the TCP listener and
//! `p2pc/http/1` all reach [`connect`], and one function decides who reaches which job
//! ([`crate::jobs_api::visible_job`] with [`JobRoute::Port`]): `services:connect` for any service of the caller's
//! project, `templates:launch` for a template service of the caller's template view (§5.5), and `404` for anything
//! else, as for a job that does not exist.
//!
//! **Template services are filtered** for every principal that is not `admin`, whether it came through the template
//! view or through `services:connect` (a developer device): the upgraded connection is never spliced into the port.
//! The hub reads one HTTP request from it and forwards it only if the template's `allowed_routes` allow it
//! ([`filter`], [`crate::gateway::ports`]). Raw connections to a template service are for `admin` only; to a
//! service that came from no template they stay available to every principal with `services:connect`.
//!
//! **Before the upgrade** the answer is a problem like any other: `404`, `409 service_not_running`,
//! `409 service_not_ready`, `422 port_not_exposed`, `429 too_many_connections`, `502 node_unreachable`. For a raw
//! connection the stream to the node is opened before the `101`, so `502` comes before the upgrade. For a filtered
//! connection the stream is opened only once the request passed the filter, so that a refused request opens nothing
//! on the node; a node that cannot be reached is then answered `502` inside the upgraded connection, like the
//! filter's own `400`, `403`, `413` and `431`.

pub mod filter;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, Version, header};
use axum::response::Response;
use hyper_util::rt::TokioIo;
use p2pc_proto::api::{H2ErrorCode, JobKind, JobStatus, Problem, ServiceHealth};
use p2pc_proto::ids::JobId;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::app::AppState;
use crate::auth::{AnyKey, Authorized, Principal, reload};
use crate::error::ApiError;
use crate::extract::ApiQuery;
use crate::gateway::ports::{self, Accepted, Plan};
use crate::jobs_api::{JobRoute, job_visibility, visible_job};
use crate::store::jobs::{self, JobRow};
use crate::store::leases;

/// The protocol a port connection upgrades to: `Upgrade: p2pc-port/1`.
pub const UPGRADE_PROTOCOL: &str = "p2pc-port/1";
/// The `code` of the `400` for a connect request that is not an upgrade to [`UPGRADE_PROTOCOL`].
pub const UPGRADE_REQUIRED: &str = "upgrade_required";

/// `wait_ready`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ConnectParams {
    /// With `true`, a service that is still `starting` is waited for, up to 30 s, instead of answered
    /// `409 service_not_ready`.
    pub wait_ready: Option<bool>,
}

/// Whether `headers` ask for the upgrade of H2 §7.4: `Connection: Upgrade` and `Upgrade: p2pc-port/1`, with no
/// body.
fn asks_for_port_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers.get_all(header::CONNECTION).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|v| v.split(',').any(|option| option.trim().eq_ignore_ascii_case("upgrade")))
    });
    let mut protocols = headers.get_all(header::UPGRADE).iter();
    let protocol = matches!(
        (protocols.next(), protocols.next()),
        (Some(value), None) if value.to_str().is_ok_and(|v| v.trim().eq_ignore_ascii_case(UPGRADE_PROTOCOL))
    );
    let no_body = !headers.contains_key(header::TRANSFER_ENCODING)
        && headers
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .all(|value| value.as_bytes() == b"0");
    connection_upgrade && protocol && no_body
}

fn port_not_exposed() -> ApiError {
    ApiError::unprocessable(
        H2ErrorCode::PortNotExposed.as_str(),
        "The service does not expose this port: it is not in its `service.ports`.",
    )
}

fn service_not_ready() -> ApiError {
    ApiError::conflict(
        H2ErrorCode::ServiceNotReady.as_str(),
        "The service is still starting; retry, or connect with `?wait_ready=true`.",
    )
}

/// The port of the path, if `job` is a service that lists it (SI-H2-5: "a listed port").
fn listed_port(job: &JobRow, port: &str) -> Result<u16, ApiError> {
    // Digits only: `+80` and the like are not a port of anything.
    let number = port
        .parse::<u16>()
        .ok()
        .filter(|n| *n != 0 && port.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(port_not_exposed)?;
    let listed = job.spec_view.kind == JobKind::Service
        && job
            .spec_view
            .service
            .as_ref()
            .is_some_and(|service| service.ports.iter().any(|p| p.port == u32::from(number)));
    if listed { Ok(number) } else { Err(port_not_exposed()) }
}

/// Waits until the service `job` runs and its health is no longer `starting` (H2 §7.4).
///
/// Without `wait`, a service that is still starting gets `409 service_not_ready` at once. With it, the hub looks
/// again every `ready_poll`, for at most `ready_wait` on its own clock, and never longer than that in real time. A
/// service that is not `running`, now or while it is waited for, gets `409 service_not_running`.
async fn ready(state: &AppState, p: &Principal, job_id: JobId, wait: bool) -> Result<(), ApiError> {
    let limits = state.ports.limits();
    let deadline = state.clock.now() + limits.ready_wait;
    let real_deadline = tokio::time::Instant::now() + limits.ready_wait.unsigned_abs();
    loop {
        {
            let mut conn = state.db.acquire().await?;
            let running = jobs::get(&mut conn, p.account_id, p.project_id, job_id)
                .await?
                .is_some_and(|job| job.status == JobStatus::Running);
            if !running {
                return Err(ports::service_not_running());
            }
            // `healthy`, or `unhealthy` after it was healthy: the node decides whether the port still answers.
            if matches!(
                leases::service_state(&mut conn, job_id).await?.health,
                Some(ServiceHealth::Healthy | ServiceHealth::Unhealthy)
            ) {
                return Ok(());
            }
        }
        if !wait || state.clock.now() >= deadline || tokio::time::Instant::now() >= real_deadline {
            return Err(service_not_ready());
        }
        tokio::time::sleep(limits.ready_poll).await;
    }
}

/// Opens a connection into a port of a running service: an HTTP/1.1 upgrade (`Connection: Upgrade`,
/// `Upgrade: p2pc-port/1`, no body). After `101 Switching Protocols` the connection is a raw, bidirectional byte
/// stream to `127.0.0.1:<port>` inside the service's container.
///
/// **Who may connect** (H2 §5.5, SI-H2-5). With `services:connect`, any service of the caller's project. Without it
/// but with `templates:launch`, a template service of the caller's template view. Any other job answers `404`.
///
/// **Template services are filtered** for every caller that is not `admin`: the upgraded connection carries **one**
/// HTTP/1.1 request, which the hub forwards only if its method and path are one of the template's `allowed_routes`
/// (exact match, no query). The request line and headers must fit in 8 KiB and 64 headers, and a body needs
/// `Content-Length`, at most 1 MiB. The hub answers a refused request itself, inside the upgraded connection:
/// `400 invalid_request` (`Transfer-Encoding`, `Upgrade`, `Expect`, `CONNECT`, a duplicate or non-numeric
/// `Content-Length`, a malformed header line, or a `Connection` option naming a field that is not hop-by-hop),
/// `403 route_not_allowed`, `413 too_large`, `431 headers_too_large`, and `502 node_unreachable` when the node
/// cannot be reached. An allowed request is forwarded with `Connection: close`, and the response is relayed until
/// the service closes; the next request needs a new connection.
///
/// **Limits.** 64 open connections per service and 16 per caller per service; a connection closes after
/// `port_idle_s` (600 s by default) with no byte in either direction.
#[utoipa::path(
    post,
    path = "/v1/jobs/{id}/ports/{port}/connect",
    tag = "jobs",
    params(
        ("id" = String, Path, description = "The job ID (`job_…`) of a service."),
        ("port" = u16, Path, description = "A port of the service's `service.ports`."),
        ConnectParams,
    ),
    responses(
        (status = 101, description = "The connection is upgraded (`Upgrade: p2pc-port/1`): raw bytes to the port, or, for a template service and a caller that is not `admin`, one HTTP request filtered by the template's `allowed_routes`."),
        (status = 400, description = "`upgrade_required`: the request is not an upgrade to `p2pc-port/1`, or it has a body. `invalid_query`: an unknown or invalid query parameter. Inside a filtered connection, `invalid_request`: a request the hub never forwards.", content_type = "application/problem+json", body = Problem),
        (status = 401, description = "Missing or invalid key, or the caller was revoked or expired while the request was in flight.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the caller has neither `services:connect` nor `templates:launch`. `route_not_allowed`: the template allows no request on this port to a caller that is not `admin`, or (inside a filtered connection) not this one.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "No such job in this account and project, or (for a caller with only `templates:launch`) not a template service of its template view.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`service_not_running`: the job is not running. `service_not_ready`: its health is still `starting` (`?wait_ready=true` waits up to 30 s instead).", content_type = "application/problem+json", body = Problem),
        (status = 413, description = "Inside a filtered connection, `too_large`: the request body is over 1 MiB.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "`port_not_exposed`: the port is not in the service's `service.ports`.", content_type = "application/problem+json", body = Problem),
        (status = 429, description = "`too_many_connections`: the service has 64 open connections, the caller has 16 to this service, the hub's `port_conn_budget` for API-key clients is in use, or the node's connection carries its most port streams.", content_type = "application/problem+json", body = Problem),
        (status = 431, description = "Inside a filtered connection, `headers_too_large`: the request line and headers are over 8 KiB or 64 headers.", content_type = "application/problem+json", body = Problem),
        (status = 502, description = "`node_unreachable`: the hub could not open the stream to the service's node, or the node's agent refused it; `detail` has the agent's reason (`stale_lease`, `port_not_exposed`, `not_ready`, `too_many_connections`, `connect_failed`).", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn connect(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
    Path((id, port)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<ConnectParams>,
    mut request: Request,
) -> Result<Response, ApiError> {
    // The access rule before the ID: a caller with no access gets `403` whatever it asks for.
    job_visibility(&state, &p, JobRoute::Port)?;
    let job_id: JobId = id.parse().map_err(|_| ApiError::not_found())?;
    // The one authorization check of every transport (SI-H2-5): the job's account and project, and the caller's
    // view of it. A job outside it is `404`, before anything about the job is said.
    let job = {
        let mut conn = state.db.acquire().await?;
        visible_job(&mut conn, &state, &p, JobRoute::Port, job_id).await?
    };
    if request.version() != Version::HTTP_11 || !asks_for_port_upgrade(request.headers()) {
        return Err(ApiError::bad_request(
            UPGRADE_REQUIRED,
            "Connect with `Connection: Upgrade` and `Upgrade: p2pc-port/1`, and no body.",
        ));
    }
    let port = listed_port(&job, &port)?;
    if job.status != JobStatus::Running {
        return Err(ports::service_not_running());
    }
    ready(&state, &p, job_id, query.wait_ready.unwrap_or(false)).await?;
    // A template service is filtered for every principal that is not `admin` (H2 §7.4). The routes are those of
    // the bundle the hub serves now, by the job's template id; with none, nothing matches.
    let routes = match &job.spec_view.template {
        Some(template) if !p.is_admin() => {
            let routes: Vec<_> = state
                .templates
                .allowed_routes(&template.id)
                .into_iter()
                .filter(|route| route.port == u32::from(port))
                .collect();
            if routes.is_empty() {
                // Closed to this caller on this port: no request could pass.
                return Err(ports::route_not_allowed());
            }
            Some(routes)
        }
        _ => None,
    };
    // A device's connection ends with the device (SI-H2-4). Registered first, then the caller is read again: a
    // revocation before this point is seen here, one after it closes the registration.
    let session = p.device_id().map(|device_id| state.devices.register(device_id));
    {
        let mut conn = state.db.acquire().await?;
        if reload(&mut conn, p.account_id, p.id, state.clock.now())
            .await?
            .is_none()
        {
            return Err(ApiError::unauthenticated());
        }
    }
    // A device principal exists only on `p2pc/device/1`, where the stream itself holds a slot of the device budget
    // (§6.3). An API key came over TCP or `p2pc/http/1`, and takes one of `port_conn_budget`.
    let slot = state
        .ports
        .acquire(job_id, p.id, p.key_id().is_some())
        .map_err(|refused| {
            ApiError::too_many_requests(H2ErrorCode::TooManyConnections.as_str(), refused.to_string())
        })?;
    let plan = match routes {
        Some(routes) => Plan::Filtered(routes),
        // Raw: the stream to the node is opened before the upgrade, so its failure is an ordinary `502`.
        None => Plan::Raw(ports::open(&state, job_id, port).await?),
    };
    let accepted = Accepted {
        job_id,
        port,
        slot,
        session,
        plan,
    };
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        match upgrade.await {
            Ok(upgraded) => ports::serve(state, TokioIo::new(upgraded), accepted).await,
            // The client went away before the `101` was written: `accepted` is dropped, with its slot and stream.
            Err(e) => tracing::debug!(error = %e, "port connection not upgraded"),
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, UPGRADE_PROTOCOL)
        .body(Body::empty())
        .map_err(|_| ApiError::internal())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn only_an_upgrade_to_the_port_protocol_without_a_body_is_one() {
        for ok in [
            &[("connection", "Upgrade"), ("upgrade", "p2pc-port/1")][..],
            &[("connection", "keep-alive, upgrade"), ("upgrade", "P2PC-Port/1")],
            &[
                ("connection", "upgrade"),
                ("upgrade", "p2pc-port/1"),
                ("content-length", "0"),
            ],
        ] {
            assert!(asks_for_port_upgrade(&headers(ok)), "{ok:?}");
        }
        for no in [
            &[][..],
            &[("upgrade", "p2pc-port/1")],
            &[("connection", "upgrade")],
            &[("connection", "close"), ("upgrade", "p2pc-port/1")],
            &[("connection", "upgrade"), ("upgrade", "websocket")],
            &[("connection", "upgrade"), ("upgrade", "p2pc-port/2")],
            &[("connection", "upgrade"), ("upgrade", "p2pc-port/1, websocket")],
            &[
                ("connection", "upgrade"),
                ("upgrade", "p2pc-port/1"),
                ("upgrade", "p2pc-port/1"),
            ],
            &[
                ("connection", "upgrade"),
                ("upgrade", "p2pc-port/1"),
                ("content-length", "4"),
            ],
            &[
                ("connection", "upgrade"),
                ("upgrade", "p2pc-port/1"),
                ("transfer-encoding", "chunked"),
            ],
        ] {
            assert!(!asks_for_port_upgrade(&headers(no)), "{no:?}");
        }
    }
}
