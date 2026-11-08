// SPDX-License-Identifier: AGPL-3.0-only

//! API errors as RFC 9457 `application/problem+json` (spec §7), using [`p2pc_proto::api::Problem`].

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{Problem, Scope};
use p2pc_proto::units::Units;
use p2pc_proto::validate::keys::ESCALATION_DENIED;
use p2pc_proto::validate::{ErrorCode, EscalationDenied, FieldError, ValidationErrors};

use crate::store::StoreError;
use crate::store::job_state::TransitionError;

/// Media type of every error body.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// An error response. Messages never contain secrets or request bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    // Boxed: handlers return `Result<_, ApiError>`, and a small error keeps the happy path cheap.
    problem: Box<Problem>,
}

impl ApiError {
    fn new(status: StatusCode, code: &str, title: &str, detail: impl Into<String>) -> Self {
        Self {
            problem: Box::new(Problem::new(status.as_u16(), code, title).with_detail(detail)),
        }
    }

    /// `401 unauthenticated`. The body is the same for every cause (missing, malformed, unknown, wrong secret,
    /// expired, revoked), so a caller cannot tell them apart (spec §5).
    #[must_use]
    pub fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Unauthorized",
            "A valid API key is required: Authorization: Bearer p2pc_sk_…",
        )
    }

    /// `403 forbidden`: the key lacks `scope`.
    #[must_use]
    pub fn forbidden(scope: Scope) -> Self {
        let name = serde_json::to_value(scope)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        Self::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Forbidden",
            format!("This API key lacks the `{name}` scope."),
        )
    }

    /// `403 escalation_denied` (spec §5 "No escalation"): the request asks for more than its creator key has. Each
    /// offending field is listed in `errors` with the code `not_allowed`.
    #[must_use]
    pub fn escalation_denied(denied: &EscalationDenied) -> Self {
        let mut e = Self::new(
            StatusCode::FORBIDDEN,
            ESCALATION_DENIED,
            "Forbidden",
            format!(
                "A key cannot create a key with more power than it has; reduce: {}.",
                denied.fields.join(", ")
            ),
        );
        e.problem.errors = denied
            .fields
            .iter()
            .map(|f| FieldError {
                field: (*f).to_string(),
                code: ErrorCode::NotAllowed,
                message: "exceeds the creating key's own limit".to_string(),
            })
            .collect();
        e
    }

    /// `403 image_not_allowed`: the key's `allowed_images` do not cover the job's normalized image (§5, §7).
    #[must_use]
    pub fn image_not_allowed(image: &str) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "image_not_allowed",
            "Forbidden",
            format!("This API key may not run the image `{image}`: it is not covered by the key's allowed images."),
        )
    }

    /// `402 cap_exceeded`: the job's estimate does not fit under the key's daily cap (§11). The figures are the
    /// key's own, in units with three decimals.
    #[must_use]
    pub fn cap_exceeded(cap: Units, reserved: Units, estimate: Units) -> Self {
        Self::new(
            StatusCode::PAYMENT_REQUIRED,
            "cap_exceeded",
            "Payment Required",
            format!(
                "This job needs {estimate} units, but this key's daily cap is {cap} units and {reserved} are already \
                 reserved today (UTC)."
            ),
        )
    }

    /// `409 idempotency_conflict`: the idempotency key was used before with a different request (§7).
    #[must_use]
    pub fn idempotency_conflict() -> Self {
        Self::conflict(
            "idempotency_conflict",
            "This idempotency key was already used for a different job; use a new key to submit a different job.",
        )
    }

    /// `404 not_found`.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "Not Found",
            "The resource does not exist.",
        )
    }

    /// `410 expired`: the output existed, but the GC deleted it after the retention period (§7, §12).
    #[must_use]
    pub fn expired() -> Self {
        Self::new(
            StatusCode::GONE,
            "expired",
            "Gone",
            "This output was deleted after the server's retention period.",
        )
    }

    /// `405 method_not_allowed`.
    #[must_use]
    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Method Not Allowed",
            "This method is not allowed on this resource.",
        )
    }

    /// `409` with a specific code.
    #[must_use]
    pub fn conflict(code: &str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, "Conflict", detail)
    }

    /// `400` with a specific code.
    #[must_use]
    pub fn bad_request(code: &str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, "Bad Request", detail)
    }

    /// `415 unsupported_media_type`.
    #[must_use]
    pub fn unsupported_media_type() -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Unsupported Media Type",
            "The body must be JSON, with Content-Type: application/json.",
        )
    }

    /// `408 request_timeout`: the body or the whole request took longer than the server's limit (§10 "Slow
    /// clients").
    #[must_use]
    pub fn request_timeout() -> Self {
        Self::new(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "Request Timeout",
            "The request took longer than the server allows.",
        )
    }

    /// `413 payload_too_large`.
    #[must_use]
    pub fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "Payload Too Large",
            "The request body is too large.",
        )
    }

    /// `422 invalid_body`: the body is JSON but not of the expected shape.
    #[must_use]
    pub fn invalid_body(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body",
            "Unprocessable Content",
            detail,
        )
    }

    /// `422 validation_failed` with the `errors` extension (or the code `p2pc_proto` picks, such as
    /// `unsupported_pool`).
    #[must_use]
    pub fn validation(errors: &ValidationErrors) -> Self {
        let mut problem = Problem::from_validation(errors);
        problem.detail = Some("The request is invalid; see `errors`.".to_string());
        problem.title = "Unprocessable Content".to_string();
        Self {
            problem: Box::new(problem),
        }
    }

    /// `422 validation_failed` for a single field.
    #[must_use]
    pub fn field(field: &str, code: ErrorCode, message: impl Into<String>) -> Self {
        let mut e = Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Unprocessable Content",
            "The request is invalid; see `errors`.",
        );
        e.problem.errors = vec![FieldError {
            field: field.to_string(),
            code,
            message: message.into(),
        }];
        e
    }

    /// `500 internal`. The cause is logged by the caller, never returned.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal Server Error",
            "The server failed to handle the request.",
        )
    }

    /// The problem body.
    #[must_use]
    pub fn problem(&self) -> &Problem {
        &self.problem
    }

    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        // Serializing a `Problem` cannot fail; fall back to a fixed body just in case.
        let body = serde_json::to_vec(&self.problem).unwrap_or_else(|_| {
            br#"{"type":"about:blank","title":"Internal Server Error","status":500,"code":"internal"}"#.to_vec()
        });
        let mut resp = (status, body).into_response();
        resp.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        tracing::error!(error = %e, "storage error");
        Self::internal()
    }
}

impl From<TransitionError> for ApiError {
    /// An illegal or stale transition is a bug in the server, never the client's doing: `500`, logged, with the
    /// cause kept out of the response.
    fn from(e: TransitionError) -> Self {
        match e {
            TransitionError::Store(e) => e.into(),
            other => {
                tracing::error!(error = %other, "job transition refused");
                Self::internal()
            }
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::from(e).into()
    }
}

/// Fallback for unknown routes.
pub async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// Fallback for a known route with the wrong method.
pub async fn method_not_allowed() -> ApiError {
    ApiError::method_not_allowed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constructor_has_type_title_status_detail_and_code() {
        for e in [
            ApiError::unauthenticated(),
            ApiError::forbidden(Scope::Admin),
            ApiError::not_found(),
            ApiError::method_not_allowed(),
            ApiError::conflict("last_admin_key", "x"),
            ApiError::image_not_allowed("docker.io/library/alpine:3"),
            ApiError::cap_exceeded(Units::from_milli(1000), Units::from_milli(500), Units::from_milli(501)),
            ApiError::idempotency_conflict(),
            ApiError::bad_request("invalid_json", "x"),
            ApiError::unsupported_media_type(),
            ApiError::payload_too_large(),
            ApiError::invalid_body("x"),
            ApiError::field("limit", ErrorCode::OutOfRange, "x"),
            ApiError::internal(),
        ] {
            let v = serde_json::to_value(e.problem()).unwrap();
            for k in ["type", "title", "status", "detail", "code"] {
                assert!(v.get(k).is_some(), "{k} in {v}");
            }
            assert_eq!(e.status().as_u16(), e.problem().status);
        }
        assert_eq!(ApiError::image_not_allowed("x").status(), StatusCode::FORBIDDEN);
        assert_eq!(
            ApiError::cap_exceeded(Units::from_milli(1000), Units::from_milli(500), Units::from_milli(501)).status(),
            StatusCode::PAYMENT_REQUIRED
        );
        assert_eq!(ApiError::idempotency_conflict().status(), StatusCode::CONFLICT);
        assert_eq!(ApiError::idempotency_conflict().problem().code, "idempotency_conflict");
        // The figures are shown as units: 0.500 of 1.000 reserved, 0.501 needed.
        let detail = ApiError::cap_exceeded(Units::from_milli(1000), Units::from_milli(500), Units::from_milli(501))
            .problem()
            .detail
            .clone()
            .unwrap();
        assert!(
            detail.contains("0.501") && detail.contains("1.000") && detail.contains("0.500"),
            "{detail}"
        );
        assert!(
            ApiError::forbidden(Scope::JobsWrite)
                .problem()
                .detail
                .as_deref()
                .unwrap()
                .contains("jobs:write")
        );
    }
}
