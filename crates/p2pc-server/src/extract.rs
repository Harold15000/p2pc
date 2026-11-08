// SPDX-License-Identifier: AGPL-3.0-only

//! `Json` and `Query` extractors whose rejections are problem+json instead of axum's plain text.
//!
//! Rejection details never echo values from the request: a serde message such as ``invalid type: string "…"``
//! would copy user input (later, job `env` values) into the response. Only "unknown field" and "missing field"
//! messages, which name a field and nothing else, are passed through.

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// A JSON body.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(v)) => Ok(Self(v)),
            Err(JsonRejection::JsonDataError(e)) => Err(ApiError::invalid_body(safe_detail(
                &e.body_text(),
                "The body does not match the expected schema.",
            ))),
            Err(JsonRejection::JsonSyntaxError(_)) => {
                Err(ApiError::bad_request("invalid_json", "The body is not valid JSON."))
            }
            Err(JsonRejection::MissingJsonContentType(_)) => Err(ApiError::unsupported_media_type()),
            Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(ApiError::payload_too_large()),
            Err(e) if is_body_timeout(&e) => Err(ApiError::request_timeout()),
            Err(_) => Err(ApiError::bad_request("invalid_body", "The body cannot be read.")),
        }
    }
}

/// Whether reading the body failed because `RequestBodyTimeoutLayer` (§10 "Slow clients") gave up on it.
fn is_body_timeout(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cause {
        if err.is::<tower_http::timeout::TimeoutError>() {
            return true;
        }
        cause = err.source();
    }
    false
}

/// Query string parameters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(v)) => Ok(Self(v)),
            Err(QueryRejection::FailedToDeserializeQueryString(e)) => Err(ApiError::bad_request(
                "invalid_query",
                safe_detail(&e.body_text(), "The query string is invalid."),
            )),
            Err(_) => Err(ApiError::bad_request("invalid_query", "The query string is invalid.")),
        }
    }
}

/// Keeps a serde message only when it names a field and echoes no value.
fn safe_detail(text: &str, fallback: &str) -> String {
    for marker in ["unknown field `", "missing field `"] {
        if let Some(pos) = text.find(marker) {
            let rest = &text[pos..];
            // Cut after the closing backtick of the field name: the rest may list expected fields, which is fine,
            // but nothing after the name came from the request except the name itself.
            if let Some(end) = rest[marker.len()..].find('`') {
                return rest[..marker.len() + end + 1].to_string();
            }
        }
    }
    fallback.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_never_echo_values() {
        assert_eq!(
            safe_detail(
                "Failed to deserialize: unknown field `name`, expected one of `label`",
                "f"
            ),
            "unknown field `name`"
        );
        assert_eq!(
            safe_detail("Failed to deserialize: missing field `scopes` at line 1", "f"),
            "missing field `scopes`"
        );
        assert_eq!(
            safe_detail("env.KEY: invalid type: integer `12345`, expected a string", "fallback"),
            "fallback"
        );
        assert_eq!(safe_detail("unknown variant `s3cr3t`", "fallback"), "fallback");
    }
}
