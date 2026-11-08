// SPDX-License-Identifier: Apache-2.0

//! The error type of the client: an API error, a network error or an unexpected response.
//!
//! No variant ever holds the API key, the `Authorization` header or a request URL with credentials (SI-6).

use std::fmt;

use p2pc_proto::api::Problem;
use p2pc_proto::validate::FieldError;

/// What went wrong with a request.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server answered with an RFC 9457 `application/problem+json` error.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The request never got an answer: connection refused, DNS failure, TLS failure, timeout, reset.
    #[error(transparent)]
    Network(#[from] NetworkError),
    /// The server answered, but not with what the API documents: a non-JSON error page from a proxy, a body that
    /// does not match the expected type, a redirect, or a body that is too large.
    #[error(transparent)]
    Unexpected(#[from] UnexpectedResponse),
    /// The request could not be made on this machine: a header value that cannot be sent (a newline in an
    /// idempotency key, for example). Nothing reached the server, and it is never retried.
    #[error(transparent)]
    Local(#[from] LocalError),
}

impl Error {
    /// The API error, if the server sent one.
    #[must_use]
    pub fn as_api(&self) -> Option<&ApiError> {
        match self {
            Error::Api(e) => Some(e),
            _ => None,
        }
    }

    /// The `code` of the API error, if the server sent one.
    #[must_use]
    pub fn api_code(&self) -> Option<&str> {
        self.as_api().map(|e| e.code.as_str())
    }

    /// The HTTP status, when the server answered at all.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api(e) => Some(e.status),
            Error::Unexpected(e) => e.status,
            Error::Network(_) | Error::Local(_) => None,
        }
    }
}

/// An error answered by the server, parsed from `application/problem+json` (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status of the response.
    pub status: u16,
    /// The stable machine-readable `code`, for example `escalation_denied`.
    pub code: String,
    /// The short human summary (`title`).
    pub title: String,
    /// The explanation of this occurrence.
    pub detail: Option<String>,
    /// Per-field validation errors (`422`).
    pub errors: Vec<FieldError>,
}

impl ApiError {
    /// Builds the error from a parsed problem. The HTTP status wins over the `status` member of the body.
    pub(crate) fn from_problem(http_status: u16, p: Problem) -> Self {
        Self {
            status: http_status,
            code: p.code,
            title: p.title,
            detail: p.detail,
            errors: p.errors,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.detail.as_deref().unwrap_or(&self.title);
        write!(f, "{}: {} (HTTP {})", self.code, text, self.status)
    }
}

impl std::error::Error for ApiError {}

/// Why a request got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    /// The connection could not be established (refused, unreachable, DNS, TLS handshake).
    Connect,
    /// The connect or request timeout expired.
    Timeout,
    /// Anything else on the wire: the connection dropped or the stream broke.
    Other,
}

/// A request that got no answer. The message never includes the URL or any header.
#[derive(Debug)]
pub struct NetworkError {
    kind: NetworkKind,
    message: String,
}

impl NetworkError {
    /// A network error of `kind`. The message must not hold a URL, a header or a secret.
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code, reason = "used by the tunnel transport"))]
    pub(crate) fn new(kind: NetworkKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn from_reqwest(e: reqwest::Error) -> Self {
        let kind = if e.is_timeout() {
            NetworkKind::Timeout
        } else if e.is_connect() {
            NetworkKind::Connect
        } else {
            NetworkKind::Other
        };
        // Drop the URL, then walk the chain of causes: reqwest's own `Display` stops at "error sending request" and
        // hides the useful part ("connection refused", "certificate verify failed").
        let e = e.without_url();
        let mut message = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        Self { kind, message }
    }

    /// Why the request got no answer.
    #[must_use]
    pub fn kind(&self) -> NetworkKind {
        self.kind
    }

    /// What happened, without the `network error:` prefix of `Display`.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "network error: {}", self.message)
    }
}

impl std::error::Error for NetworkError {}

/// A request that could not be built on this machine. The message never quotes the offending value: it may be a
/// secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalError {
    message: String,
}

impl LocalError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LocalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the request could not be built: {}", self.message)
    }
}

impl std::error::Error for LocalError {}

/// An answer the API does not document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpectedResponse {
    /// The HTTP status, when there was one.
    pub status: Option<u16>,
    /// What was unexpected. Never contains the key; a body excerpt is cut and stripped of control characters.
    pub message: String,
}

impl UnexpectedResponse {
    pub(crate) fn new(status: Option<u16>, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl fmt::Display for UnexpectedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(s) => write!(f, "unexpected response (HTTP {s}): {}", self.message),
            None => write!(f, "unexpected response: {}", self.message),
        }
    }
}

impl std::error::Error for UnexpectedResponse {}

/// A readable excerpt of a body, for error messages: at most 200 characters, control characters replaced.
pub(crate) fn excerpt(body: &[u8]) -> String {
    const MAX: usize = 200;
    let text = String::from_utf8_lossy(body);
    let mut out: String = text
        .chars()
        .take(MAX)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().count() > MAX {
        out.push('…');
    }
    out.trim().to_string()
}

/// The client could not be built: a bad base URL or a TLS setup failure.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The base URL is not an `http://` or `https://` URL, or it carries credentials, a query or a fragment.
    #[error("invalid server URL: {0}")]
    InvalidUrl(String),
    /// The TLS configuration could not be created (no usable certificate store, for example).
    #[error("could not set up TLS: {0}")]
    Tls(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_display_uses_detail_then_title() {
        let mut e = ApiError {
            status: 403,
            code: "escalation_denied".into(),
            title: "Forbidden".into(),
            detail: None,
            errors: vec![],
        };
        assert_eq!(e.to_string(), "escalation_denied: Forbidden (HTTP 403)");
        e.detail = Some("the new key would have more scopes".into());
        assert_eq!(
            e.to_string(),
            "escalation_denied: the new key would have more scopes (HTTP 403)"
        );
    }

    #[test]
    fn excerpt_cuts_and_strips_control_characters() {
        let body = format!("a\u{1b}[31mb{}", "x".repeat(500));
        let text = excerpt(body.as_bytes());
        assert!(!text.contains('\u{1b}'));
        assert!(text.chars().count() <= 201);
        assert!(text.ends_with('…'));
    }
}
