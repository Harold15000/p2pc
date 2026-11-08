// SPDX-License-Identifier: Apache-2.0

//! Parsing of the proxy request head: `CONNECT host:port` and absolute-URI plain HTTP. Everything here is pure and
//! works on bytes the job controls, so it is strict and never panics.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The most headers accepted in one request head.
const MAX_HEADERS: usize = 128;

/// Headers never forwarded upstream: hop-by-hop (RFC 9110 §7.6.1) plus `Host`, which is rebuilt from the URI.
/// `Proxy-*` headers are dropped by prefix. `Transfer-Encoding` is kept: the body is relayed as is, not decoded.
const DROPPED_HEADERS: &[&str] = &["connection", "keep-alive", "te", "trailer", "upgrade", "host"];

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    /// `CONNECT host:port`.
    Connect(Target),
    /// An absolute-URI `http://` request, with its head already rewritten to origin-form for the upstream.
    Http {
        /// Where it goes.
        target: Target,
        /// The rewritten request head, ending with the blank line.
        head: Vec<u8>,
        /// How the request body is framed. The proxy forwards exactly this body, then nothing more.
        body: Body,
    },
}

/// The framing of a plain-HTTP request body (RFC 9112 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Body {
    /// No `Content-Length` and no `Transfer-Encoding`: no body.
    None,
    /// `Content-Length: n`.
    Length(u64),
    /// `Transfer-Encoding: chunked`, up to the last chunk and its trailers.
    Chunked,
}

impl Request {
    pub(crate) fn target(&self) -> &Target {
        match self {
            Request::Connect(t) | Request::Http { target: t, .. } => t,
        }
    }
}

/// The destination as the client wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The host, exactly as written (brackets included for IPv6).
    pub(crate) host: String,
    /// The port.
    pub(crate) port: u16,
}

/// A malformed request (answered with `400`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("bad request: {0}")]
pub(crate) struct BadRequest(pub(crate) &'static str);

/// Finds the end of the head (`\r\n\r\n`), returning the length of the head including it.
pub(crate) fn head_len(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parses a full request head (as delimited by [`head_len`]).
pub(crate) fn parse_head(head: &[u8]) -> Result<Request, BadRequest> {
    let text = std::str::from_utf8(head).map_err(|_| BadRequest("not ASCII"))?;
    if !text.is_ascii() {
        return Err(BadRequest("not ASCII"));
    }
    let text = text.strip_suffix("\r\n\r\n").ok_or(BadRequest("unterminated head"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(BadRequest("empty"))?;
    let mut headers = Vec::new();
    for line in lines {
        headers.push(parse_header(line)?);
        if headers.len() > MAX_HEADERS {
            return Err(BadRequest("too many headers"));
        }
    }

    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(BadRequest("request line"));
    };
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(BadRequest("method"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(BadRequest("version"));
    }
    if !target.bytes().all(|b| b.is_ascii_graphic()) || target.is_empty() {
        return Err(BadRequest("target"));
    }

    if method == "CONNECT" {
        return Ok(Request::Connect(parse_authority(target, None)?));
    }
    let (target, path) = parse_absolute_http(target)?;
    let (head, body) = rewrite_head(method, &path, version, &target, &headers)?;
    Ok(Request::Http { target, head, body })
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn parse_header(line: &str) -> Result<(&str, &str), BadRequest> {
    if line.starts_with([' ', '\t']) {
        return Err(BadRequest("obsolete line folding"));
    }
    let (name, value) = line.split_once(':').ok_or(BadRequest("header without a colon"))?;
    if name.is_empty() || !name.bytes().all(is_tchar) {
        return Err(BadRequest("header name"));
    }
    let value = value.trim_matches([' ', '\t']);
    // CR and LF cannot appear (lines are split on CRLF, but a lone CR or LF could); other controls are refused too.
    if value.bytes().any(|b| b != b'\t' && b.is_ascii_control()) {
        return Err(BadRequest("header value"));
    }
    Ok((name, value))
}

/// `host:port`, or `host` when `default_port` is given. IPv6 literals keep their brackets so the caller refuses
/// them as IP literals.
fn parse_authority(auth: &str, default_port: Option<u16>) -> Result<Target, BadRequest> {
    if auth.contains('@') {
        return Err(BadRequest("userinfo"));
    }
    // A path, query or fragment has no place in an authority. `\` is refused too, because WHATWG URL parsers treat
    // it as `/` in `http` URLs: no parser differential between the proxy and the client.
    if auth.contains(['/', '?', '#', '\\']) {
        return Err(BadRequest("path in authority"));
    }
    let (host, port) = if auth.starts_with('[') {
        let end = auth.find(']').ok_or(BadRequest("unclosed bracket"))?;
        let (host, rest) = auth.split_at(end + 1);
        match rest.strip_prefix(':') {
            Some(p) => (host, Some(p)),
            None if rest.is_empty() => (host, None),
            None => return Err(BadRequest("authority")),
        }
    } else if auth.matches(':').count() > 1 {
        // An unbracketed IPv6 address (`::1:443`): there is no way to split it, and it is an IP literal anyway.
        (auth, None)
    } else {
        match auth.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (auth, None),
        }
    };
    if host.is_empty() {
        return Err(BadRequest("empty host"));
    }
    let port = match port {
        Some(p) => parse_port(p)?,
        None if host.contains(':') && !host.starts_with('[') => 0,
        None => default_port.ok_or(BadRequest("missing port"))?,
    };
    Ok(Target {
        host: host.to_string(),
        port,
    })
}

fn parse_port(p: &str) -> Result<u16, BadRequest> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BadRequest("port"));
    }
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(BadRequest("port")),
        Ok(n) => Ok(n),
    }
}

/// `http://authority/path?query` → the target and the origin-form path. `https://` is refused: clients use
/// `CONNECT` for TLS.
fn parse_absolute_http(uri: &str) -> Result<(Target, String), BadRequest> {
    let rest = uri
        .get(..7)
        .filter(|s| s.eq_ignore_ascii_case("http://"))
        .and_then(|_| uri.get(7..))
        .ok_or(BadRequest("only absolute http:// URIs are proxied"))?;
    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (auth, tail) = rest.split_at(split);
    let target = parse_authority(auth, Some(80))?;
    let tail = tail.split('#').next().unwrap_or("");
    let path = match tail.chars().next() {
        Some('/') => tail.to_string(),
        Some(_) => format!("/{tail}"),
        None => "/".to_string(),
    };
    Ok((target, path))
}

/// Headers a `Connection` header may not name: dropping them as hop-by-hop would change how the upstream frames
/// the request (spec §9).
const FRAMING_HEADERS: &[&str] = &["content-length", "transfer-encoding", "host"];

fn rewrite_head(
    method: &str,
    path: &str,
    version: &str,
    target: &Target,
    headers: &[(&str, &str)],
) -> Result<(Vec<u8>, Body), BadRequest> {
    let mut nominated: Vec<String> = Vec::new();
    let mut content_length: Option<&str> = None;
    let mut transfer_encoding = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',').map(|t| t.trim().to_ascii_lowercase()) {
                if FRAMING_HEADERS.contains(&token.as_str()) {
                    return Err(BadRequest("Connection names a framing header"));
                }
                nominated.push(token);
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some_and(|v| v != *value) {
                return Err(BadRequest("conflicting Content-Length"));
            }
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(BadRequest("Content-Length"));
            }
            content_length = Some(value);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // RFC 9112 §6.1: HTTP/1.0 has no transfer codings, so this framing is faulty: refuse it, whatever the
            // value, rather than guess how the upstream would read the body.
            if version == "HTTP/1.0" {
                return Err(BadRequest("Transfer-Encoding in an HTTP/1.0 request"));
            }
            if transfer_encoding || !value.eq_ignore_ascii_case("chunked") {
                return Err(BadRequest("Transfer-Encoding other than chunked"));
            }
            transfer_encoding = true;
        }
    }
    if transfer_encoding && content_length.is_some() {
        return Err(BadRequest("both Content-Length and Transfer-Encoding"));
    }
    let body = match (transfer_encoding, content_length) {
        (true, _) => Body::Chunked,
        (false, Some(len)) => Body::Length(len.parse().map_err(|_| BadRequest("Content-Length"))?),
        (false, None) => Body::None,
    };

    let mut out = format!("{method} {path} {version}\r\nHost: {}", target.host);
    if target.port != 80 {
        out.push_str(&format!(":{}", target.port));
    }
    out.push_str("\r\n");
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if DROPPED_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") || nominated.contains(&lower) {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    Ok((out.into_bytes(), body))
}

/// Whether `host` is an IP literal in **any** form a resolver or URL parser might accept: dotted, bracketed or bare
/// IPv6, scope IDs, percent-encoding, and the WHATWG/`inet_aton` numeric forms (`2130706433`, `0x7f.1`,
/// `0177.0.0.1`, `127.1`). The WHATWG rule is: a host whose last label is a number (decimal, or `0x` hex) is an
/// IPv4 address.
pub(crate) fn is_ip_literal(host: &str) -> bool {
    if host.starts_with('[') || host.contains(':') || host.contains('%') {
        return true;
    }
    if host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok() {
        return true;
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    let last = name.rsplit('.').next().unwrap_or("");
    if last.is_empty() {
        return false;
    }
    let decimal = last.bytes().all(|b| b.is_ascii_digit());
    let hex = last
        .get(..2)
        .filter(|p| p.eq_ignore_ascii_case("0x"))
        .and_then(|_| last.get(2..))
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    decimal || hex
}
