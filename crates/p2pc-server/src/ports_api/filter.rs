// SPDX-License-Identifier: AGPL-3.0-only

//! The `allowed_routes` filter of template services (H2 spec §7.4, §7.6, SI-H2-18): pure parsing and matching, no
//! I/O.
//!
//! A principal that is not `admin` never gets raw bytes into a template service. The hub reads **one** HTTP/1.1
//! request from the upgraded connection and forwards it only if this module admits it. The rules, all of them fail
//! closed:
//!
//! - **The head** (request line and headers) is at most [`MAX_HEAD_BYTES`] and [`MAX_HEADERS`] header lines
//!   ([`Refusal::HeadersTooLarge`]). Lines end with CRLF: a bare CR or a bare LF anywhere in the head, a folded line
//!   (obs-fold), a line without a colon, whitespace before the colon, a control character or a byte above `0x7E` are
//!   malformed ([`Refusal::BadRequest`]).
//! - **Framing has one reading.** `Transfer-Encoding`, `Upgrade` and `Expect` are refused whatever their value, as
//!   is the `CONNECT` method. A body exists only with `Content-Length`: one header line, plain decimal digits, at
//!   most [`MAX_BODY_BYTES`] ([`Refusal::TooLarge`] above it). More than one `Host` is refused too, and so is a
//!   name that imitates one of these fields with an underscore (`Content_Length`), which some servers fold into it.
//! - **`Connection`** may name `close` and the fields the hub treats as hop-by-hop (`Connection`, `Keep-Alive`,
//!   `Proxy-*`, `TE`, `Trailer`). An option that names anything else (`Content-Length`, `Host`,
//!   `Transfer-Encoding`, an end-to-end field) is refused: a service that honoured it would drop a header the hub
//!   relied on.
//! - **The route.** The method and the request target must equal an entry `{port, method, path}` of the template's
//!   `allowed_routes` byte for byte: origin-form, no query, no fragment, no decoding, no normalization. The only
//!   wildcard is a final path segment `*`, which stands for one non-empty segment of `[A-Za-z0-9._-]` that is
//!   neither `.` nor `..`. Anything else is [`Refusal::RouteNotAllowed`].
//!
//! An admitted request is **re-serialized from its parsed form**, never forwarded as the bytes received
//! ([`Request::head`]): the request line, `Host` (only if one was received), the end-to-end header fields,
//! `Content-Length` and `Connection: close`, the last two always written by the hub. The caller then forwards exactly
//! [`Request::body_len`] bytes of body and nothing after them.

use p2pc_proto::api::AllowedRoute;

/// Most bytes of a request head, its final empty line included (H2 §7.4: 8 KiB).
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Most header lines of a request (H2 §7.4).
pub const MAX_HEADERS: usize = 64;
/// Largest body of a request, in bytes (H2 §7.4: 1 MiB).
pub const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Why a request is not forwarded. Nothing of it reaches the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `400`: the request is malformed, or uses something the filter never forwards. The text says what, without
    /// quoting the request.
    BadRequest(&'static str),
    /// `431 headers_too_large`: the head is over [`MAX_HEAD_BYTES`] or has more than [`MAX_HEADERS`] header lines.
    HeadersTooLarge,
    /// `413 too_large`: `Content-Length` is over [`MAX_BODY_BYTES`].
    TooLarge,
    /// `403 route_not_allowed`: the method and path match no entry of the template's `allowed_routes`.
    RouteNotAllowed,
}

/// Finds the end of the request head in `buf`, the bytes received so far.
///
/// `scanned` is the caller's cursor, 0 for a new connection: the bytes before it were already checked, so the scan is
/// linear however the bytes arrive. Returns the length of the head, its final empty line included, once the whole
/// head is there; `None` while more bytes are needed.
///
/// # Errors
/// [`Refusal::BadRequest`] at the first bare CR or bare LF, and [`Refusal::HeadersTooLarge`] when the first
/// [`MAX_HEAD_BYTES`] bytes hold no end of head. Both are decided as soon as the bytes are there, so a client that
/// never sends a CRLF is not read forever.
pub fn head_end(buf: &[u8], scanned: &mut usize) -> Result<Option<usize>, Refusal> {
    let limit = buf.len().min(MAX_HEAD_BYTES);
    let mut i = *scanned;
    while i < limit {
        match buf[i] {
            b'\n' => {
                if i == 0 || buf[i - 1] != b'\r' {
                    return Err(Refusal::BadRequest("a bare LF in the request head"));
                }
                if i >= 3 && &buf[i - 3..i] == b"\r\n\r" {
                    return Ok(Some(i + 1));
                }
            }
            b'\r' => match buf.get(i + 1) {
                Some(b'\n') => {}
                Some(_) => return Err(Refusal::BadRequest("a bare CR in the request head")),
                // The next byte decides: come back to this one.
                None => break,
            },
            _ => {}
        }
        i += 1;
    }
    *scanned = i;
    if buf.len() >= MAX_HEAD_BYTES {
        return Err(Refusal::HeadersTooLarge);
    }
    Ok(None)
}

/// A request the filter parsed: only what is forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    method: String,
    target: String,
    host: Option<String>,
    content_length: u64,
    /// The end-to-end header fields in the order received: every field but `Host`, `Content-Length` and the
    /// hop-by-hop ones.
    headers: Vec<(String, String)>,
}

/// `tchar` of RFC 9110: the characters of a method and of a field name.
const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|b| is_tchar(*b))
}

/// A printable ASCII character that is not a space.
const fn is_visible(b: u8) -> bool {
    matches!(b, 0x21..=0x7E)
}

fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// The fields the hub treats as hop-by-hop (H2 §7.4): never forwarded, and the only fields a `Connection` option may
/// name. `name` is lower case.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(name, "connection" | "keep-alive" | "te" | "trailer") || name.starts_with("proxy-")
}

/// The fields that decide how a request is framed or where it goes, and the hop-by-hop ones: what the filter refuses,
/// rewrites or drops. `name` is lower case.
fn is_framing_field(name: &str) -> bool {
    matches!(
        name,
        "content-length" | "transfer-encoding" | "host" | "upgrade" | "expect"
    ) || is_hop_by_hop(name)
}

/// A `Host` value the hub writes back: `host[:port]`, a name, an IPv4 address or a bracketed IPv6 address.
fn is_host(value: &str) -> bool {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let Some((address, after)) = rest.split_once(']') else {
            return false;
        };
        let address_ok =
            !address.is_empty() && address.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        if !address_ok {
            return false;
        }
        match after.strip_prefix(':') {
            Some(port) => ("x", Some(port)),
            None if after.is_empty() => ("x", None),
            None => return false,
        }
    } else {
        match value.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        }
    };
    let host_ok = !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    let port_ok = port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()));
    host_ok && port_ok
}

/// A `Content-Length` value: plain decimal digits and nothing else (no sign, no list, no space), that fit a `u64`.
fn content_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value
        .iter()
        .try_fold(0u64, |n, digit| n.checked_mul(10)?.checked_add(u64::from(digit - b'0')))
}

/// Parses a request head: the bytes up to and including its final empty line ([`head_end`]).
///
/// # Errors
/// [`Refusal::BadRequest`] and [`Refusal::HeadersTooLarge`] as the module docs say. The route and the body size are
/// checked by [`admit`].
pub fn parse(head: &[u8]) -> Result<Request, Refusal> {
    if head.len() > MAX_HEAD_BYTES {
        return Err(Refusal::HeadersTooLarge);
    }
    let Some(lines) = head.strip_suffix(b"\r\n\r\n") else {
        return Err(Refusal::BadRequest("the request head does not end with an empty line"));
    };
    let lines = split_lines(lines)?;
    let (request_line, header_lines) = lines.split_first().ok_or(Refusal::BadRequest("no request line"))?;
    let (method, target) = parse_request_line(request_line)?;
    if header_lines.len() > MAX_HEADERS {
        return Err(Refusal::HeadersTooLarge);
    }
    let mut request = Request {
        method,
        target,
        host: None,
        content_length: 0,
        headers: Vec::new(),
    };
    let mut seen_length = false;
    for line in header_lines {
        let (name, value) = parse_header_line(line)?;
        let lower = name.to_ascii_lowercase();
        // Some servers read `Content_Length` as `Content-Length`. Forwarded as an end-to-end field next to the hub's
        // own `Content-Length`, it would give such a server two framings: refused.
        if lower.contains('_') && is_framing_field(&lower.replace('_', "-")) {
            return Err(Refusal::BadRequest(
                "a header name that imitates a framing field with an underscore",
            ));
        }
        match lower.as_str() {
            "transfer-encoding" => return Err(Refusal::BadRequest("Transfer-Encoding is not forwarded")),
            "upgrade" => return Err(Refusal::BadRequest("Upgrade is not forwarded")),
            "expect" => return Err(Refusal::BadRequest("Expect is not forwarded")),
            "content-length" => {
                if seen_length {
                    return Err(Refusal::BadRequest("more than one Content-Length"));
                }
                seen_length = true;
                request.content_length = content_length(value.as_bytes())
                    .ok_or(Refusal::BadRequest("Content-Length is not a plain decimal number"))?;
            }
            "host" => {
                if request.host.is_some() {
                    return Err(Refusal::BadRequest("more than one Host"));
                }
                if !is_host(&value) {
                    return Err(Refusal::BadRequest("Host is not a host name with an optional port"));
                }
                request.host = Some(value);
            }
            "connection" => check_connection_options(&value)?,
            // Hop-by-hop: dropped.
            other if is_hop_by_hop(other) => {}
            _ => request.headers.push((name, value)),
        }
    }
    Ok(request)
}

/// Splits the head (without its final empty line) at every CRLF. A CR or an LF left inside a line is a bare one.
fn split_lines(mut rest: &[u8]) -> Result<Vec<&[u8]>, Refusal> {
    let mut lines = Vec::new();
    loop {
        let (line, next) = match rest.windows(2).position(|pair| pair == b"\r\n") {
            Some(at) => (&rest[..at], Some(&rest[at + 2..])),
            None => (rest, None),
        };
        if line.iter().any(|b| matches!(b, b'\r' | b'\n')) {
            return Err(Refusal::BadRequest("a bare CR or LF in the request head"));
        }
        lines.push(line);
        match next {
            Some(next) => rest = next,
            None => return Ok(lines),
        }
    }
}

/// `METHOD SP request-target SP HTTP/1.1`, with single spaces.
fn parse_request_line(line: &[u8]) -> Result<(String, String), Refusal> {
    const MALFORMED: Refusal = Refusal::BadRequest("the request line is malformed");
    let mut parts = line.split(|b| *b == b' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(MALFORMED);
    };
    if !is_token(method) || target.is_empty() || !target.iter().all(|b| is_visible(*b)) {
        return Err(MALFORMED);
    }
    if version != b"HTTP/1.1" {
        return Err(Refusal::BadRequest("only HTTP/1.1 is forwarded"));
    }
    if method == b"CONNECT" {
        return Err(Refusal::BadRequest("CONNECT is not forwarded"));
    }
    // Both are ASCII by the checks above.
    Ok((
        String::from_utf8_lossy(method).into_owned(),
        String::from_utf8_lossy(target).into_owned(),
    ))
}

/// `field-name ":" OWS field-value OWS`: no whitespace before the colon, no folding, printable ASCII only.
fn parse_header_line(line: &[u8]) -> Result<(String, String), Refusal> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(Refusal::BadRequest("a folded header line"));
    }
    let colon = line
        .iter()
        .position(|b| *b == b':')
        .ok_or(Refusal::BadRequest("a header line without a colon"))?;
    let (name, value) = (&line[..colon], trim_ows(&line[colon + 1..]));
    if !is_token(name) {
        return Err(Refusal::BadRequest("a header name that is not a token"));
    }
    if !value.iter().all(|b| is_visible(*b) || matches!(b, b' ' | b'\t')) {
        return Err(Refusal::BadRequest(
            "a header value with a byte that is not printable ASCII",
        ));
    }
    Ok((
        String::from_utf8_lossy(name).into_owned(),
        String::from_utf8_lossy(value).into_owned(),
    ))
}

/// A `Connection` value: a comma-separated list of tokens, each `close` or the name of a hop-by-hop field.
fn check_connection_options(value: &str) -> Result<(), Refusal> {
    for option in value.split(',') {
        let option = trim_ows(option.as_bytes());
        if option.is_empty() {
            continue;
        }
        if !is_token(option) {
            return Err(Refusal::BadRequest("a Connection option that is not a token"));
        }
        let name = String::from_utf8_lossy(option).to_ascii_lowercase();
        if name != "close" && !is_hop_by_hop(&name) {
            return Err(Refusal::BadRequest(
                "a Connection option names a field that is not hop-by-hop",
            ));
        }
    }
    Ok(())
}

/// Whether `target` is `pattern`: byte for byte, or with a final segment `*` standing for one plain segment.
fn path_matches(pattern: &str, target: &str) -> bool {
    // Origin-form only: `*`, an absolute URI and an authority never match.
    if !target.starts_with('/') {
        return false;
    }
    match pattern.strip_suffix("/*") {
        Some(prefix) => target
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            }),
        None => pattern == target,
    }
}

impl Request {
    /// The method, as received.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The request target, as received.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// How many bytes of body follow the head: the parsed `Content-Length`, 0 without one.
    #[must_use]
    pub fn body_len(&self) -> u64 {
        self.content_length
    }

    /// Whether an entry of `routes` allows this request on `port`.
    #[must_use]
    pub fn allowed_by(&self, routes: &[AllowedRoute], port: u16) -> bool {
        routes.iter().any(|route| {
            route.port == u32::from(port) && route.method == self.method && path_matches(&route.path, &self.target)
        })
    }

    /// The head the hub sends to the service, written from the parsed form: the request line, `Host` if one was
    /// received, the end-to-end fields, then `Content-Length` and `Connection: close` written by the hub itself.
    #[must_use]
    pub fn head(&self) -> Vec<u8> {
        let mut out = format!("{} {} HTTP/1.1\r\n", self.method, self.target);
        if let Some(host) = &self.host {
            out.push_str(&format!("Host: {host}\r\n"));
        }
        for (name, value) in &self.headers {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.content_length
        ));
        out.into_bytes()
    }
}

/// Parses `head` and admits the request only if `routes` allow it on `port` and its body fits.
///
/// # Errors
/// The [`Refusal`] to answer with. A malformed request is refused as such whatever its route, a well-formed one to a
/// route that is not allowed gets [`Refusal::RouteNotAllowed`], and only then is the body size looked at.
pub fn admit(head: &[u8], routes: &[AllowedRoute], port: u16) -> Result<Request, Refusal> {
    let request = parse(head)?;
    if !request.allowed_by(routes, port) {
        return Err(Refusal::RouteNotAllowed);
    }
    if request.content_length > MAX_BODY_BYTES {
        return Err(Refusal::TooLarge);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const PORT: u16 = 11434;

    /// Built from JSON, as a bundle is: a field added to `AllowedRoute` does not break the tests.
    fn route(method: &str, path: &str) -> AllowedRoute {
        serde_json::from_value(serde_json::json!({"port": PORT, "method": method, "path": path})).unwrap()
    }

    /// The beta's `private-chat` routes.
    fn chat_routes() -> Vec<AllowedRoute> {
        vec![route("POST", "/api/chat"), route("GET", "/api/tags")]
    }

    fn admit_chat(head: &str) -> Result<Request, Refusal> {
        admit(head.as_bytes(), &chat_routes(), PORT)
    }

    fn bad(head: &str) {
        assert!(
            matches!(admit_chat(head), Err(Refusal::BadRequest(_))),
            "{head:?} → {:?}",
            admit_chat(head)
        );
    }

    #[test]
    fn the_allowed_routes_pass_and_are_rewritten_from_the_parsed_form() {
        let r = admit_chat(
            "POST /api/chat HTTP/1.1\r\nhost: hub.example.invalid:8080\r\nContent-Type:  application/json \r\n\
             content-length: 17\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!((r.method(), r.target(), r.body_len()), ("POST", "/api/chat", 17));
        assert_eq!(
            String::from_utf8(r.head()).unwrap(),
            "POST /api/chat HTTP/1.1\r\nHost: hub.example.invalid:8080\r\nContent-Type: application/json\r\n\
             Accept: */*\r\nContent-Length: 17\r\nConnection: close\r\n\r\n"
        );
        // No Host received: none written. No Content-Length: the hub writes 0, so the service reads no body.
        let r = admit_chat("GET /api/tags HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            String::from_utf8(r.head()).unwrap(),
            "GET /api/tags HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn hop_by_hop_fields_are_dropped_and_connection_may_name_only_them() {
        let r = admit_chat(
            "POST /api/chat HTTP/1.1\r\nHost: hub\r\nConnection: keep-alive, TE, Proxy-Authorization,, close\r\n\
             Keep-Alive: timeout=5\r\nTE: trailers\r\nTrailer: X-Sum\r\nProxy-Authorization: none\r\n\
             Proxy-Connection: keep-alive\r\nX-Kept: 1\r\nContent-Length: 2\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(r.head()).unwrap(),
            "POST /api/chat HTTP/1.1\r\nHost: hub\r\nX-Kept: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
        // An option that names a field the hub does not treat as hop-by-hop: a service that honoured it would drop
        // that field (SI-H2-18: `Connection: content-length`).
        for option in [
            "content-length",
            "Content-Length",
            "host",
            "transfer-encoding",
            "upgrade",
            "x-kept",
            "close, content-length",
            "keep-alive,Host",
            "content-type",
            "authorization",
        ] {
            bad(&format!(
                "POST /api/chat HTTP/1.1\r\nHost: hub\r\nConnection: {option}\r\nContent-Length: 2\r\n\r\n"
            ));
        }
        // Not a token list at all.
        bad("POST /api/chat HTTP/1.1\r\nConnection: \"close\"\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nConnection: keep alive\r\n\r\n");
        // Split over two lines, each is checked.
        bad("POST /api/chat HTTP/1.1\r\nConnection: close\r\nConnection: content-length\r\n\r\n");
    }

    #[test]
    fn anything_but_an_exact_route_is_not_allowed() {
        for head in [
            // The model-writing routes of Ollama (SI-H2-18).
            "POST /api/pull HTTP/1.1\r\n\r\n",
            "POST /api/create HTTP/1.1\r\n\r\n",
            "POST /api/blobs/sha256:0000 HTTP/1.1\r\n\r\n",
            "HEAD /api/blobs/sha256:0000 HTTP/1.1\r\n\r\n",
            "POST /api/copy HTTP/1.1\r\n\r\n",
            "DELETE /api/delete HTTP/1.1\r\n\r\n",
            "POST /api/push HTTP/1.1\r\n\r\n",
            // An unknown path, a query string, a fragment, the wrong method.
            "GET /api/version HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\n",
            "POST /api/chat?x=1 HTTP/1.1\r\n\r\n",
            "POST /api/chat? HTTP/1.1\r\n\r\n",
            "POST /api/chat#x HTTP/1.1\r\n\r\n",
            "GET /api/chat HTTP/1.1\r\n\r\n",
            "POST /api/tags HTTP/1.1\r\n\r\n",
            "HEAD /api/tags HTTP/1.1\r\n\r\n",
            // No decoding, no normalization, no case folding.
            "POST /api/cha%74 HTTP/1.1\r\n\r\n",
            "POST /api/./chat HTTP/1.1\r\n\r\n",
            "POST /api/pull/../chat HTTP/1.1\r\n\r\n",
            "POST //api/chat HTTP/1.1\r\n\r\n",
            "POST /api/chat/ HTTP/1.1\r\n\r\n",
            "POST /API/chat HTTP/1.1\r\n\r\n",
            "post /api/chat HTTP/1.1\r\n\r\n",
            // Not origin-form.
            "POST http://hub.example.invalid/api/chat HTTP/1.1\r\n\r\n",
            "OPTIONS * HTTP/1.1\r\n\r\n",
            "POST api/chat HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(admit_chat(head), Err(Refusal::RouteNotAllowed), "{head:?}");
        }
        // The port is part of the route.
        assert_eq!(
            admit(b"GET /api/tags HTTP/1.1\r\n\r\n", &chat_routes(), 8080),
            Err(Refusal::RouteNotAllowed)
        );
        // No routes (no bundle served, or a template without them): nothing matches.
        assert_eq!(
            admit(b"GET /api/tags HTTP/1.1\r\n\r\n", &[], PORT),
            Err(Refusal::RouteNotAllowed)
        );
    }

    #[test]
    fn the_only_wildcard_is_one_plain_final_segment() {
        let routes = vec![route("GET", "/files/*"), route("GET", "*")];
        let get = |target: &str| admit(format!("GET {target} HTTP/1.1\r\n\r\n").as_bytes(), &routes, PORT);
        for ok in ["/files/a", "/files/model-1.2_x", "/files/..."] {
            assert!(get(ok).is_ok(), "{ok}");
        }
        for no in [
            "/files/",
            "/files",
            "/files/a/b",
            "/files/a/",
            "/files/.",
            "/files/..",
            "/files/a%2Fb",
            "/files/a?b",
            "/files/a:b",
            "/files/*",
            "/other/a",
            "/filesx/a",
            // A route whose path is not absolute matches nothing, and `*` is not a path.
            "*",
        ] {
            assert_eq!(get(no), Err(Refusal::RouteNotAllowed), "{no}");
        }
        // A `*` that is not the final segment is a literal.
        let literal = vec![route("GET", "/a/*/b")];
        assert!(admit(b"GET /a/*/b HTTP/1.1\r\n\r\n", &literal, PORT).is_ok());
        assert_eq!(
            admit(b"GET /a/x/b HTTP/1.1\r\n\r\n", &literal, PORT),
            Err(Refusal::RouteNotAllowed)
        );
    }

    #[test]
    fn ambiguous_framing_is_refused() {
        // SI-H2-18: `Transfer-Encoding`, two `Content-Length` headers, a non-numeric one, a folded header line.
        bad("POST /api/chat HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nTransfer-Encoding: identity\r\nContent-Length: 2\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\ntransfer-encoding:\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nContent-Length: 2\r\ncontent-length: 3\r\n\r\n");
        for value in [
            "abc",
            "",
            "+2",
            "-2",
            "2, 2",
            "2,2",
            "0x10",
            "1e3",
            "2 2",
            "2.0",
            "18446744073709551616",
            "99999999999999999999999999",
        ] {
            bad(&format!("POST /api/chat HTTP/1.1\r\nContent-Length: {value}\r\n\r\n"));
        }
        bad("POST /api/chat HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX-A: 1\r\n\tfolded\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nExpect: 100-continue\r\n\r\n");
        bad("CONNECT /api/chat HTTP/1.1\r\n\r\n");
        bad("CONNECT hub.example.invalid:443 HTTP/1.1\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
        // A name some servers fold into a framing field.
        bad("POST /api/chat HTTP/1.1\r\nContent_Length: 9\r\nContent-Length: 2\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\ncontent_length: 2\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nTransfer_Encoding: chunked\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nHost: hub\r\nProxy_Connection: x\r\n\r\n");
        // Any other name with an underscore is an ordinary end-to-end field.
        assert!(admit_chat("POST /api/chat HTTP/1.1\r\nX_Trace: 1\r\n\r\n").is_ok());
        // Leading zeros are plain decimal digits: one reading only.
        assert_eq!(
            admit_chat("POST /api/chat HTTP/1.1\r\nContent-Length: 007\r\n\r\n")
                .unwrap()
                .body_len(),
            7
        );
    }

    #[test]
    fn malformed_lines_are_refused() {
        bad("POST /api/chat HTTP/1.1\r\nNoColon\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX-A : 1\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX-A\t: 1\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\n: 1\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX A: 1\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX-A: a\0b\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX-A: caf\u{e9}\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX-A: a\x7fb\r\n\r\n");
        // Bare CR, bare LF.
        bad("POST /api/chat HTTP/1.1\r\nX-A: a\rb\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\r\nX-A: a\nX-B: b\r\n\r\n");
        bad("POST /api/chat HTTP/1.1\nX-A: a\r\n\r\n");
        // The request line.
        bad("\r\n\r\n");
        bad("POST /api/chat\r\n\r\n");
        bad("POST  /api/chat HTTP/1.1\r\n\r\n");
        bad("POST /api/chat HTTP/1.1 \r\n\r\n");
        bad(" POST /api/chat HTTP/1.1\r\n\r\n");
        bad("POST /api/chat HTTP/1.0\r\n\r\n");
        bad("POST /api/chat HTTP/2\r\n\r\n");
        bad("POST /api/chat http/1.1\r\n\r\n");
        bad("PO(ST /api/chat HTTP/1.1\r\n\r\n");
        bad("POST /api/\tchat HTTP/1.1\r\n\r\n");
        bad("POST /api/ch\u{e4}t HTTP/1.1\r\n\r\n");
        // An empty line before the request line.
        bad("\r\nPOST /api/chat HTTP/1.1\r\n\r\n");
        // Host values the hub would not write back.
        for host in [
            "",
            "a b",
            "a/b",
            "a@b",
            "[::1",
            "[::1]x",
            "hub:",
            "hub:99999999",
            "hub:8o",
        ] {
            bad(&format!("GET /api/tags HTTP/1.1\r\nHost: {host}\r\n\r\n"));
        }
        for host in [
            "hub",
            "hub.example.invalid",
            "192.0.2.1:11434",
            "[2001:db8::1]",
            "[2001:db8::1]:80",
        ] {
            assert!(
                admit_chat(&format!("GET /api/tags HTTP/1.1\r\nHost: {host}\r\n\r\n")).is_ok(),
                "{host}"
            );
        }
        // Not a complete head.
        assert!(matches!(
            parse(b"GET /api/tags HTTP/1.1\r\n"),
            Err(Refusal::BadRequest(_))
        ));
    }

    #[test]
    fn the_head_and_body_limits() {
        // 64 header lines pass, 65 do not.
        let with = |n: usize| {
            let mut head = String::from("GET /api/tags HTTP/1.1\r\n");
            for i in 0..n {
                head.push_str(&format!("X-{i}: v\r\n"));
            }
            head.push_str("\r\n");
            head
        };
        assert!(admit_chat(&with(MAX_HEADERS)).is_ok());
        assert_eq!(admit_chat(&with(MAX_HEADERS + 1)), Err(Refusal::HeadersTooLarge));
        // The head is at most 8 KiB, its final empty line included.
        let sized = |len: usize| {
            let fixed = "GET /api/tags HTTP/1.1\r\nX-Pad: \r\n\r\n".len();
            format!("GET /api/tags HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(len - fixed))
        };
        let exact = sized(MAX_HEAD_BYTES);
        assert_eq!(exact.len(), MAX_HEAD_BYTES);
        assert_eq!(head_end(exact.as_bytes(), &mut 0), Ok(Some(MAX_HEAD_BYTES)));
        assert!(admit_chat(&exact).is_ok());
        let over = sized(MAX_HEAD_BYTES + 1);
        assert_eq!(head_end(over.as_bytes(), &mut 0), Err(Refusal::HeadersTooLarge));
        assert_eq!(admit_chat(&over), Err(Refusal::HeadersTooLarge));
        // The body: 1 MiB passes, one byte more is too large; on a route that is not allowed the answer stays 403.
        let length = |n: u64, path: &str| format!("POST {path} HTTP/1.1\r\nContent-Length: {n}\r\n\r\n");
        assert_eq!(
            admit_chat(&length(MAX_BODY_BYTES, "/api/chat")).unwrap().body_len(),
            MAX_BODY_BYTES
        );
        assert_eq!(
            admit_chat(&length(MAX_BODY_BYTES + 1, "/api/chat")),
            Err(Refusal::TooLarge)
        );
        assert_eq!(admit_chat(&length(u64::MAX, "/api/chat")), Err(Refusal::TooLarge));
        assert_eq!(
            admit_chat(&length(MAX_BODY_BYTES + 1, "/api/pull")),
            Err(Refusal::RouteNotAllowed)
        );
    }

    #[test]
    fn the_end_of_the_head_is_found_however_the_bytes_arrive() {
        let head = b"POST /api/chat HTTP/1.1\r\nHost: hub\r\n\r\n";
        let mut all = head.to_vec();
        all.extend_from_slice(b"body\r\n\r\nmore");
        // Byte by byte, with one cursor: found exactly when the last byte of the head is there.
        let mut scanned = 0;
        for have in 0..head.len() {
            assert_eq!(head_end(&all[..have], &mut scanned), Ok(None), "{have}");
            assert!(scanned <= have);
        }
        assert_eq!(head_end(&all[..head.len()], &mut scanned), Ok(Some(head.len())));
        // All at once: the end of the head, not a later empty line of the body.
        assert_eq!(head_end(&all, &mut 0), Ok(Some(head.len())));
        // A bare LF or CR is refused as soon as it is seen, without waiting for more.
        assert!(matches!(
            head_end(b"GET /api/tags HTTP/1.1\nHost", &mut 0),
            Err(Refusal::BadRequest(_))
        ));
        assert!(matches!(head_end(b"GET /a\rb", &mut 0), Err(Refusal::BadRequest(_))));
        assert!(matches!(head_end(b"\n", &mut 0), Err(Refusal::BadRequest(_))));
        // A CR at the end of what arrived waits for its LF.
        let mut scanned = 0;
        assert_eq!(head_end(b"GET /api/tags HTTP/1.1\r", &mut scanned), Ok(None));
        assert_eq!(head_end(b"GET /api/tags HTTP/1.1\r\n\r", &mut scanned), Ok(None));
        assert_eq!(head_end(b"GET /api/tags HTTP/1.1\r\n\r\n", &mut scanned), Ok(Some(26)));
        // 8 KiB with no end of head: too large, also when it is all one line.
        let endless = vec![b'a'; MAX_HEAD_BYTES];
        assert_eq!(head_end(&endless, &mut 0), Err(Refusal::HeadersTooLarge));
        assert_eq!(head_end(&endless[..MAX_HEAD_BYTES - 1], &mut 0), Ok(None));
    }

    /// The smuggling case of SI-H2-18: `Connection: content-length` on a `POST /api/chat` whose body holds a
    /// `POST /api/pull`. A service that dropped `Content-Length` as hop-by-hop would read the body as a second
    /// request, so the hub refuses the request and forwards nothing.
    #[test]
    fn a_connection_option_cannot_make_the_service_drop_the_framing() {
        let smuggled = "POST /api/pull HTTP/1.1\r\nHost: hub\r\nContent-Length: 2\r\n\r\n{}";
        let head = format!(
            "POST /api/chat HTTP/1.1\r\nHost: hub\r\nConnection: content-length\r\nContent-Length: {}\r\n\r\n",
            smuggled.len()
        );
        assert!(matches!(admit_chat(&head), Err(Refusal::BadRequest(_))));
    }

    /// Lines that end up in generated heads: valid ones, hop-by-hop ones and every kind the filter refuses.
    fn line() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("Host: hub.example.invalid".to_string()),
            Just("Content-Type: application/json".to_string()),
            Just("Content-Length: 5".to_string()),
            Just("content-length: 0".to_string()),
            Just("Content-Length: 5, 5".to_string()),
            Just("Content-Length: 1048577".to_string()),
            Just("Transfer-Encoding: chunked".to_string()),
            Just("Content_Length: 9".to_string()),
            Just("Transfer_Encoding: chunked".to_string()),
            Just("Connection: close".to_string()),
            Just("Connection: keep-alive, te".to_string()),
            Just("Connection: content-length".to_string()),
            Just("Connection: x-secret".to_string()),
            Just("Keep-Alive: timeout=1".to_string()),
            Just("TE: trailers".to_string()),
            Just("Trailer: X".to_string()),
            Just("Proxy-Authorization: x".to_string()),
            Just("Upgrade: h2c".to_string()),
            Just("Expect: 100-continue".to_string()),
            Just(" folded".to_string()),
            Just("NoColon".to_string()),
            Just("X-A : b".to_string()),
            "[A-Za-z-]{1,12}: [ -~]{0,24}",
            "[ -~\t\r\n]{0,24}",
        ]
    }

    fn request_line() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("POST /api/chat HTTP/1.1".to_string()),
            Just("GET /api/tags HTTP/1.1".to_string()),
            Just("POST /api/pull HTTP/1.1".to_string()),
            Just("POST /api/chat?a HTTP/1.1".to_string()),
            Just("CONNECT /api/chat HTTP/1.1".to_string()),
            Just("POST /api/chat HTTP/1.0".to_string()),
            "[A-Z]{1,7} /[a-z/.%?#*]{0,16} HTTP/1\\.[01]",
            "[ -~]{0,32}",
        ]
    }

    proptest! {
        /// Whatever the head, what the hub forwards is one unambiguous request to an allowed route: the rewritten
        /// head parses to the same request, has exactly one `Content-Length` and one `Connection: close`, no
        /// `Transfer-Encoding`, `Upgrade` or `Expect`, no hop-by-hop field, at most one `Host`, and only clean
        /// lines.
        #[test]
        fn what_is_admitted_is_forwarded_as_one_unambiguous_request(
            first in request_line(),
            lines in proptest::collection::vec(line(), 0..12),
        ) {
            let mut head = first;
            head.push_str("\r\n");
            for l in &lines {
                head.push_str(l);
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            let Ok(request) = admit(head.as_bytes(), &chat_routes(), PORT) else {
                return Ok(());
            };
            prop_assert!(request.body_len() <= MAX_BODY_BYTES);
            prop_assert!(
                (request.method(), request.target()) == ("POST", "/api/chat")
                    || (request.method(), request.target()) == ("GET", "/api/tags")
            );
            let out = request.head();
            prop_assert_eq!(head_end(&out, &mut 0), Ok(Some(out.len())));
            let text = String::from_utf8(out.clone()).unwrap();
            let names: Vec<String> = text
                .trim_end_matches("\r\n")
                .split("\r\n")
                .skip(1)
                // Underscores folded, as a lenient server would read the names.
                .map(|l| l.split(':').next().unwrap().to_ascii_lowercase().replace('_', "-"))
                .collect();
            let count = |name: &str| names.iter().filter(|n| *n == name).count();
            prop_assert_eq!(count("content-length"), 1);
            prop_assert_eq!(count("connection"), 1);
            prop_assert!(count("host") <= 1);
            for gone in ["transfer-encoding", "upgrade", "expect", "keep-alive", "te", "trailer"] {
                prop_assert_eq!(count(gone), 0, "{}", gone);
            }
            prop_assert!(!names.iter().any(|n| n.starts_with("proxy-")));
            let tail = format!("Content-Length: {}\r\nConnection: close\r\n\r\n", request.body_len());
            prop_assert!(text.ends_with(&tail));
            // Stable: the forwarded head is admitted again as the same request.
            let again = admit(&out, &chat_routes(), PORT);
            prop_assert_eq!(again.as_ref().map(Request::head), Ok(out));
        }

        /// The parser never panics, on any bytes.
        #[test]
        fn any_bytes_are_handled(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut scanned = 0;
            if let Ok(Some(end)) = head_end(&bytes, &mut scanned) {
                let _ = admit(&bytes[..end], &chat_routes(), PORT);
            }
            let _ = parse(&bytes);
        }
    }
}
