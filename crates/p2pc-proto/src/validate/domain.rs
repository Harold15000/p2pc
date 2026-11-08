// SPDX-License-Identifier: Apache-2.0

//! Egress domains: syntax of `egress.allow` entries and whole-label allowlist matching (spec §7, §9, SI-5).
//!
//! The T09 egress proxy calls [`domain_allowed`] on the host of every `CONNECT` and absolute-URI request. It only
//! decides on names: the proxy still resolves DNS itself and refuses private, loopback, CGNAT, link-local and host
//! addresses (SI-4).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Longest domain name, in bytes, without a trailing dot (RFC 1035).
pub const MAX_DOMAIN_LEN: usize = 253;
/// Longest label (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// Why a domain name is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// The name is empty.
    #[error("the domain is empty")]
    Empty,
    /// Longer than 253 bytes.
    #[error("the domain is longer than 253 characters")]
    TooLong,
    /// Wildcards are not allowed: an entry already matches its subdomains.
    #[error("wildcards are not allowed; an entry already matches its subdomains")]
    Wildcard,
    /// IP literals are never allowed.
    #[error("IP addresses are not allowed, only domain names")]
    IpLiteral,
    /// Entries must be lowercase.
    #[error("the domain must be lowercase")]
    NotLowercase,
    /// Entries must not end with a dot.
    #[error("the domain must not end with a dot")]
    TrailingDot,
    /// A label is empty, too long, or not letters, digits and inner hyphens (non-ASCII names must be punycode).
    #[error("each label must be 1-63 characters of a-z, 0-9 and inner hyphens (use punycode for non-ASCII)")]
    InvalidLabel,
    /// A single-label name (such as `localhost`) could resolve through local search domains.
    #[error("the domain must have at least two labels")]
    SingleLabel,
    /// The last label looks numeric, which URL parsers treat as an IPv4 address.
    #[error("the top-level label must not be numeric")]
    NumericTld,
}

/// Checks the syntax of an `egress.allow` entry (§7): lowercase LDH labels, at most 253 characters, at least two
/// labels, no wildcards, no IP literals and no trailing dot. Internationalized names must be given as punycode
/// (`xn--…`); they are not converted.
pub fn validate_egress_domain(domain: &str) -> Result<(), DomainError> {
    if domain.is_empty() {
        return Err(DomainError::Empty);
    }
    if domain.contains('*') {
        return Err(DomainError::Wildcard);
    }
    if is_ip_literal(domain) {
        return Err(DomainError::IpLiteral);
    }
    if domain.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(DomainError::NotLowercase);
    }
    if domain.ends_with('.') {
        return Err(DomainError::TrailingDot);
    }
    check_labels(domain)
}

/// IPv4 or IPv6, with or without brackets.
fn is_ip_literal(s: &str) -> bool {
    let inner = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
    inner.parse::<Ipv4Addr>().is_ok() || inner.parse::<Ipv6Addr>().is_ok()
}

/// Lowercase LDH labels, total length, at least two labels, and a non-numeric last label.
fn check_labels(domain: &str) -> Result<(), DomainError> {
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(DomainError::TooLong);
    }
    let mut count = 0;
    let mut last = "";
    for label in domain.split('.') {
        let b = label.as_bytes();
        let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        let ok = !b.is_empty()
            && b.len() <= MAX_LABEL_LEN
            && b.first().is_some_and(edge)
            && b.last().is_some_and(edge)
            && b.iter().all(|c| edge(c) || *c == b'-');
        if !ok {
            return Err(DomainError::InvalidLabel);
        }
        count += 1;
        last = label;
    }
    if count < 2 {
        return Err(DomainError::SingleLabel);
    }
    // WHATWG URL parsing treats a host whose last label is a number (decimal or 0x hex) as IPv4.
    let numeric = last.bytes().all(|c| c.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|h| h.bytes().all(|c| c.is_ascii_hexdigit()));
    if numeric {
        return Err(DomainError::NumericTld);
    }
    Ok(())
}

/// Lowercases, strips one trailing dot, and returns the host only if it is a valid domain name.
fn normalize_host(host: &str) -> Option<String> {
    let lower = host.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    if name.is_empty() || name.contains('*') || is_ip_literal(name) {
        return None;
    }
    check_labels(name).ok()?;
    Some(name.to_string())
}

/// Whether `host` is allowed by `allowlist`, matching whole labels.
///
/// `example.com` allows `example.com` and `a.example.com`, but neither `evilexample.com` nor
/// `example.com.evil.net`. The host is lowercased and one trailing dot is stripped. IP literals (IPv4, IPv6,
/// bracketed or not) and syntactically invalid hosts are always refused. Allowlist entries are normalized the same
/// way, and invalid entries match nothing.
#[must_use]
pub fn domain_allowed(allowlist: &[String], host: &str) -> bool {
    let Some(host) = normalize_host(host) else {
        return false;
    };
    allowlist.iter().filter_map(|entry| normalize_host(entry)).any(|entry| {
        // Equal, or a subdomain: `host` ends with `.` + `entry`. Both are valid LDH names, so this is whole-label.
        host == entry
            || host
                .strip_suffix(entry.as_str())
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn domain_allowed_table() {
        let ex = list(&["example.com"]);
        let pypi = list(&["pypi.org", "files.pythonhosted.org"]);
        let puny = list(&["xn--bcher-kva.example"]);
        let cases: Vec<(&Vec<String>, &str, bool)> = vec![
            (&ex, "example.com", true),
            (&ex, "a.example.com", true),
            (&ex, "a.b.example.com", true),
            (&ex, "EXAMPLE.COM", true),
            (&ex, "example.com.", true),
            (&ex, "A.Example.Com.", true),
            (&ex, "1.2.3.4.example.com", true),
            (&ex, "evilexample.com", false),
            (&ex, "a.evilexample.com", false),
            (&ex, "example.com.evil.net", false),
            (&ex, "example.co", false),
            (&ex, "xample.com", false),
            (&ex, "com", false),
            (&ex, "", false),
            (&ex, ".", false),
            (&ex, "example.com..", false),
            (&ex, ".example.com", false),
            (&ex, "a..example.com", false),
            (&ex, "example.com:443", false),
            (&ex, "*.example.com", false),
            (&ex, "exa_mple.com", false),
            (&ex, "a_b.example.com", false),
            (&ex, "exa mple.com", false),
            (&ex, "example.com\0", false),
            (&ex, "-a.example.com", false),
            (&ex, "a-.example.com", false),
            (&ex, "192.0.2.1", false),
            (&ex, "::1", false),
            (&ex, "[::1]", false),
            (&ex, "2001:db8::1", false),
            (&ex, "[2001:db8::1]", false),
            (&ex, "::ffff:192.0.2.1", false),
            (&ex, "example.123", false),
            // §9 egress test vectors (from E8: the gaps found in Bacalhau's gateway).
            (&ex, "user@example.com", false),
            (&ex, "user@a.example.com", false),
            (&ex, "example.com@evil.net", false),
            (&ex, "example.com/path", false),
            (&ex, "evil.net/example.com", false),
            (&ex, "[::ffff:192.0.2.1]", false),
            (&ex, "::ffff:c000:201", false),
            (&ex, "[::ffff:c000:201]", false),
            (&ex, "EXAMPLE.COM.", true),
            (&ex, "A.EXAMPLE.COM.", true),
            (&ex, "EVILEXAMPLE.COM.", false),
            (&ex, "example.com.evil.net.", false),
            (&ex, "0x7f.0x0.0x0.0x1", false),
            (&pypi, "files.pythonhosted.org", true),
            (&pypi, "pythonhosted.org", false),
            (&pypi, "pypi.org", true),
            (&pypi, "upload.pypi.org", true),
            (&pypi, "pypi.org.example.com", false),
            (&puny, "xn--bcher-kva.example", true),
            (&puny, "sub.xn--bcher-kva.example", true),
            (&puny, "bücher.example", false),
        ];
        for (allow, host, want) in cases {
            assert_eq!(domain_allowed(allow, host), want, "{allow:?} vs {host:?}");
        }
    }

    #[test]
    fn ip_literals_are_refused_even_when_allowlisted() {
        for ip in [
            "192.0.2.1",
            "198.51.100.7",
            "2001:db8::1",
            "[2001:db8::1]",
            "127.0.0.1",
            "::1",
        ] {
            assert!(!domain_allowed(&list(&[ip]), ip), "{ip}");
        }
    }

    #[test]
    fn invalid_entries_match_nothing() {
        assert!(!domain_allowed(&list(&["*.example.com"]), "a.example.com"));
        assert!(!domain_allowed(&list(&["com"]), "example.com"));
        assert!(!domain_allowed(&list(&[""]), "example.com"));
        assert!(!domain_allowed(&list(&["."]), "example.com"));
        assert!(!domain_allowed(&[], "example.com"));
        // Entries are normalized like hosts.
        assert!(domain_allowed(&list(&["Example.COM."]), "a.example.com"));
    }

    #[test]
    fn overlong_hosts_and_labels_are_refused() {
        let label64 = "a".repeat(64);
        assert!(!domain_allowed(
            &list(&["example.com"]),
            &format!("{label64}.example.com")
        ));
        let label63 = "a".repeat(63);
        assert!(domain_allowed(
            &list(&["example.com"]),
            &format!("{label63}.example.com")
        ));
        let long = format!("{}example.com", "a.".repeat(122)); // 255 bytes
        assert!(!domain_allowed(&list(&["example.com"]), &long));
    }

    #[test]
    fn validate_egress_domain_table() {
        use DomainError::*;
        let label64 = "a".repeat(64);
        let too_long = format!("{}example.com", "a.".repeat(122));
        let ok = [
            "pypi.org",
            "files.pythonhosted.org",
            "xn--bcher-kva.example",
            "a-b.example.com",
            "1.example.com",
            "a.b.c.d.e",
            "example.com",
        ];
        for d in ok {
            assert_eq!(validate_egress_domain(d), Ok(()), "{d:?}");
        }
        let bad: Vec<(String, DomainError)> = vec![
            ("".into(), Empty),
            ("Pypi.org".into(), NotLowercase),
            ("*.pypi.org".into(), Wildcard),
            ("pypi.*".into(), Wildcard),
            ("192.0.2.1".into(), IpLiteral),
            ("2001:db8::1".into(), IpLiteral),
            ("[2001:db8::1]".into(), IpLiteral),
            ("pypi.org:443".into(), InvalidLabel),
            ("pypi.org.".into(), TrailingDot),
            ("localhost".into(), SingleLabel),
            ("-a.com".into(), InvalidLabel),
            ("a-.com".into(), InvalidLabel),
            ("a..com".into(), InvalidLabel),
            (".a.com".into(), InvalidLabel),
            ("a_b.com".into(), InvalidLabel),
            ("a b.com".into(), InvalidLabel),
            ("bücher.example".into(), InvalidLabel),
            (format!("{label64}.com"), InvalidLabel),
            (too_long, TooLong),
            ("example.123".into(), NumericTld),
            ("1.2.3.256".into(), NumericTld),
            ("a.0x1f".into(), NumericTld),
        ];
        for (d, want) in bad {
            assert_eq!(validate_egress_domain(&d), Err(want), "{d:?}");
        }
    }
}
