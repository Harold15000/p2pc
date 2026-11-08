// SPDX-License-Identifier: Apache-2.0

//! OCI image references: parsing and normalization.
//!
//! Follows the grammar of the OCI distribution reference (the `distribution/reference` package used by Docker and
//! Podman):
//!
//! ```text
//! reference       := name [ ":" tag ] [ "@" digest ]
//! name            := [ domain "/" ] path
//! domain          := host [ ":" port ]
//! host            := domain-component ( "." domain-component )* | "[" ipv6 "]"
//! domain-component:= [a-zA-Z0-9] | [a-zA-Z0-9] [a-zA-Z0-9-]* [a-zA-Z0-9]
//! path            := path-component ( "/" path-component )*
//! path-component  := [a-z0-9]+ ( separator [a-z0-9]+ )*
//! separator       := "." | "_" | "__" | "-"+
//! tag             := [A-Za-z0-9_] [A-Za-z0-9_.-]{0,127}
//! digest          := "sha256:" [a-f0-9]{64}
//! ```
//!
//! The first path component is a domain only if it contains `.` or `:`, is `localhost`, or has an uppercase letter;
//! otherwise the image is on Docker Hub. Only `sha256` digests are accepted.
//!
//! **Stricter than Docker:** a single-label registry detected only because of an uppercase letter (`Registry/app`)
//! is refused. Lowercased, it would re-parse as a Docker Hub path (`docker.io/registry/app`), so its normalized form
//! would name a different image. With this rule, normalization is idempotent: parsing the normalized form gives the
//! same reference.
//!
//! Normalization:
//! - `python:3.12` becomes `docker.io/library/python:3.12` (and `index.docker.io` becomes `docker.io`);
//! - a missing tag becomes `:latest`, unless a digest is given;
//! - the registry host is lowercased.

use std::fmt;
use std::str::FromStr;

/// The default registry.
pub const DOCKER_HUB: &str = "docker.io";
/// Docker Hub's legacy name, normalized to [`DOCKER_HUB`].
const DOCKER_HUB_LEGACY: &str = "index.docker.io";
/// Longest accepted input, before any parsing.
const MAX_INPUT_LEN: usize = 1024;
/// Longest normalized name (registry plus repository), as in `distribution/reference`.
const MAX_NAME_LEN: usize = 255;
/// Longest tag.
const MAX_TAG_LEN: usize = 128;
/// Longest domain component.
const MAX_LABEL_LEN: usize = 63;

/// Why an image reference is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImageRefError {
    /// The reference is empty.
    #[error("the image reference is empty")]
    Empty,
    /// The reference or its name is too long.
    #[error("the image reference is too long")]
    TooLong,
    /// The registry host or port is invalid.
    #[error("the image registry is invalid")]
    InvalidRegistry,
    /// The repository path is invalid (it must be lowercase).
    #[error("the image repository is invalid (lowercase letters, digits and . _ __ - separators)")]
    InvalidRepository,
    /// The tag is invalid.
    #[error("the image tag is invalid")]
    InvalidTag,
    /// The digest is not `sha256:` plus 64 lowercase hex characters.
    #[error("the image digest must be sha256: followed by 64 lowercase hex characters")]
    InvalidDigest,
}

/// A parsed and normalized OCI image reference.
///
/// Its `Display` is the normalized form, for example `docker.io/library/python:3.12`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageRef {
    registry: String,
    repository: String,
    tag: Option<String>,
    digest: Option<String>,
}

impl ImageRef {
    /// Parses and normalizes a reference.
    pub fn parse(input: &str) -> Result<Self, ImageRefError> {
        if input.is_empty() {
            return Err(ImageRefError::Empty);
        }
        if input.len() > MAX_INPUT_LEN {
            return Err(ImageRefError::TooLong);
        }
        let (name_tag, digest) = match input.split_once('@') {
            Some((name_tag, digest)) => {
                check_digest(digest)?;
                (name_tag, Some(digest.to_string()))
            }
            None => (input, None),
        };
        // The tag follows the last `:`, unless a `/` comes after it (then the `:` belongs to a registry port).
        let (name, tag) = match name_tag.rfind(':') {
            Some(i) if !name_tag[i + 1..].contains('/') => (&name_tag[..i], Some(&name_tag[i + 1..])),
            _ => (name_tag, None),
        };
        if let Some(tag) = tag {
            check_tag(tag)?;
        }
        let (domain, path) = split_domain(name);
        let registry = match domain {
            Some(domain) => normalize_domain(domain)?,
            None => DOCKER_HUB.to_string(),
        };
        check_path(path)?;
        let repository = if registry == DOCKER_HUB && !path.contains('/') {
            format!("library/{path}")
        } else {
            path.to_string()
        };
        if registry.len() + 1 + repository.len() > MAX_NAME_LEN {
            return Err(ImageRefError::TooLong);
        }
        let tag = match (tag, &digest) {
            (Some(tag), _) => Some(tag.to_string()),
            (None, None) => Some("latest".to_string()),
            (None, Some(_)) => None,
        };
        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// The registry, lowercase, with its port if any (for example `docker.io` or `localhost:5000`).
    #[must_use]
    pub fn registry(&self) -> &str {
        &self.registry
    }

    /// The repository path, for example `library/python`.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The tag. `latest` when the input had neither a tag nor a digest.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The digest, `sha256:<hex>`, if pinned.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

/// Splits off the registry: the first component is one only if it contains `.` or `:`, is `localhost`, or has an
/// uppercase letter (the rule of `distribution/reference`).
fn split_domain(name: &str) -> (Option<&str>, &str) {
    match name.split_once('/') {
        Some((first, rest))
            if first.contains(['.', ':']) || first == "localhost" || first.bytes().any(|b| b.is_ascii_uppercase()) =>
        {
            (Some(first), rest)
        }
        _ => (None, name),
    }
}

/// Validates `host[:port]` and returns it lowercased, with Docker Hub's legacy name mapped to `docker.io`.
fn normalize_domain(domain: &str) -> Result<String, ImageRefError> {
    let bad = ImageRefError::InvalidRegistry;
    let port = if let Some(rest) = domain.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port`
        let (inner, after) = rest.split_once(']').ok_or(bad)?;
        inner.parse::<std::net::Ipv6Addr>().map_err(|_| bad)?;
        match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(bad)?),
        }
    } else {
        let (host, port) = match domain.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (domain, None),
        };
        if !host.split('.').all(domain_component_ok) {
            return Err(bad);
        }
        port
    };
    if let Some(port) = port {
        let digits_ok = (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit());
        if !digits_ok || port.parse::<u16>().map_or(true, |p| p == 0) {
            return Err(bad);
        }
    }
    let normalized = domain.to_ascii_lowercase();
    // A single-label registry that was detected only because of its uppercase letters (`Registry/app`) would lose
    // that signal when lowercased, and `registry/app` re-parses as a Docker Hub path: a different image. Refuse it,
    // so normalization stays idempotent. `localhost` is a registry in any case.
    if !normalized.contains(['.', ':', '[']) && normalized != "localhost" {
        return Err(bad);
    }
    Ok(if normalized == DOCKER_HUB_LEGACY {
        DOCKER_HUB.to_string()
    } else {
        normalized
    })
}

/// `[a-zA-Z0-9]` or `[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]`, at most 63 characters.
fn domain_component_ok(c: &str) -> bool {
    let b = c.as_bytes();
    let edge = |x: &u8| x.is_ascii_alphanumeric();
    !b.is_empty()
        && b.len() <= MAX_LABEL_LEN
        && b.first().is_some_and(edge)
        && b.last().is_some_and(edge)
        && b.iter().all(|x| x.is_ascii_alphanumeric() || *x == b'-')
}

fn check_path(path: &str) -> Result<(), ImageRefError> {
    if !path.is_empty() && path.split('/').all(path_component_ok) {
        Ok(())
    } else {
        Err(ImageRefError::InvalidRepository)
    }
}

/// `[a-z0-9]+ ( ( "." | "_" | "__" | "-"+ ) [a-z0-9]+ )*`
fn path_component_ok(c: &str) -> bool {
    let b = c.as_bytes();
    let alnum = |i: usize| b.get(i).is_some_and(|x| x.is_ascii_lowercase() || x.is_ascii_digit());
    let mut i = 0;
    loop {
        let start = i;
        while alnum(i) {
            i += 1;
        }
        if i == start {
            return false;
        }
        match b.get(i) {
            None => return true,
            Some(b'.') => i += 1,
            Some(b'_') => i += if b.get(i + 1) == Some(&b'_') { 2 } else { 1 },
            Some(b'-') => {
                while b.get(i) == Some(&b'-') {
                    i += 1;
                }
            }
            Some(_) => return false,
        }
    }
}

/// `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`
fn check_tag(tag: &str) -> Result<(), ImageRefError> {
    let b = tag.as_bytes();
    let word = |x: &u8| x.is_ascii_alphanumeric() || *x == b'_';
    let ok = !b.is_empty()
        && b.len() <= MAX_TAG_LEN
        && b.first().is_some_and(word)
        && b.iter().all(|x| word(x) || *x == b'.' || *x == b'-');
    if ok { Ok(()) } else { Err(ImageRefError::InvalidTag) }
}

/// `sha256:` plus 64 lowercase hex characters.
fn check_digest(digest: &str) -> Result<(), ImageRefError> {
    let hex = digest.strip_prefix("sha256:").ok_or(ImageRefError::InvalidDigest)?;
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(ImageRefError::InvalidDigest)
    }
}

impl FromStr for ImageRef {
    type Err = ImageRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn norm(s: &str) -> String {
        ImageRef::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}")).to_string()
    }

    /// Every valid reference with its normalized form. Shared by the normalization and idempotence tests.
    fn valid_cases() -> Vec<(String, String)> {
        let tag128 = format!("t{}", "a".repeat(127));
        vec![
            ("python:3.12".into(), "docker.io/library/python:3.12".into()),
            ("python".into(), "docker.io/library/python:latest".into()),
            ("python:3.12-slim".into(), "docker.io/library/python:3.12-slim".into()),
            ("library/python".into(), "docker.io/library/python:latest".into()),
            ("user/app:v1".into(), "docker.io/user/app:v1".into()),
            ("docker.io/python".into(), "docker.io/library/python:latest".into()),
            ("docker.io/library/python:3".into(), "docker.io/library/python:3".into()),
            (
                "index.docker.io/library/python:3".into(),
                "docker.io/library/python:3".into(),
            ),
            (
                "index.docker.io/python".into(),
                "docker.io/library/python:latest".into(),
            ),
            ("ghcr.io/org/team/app:1.0.0".into(), "ghcr.io/org/team/app:1.0.0".into()),
            ("localhost:5000/app".into(), "localhost:5000/app:latest".into()),
            ("localhost/app".into(), "localhost/app:latest".into()),
            (
                "registry.example.com:8443/a/b:tag".into(),
                "registry.example.com:8443/a/b:tag".into(),
            ),
            (
                "REGISTRY.Example.COM/app:Tag".into(),
                "registry.example.com/app:Tag".into(),
            ),
            ("Docker.IO/python".into(), "docker.io/library/python:latest".into()),
            // `localhost` is a registry in any case, so the lowercased form re-parses to the same registry.
            ("LOCALHOST/app".into(), "localhost/app:latest".into()),
            (
                format!("python@sha256:{D}"),
                format!("docker.io/library/python@sha256:{D}"),
            ),
            (
                format!("ghcr.io/a/b:1.0@sha256:{D}"),
                format!("ghcr.io/a/b:1.0@sha256:{D}"),
            ),
            ("quay.io/a/b_c.d-e:1".into(), "quay.io/a/b_c.d-e:1".into()),
            ("a/b__c".into(), "docker.io/a/b__c:latest".into()),
            ("a/b---c".into(), "docker.io/a/b---c:latest".into()),
            ("192.0.2.10:5000/app:1".into(), "192.0.2.10:5000/app:1".into()),
            ("[2001:DB8::1]:5000/app".into(), "[2001:db8::1]:5000/app:latest".into()),
            (format!("python:{tag128}"), format!("docker.io/library/python:{tag128}")),
            (
                "nvcr.io/nvidia/pytorch:24.01-py3".into(),
                "nvcr.io/nvidia/pytorch:24.01-py3".into(),
            ),
            (
                "registry.gitlab.com/group/sub/project/image:main".into(),
                "registry.gitlab.com/group/sub/project/image:main".into(),
            ),
            ("app:V1.2_3-rc".into(), "docker.io/library/app:V1.2_3-rc".into()),
            ("app:_x".into(), "docker.io/library/app:_x".into()),
            ("example.com:443/x".into(), "example.com:443/x:latest".into()),
            // No slash: `ghcr.io` and `localhost` are repository names, and `:5000` is a tag (as in Docker).
            ("ghcr.io".into(), "docker.io/library/ghcr.io:latest".into()),
            ("localhost:5000".into(), "docker.io/library/localhost:5000".into()),
            ("a0-b.example/x".into(), "a0-b.example/x:latest".into()),
        ]
    }

    #[test]
    fn valid_references_normalize() {
        for (input, want) in valid_cases() {
            assert_eq!(norm(&input), want, "{input:?}");
        }
    }

    #[test]
    fn parts_are_exposed() {
        let r = ImageRef::parse(&format!("LocalHost:5000/a/b:t@sha256:{D}")).unwrap();
        assert_eq!(r.registry(), "localhost:5000");
        assert_eq!(r.repository(), "a/b");
        assert_eq!(r.tag(), Some("t"));
        assert_eq!(r.digest(), Some(format!("sha256:{D}").as_str()));
        let r = ImageRef::parse(&format!("python@sha256:{D}")).unwrap();
        assert_eq!(r.tag(), None);
    }

    #[test]
    /// Review P3: normalizing the normalized form changes nothing, for **every** valid case.
    fn normalization_is_idempotent() {
        let mut inputs: Vec<String> = valid_cases().into_iter().map(|(input, _)| input).collect();
        inputs.extend(["a/b:c", "LOCALHOST:1/x"].map(String::from));
        for input in inputs {
            let once = norm(&input);
            assert_eq!(norm(&once), once, "{input:?}");
            assert_eq!(ImageRef::parse(&once), ImageRef::parse(&input), "{input:?}");
        }
    }

    #[test]
    fn single_label_registries_detected_only_by_uppercase_are_rejected() {
        // `Registry/app` would normalize to `registry/app:latest`, which re-parses as a Docker Hub path
        // (`docker.io/registry/app`): a different image. It is refused instead.
        for input in ["Registry/app", "MyReg/team/app:1", "R/x"] {
            assert_eq!(ImageRef::parse(input), Err(ImageRefError::InvalidRegistry), "{input:?}");
        }
        // With a dot, a port or `localhost`, the registry survives lowercasing, so it is accepted.
        for input in ["Registry.example/app", "Registry:5000/app", "LocalHost/app"] {
            assert!(ImageRef::parse(input).is_ok(), "{input:?}");
        }
    }

    #[test]
    fn invalid_references_are_rejected() {
        use ImageRefError::*;
        let long_path = format!("ghcr.io/{}", "a".repeat(250));
        let long_tag = format!("python:t{}", "a".repeat(128));
        let cases: Vec<(String, ImageRefError)> = vec![
            ("".into(), Empty),
            ("Python:3.12".into(), InvalidRepository),
            ("docker.io/Library/python".into(), InvalidRepository),
            ("python:".into(), InvalidTag),
            ("python:-bad".into(), InvalidTag),
            ("python:.bad".into(), InvalidTag),
            ("python:a+b".into(), InvalidTag),
            (long_tag, InvalidTag),
            ("python@sha256:abc".into(), InvalidDigest),
            (format!("python@sha512:{D}{D}"), InvalidDigest),
            (format!("python@sha256:{}", D.to_uppercase()), InvalidDigest),
            ("python@".into(), InvalidDigest),
            (format!("python@sha256:{D}@sha256:{D}"), InvalidDigest),
            ("a//b".into(), InvalidRepository),
            ("a/b/".into(), InvalidRepository),
            ("/a".into(), InvalidRepository),
            ("a/.b".into(), InvalidRepository),
            ("a/b..c".into(), InvalidRepository),
            ("a/b._c".into(), InvalidRepository),
            ("a/b___c".into(), InvalidRepository),
            ("a_/b".into(), InvalidRepository),
            ("a/-b".into(), InvalidRepository),
            ("a/b-".into(), InvalidRepository),
            ("ghcr.io:abc/app".into(), InvalidRegistry),
            ("ghcr.io:70000/app".into(), InvalidRegistry),
            ("ghcr.io:0/app".into(), InvalidRegistry),
            ("ghcr.io:/app".into(), InvalidRegistry),
            ("-ghcr.io/app".into(), InvalidRegistry),
            ("ghcr-.io/app".into(), InvalidRegistry),
            ("ghcr..io/app".into(), InvalidRegistry),
            ("gh_cr.io/app".into(), InvalidRegistry),
            ("[2001:db8::1/app".into(), InvalidRegistry),
            ("[]:5000/app".into(), InvalidRegistry),
            (format!("{}.example/app", "a".repeat(64)), InvalidRegistry),
            ("ghcr.io/".into(), InvalidRepository),
            ("python:3 x".into(), InvalidTag),
            ("pyth on".into(), InvalidRepository),
            ("python\n".into(), InvalidRepository),
            ("pythön".into(), InvalidRepository),
            (":tag".into(), InvalidRepository),
            ("@sha256:x".into(), InvalidDigest),
            (long_path, TooLong),
            ("a".repeat(2000), TooLong),
        ];
        for (input, want) in cases {
            assert_eq!(ImageRef::parse(&input), Err(want), "{input:?}");
        }
    }
}
