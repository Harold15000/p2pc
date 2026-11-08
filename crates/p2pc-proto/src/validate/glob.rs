// SPDX-License-Identifier: Apache-2.0

//! Glob matching for a key's `allowed_images` (spec §5).
//!
//! A pattern is matched against the **normalized** image reference (see [`ImageRef`]), for example
//! `docker.io/library/python:3.12`. Write patterns in that normalized form: `python:*` matches nothing, while
//! `docker.io/library/python:*` matches every tag (and a tag pinned with a digest, since `*` also matches `@`).
//!
//! - `*` matches any run of characters except `/` (within one path segment);
//! - `**` matches any run of characters, `/` included (across segments);
//! - every other character matches itself. Matching is case-sensitive.
//!
//! Matching is dynamic programming over the pattern and the text, so no pattern can make it take exponential time.

use super::image::ImageRef;

/// Longest pattern that can match. Longer patterns match nothing.
pub const MAX_PATTERN_LEN: usize = 1024;

/// Why an `allowed_images` pattern is refused when a key is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    /// Empty.
    #[error("the pattern is empty")]
    Empty,
    /// Not printable ASCII, or contains whitespace.
    #[error("the pattern must be printable ASCII without spaces")]
    InvalidChar,
    /// Uses a glob feature that is not supported: `? [ ] { } \` would only match themselves.
    #[error("only `*` and `**` are supported; `? [ ] {{ }} \\` are not")]
    Unsupported,
    /// Three or more `*` in a row.
    #[error("use `*` or `**`, not three or more `*` in a row")]
    TooManyStars,
}

/// Checks the syntax of an `allowed_images` pattern: printable ASCII without spaces, only `*` and `**` as
/// wildcards, and no run of three or more `*`. (Length limits are the caller's: see `CreateApiKey::validate`.)
pub fn validate_pattern(pattern: &str) -> Result<(), PatternError> {
    if pattern.is_empty() {
        return Err(PatternError::Empty);
    }
    if !pattern.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(PatternError::InvalidChar);
    }
    if pattern.contains(['?', '[', ']', '{', '}', '\\']) {
        return Err(PatternError::Unsupported);
    }
    if pattern.contains("***") {
        return Err(PatternError::TooManyStars);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    Byte(u8),
    /// `*`
    Star,
    /// `**`
    DoubleStar,
}

/// Whether `pattern` matches the whole of `text`.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern.len() > MAX_PATTERN_LEN {
        return false;
    }
    let text = text.as_bytes();
    // `reach[j]`: the tokens seen so far match `text[..j]`. O(pattern × text) time, O(text) memory.
    let mut reach = vec![false; text.len() + 1];
    reach[0] = true;
    let mut next = vec![false; text.len() + 1];
    for token in tokenize(pattern.as_bytes()) {
        match token {
            Token::Star | Token::DoubleStar => {
                next[0] = reach[0];
                for j in 1..=text.len() {
                    let extends = next[j - 1] && (token == Token::DoubleStar || text[j - 1] != b'/');
                    next[j] = reach[j] || extends;
                }
            }
            Token::Byte(b) => {
                next[0] = false;
                for j in 1..=text.len() {
                    next[j] = reach[j - 1] && text[j - 1] == b;
                }
            }
        }
        std::mem::swap(&mut reach, &mut next);
    }
    reach[text.len()]
}

fn tokenize(pattern: &[u8]) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(pattern.len());
    let mut i = 0;
    while i < pattern.len() {
        if pattern[i] == b'*' {
            if pattern.get(i + 1) == Some(&b'*') {
                tokens.push(Token::DoubleStar);
                i += 2;
            } else {
                tokens.push(Token::Star);
                i += 1;
            }
        } else {
            tokens.push(Token::Byte(pattern[i]));
            i += 1;
        }
    }
    tokens
}

/// Whether the normalized `image` matches at least one of `patterns`. An empty list allows nothing (a key without
/// an allowlist is represented by `None` at the API level and does not call this).
#[must_use]
pub fn image_allowed(patterns: &[String], image: &ImageRef) -> bool {
    let text = image.to_string();
    patterns.iter().any(|p| glob_match(p, &text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn glob_table() {
        let cases: &[(&str, &str, bool)] = &[
            ("docker.io/library/python:3.12", "docker.io/library/python:3.12", true),
            ("docker.io/library/python:3.12", "docker.io/library/python:3.13", false),
            ("docker.io/library/python:*", "docker.io/library/python:3.12", true),
            ("docker.io/library/python:*", "docker.io/library/pythonx:3.12", false),
            (
                "docker.io/library/python*",
                "docker.io/library/python-evil:latest",
                true,
            ),
            ("ghcr.io/me/*", "ghcr.io/me/app:1", true),
            ("ghcr.io/me/*", "ghcr.io/me/a/b:1", false),
            ("ghcr.io/me/*", "ghcr.io/meow/app:1", false),
            ("ghcr.io/me/**", "ghcr.io/me/a/b:1", true),
            ("ghcr.io/me/**", "ghcr.io/me/app:1", true),
            ("ghcr.io/me/**", "ghcr.io/mex/a:1", false),
            ("ghcr.io/me/**", "ghcr.io/me", false),
            ("ghcr.io/*/app:*", "ghcr.io/x/app:1", true),
            ("ghcr.io/*/app:*", "ghcr.io/x/y/app:1", false),
            ("ghcr.io/**/app:*", "ghcr.io/x/y/app:1", true),
            ("ghcr.io/**/app:*", "ghcr.io/app:1", false),
            ("**", "anything/at/all:x", true),
            ("*", "docker.io/library/python:3", false),
            ("*", "", true),
            ("", "", true),
            ("", "a", false),
            ("a", "", false),
            ("***", "a/b", true),
            ("*:latest", "python:latest", true),
            ("docker.io/library/python", "docker.io/library/python:latest", false),
            ("Docker.io/**", "docker.io/library/python:latest", false),
            ("?", "a", false),
            ("[ab]", "a", false),
        ];
        for &(pattern, text, want) in cases {
            assert_eq!(glob_match(pattern, text), want, "{pattern:?} vs {text:?}");
        }
    }

    #[test]
    fn pathological_patterns_are_fast() {
        let text = "a".repeat(600);
        let pattern = format!("{}b", "*a".repeat(200));
        assert!(!glob_match(&pattern, &text));
        let pattern = format!("{}b", "**a".repeat(200));
        assert!(!glob_match(&pattern, &text));
    }

    #[test]
    fn overlong_patterns_match_nothing() {
        let pattern = format!("{}**", "a".repeat(MAX_PATTERN_LEN));
        assert!(!glob_match(&pattern, &"a".repeat(MAX_PATTERN_LEN + 1)));
    }

    #[test]
    fn image_allowed_uses_the_normalized_reference() {
        let img = ImageRef::parse("python:3.12").unwrap();
        assert!(image_allowed(&["docker.io/library/python:*".into()], &img));
        assert!(!image_allowed(&["python:*".into()], &img));
        assert!(!image_allowed(&[], &img));
        assert!(image_allowed(
            &["ghcr.io/**".into(), "docker.io/library/**".into()],
            &img
        ));

        let pinned = ImageRef::parse(&format!("python:3.12@sha256:{D}")).unwrap();
        assert!(!image_allowed(&["docker.io/library/python:3.12".into()], &pinned));
        assert!(image_allowed(&["docker.io/library/python:3.12@*".into()], &pinned));
        assert!(image_allowed(&["docker.io/library/python:*".into()], &pinned));

        let gl = ImageRef::parse("registry.gitlab.com/group/sub/img:main").unwrap();
        assert!(image_allowed(&["registry.gitlab.com/group/**".into()], &gl));
        assert!(!image_allowed(&["registry.gitlab.com/group/*".into()], &gl));
    }
}
