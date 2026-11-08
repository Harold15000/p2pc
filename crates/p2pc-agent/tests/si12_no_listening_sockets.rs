// SPDX-License-Identifier: Apache-2.0

//! SI-12 groundwork (spec §13, CONTRIBUTING hard rule 4): the agent never listens on the network. It only dials out
//! (iroh, T05b).
//!
//! This test scans every Rust source file of the crate for the ways to open a listening socket: `bind(`,
//! `TcpListener` and `UdpSocket`. The rule, line by line:
//!
//! - Each mention is checked on its own **call**: the path before it and the parenthesized arguments after it
//!   (`UnixListener::bind(&path)`, `TcpListener::bind("127.0.0.1:0")`). The call must show that it is **local only**:
//!   a unix socket (`Unix…`, such as the egress proxy's `UnixListener` in T09) or a loopback address literal
//!   (`127.0.0.1`, `[::1]`, `::1`, `Ipv4Addr::LOCALHOST`, `Ipv6Addr::LOCALHOST`), for example a test server on
//!   `127.0.0.1:0`. A token elsewhere on the line, such as in an unrelated `UnixStream`, does not count.
//! - Comments (`//`, `///`, `/* … */`, nested ones) are removed before matching, string literals (raw ones too) are
//!   kept, and so is this file, which has to name the patterns.
//! - Anything else fails the test. Binding to an address held in a variable is refused too: make the loopback
//!   address visible in the call, so a reviewer can see it.
//! - The agent's iroh endpoint is bound by the shared `p2pc-net` crate (which the server uses too, to accept), with
//!   **no ALPN**: it accepts no connection. That is checked at runtime, not here: `si12_runtime_sockets.rs`
//!   enumerates the sockets, and `iroh_fake_server.rs` shows the endpoint refuses a dial.
//!
//! The runtime half of SI-12, enumerating the running agent's sockets, is `si12_runtime_sockets.rs`.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

const PATTERNS: [&str; 3] = ["bind(", "TcpListener", "UdpSocket"];
const LOCAL_ONLY: [&str; 6] = [
    "Unix",
    "127.0.0.1",
    "[::1]",
    "\"::1\"",
    "Ipv4Addr::LOCALHOST",
    "Ipv6Addr::LOCALHOST",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The length of the raw string literal (`r"…"`, `r#"…"#`, `br##"…"##`, …) that starts at `i`, if one does.
fn raw_string_len(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && is_ident_char(b[i - 1]) {
        return None;
    }
    let mut j = i;
    if b.get(j) == Some(&b'b') {
        j += 1;
    }
    if b.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    let hashes = b[j..].iter().take_while(|&&c| c == b'#').count();
    j += hashes;
    if b.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < b.len() {
        if b[j] == b'"' && b[j + 1..].iter().take(hashes).filter(|&&c| c == b'#').count() == hashes {
            return Some(j + 1 + hashes - i);
        }
        j += 1;
    }
    Some(b.len() - i)
}

/// `source` with every comment (`//`, `///`, `/* … */`, nested block comments) replaced by spaces, newlines kept so
/// that line numbers do not move. String literals, raw strings included, are kept as they are: a `//` or `/*` inside
/// one is not a comment, and a quote inside a raw string does not end it (T07b review, carry-over 4).
fn strip_comments(source: &str) -> String {
    let b = source.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let blank = |out: &mut Vec<u8>, c: u8| out.push(if c == b'\n' { b'\n' } else { b' ' });
    let mut i = 0;
    while i < b.len() {
        if let Some(len) = raw_string_len(b, i) {
            out.extend_from_slice(&b[i..i + len]);
            i += len;
            continue;
        }
        match b[i] {
            b'"' => {
                // A normal string: up to the closing quote, skipping escaped characters.
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(b.len());
                out.extend_from_slice(&b[i..end]);
                i = end;
            }
            b'\'' => {
                // A char literal ('"', '\\', '\u{1b}') is copied whole; a lifetime has no closing quote.
                let len = if b.get(i + 1) == Some(&b'\\') {
                    b[i + 2..]
                        .iter()
                        .take(10)
                        .position(|&c| c == b'\'')
                        .map_or(1, |p| p + 3)
                } else if b.get(i + 2) == Some(&b'\'') {
                    3
                } else {
                    1
                };
                let end = (i + len).min(b.len());
                out.extend_from_slice(&b[i..end]);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    out.push(b' ');
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 0usize;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        out.extend_from_slice(b"  ");
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        out.extend_from_slice(b"  ");
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        blank(&mut out, b[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_path_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b':' | b'.')
}

/// The call that the mention at `at` (of a pattern `len` bytes long) belongs to: the path before it, up to the
/// closing parenthesis of its arguments (or the end of the line).
fn call_span(code: &str, at: usize, len: usize) -> &str {
    let b = code.as_bytes();
    let mut start = at;
    while start > 0 && is_path_char(b[start - 1]) {
        start -= 1;
    }
    // The pattern `bind(` ends at the opening parenthesis of the arguments.
    let mut end = if b[at + len - 1] == b'(' {
        at + len - 1
    } else {
        at + len
    };
    // Follow a path such as `TcpListener::bind` to its argument list.
    while end < b.len() && is_path_char(b[end]) {
        end += 1;
    }
    if b.get(end) == Some(&b'(') {
        let mut depth = 0usize;
        for (i, c) in b[end..].iter().enumerate() {
            match c {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &code[start..=end + i];
                    }
                }
                _ => {}
            }
        }
        return &code[start..];
    }
    &code[start..end]
}

/// The offending lines of `source`, as `line: text`.
fn violations(source: &str) -> Vec<String> {
    let code = strip_comments(source);
    source
        .lines()
        .zip(code.lines())
        .enumerate()
        .filter(|(_, (_, code))| {
            PATTERNS.iter().any(|p| {
                code.match_indices(p).any(|(at, _)| {
                    let call = call_span(code, at, p.len());
                    !LOCAL_ONLY.iter().any(|ok| call.contains(ok))
                })
            })
        })
        .map(|(n, (l, _))| format!("{}: {}", n + 1, l.trim()))
        .collect()
}

#[test]
fn the_rule_itself() {
    assert!(violations("let l = TcpListener::bind(\"0.0.0.0:7000\").await?;").len() == 1);
    assert!(violations("let s = std::net::UdpSocket::bind(addr)?;").len() == 1);
    assert!(violations("socket.bind(&addr)?;").len() == 1);
    assert!(violations("let l = UnixListener::bind(&socket_path)?;").is_empty());
    assert!(violations("let l = tokio::net::TcpListener::bind(\"127.0.0.1:0\").await?;").is_empty());
    assert!(violations("let l = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))?;").is_empty());
    assert!(violations("    // TcpListener::bind(\"0.0.0.0:1\") in a comment").is_empty());
    assert!(violations("    /// TcpListener::bind(addr) in a doc comment").is_empty());
}

/// Bypass 1 of the T07 review: a loopback or unix token in a trailing comment is not a proof.
#[test]
fn a_token_in_a_trailing_comment_does_not_count() {
    assert_eq!(violations("let l = TcpListener::bind(addr)?; // 127.0.0.1").len(), 1);
    assert_eq!(
        violations("let l = UdpSocket::bind(addr)?; // only for UnixListener tests").len(),
        1
    );
    assert_eq!(violations("socket.bind(&addr)?; // [::1]").len(), 1);
    // A `//` inside a string is not a comment, and what follows it is still code.
    assert_eq!(
        violations("let l = TcpListener::bind(\"0.0.0.0:80\")?; let u = \"http://x\"; // 127.0.0.1").len(),
        1
    );
    assert!(violations("let l = TcpListener::bind(\"127.0.0.1:0\")?; // loopback").is_empty());
}

/// Bypass 2 of the T07 review: the token must be inside the `bind(` / `Listener` call itself, not anywhere on the
/// line.
#[test]
fn a_token_elsewhere_on_the_line_does_not_count() {
    assert_eq!(
        violations("let a = Ipv4Addr::LOCALHOST; let l = TcpListener::bind((addr, 0))?;").len(),
        1
    );
    assert_eq!(
        violations("let s = UnixStream::connect(p)?; let l = TcpListener::bind(\"0.0.0.0:0\")?;").len(),
        1
    );
    assert_eq!(
        violations("let l = TcpListener::bind(wide_addr(\"0.0.0.0:0\"))?; log(\"127.0.0.1\");").len(),
        1
    );
    assert_eq!(
        violations("let l = std::net::UdpSocket::bind(addr)?; let u = UnixDatagram::unbound()?;").len(),
        1
    );
    // The call may be nested or have a receiver; its own arguments are what count.
    assert!(violations("let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;").is_empty());
    assert!(violations("let l = UnixListener::bind(dir.join(\"p.sock\"))?;").is_empty());
}

/// T07b review, carry-over 4: block comments and raw strings can no longer hide a call or fake a proof.
#[test]
fn block_comments_and_raw_strings_are_handled() {
    // A loopback token inside a block comment is not a proof, even inside the call.
    assert_eq!(violations("let l = TcpListener::bind(addr /* 127.0.0.1 */)?;").len(), 1);
    assert_eq!(violations("let l = TcpListener::bind(/* [::1] */ addr)?;").len(), 1);
    // A call inside a block comment, on one line or several, nested or not, is not code.
    assert!(violations("/* TcpListener::bind(\"0.0.0.0:1\") */ let x = 1;").is_empty());
    assert!(violations("/*\n let l = TcpListener::bind(addr)?;\n*/").is_empty());
    assert!(violations("/* outer /* inner */ TcpListener::bind(addr) */").is_empty());
    // Code after a block comment on the same line is still checked.
    assert_eq!(violations("/* x */ let l = TcpListener::bind(addr)?;").len(), 1);
    // A `//` or `/*` inside a raw string does not start a comment that hides what follows.
    assert_eq!(
        violations("let u = r\"http://x\"; let l = TcpListener::bind(addr)?;").len(),
        1
    );
    assert_eq!(
        violations("let s = r#\"a \"quoted\" // x\"#; let l = TcpListener::bind(addr)?;").len(),
        1
    );
    assert_eq!(
        violations("let s = r##\"/* x\"##; let l = UdpSocket::bind(addr)?;").len(),
        1
    );
    assert_eq!(violations("let b = br#\"//\"#; socket.bind(&addr)?;").len(), 1);
    // A quote inside a raw string does not end it early and turn the rest into a "string".
    assert_eq!(
        violations("let s = r#\"\" \"#; let l = TcpListener::bind(addr)?; let t = \"\";").len(),
        1
    );
    // Line numbers survive a multi-line block comment.
    assert_eq!(
        violations("/*\n\n*/\nlet l = TcpListener::bind(addr)?;"),
        ["4: let l = TcpListener::bind(addr)?;"]
    );
    // A loopback literal in a real string still counts.
    assert!(violations("let l = TcpListener::bind(r\"127.0.0.1:0\")?;").is_empty());
}

#[test]
fn the_agent_opens_no_listening_socket() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "tests", "benches", "examples"] {
        if root.join(dir).is_dir() {
            rust_files(&root.join(dir), &mut files);
        }
    }
    let this = Path::new(file!()).file_name().unwrap();
    let mut found = Vec::new();
    for file in files.iter().filter(|f| f.file_name() != Some(this)) {
        let source = fs::read_to_string(file).unwrap();
        let rel = file.strip_prefix(root).unwrap().display().to_string();
        for v in violations(&source) {
            found.push(format!("{rel}:{v}"));
        }
    }
    assert!(files.len() > 5, "the scan found too few files: {files:?}");
    assert!(
        found.is_empty(),
        "SI-12: the agent must not listen on the network; only unix sockets and loopback are allowed:\n{}",
        found.join("\n")
    );
}
