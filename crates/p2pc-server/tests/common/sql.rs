// SPDX-License-Identifier: AGPL-3.0-only

//! SQL scanning shared by the static checks over the crate's sources (`status_writes.rs`, `read_path_sql.rs`):
//! the string literals of a Rust file, and a small SQL tokenizer. They are tripwires, not parsers.

/// The decoded contents of every string literal in Rust source `src`, in order. Comments and char literals are
/// skipped; `\`-newline continuations and escapes are decoded; raw strings are supported.
pub fn string_literals(src: &str) -> Vec<String> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                let mut depth = 1;
                i += 2;
                while i < c.len() && depth > 0 {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            // A raw string: r"…", r#"…"#, br"…".
            'r' | 'b' if is_raw_string_start(&c, i) => {
                let mut j = i;
                if c[j] == 'b' {
                    j += 1;
                }
                j += 1; // the `r`
                let mut hashes = 0;
                while c[j] == '#' {
                    hashes += 1;
                    j += 1;
                }
                j += 1; // the opening quote
                let start = j;
                loop {
                    if j >= c.len() {
                        break;
                    }
                    if c[j] == '"' && (0..hashes).all(|k| c.get(j + 1 + k) == Some(&'#')) {
                        break;
                    }
                    j += 1;
                }
                out.push(c[start..j.min(c.len())].iter().collect());
                i = j + 1 + hashes;
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        i += 1;
                        match c.get(i) {
                            // A line continuation skips the newline and the next line's indentation.
                            Some('\n') => {
                                while c.get(i).is_some_and(|ch| ch.is_whitespace()) {
                                    i += 1;
                                }
                                continue;
                            }
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            Some('r') => s.push('\r'),
                            Some('0') => s.push('\0'),
                            Some('x') => {
                                s.push(' ');
                                i += 2;
                            }
                            Some('u') => {
                                s.push(' ');
                                while i < c.len() && c[i] != '}' {
                                    i += 1;
                                }
                            }
                            Some(other) => s.push(*other),
                            None => {}
                        }
                        i += 1;
                    } else {
                        s.push(c[i]);
                        i += 1;
                    }
                }
                out.push(s);
                i += 1;
            }
            // A char literal (`'x'`, `'\n'`, `'"'`) must not be mistaken for the start of a string; a lifetime
            // (`'a`) is just skipped.
            '\'' => {
                if c.get(i + 1) == Some(&'\\') {
                    i += 2;
                    while i < c.len() && c[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                } else if c.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

fn is_raw_string_start(c: &[char], i: usize) -> bool {
    // Not the tail of an identifier (`for"`), and `r` or `br`, then `#`*, then a quote.
    if i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_') {
        return false;
    }
    let mut j = i;
    if c[j] == 'b' {
        j += 1;
    }
    if c.get(j) != Some(&'r') {
        return false;
    }
    j += 1;
    while c.get(j) == Some(&'#') {
        j += 1;
    }
    c.get(j) == Some(&'"')
}

/// SQL tokens: lowercase words, single punctuation characters, and each quoted SQL string as one token that keeps
/// its quotes (`'queued'`), so the text of a string is never mistaken for a column. Double quotes, backticks and
/// brackets around identifiers are dropped (`"jobs"` is `jobs`).
pub fn tokens(sql: &str) -> Vec<String> {
    let c: Vec<char> = sql.to_lowercase().chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() || matches!(ch, '"' | '`' | '[' | ']') {
            i += 1;
        } else if ch.is_alphanumeric() || ch == '_' {
            let start = i;
            while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(c[start..i].iter().collect());
        } else if ch == '\'' {
            let start = i;
            i += 1;
            while i < c.len() {
                if c[i] == '\'' {
                    if c.get(i + 1) == Some(&'\'') {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i += 1;
            out.push(c[start..i.min(c.len())].iter().collect());
        } else {
            out.push(ch.to_string());
            i += 1;
        }
    }
    out
}
