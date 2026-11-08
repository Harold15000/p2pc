// SPDX-License-Identifier: Apache-2.0

//! Human output: plain-text tables and humanised sizes and times. `--json` bypasses all of this.
//!
//! The table renderer is a few lines on purpose: a table crate would be one more dependency to keep inside the
//! licence allowlist for no gain.

use std::fmt::Write as _;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// A plain-text table: a header row and aligned columns separated by two spaces.
#[derive(Debug, Clone, Default)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A table with the given column headers.
    pub fn new<S: Into<String>>(headers: impl IntoIterator<Item = S>) -> Self {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    /// Adds a row. Missing cells are empty; extra cells are dropped.
    pub fn row<S: Into<String>>(&mut self, cells: impl IntoIterator<Item = S>) {
        let mut row: Vec<String> = cells.into_iter().map(|c| one_line(&c.into())).collect();
        row.resize(self.headers.len(), String::new());
        self.rows.push(row);
    }

    /// Whether there are no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The table as text, one line per row, with no trailing spaces.
    #[must_use]
    pub fn render(&self) -> String {
        let widths: Vec<usize> = (0..self.headers.len())
            .map(|i| {
                self.rows
                    .iter()
                    .map(|r| r[i].chars().count())
                    .chain([self.headers[i].chars().count()])
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let mut out = String::new();
        for line in std::iter::once(&self.headers).chain(self.rows.iter()) {
            let mut text = String::new();
            for (i, cell) in line.iter().enumerate() {
                if i > 0 {
                    text.push_str("  ");
                }
                let _ = write!(text, "{cell:<width$}", width = widths[i]);
            }
            out.push_str(text.trim_end());
            out.push('\n');
        }
        out
    }
}

/// Text for a terminal: control characters other than newlines become spaces, so a name, a label or an error message
/// from the server cannot move the cursor, change colours or set the window title with an escape sequence.
#[must_use]
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect()
}

/// Whether a terminal could act on `c` (or be misled by it): the C0 controls, `DEL`, the C1 controls (U+0080 to U+009F)
/// and the bidirectional overrides and isolates (U+202A to U+202E, U+2066 to U+2069). One definition for everything that
/// prints text from the server or from a job: [`escape_terminal`], [`escape_json_terminal`] and the shell quoting.
#[must_use]
pub fn is_terminal_hazard(c: char) -> bool {
    c.is_control() || matches!(c as u32, 0x202a..=0x202e | 0x2066..=0x2069)
}

/// One line of JSON (as `serde_json` wrote it) made safe for a terminal: every [`is_terminal_hazard`] character that
/// JSON leaves as it is (`DEL`, C1, the bidi controls) becomes `\uXXXX`, which is the same string to a JSON parser. The
/// C0 controls are escaped by JSON itself.
#[must_use]
pub fn escape_json_terminal(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if is_terminal_hazard(c) {
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// Job output made safe for a terminal. Everything a terminal would act on is shown instead of sent:
///
/// - C0 controls except `\n`, `\t` and the `CR` of a `CRLF` (`ESC`, `BEL`, `BS`, …) and `DEL` as `\xNN`, and a bare
///   `CR`, which rewrites the line, as `\r`;
/// - C1 controls (U+0080 to U+009F: the 8-bit `CSI` and `OSC`) and the bidirectional overrides and isolates (U+202A to
///   U+202E, U+2066 to U+2069, which reorder the text that follows) as `\u{XXXX}`.
///
/// An escape sequence is `ESC` and printable characters, so with the `ESC` shown it is inert: `\x1b[31m` is text.
/// That covers colours and cursor moves (CSI), the window title and the clipboard (OSC 0/2 and OSC 52), and the rest.
/// Job output is untrusted (spec §13): it goes through this whenever it would reach a terminal. Piped, it is written
/// as stored.
#[must_use]
pub fn escape_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' | '\t' => out.push(c),
            // CRLF is a line ending and stays. A CR on its own moves the cursor back and lets what follows overwrite
            // what was shown: it is shown as `\r`.
            '\r' if chars.peek() == Some(&'\n') => out.push(c),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if is_terminal_hazard(c) => {
                let _ = write!(out, "\\u{{{:04x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Cell text on one line: control characters (newlines, escape sequences in a hostile label) become spaces.
fn one_line(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// MiB as `512 MiB`, `4 GiB`, `1.5 GiB` or `2 TiB`.
#[must_use]
pub fn fmt_mib(mib: u64) -> String {
    const GIB: u64 = 1024;
    const TIB: u64 = 1024 * 1024;
    let (unit, div) = if mib >= TIB {
        ("TiB", TIB)
    } else if mib >= GIB {
        ("GiB", GIB)
    } else {
        return format!("{mib} MiB");
    };
    if mib.is_multiple_of(div) {
        format!("{} {unit}", mib / div)
    } else {
        // `f64` is exact for these magnitudes.
        format!("{:.1} {unit}", mib as f64 / div as f64)
    }
}

/// Bytes as `812 B`, `1.5 KiB`, `3.2 MiB` or `1.0 GiB`.
#[must_use]
pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)];
    for (name, size) in UNITS {
        if bytes >= size {
            // `f64` is exact enough for a display with one decimal.
            return format!("{:.1} {name}", bytes as f64 / size as f64);
        }
    }
    format!("{bytes} B")
}

/// A vCPU count without trailing zeros: `4`, `3.5`, `0.25`.
#[must_use]
pub fn fmt_cpu(cpu: f64) -> String {
    let text = format!("{cpu:.3}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// How long ago `then` was, at `now`: `5s ago`, `3m ago`, `2h ago`, `4d ago`. A time in the future reads `just now`.
#[must_use]
pub fn fmt_age(now: OffsetDateTime, then: OffsetDateTime) -> String {
    let secs = (now - then).whole_seconds();
    match secs {
        i64::MIN..=0 => "just now".to_string(),
        1..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// A span in seconds as `45s`, `3m 5s`, `2h 10m` or `1d 4h`.
#[must_use]
pub fn fmt_duration_secs(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m {}s", secs / 60, secs % 60),
        3600..=86_399 => format!("{}h {}m", secs / 3600, secs % 3600 / 60),
        _ => format!("{}d {}h", secs / 86_400, secs % 86_400 / 3600),
    }
}

/// A timestamp as RFC 3339 in UTC, the same text as the API.
#[must_use]
pub fn fmt_time(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_else(|_| at.to_string())
}

/// `key: value` lines with the values aligned, for the detail views (`status`, `whoami`, `machines show`).
#[must_use]
pub fn render_kv(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in rows {
        let label = format!("{key}:");
        let _ = writeln!(out, "{label:<w$} {}", one_line(value), w = width + 1);
    }
    out
}

/// The name an enum has on the wire (`timed_out`, `jobs:write`, `wsl2`), taken from its `Serialize` impl.
#[must_use]
pub fn wire_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(other) => other.to_string(),
        Err(_) => "?".to_string(),
    }
}

/// An argv for people, quoted the way a POSIX shell reads it back: what is made of safe characters stays as it is, the
/// rest goes in single quotes (`print(6*7)` becomes `'print(6*7)'`, an embedded `'` becomes `'\''`), and an argument
/// with control characters is shown in `$'…'` form so that none reaches the terminal (it comes from a job spec).
#[must_use]
pub fn join_argv(argv: &[String]) -> String {
    argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

fn shell_quote(arg: &str) -> String {
    let safe =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '=' | '@' | '%' | '+' | ',');
    if !arg.is_empty() && arg.chars().all(safe) {
        return arg.to_string();
    }
    if arg.chars().any(is_terminal_hazard) {
        let mut out = String::from("$'");
        for c in arg.chars() {
            match c {
                '\'' => out.push_str("\\'"),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                c if is_terminal_hazard(c) => {
                    let mut buf = [0u8; 4];
                    for byte in c.encode_utf8(&mut buf).bytes() {
                        let _ = write!(out, "\\x{byte:02x}");
                    }
                }
                c => out.push(c),
            }
        }
        out.push('\'');
        return out;
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// `-` for a missing value, so a table cell is never empty.
#[must_use]
pub fn or_dash(text: Option<String>) -> String {
    text.unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    #[test]
    fn tables_align_columns_and_trim_trailing_spaces() {
        let mut t = Table::new(["ID", "NAME"]);
        t.row(["job_1", "a"]);
        t.row(["j", "a longer name"]);
        assert_eq!(t.render(), "ID     NAME\njob_1  a\nj      a longer name\n");
    }

    #[test]
    fn printable_text_has_no_escape_sequences_but_keeps_newlines() {
        assert_eq!(printable("a\u{1b}]0;title\u{7}b\nc\td"), "a ]0;title b\nc d");
    }

    #[test]
    fn a_table_pads_short_rows_and_keeps_cells_on_one_line() {
        let mut t = Table::new(["A", "B"]);
        t.row(["x"]);
        t.row(["multi\nline\u{1b}[31m", "y"]);
        let text = t.render();
        assert_eq!(text.lines().count(), 3);
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn sizes_are_humanised() {
        assert_eq!(fmt_mib(512), "512 MiB");
        assert_eq!(fmt_mib(1023), "1023 MiB");
        assert_eq!(fmt_mib(4096), "4 GiB");
        assert_eq!(fmt_mib(1536), "1.5 GiB");
        assert_eq!(fmt_mib(2 * 1024 * 1024), "2 TiB");
        assert_eq!(fmt_mib(0), "0 MiB");
    }

    #[test]
    fn byte_counts_are_humanised() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 + 200_000), "3.2 MiB");
        assert_eq!(fmt_bytes(5 << 30), "5.0 GiB");
    }

    #[test]
    fn cpu_counts_lose_their_trailing_zeros() {
        assert_eq!(fmt_cpu(4.0), "4");
        assert_eq!(fmt_cpu(3.5), "3.5");
        assert_eq!(fmt_cpu(0.25), "0.25");
        assert_eq!(fmt_cpu(0.001), "0.001");
        assert_eq!(fmt_cpu(0.0), "0");
    }

    #[test]
    fn ages_are_relative() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(fmt_age(now, now - Duration::seconds(5)), "5s ago");
        assert_eq!(fmt_age(now, now - Duration::seconds(125)), "2m ago");
        assert_eq!(fmt_age(now, now - Duration::hours(3)), "3h ago");
        assert_eq!(fmt_age(now, now - Duration::days(9)), "9d ago");
        assert_eq!(fmt_age(now, now + Duration::seconds(30)), "just now");
        assert_eq!(fmt_age(now, now), "just now");
    }

    #[test]
    fn durations_are_humanised() {
        assert_eq!(fmt_duration_secs(45), "45s");
        assert_eq!(fmt_duration_secs(185), "3m 5s");
        assert_eq!(fmt_duration_secs(7800), "2h 10m");
        assert_eq!(fmt_duration_secs(100_800), "1d 4h");
    }

    #[test]
    fn terminal_escaping_shows_every_control_and_keeps_newline_and_tab() {
        // ANSI CSI: colours and cursor moves.
        assert_eq!(escape_terminal("\u{1b}[31mred\u{1b}[0m"), "\\x1b[31mred\\x1b[0m");
        assert_eq!(escape_terminal("\u{1b}[2J\u{1b}[H"), "\\x1b[2J\\x1b[H");
        // OSC 52 (the clipboard), ended by BEL and by ST, and OSC 0 (the title).
        assert_eq!(escape_terminal("\u{1b}]52;c;SGVsbG8=\u{7}"), "\\x1b]52;c;SGVsbG8=\\x07");
        assert_eq!(escape_terminal("\u{1b}]52;c;AAAA\u{1b}\\"), "\\x1b]52;c;AAAA\\x1b\\");
        assert_eq!(escape_terminal("\u{1b}]0;pwned\u{7}"), "\\x1b]0;pwned\\x07");
        // A bare CR rewrites the line, so it is shown; the CR of a CRLF line ending stays.
        assert_eq!(escape_terminal("good\rbad"), "good\\rbad");
        assert_eq!(escape_terminal("a\r\nb"), "a\r\nb");
        assert_eq!(escape_terminal("progress 50%\r"), "progress 50%\\r");
        assert_eq!(escape_terminal("a\r\rb\r\n"), "a\\r\\rb\r\n");
        // C1: the 8-bit CSI, OSC and ST.
        assert_eq!(
            escape_terminal("\u{9b}31m\u{9d}52;c;x\u{9c}"),
            "\\u{009b}31m\\u{009d}52;c;x\\u{009c}"
        );
        // BS, DEL, NUL, FF, VT.
        assert_eq!(
            escape_terminal("a\u{8}\u{7f}\0\u{c}\u{b}"),
            "a\\x08\\x7f\\x00\\x0c\\x0b"
        );
        // Bidirectional overrides.
        assert_eq!(escape_terminal("a\u{202e}b\u{2066}"), "a\\u{202e}b\\u{2066}");
        // Plain text, accents, emoji, newlines and tabs are untouched.
        let plain = "héllo wörld 日本語 🎉\tcol\nnext\n";
        assert_eq!(escape_terminal(plain), plain);
    }

    #[test]
    fn the_hazard_set_is_the_same_for_text_json_and_shell_quoting() {
        let all: String = (0u32..0x3000).filter_map(char::from_u32).collect();
        let hazards: Vec<char> = all.chars().filter(|c| is_terminal_hazard(*c)).collect();
        assert!(hazards.contains(&'\u{7f}') && hazards.contains(&'\u{9b}') && hazards.contains(&'\u{202e}'));
        for c in hazards {
            let s = c.to_string();
            // Text: shown as `\x..` or `\u{..}` (a CRLF's CR and the newline and tab are the only ones left alone).
            if !matches!(c, '\n' | '\t' | '\r') {
                assert!(escape_terminal(&s).chars().all(|x| !is_terminal_hazard(x)), "{c:?}");
            }
            // JSON: nothing of the set is left in the line.
            let json = serde_json::to_string(&s).unwrap();
            assert!(
                escape_json_terminal(&json).chars().all(|x| !is_terminal_hazard(x)),
                "{c:?}"
            );
            // Shell: never printed as it is.
            assert!(join_argv(&[s]).chars().all(|x| !is_terminal_hazard(x)), "{c:?}");
        }
    }

    #[test]
    fn json_for_a_terminal_stays_valid_and_means_the_same() {
        let line =
            serde_json::to_string(&serde_json::json!({"data": "a\u{7f}b\u{9b}2J\u{202e}c\u{1b}[0m \"q\" é"})).unwrap();
        let safe = escape_json_terminal(&line);
        assert!(safe.chars().all(|c| !is_terminal_hazard(c)), "{safe:?}");
        let back: serde_json::Value = serde_json::from_str(&safe).unwrap();
        assert_eq!(back, serde_json::from_str::<serde_json::Value>(&line).unwrap());
        // Text without hazards is untouched.
        assert_eq!(escape_json_terminal(r#"{"a":"é 日本"}"#), r#"{"a":"é 日本"}"#);
    }

    #[test]
    fn escaped_text_contains_no_control_character_but_newline_and_tab() {
        let all: String = (0u32..0x3000).filter_map(char::from_u32).collect();
        let escaped = escape_terminal(&all);
        assert!(
            escaped
                .chars()
                .all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r'),
            "a control character got through"
        );
        // The only CR left is the one before a LF.
        assert_eq!(escaped.matches('\r').count(), escaped.matches("\r\n").count());
    }

    #[test]
    fn key_value_views_align_their_values() {
        let text = render_kv(&[("id", "job_1".into()), ("exit code", "3".into())]);
        assert_eq!(text, "id:        job_1\nexit code: 3\n");
    }

    #[test]
    fn wire_names_come_from_serde() {
        use p2pc_proto::api::{JobStatus, Scope};
        assert_eq!(wire_name(&JobStatus::TimedOut), "timed_out");
        assert_eq!(wire_name(&Scope::JobsWrite), "jobs:write");
    }

    #[test]
    fn argv_is_quoted_for_a_shell_and_only_where_needed() {
        let show = |args: &[&str]| join_argv(&args.iter().map(ToString::to_string).collect::<Vec<_>>());
        // The T06 real run: `python -c print(6*7)` could not be pasted back into a shell.
        assert_eq!(show(&["python", "-c", "print(6*7)"]), "python -c 'print(6*7)'");
        // Spaces, the empty string, and safe punctuation.
        assert_eq!(
            show(&["python", "-c", "print(6 * 7)", ""]),
            "python -c 'print(6 * 7)' ''"
        );
        assert_eq!(show(&["--opt=a/b.c:d@e,f+g%h", "x_y-z"]), "--opt=a/b.c:d@e,f+g%h x_y-z");
        // Quotes, in both kinds, and shell metacharacters.
        assert_eq!(show(&["echo", "it's"]), "echo 'it'\\''s'");
        assert_eq!(
            show(&["echo", "say \"hi\" $HOME `x` a;b"]),
            "echo 'say \"hi\" $HOME `x` a;b'"
        );
        // Neither do DEL, C1 and the bidi controls (the same set as `escape_terminal`).
        assert_eq!(show(&["a\u{7f}b"]), "$'a\\x7fb'");
        assert_eq!(show(&["a\u{9b}b"]), "$'a\\xc2\\x9bb'");
        assert_eq!(show(&["txt\u{202e}gpj.exe"]), "$'txt\\xe2\\x80\\xaegpj.exe'");
        // Control characters never reach the terminal.
        assert_eq!(show(&["a\nb\u{1b}[31m"]), "$'a\\nb\\x1b[31m'");
        assert_eq!(show(&["it's\tok"]), "$'it\\'s\\tok'");
    }

    #[test]
    fn times_use_rfc3339_in_utc() {
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(fmt_time(at), "2023-11-14T22:13:20Z");
    }
}
