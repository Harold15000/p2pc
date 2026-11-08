// SPDX-License-Identifier: AGPL-3.0-only

//! The read path never loads a job's `spec` (T04 re-review, P2).
//!
//! `jobs.spec` holds the env values and the input file contents (up to 512 KiB per job). A page of 100 jobs would
//! pull about 100 MiB out of SQLite, and parse it, only to build a `JobSpecView` that holds no content. So the API's
//! reads (list, get, cancel, the idempotent replay) select `spec_view`, the redacted view stored at insert time, and
//! **only** `store::jobs::load_spec` selects `spec`, for one row at a time (lease building, T06).
//!
//! Like the status-write tripwire (`status_writes.rs`), this scans every SQL string literal of the crate's sources.
//! It fails on any select that involves the `jobs` table and lists `spec` or `*`, unless it is exactly
//! `SELECT spec FROM jobs …` in `store/jobs.rs`. It is a tripwire, not a proof: it cannot see SQL that is not a string
//! literal. `jobs.rs` has the behavioural twin: it replaces `spec` in the database with garbage and checks that the
//! API reads still answer.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};

use common::sql::{string_literals, tokens};

/// Selects of `sql` that involve the `jobs` table and read `spec` or `*`, each described. `allow_spec_only` allows
/// the exact form `SELECT spec FROM jobs …` (`store/jobs.rs`, for `load_spec`).
fn spec_read_violations(sql: &str, allow_spec_only: bool) -> Vec<String> {
    let t = tokens(sql);
    let mut found = Vec::new();
    for i in 0..t.len() {
        if t[i] == "select" {
            // The select list: up to the `from` at the same depth (a `from` inside a function call is skipped).
            let mut depth = 0i32;
            let mut from = None;
            for (k, tok) in t.iter().enumerate().skip(i + 1) {
                match tok.as_str() {
                    "(" => depth += 1,
                    ")" => {
                        depth -= 1;
                        if depth < 0 {
                            break;
                        }
                    }
                    "from" if depth == 0 => {
                        from = Some(k);
                        break;
                    }
                    ";" if depth == 0 => break,
                    _ => {}
                }
            }
            let Some(from) = from else { continue };
            let list = &t[i + 1..from];
            // The allowed form is a statement of its own, not a subquery or a branch of a compound select: those
            // could hand `spec` to an outer query.
            let top_level = i == 0 || !matches!(t[i - 1].as_str(), "(" | "union" | "all" | "intersect" | "except");
            // The rest of this statement: until its closing parenthesis (a subquery), a `;`, or the next statement
            // (all the literals of a file are joined by spaces, so another `select` at depth 0 starts a new one).
            let mut depth = 0i32;
            let mut end = t.len();
            for (k, tok) in t.iter().enumerate().skip(from + 1) {
                match tok.as_str() {
                    "(" => depth += 1,
                    ")" => {
                        depth -= 1;
                        if depth < 0 {
                            end = k;
                            break;
                        }
                    }
                    ";" | "select" if depth == 0 => {
                        end = k;
                        break;
                    }
                    _ => {}
                }
            }
            if !t[from + 1..end].iter().any(|x| x == "jobs") {
                continue;
            }
            let reads_spec = list.iter().any(|x| x == "spec");
            // A bare `*` or `j.*` selects every column; `count(*)` does not (a `*` inside parentheses).
            let mut depth = 0i32;
            let mut reads_star = false;
            for tok in list {
                match tok.as_str() {
                    "(" => depth += 1,
                    ")" => depth -= 1,
                    "*" if depth == 0 => reads_star = true,
                    _ => {}
                }
            }
            if reads_star {
                found.push("SELECT * (or `j.*`) from jobs".to_string());
            } else if reads_spec && !(allow_spec_only && list.len() == 1 && top_level) {
                found.push("SELECT … spec … from jobs".to_string());
            }
        } else if t[i] == "returning" {
            // `UPDATE/INSERT jobs … RETURNING spec` or `RETURNING *` would read it too.
            let end = (i + 1..t.len())
                .find(|&k| t[k] == ";" || t[k] == "select")
                .unwrap_or(t.len());
            let involves_jobs = t[..i].iter().rev().take(60).any(|x| x == "jobs");
            if involves_jobs && t[i + 1..end].iter().any(|x| x == "spec" || x == "*") {
                found.push("RETURNING spec / * on jobs".to_string());
            }
        }
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The real crate: no SQL string reads `jobs.spec` except `load_spec`'s single-row `SELECT spec FROM jobs`.
#[test]
fn only_load_spec_selects_the_spec_column() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 15, "found the sources");
    let mut saw_read_path = false;
    let mut saw_load_spec = false;
    for file in files {
        let rel = file.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&file).unwrap();
        let sql = string_literals(&text).join(" ");
        let tokens = tokens(&sql);
        if rel == "store/jobs.rs" {
            // The scanner really sees the two selects this file is about.
            saw_read_path = tokens.windows(2).any(|w| w[0] == "spec_view" && w[1] == ",");
            saw_load_spec = tokens.windows(4).any(|w| w == ["select", "spec", "from", "jobs"]);
        }
        let violations = spec_read_violations(&sql, rel == "store/jobs.rs");
        assert!(
            violations.is_empty(),
            "src/{rel} reads jobs.spec ({violations:?}): the API reads `spec_view`; only `store::jobs::load_spec` may \
             select `spec`"
        );
    }
    assert!(
        saw_read_path,
        "the scanner did not find the read path's `spec_view` select"
    );
    assert!(saw_load_spec, "the scanner did not find `load_spec`'s select");
}

/// Every way of reading `spec` is caught, in every layout.
#[test]
fn the_scanner_catches_every_way_of_reading_the_spec() {
    let bad = [
        "SELECT job_id, spec, status FROM jobs WHERE job_id = ?",
        "SELECT spec, spec_view FROM jobs WHERE job_id = ?",
        "select SPEC from jobs",
        "SELECT * FROM jobs WHERE account_id = ?",
        "SELECT j.* FROM jobs j",
        "SELECT j.spec FROM jobs AS j",
        "SELECT length(spec) FROM jobs",
        "SELECT json_extract(spec, '$.env') FROM jobs",
        "SELECT job_id, spec FROM main.jobs",
        "SELECT \"spec\" FROM \"jobs\"",
        // Through a join, or a subquery.
        "SELECT e.at, j.spec FROM job_events e JOIN jobs j ON j.job_id = e.job_id",
        "SELECT e.at, j.* FROM job_events e JOIN jobs j ON j.job_id = e.job_id",
        "SELECT x FROM (SELECT job_id, spec FROM jobs)",
        "SELECT status FROM jobs WHERE job_id IN (SELECT spec FROM jobs)",
        "SELECT job_id FROM jobs UNION SELECT spec FROM jobs",
        "SELECT job_id FROM jobs UNION ALL SELECT spec FROM jobs",
        "WITH s AS (SELECT spec FROM jobs) SELECT * FROM s",
        "SELECT (SELECT spec FROM jobs WHERE job_id = ?) FROM api_keys",
        "WITH s AS (SELECT * FROM jobs) SELECT 1 FROM s",
        // A multi-line statement, with the list after the first line.
        "SELECT job_id,\n       spec\n  FROM jobs",
        // RETURNING.
        "UPDATE jobs SET reason = NULL WHERE job_id = ? RETURNING spec",
        "UPDATE jobs SET reason = NULL WHERE job_id = ? RETURNING *",
    ];
    for sql in bad {
        assert!(!spec_read_violations(sql, false).is_empty(), "not caught: {sql}");
        // Even in `store/jobs.rs`, only the exact single-column form is allowed (quotes do not make it another
        // form: `SELECT "spec" FROM "jobs"` is the same statement).
        if tokens(sql) != ["select", "spec", "from", "jobs"] {
            assert!(
                !spec_read_violations(sql, true).is_empty(),
                "not caught in store/jobs.rs: {sql}"
            );
        }
    }
    // After another statement, as all the literals of a file are joined: still a read of `spec` outside
    // `store/jobs.rs`, and the allowed form inside it (that is how `load_spec` follows the other literals there).
    let after = "SELECT 1 FROM api_keys SELECT spec FROM jobs";
    assert!(!spec_read_violations(after, false).is_empty());
    assert!(spec_read_violations(after, true).is_empty());
    // `load_spec`'s select is the one allowed form, and only where it is allowed.
    let load = "SELECT spec FROM jobs WHERE account_id = ? AND project_id = ? AND job_id = ?";
    assert!(spec_read_violations(load, true).is_empty());
    assert!(!spec_read_violations(load, false).is_empty(), "outside store/jobs.rs");
}

/// What must pass: the read path's own select, other tables, and other columns.
#[test]
fn the_scanner_lets_the_read_path_through() {
    for sql in [
        "SELECT job_id, account_id, project_id, key_id, spec_view, spec_hash, status FROM jobs WHERE job_id = ?",
        "SELECT job_id, spec_view FROM jobs WHERE job_id = ?",
        "SELECT COALESCE(SUM(units_reserved), 0) FROM jobs WHERE key_id = ?1",
        "SELECT count(*) FROM jobs",
        "SELECT e.at, e.from_status, e.to_status, e.reason FROM job_events e JOIN jobs j ON j.job_id = e.job_id \
         WHERE j.account_id = ? AND j.project_id = ? AND e.job_id = ?",
        "SELECT * FROM api_keys WHERE key_id = ?",
        "SELECT scopes, spec FROM some_other_table",
        "UPDATE jobs SET cancel_requested_at = ?1 WHERE job_id = ?2 RETURNING job_id",
        "INSERT INTO jobs (job_id, spec, spec_view) VALUES (?, ?, ?)",
        // A statement that follows a `jobs` one in the same file does not inherit it.
        "SELECT job_id FROM jobs SELECT spec FROM some_other_table",
    ] {
        assert!(spec_read_violations(sql, false).is_empty(), "wrongly flagged: {sql}");
    }
}
