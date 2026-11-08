// SPDX-License-Identifier: AGPL-3.0-only

//! The tripwire for T06 and T10: **nothing but `store::job_state` may write `jobs.status`** (spec §7, T04).
//!
//! It scans every SQL string of the crate's sources, case-insensitively and whatever the layout, for a write to
//! `jobs.status`, and fails unless the write is in `store/job_state.rs` or is the creation insert in
//! `store/jobs.rs` (`INSERT INTO jobs … 'queued' …`, with no upsert). The forms it recognizes:
//! - `UPDATE jobs SET … status …`, with `status` in any position of the `SET` clause (`SET a = 1, status = ?`, a
//!   row value `SET (a, status) = (…)`), in any case, with an alias (`UPDATE jobs AS j`, `UPDATE jobs j`), a
//!   qualified or quoted table (`main.jobs`, `"jobs"`) or a conflict clause (`UPDATE OR REPLACE jobs`);
//! - `INSERT … INTO jobs … ON CONFLICT … DO UPDATE SET … status`, `INSERT OR REPLACE INTO jobs`, `REPLACE INTO jobs`;
//! - any `INSERT INTO jobs` outside `store/jobs.rs`, which would create a job in a state of its choosing;
//! - statements split over several lines (a `\` continuation), over several adjacent literals (`concat!`), or in a
//!   raw string.
//!
//! It is a tripwire, not a proof: it is conservative (a `status` anywhere in a `SET` clause of `jobs` counts), and
//! it cannot see SQL that is not a string literal in the sources. The database itself still refuses to move a job
//! out of a terminal state (a trigger), and `job_state::transition` is the one place that checks the table of legal
//! moves.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

mod common;

use common::sql::{string_literals, tokens};

fn is_clause_end(t: &str) -> bool {
    matches!(
        t,
        "where" | "from" | "returning" | ";" | "update" | "insert" | "select" | "delete" | "replace"
    )
}

/// Skips an optional `main .` before a table name; returns the index of the table token.
fn table_at(t: &[String], mut i: usize) -> usize {
    if t.get(i).is_some_and(|x| x == "main") && t.get(i + 1).is_some_and(|x| x == ".") {
        i += 2;
    }
    i
}

/// Writes to `jobs.status` found in the SQL text `sql`. `allow_creation_insert` is true only for `store/jobs.rs`,
/// where the one creation insert (`INSERT INTO jobs … 'queued' …`, no upsert) is expected.
fn status_write_violations(sql: &str, allow_creation_insert: bool) -> Vec<String> {
    let t = tokens(sql);
    let mut found = Vec::new();
    for i in 0..t.len() {
        match t[i].as_str() {
            "update" => {
                // `UPDATE [OR <conflict>] [main.]jobs [AS] [alias] SET …`
                let mut j = i + 1;
                if t.get(j).is_some_and(|x| x == "or") {
                    j += 2;
                }
                j = table_at(&t, j);
                if t.get(j).is_none_or(|x| x != "jobs") {
                    continue;
                }
                let Some(set) = (j + 1..t.len())
                    .take_while(|&k| !is_clause_end(&t[k]))
                    .find(|&k| t[k] == "set")
                else {
                    continue;
                };
                if (set + 1..t.len())
                    .take_while(|&k| !is_clause_end(&t[k]))
                    .any(|k| t[k] == "status")
                {
                    found.push("UPDATE jobs SET … status".to_string());
                }
            }
            "insert" | "replace" => {
                // `INSERT [OR <conflict>] INTO [main.]jobs …`, `REPLACE INTO [main.]jobs …`
                let Some(into) = (i + 1..(i + 4).min(t.len())).find(|&k| t[k] == "into") else {
                    continue;
                };
                let target = table_at(&t, into + 1);
                if t.get(target).is_none_or(|x| x != "jobs") {
                    continue;
                }
                let replaces = t[i] == "replace" || t[i + 1..into].iter().any(|x| x == "replace");
                // Where the statement ends is found structurally, not by "the next keyword": all the literals of a
                // file are joined by spaces, so the next statement's `SELECT` may follow this one directly.
                // `INSERT INTO jobs [(columns)] SELECT …` selects before any `VALUES`; otherwise the statement is the
                // balanced `VALUES (…), (…)` groups, and an upsert is an `ON CONFLICT` right after them.
                let Some(source) = (target + 1..t.len()).find(|&k| matches!(t[k].as_str(), "values" | "select")) else {
                    continue;
                };
                if replaces {
                    found.push("INSERT OR REPLACE / REPLACE INTO jobs".to_string());
                } else if t[source] == "select" {
                    found.push("INSERT INTO jobs … SELECT".to_string());
                } else {
                    let mut end = source + 1;
                    loop {
                        if t.get(end).is_some_and(|x| x == "(") {
                            let mut depth = 0;
                            while end < t.len() {
                                match t[end].as_str() {
                                    "(" => depth += 1,
                                    ")" => depth -= 1,
                                    _ => {}
                                }
                                end += 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                        }
                        if t.get(end).is_some_and(|x| x == ",") {
                            end += 1;
                        } else {
                            break;
                        }
                    }
                    let values = &t[source..end.min(t.len())];
                    if t.get(end).is_some_and(|x| x == "on") && t.get(end + 1).is_some_and(|x| x == "conflict") {
                        found.push("INSERT INTO jobs … ON CONFLICT (an upsert can overwrite status)".to_string());
                    } else if !allow_creation_insert {
                        found.push("INSERT INTO jobs outside store/jobs.rs".to_string());
                    } else if !values.iter().any(|x| x == "'queued'") {
                        found.push("INSERT INTO jobs that does not create the job 'queued'".to_string());
                    }
                }
            }
            _ => {}
        }
    }
    found
}

/// All SQL in a source file: its string literals, joined by a space so that a statement split over `concat!`
/// pieces is still one statement.
fn sql_of_source(src: &str) -> String {
    string_literals(src).join(" ")
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

/// The real crate: no source writes `jobs.status` but `store/job_state.rs` (and the creation insert).
#[test]
fn only_the_state_machine_writes_the_status() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 15, "found the sources: {files:?}");
    let mut saw_state_machine = false;
    let mut saw_creation = false;
    for file in files {
        let rel = file.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&file).unwrap();
        if rel == "store/job_state.rs" {
            // The one place that may write it: the check below proves the scanner can see it.
            saw_state_machine |= !status_write_violations(&sql_of_source(&text), false).is_empty();
            continue;
        }
        let creation = rel == "store/jobs.rs";
        let sql = sql_of_source(&text);
        saw_creation |= creation && sql.to_lowercase().contains("insert into jobs");
        let violations = status_write_violations(&sql, creation);
        assert!(
            violations.is_empty(),
            "src/{rel} writes jobs.status ({violations:?}): go through store::job_state::transition"
        );
    }
    assert!(
        saw_state_machine,
        "the scanner no longer recognizes the state machine's own UPDATE"
    );
    assert!(saw_creation, "the scanner did not find the creation insert");
}

/// Every bypass form is caught, in every layout.
#[test]
fn the_scanner_catches_every_form_of_status_write() {
    let bad_sql = [
        "UPDATE jobs SET status = 'running' WHERE job_id = ?",
        "update jobs set status=?1",
        "UPDATE JOBS SET Status = ?",
        // `status` in another position of the SET clause.
        "UPDATE jobs SET updated_at = 1, status = ?, reason = NULL WHERE job_id = ?",
        "UPDATE jobs SET reason = NULL, updated_at = 1,\n    status = ?",
        // Aliases, qualified and quoted tables, conflict clauses.
        "UPDATE jobs AS j SET status = ? WHERE j.job_id = ?",
        "UPDATE jobs j SET reason = NULL, status = ?",
        "UPDATE main.jobs SET status = ?",
        "UPDATE \"jobs\" SET status = ?",
        "UPDATE `jobs` SET status = ?",
        "UPDATE OR REPLACE jobs SET status = ?",
        "UPDATE OR IGNORE jobs SET updated_at = 1, status = ?",
        // A row value.
        "UPDATE jobs SET (reason, status) = (NULL, ?)",
        // `status` read in the SET clause is still treated as a write: conservative.
        "UPDATE jobs SET reason = status",
        // Upserts and replaces.
        "INSERT INTO jobs (job_id, status) VALUES (?, 'queued') ON CONFLICT (job_id) DO UPDATE SET status = excluded.status",
        "INSERT INTO jobs (job_id) VALUES (?) ON CONFLICT DO UPDATE SET updated_at = 1, status = 'lost'",
        "insert or replace into jobs (job_id, status) values (?, 'queued')",
        "REPLACE INTO jobs (job_id, status) VALUES (?, 'running')",
        "INSERT INTO main.jobs SELECT * FROM jobs_old",
        // Behind a CTE.
        "WITH x AS (SELECT 1) UPDATE jobs SET status = ? WHERE job_id = ?",
        // Two statements: the second writes.
        "UPDATE jobs SET reason = NULL WHERE job_id = ?; UPDATE jobs SET status = ?",
    ];
    for sql in bad_sql {
        assert!(
            !status_write_violations(sql, false).is_empty(),
            "not caught (outside jobs.rs): {sql}"
        );
    }
    // In `store/jobs.rs`, every form except the plain creation insert is still caught.
    for sql in bad_sql {
        let found = status_write_violations(sql, true);
        assert!(!found.is_empty(), "not caught (in jobs.rs): {sql}");
    }
    // A creation insert is allowed only there, and only if it creates the job `queued`.
    let creation = "INSERT INTO jobs (job_id, status, attempt) VALUES (?, 'queued', 1)";
    assert!(status_write_violations(creation, true).is_empty());
    // A statement that follows the insert in the same file (all literals are joined by spaces) is not part of it.
    let followed = "INSERT INTO jobs (job_id, status) VALUES (?, 'queued') SELECT spec FROM jobs WHERE job_id = ?";
    assert!(status_write_violations(followed, true).is_empty(), "{followed}");
    assert!(
        !status_write_violations(
            "INSERT INTO jobs (job_id) VALUES (?, 'queued'), (?, 'running') ON CONFLICT DO NOTHING",
            true
        )
        .is_empty()
    );
    assert!(
        !status_write_violations(creation, false).is_empty(),
        "outside store/jobs.rs"
    );
    let sneaky = "INSERT INTO jobs (job_id, status, attempt) VALUES (?, 'running', 1)";
    assert!(
        !status_write_violations(sneaky, true).is_empty(),
        "a job created in another state"
    );
}

/// Things that are not a write to `jobs.status` must pass: reading it, writing other columns, other tables.
#[test]
fn the_scanner_lets_other_sql_through() {
    for sql in [
        "SELECT status FROM jobs WHERE status = 'queued'",
        "UPDATE jobs SET cancel_requested_at = ?1, updated_at = ?1 WHERE job_id = ?2 AND status IN ('assigned', 'running')",
        "UPDATE jobs SET reason = 'status', node_id = ? WHERE job_id = ? AND status = 'queued'",
        "UPDATE jobs SET node_id = ?, attempt = attempt + 1 WHERE job_id = ?",
        "UPDATE api_keys SET revoked_at = ?1 WHERE key_id = ?2",
        "UPDATE job_events_x SET status = ?",
        "INSERT INTO job_events (job_id, at, from_status, to_status, reason) VALUES (?, ?, ?, ?, ?)",
        "INSERT INTO jobs_archive (job_id, status) VALUES (?, ?)",
        "DELETE FROM jobs WHERE job_id = ?",
    ] {
        assert!(status_write_violations(sql, false).is_empty(), "wrongly flagged: {sql}");
    }
}

/// The literal extractor sees the layouts SQL hides in.
#[test]
fn the_literal_extractor_handles_continuations_concat_raw_strings_and_comments() {
    let sql = |src: &str| status_write_violations(&sql_of_source(src), false);
    // A `\` line continuation.
    assert!(!sql("let q = \"UPDATE jobs \\\n        SET status = ?\";").is_empty());
    // `concat!` pieces.
    assert!(!sql(r#"sqlx::query(concat!("UPDATE jobs SET ", "status = ?"))"#).is_empty());
    assert!(
        !sql(r#"concat!("UPDATE jobs SET reason = NULL, ", "updated_at = 1, ", "status = ? WHERE job_id = ?")"#)
            .is_empty()
    );
    // A raw string, with and without hashes.
    assert!(!sql(r##"let q = r#"UPDATE jobs SET status = "x""#;"##).is_empty());
    assert!(!sql(r#"let q = r"UPDATE jobs SET status = ?";"#).is_empty());
    // An escaped quote and a char literal that is a double quote do not derail the scan.
    assert!(!sql(r#"let a = '"'; let q = "say \"hi\"; UPDATE jobs SET status = ?";"#).is_empty());
    // Comments are not code.
    assert!(sql("// UPDATE jobs SET status = ?\nlet x = 1;").is_empty());
    assert!(sql("/* UPDATE jobs SET status = ? */ let x = 1;").is_empty());
    // A lifetime is not a char literal.
    assert!(!sql("fn f<'a>(x: &'a str) { q(\"UPDATE jobs SET status = ?\") }").is_empty());
}
