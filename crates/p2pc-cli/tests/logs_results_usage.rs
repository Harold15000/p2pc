// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc logs`, `p2pc run` (the live follow), `p2pc results` and `p2pc usage`, in process, against a mock HTTP server on
//! `127.0.0.1:0`. The shapes are the spec's (§7, §11) and `docs/api/openapi.json`; T10b (the real routes) is in flight.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, RecordedRequest, fixtures};
use p2pc_proto::api::{
    Job, JobStatus, LogLine, LogStream, OutputFile, Sha256Digest, UsageGroupBy, UsageReport, UsageTotals,
};
use p2pc_proto::ids::JobId;
use p2pc_proto::units::Units;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn json_of<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serializable")
}

fn line(seq: u64, stream: LogStream, data: &str) -> LogLine {
    LogLine {
        seq,
        stream,
        ts: fixtures::t0(),
        data: data.into(),
    }
}

fn out_line(seq: u64, data: &str) -> LogLine {
    line(seq, LogStream::Stdout, data)
}

fn ndjson(lines: &[LogLine]) -> MockResponse {
    let mut body = String::new();
    for l in lines {
        body.push_str(&serde_json::to_string(l).unwrap());
        body.push('\n');
    }
    MockResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/x-ndjson".into())],
        body: body.into_bytes(),
    }
}

/// What the real server answers for `since_seq`: the lines from there on.
fn ndjson_since(lines: &[LogLine], req: &RecordedRequest) -> MockResponse {
    let since: u64 = param(req, "since_seq").map_or(0, |v| v.parse().unwrap());
    let rest: Vec<_> = lines.iter().filter(|l| l.seq >= since).cloned().collect();
    ndjson(&rest)
}

fn param(req: &RecordedRequest, name: &str) -> Option<String> {
    url::form_urlencoded::parse(req.query.clone().unwrap_or_default().as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn not_found() -> MockResponse {
    MockResponse::problem(404, "not_found", "no such route")
}

// ---------------------------------------------------------------------------------------------------------------
// p2pc logs
// ---------------------------------------------------------------------------------------------------------------

/// A server whose logs are `lines`, whatever is asked.
fn logs_server(lines: Vec<LogLine>) -> MockServer {
    MockServer::start(move |req| {
        if req.path.ends_with("/logs") {
            ndjson(&lines)
        } else {
            not_found()
        }
    })
}

#[test]
fn logs_send_stdout_lines_to_stdout_and_stderr_lines_to_stderr() {
    let id = JobId::generate();
    let server = logs_server(vec![
        out_line(0, "hello\n"),
        line(1, LogStream::Stderr, "warning\n"),
        out_line(2, "partial"),
        out_line(3, " line\n"),
    ]);
    let out = Cli::new().with_server(&server).run(&["logs", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    // The data is written as it came: no newline is added or removed.
    assert_eq!(out.stdout, "hello\npartial line\n");
    assert_eq!(out.stderr, "warning\n");
    let req = &server.requests()[0];
    assert_eq!(req.path, format!("/v1/jobs/{id}/logs"));
    assert_eq!(param(req, "since_seq").as_deref(), Some("0"));
    assert_eq!(param(req, "follow"), None);
    assert_eq!(param(req, "attempt"), None);
}

#[test]
fn logs_pass_the_attempt_and_the_first_line_wanted() {
    let id = JobId::generate();
    let server = logs_server(vec![out_line(5, "five\n"), out_line(6, "six\n")]);
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--attempt", "2", "--since-seq", "5"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, "five\nsix\n");
    let req = &server.requests()[0];
    assert_eq!(param(req, "attempt").as_deref(), Some("2"));
    assert_eq!(param(req, "since_seq").as_deref(), Some("5"));
}

#[test]
fn logs_with_json_print_the_ndjson_records_as_they_are() {
    let id = JobId::generate();
    let lines = vec![out_line(0, "a\n"), line(1, LogStream::Stderr, "\u{1b}[31mb\n")];
    let server = logs_server(lines.clone());
    // Even on a terminal: JSON escapes the control characters itself.
    let out = Cli::new()
        .with_server(&server)
        .with_terminal_output()
        .run(&["logs", &id.to_string(), "--json"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stderr, "");
    let records: Vec<LogLine> = out.stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(records, lines);
    assert!(!out.stdout.contains('\u{1b}'), "{:?}", out.stdout);
}

/// The job's output is untrusted (spec §13): what it writes must not drive the user's terminal.
#[test]
fn on_a_terminal_a_job_cannot_drive_the_terminal() {
    let id = JobId::generate();
    let hostile = [
        // ANSI CSI: clear the screen, colours.
        "\u{1b}[2J\u{1b}[31mred\u{1b}[0m\n",
        // OSC 52: write to the clipboard; OSC 0: the window title.
        "\u{1b}]52;c;cm0gLXJmIH4=\u{7}\u{1b}]0;pwned\u{7}\n",
        // A bare CR: overwrite what was shown on this line.
        "all good\rrm -rf ~\n",
        // The 8-bit C1 forms.
        "\u{9b}2J\u{9d}52;c;eA==\u{9c}\n",
    ];
    let lines: Vec<_> = hostile.iter().enumerate().map(|(i, d)| out_line(i as u64, d)).collect();
    let mut errs = lines.clone();
    errs.iter_mut().for_each(|l| l.stream = LogStream::Stderr);
    let all: Vec<_> = lines
        .into_iter()
        .chain(errs.into_iter().map(|mut l| {
            l.seq += 10;
            l
        }))
        .collect();
    let server = logs_server(all);
    let out = Cli::new()
        .with_server(&server)
        .with_terminal_output()
        .run(&["logs", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    for text in [&out.stdout, &out.stderr] {
        // The only control characters left are the line ends.
        assert!(
            text.chars().all(|c| !c.is_control() || c == '\n'),
            "a control character reached the terminal: {text:?}"
        );
        // And the user can see what the job tried.
        assert!(text.contains("\\x1b[2J\\x1b[31mred\\x1b[0m"), "{text:?}");
        assert!(
            text.contains("\\x1b]52;c;cm0gLXJmIH4=\\x07\\x1b]0;pwned\\x07"),
            "{text:?}"
        );
        assert!(text.contains("all good\\rrm -rf ~"), "{text:?}");
        assert!(text.contains("\\u{009b}2J\\u{009d}52;c;eA==\\u{009c}"), "{text:?}");
    }
}

#[test]
fn when_piped_the_bytes_are_written_as_stored() {
    let id = JobId::generate();
    let data = "\u{1b}[31mred\u{1b}[0m\r\u{1b}]52;c;eA==\u{7}\n";
    let server = logs_server(vec![out_line(0, data), line(1, LogStream::Stderr, data)]);
    // Neither stdout nor stderr is a terminal.
    let out = Cli::new().with_server(&server).run(&["logs", &id.to_string()]);
    assert_eq!(out.stdout, data);
    assert_eq!(out.stderr, data);
}

#[test]
fn raw_forces_the_stored_bytes_on_a_terminal_too() {
    let id = JobId::generate();
    let data = "\u{1b}[31mred\u{1b}[0m\n";
    let server = logs_server(vec![out_line(0, data)]);
    let out = Cli::new()
        .with_server(&server)
        .with_terminal_output()
        .run(&["logs", &id.to_string(), "--raw"]);
    assert_eq!(out.stdout, data);
}

#[test]
fn a_job_without_log_output_says_so_and_a_missing_job_is_an_error() {
    let id = JobId::generate();
    let empty = logs_server(vec![]);
    let out = Cli::new().with_server(&empty).run(&["logs", &id.to_string()]);
    assert_eq!((out.code, out.stdout.as_str()), (0, ""), "{out:?}");
    assert!(out.stderr.contains("No log output"), "{out:?}");

    let missing = MockServer::start(|_| MockResponse::problem(404, "job_not_found", "no such job"));
    let out = Cli::new().with_server(&missing).run(&["logs", &id.to_string()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("no such job"), "{out:?}");
    assert_eq!(out.stdout, "");
}

#[test]
fn a_log_that_is_too_big_for_one_page_is_read_page_after_page() {
    let id = JobId::generate();
    // 40 lines of ~64 KiB: more than the 1 MiB a page asks for. The mock sends everything, `since_seq` is the client's job.
    let big = "x".repeat(64 * 1024);
    let lines: Vec<_> = (0..40).map(|i| out_line(i, &format!("{big}{i}\n"))).collect();
    let server = logs_server(lines);
    let out = Cli::new().with_server(&server).run(&["logs", &id.to_string()]);
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.lines().count(), 40);
    assert!(server.requests().len() > 1, "more than one page was needed");
    // Each page resumes at the last seq + 1.
    let since: Vec<_> = server
        .requests()
        .iter()
        .map(|r| param(r, "since_seq").unwrap())
        .collect();
    assert_eq!(since[0], "0");
    assert!(since[1].parse::<u64>().unwrap() > 0, "{since:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// p2pc logs --follow
// ---------------------------------------------------------------------------------------------------------------

/// A job server for the follow tests: `GET job` says `running` until the log stream has been asked for `streams`
/// times, then `done`. `logs` answers each request of the stream.
fn follow_server(
    id: JobId,
    done: Job,
    logs: impl Fn(&RecordedRequest, usize) -> MockResponse + Send + Sync + 'static,
) -> MockServer {
    let running = json_of(&fixtures::job(id, JobStatus::Running, None));
    let done = json_of(&done);
    let streams = Arc::new(AtomicUsize::new(0));
    MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => {
            let n = streams.fetch_add(1, Ordering::SeqCst);
            logs(req, n)
        }
        r if r.starts_with("GET /v1/jobs/") => {
            // The job is over once the log has been read to its end (the last answer is a complete one).
            if streams.load(Ordering::SeqCst) > 0 && req.header("x-test-never").is_none() {
                MockResponse::json(200, &done)
            } else {
                MockResponse::json(200, &running)
            }
        }
        _ => not_found(),
    })
}

#[test]
fn follow_survives_a_dropped_connection_and_prints_no_line_twice() {
    let id = JobId::generate();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    let server = follow_server(id, fixtures::job(id, JobStatus::Succeeded, Some(0)), move |req, n| {
        seen.lock()
            .unwrap()
            .push((param(req, "since_seq").unwrap(), param(req, "follow").unwrap()));
        match n {
            0 => ndjson(&[out_line(0, "zero\n"), line(1, LogStream::Stderr, "one\n")]).cut(),
            // The server repeats line 1 on resume: it must not be printed again.
            1 => ndjson(&[line(1, LogStream::Stderr, "one\n"), out_line(2, "two\n")]),
            // The job is final now: the conclusive read after it finds nothing more.
            _ => ndjson_since(
                &[
                    out_line(0, "zero\n"),
                    line(1, LogStream::Stderr, "one\n"),
                    out_line(2, "two\n"),
                ],
                req,
            ),
        }
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--follow"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, "zero\ntwo\n");
    assert_eq!(out.stderr, "one\n");
    // The second request resumed from the last seq + 1, still with follow=true.
    assert_eq!(
        *asked.lock().unwrap(),
        vec![
            ("0".into(), "true".into()),
            ("2".into(), "true".into()),
            ("3".into(), "true".into())
        ]
    );
}

#[test]
fn follow_ends_when_the_server_ends_the_stream_and_the_job_is_final() {
    let id = JobId::generate();
    // A failed job: `logs --follow` still worked, so it exits 0.
    let server = follow_server(id, fixtures::job(id, JobStatus::Failed, Some(3)), |_, _| {
        ndjson(&[out_line(0, "bye\n")])
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "-f", "--attempt", "1"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, "bye\n");
    assert_eq!(
        param(&server.requests_to(&format!("GET /v1/jobs/{id}/logs"))[0], "attempt").as_deref(),
        Some("1")
    );
}

#[test]
fn follow_of_a_job_that_is_already_over_prints_its_log_and_returns() {
    let id = JobId::generate();
    let done = json_of(&fixtures::job(id, JobStatus::Succeeded, Some(0)));
    let server = MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => ndjson(&[out_line(0, "all\n")]),
        r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &done),
        _ => not_found(),
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--follow"]);
    assert_eq!((out.code, out.stdout.as_str()), (0, "all\n"), "{out:?}");
}

#[test]
fn follow_goes_on_with_the_next_attempt_after_a_node_is_lost() {
    let id = JobId::generate();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let log = attempts.clone();
    let state = Arc::new(AtomicUsize::new(0));
    let first = {
        let mut j = fixtures::job(id, JobStatus::Running, None);
        j.attempt = 1;
        json_of(&j)
    };
    let second = {
        let mut j = fixtures::job(id, JobStatus::Running, None);
        j.attempt = 2;
        json_of(&j)
    };
    let done = {
        let mut j = fixtures::job(id, JobStatus::Succeeded, Some(0));
        j.attempt = 2;
        json_of(&j)
    };
    let server = {
        let state = state.clone();
        MockServer::start(move |req| match req.route().as_str() {
            r if r.ends_with("/logs") => {
                let attempt = param(req, "attempt").unwrap();
                log.lock()
                    .unwrap()
                    .push((attempt.clone(), param(req, "since_seq").unwrap()));
                match attempt.as_str() {
                    "1" => {
                        state.store(1, Ordering::SeqCst);
                        ndjson(&[out_line(0, "a1-0\n"), out_line(1, "a1-1\n")])
                    }
                    "2" => {
                        state.store(2, Ordering::SeqCst);
                        ndjson(&[out_line(0, "a2-0\n")])
                    }
                    other => panic!("attempt {other}"),
                }
            }
            r if r.starts_with("GET /v1/jobs/") => match state.load(Ordering::SeqCst) {
                0 => MockResponse::json(200, &first),
                // Attempt 1's stream ended and the job is on its second attempt.
                1 => MockResponse::json(200, &second),
                _ => MockResponse::json(200, &done),
            },
            _ => not_found(),
        })
    };
    // `logs --follow` starts from the job as `GET job` first returns it.
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--follow"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, "a1-0\na1-1\na2-0\n");
    // The second attempt's `seq` starts again at 0.
    // Attempt 1's tail is read once more when the job moves on (it was not known to be over before), and attempt
    // 2 is read once more when it ends.
    assert_eq!(
        *attempts.lock().unwrap(),
        vec![
            ("1".into(), "0".into()),
            ("1".into(), "2".into()),
            ("2".into(), "0".into()),
            ("2".into(), "1".into())
        ]
    );
}

#[test]
fn ctrl_c_stops_following_and_does_not_touch_the_job() {
    let id = JobId::generate();
    let ctrl_c = Arc::new(tokio::sync::Notify::new());
    let running = json_of(&fixtures::job(id, JobStatus::Running, None));
    let server = {
        let ctrl_c = ctrl_c.clone();
        MockServer::start(move |req| match req.route().as_str() {
            r if r.ends_with("/logs") => {
                ctrl_c.notify_one();
                ndjson(&[out_line(0, "still going\n")])
            }
            r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &running),
            _ => not_found(),
        })
    };
    let out = Cli::new()
        .with_server(&server)
        .interrupted_on(ctrl_c)
        .run(&["logs", &id.to_string(), "--follow"]);
    assert_eq!(out.code, 130, "{out:?}");
    // (Whether "still going" was printed before Ctrl-C won the race is not the point.)
    assert!(server.requests().iter().all(|r| r.method == "GET"), "nothing but reads");
}

#[test]
fn follow_of_a_missing_job_is_an_error_at_once() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::problem(404, "job_not_found", "no such job"));
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--follow"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("no such job"), "{out:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// p2pc run: the live follow
// ---------------------------------------------------------------------------------------------------------------

const RUN: [&str; 8] = ["run", "--image", "python:3.12-slim", "--cpu", "1", "--mem", "1G", "--"];

fn run_args<'a>(extra: &[&'a str], command: &[&'a str]) -> Vec<&'a str> {
    let mut args = RUN[..7].to_vec();
    args.extend_from_slice(extra);
    args.push("--");
    args.extend_from_slice(command);
    args
}

/// A server for `run`: it accepts the job (queued), then reports `done` once the log has been read.
fn run_server(
    id: JobId,
    done: Job,
    logs: impl Fn(&RecordedRequest, usize) -> MockResponse + Send + Sync + 'static,
) -> MockServer {
    let created = json_of(&fixtures::job(id, JobStatus::Running, None));
    let running = created.clone();
    let done = json_of(&done);
    let streams = Arc::new(AtomicUsize::new(0));
    MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &created),
        r if r.ends_with("/logs") => {
            let n = streams.fetch_add(1, Ordering::SeqCst);
            logs(req, n)
        }
        r if r.starts_with("GET /v1/jobs/") => {
            if streams.load(Ordering::SeqCst) > 0 {
                MockResponse::json(200, &done)
            } else {
                MockResponse::json(200, &running)
            }
        }
        _ => not_found(),
    })
}

#[test]
fn run_streams_the_logs_then_prints_the_final_status_and_exits_with_the_jobs_code() {
    let id = JobId::generate();
    let server = run_server(id, fixtures::job(id, JobStatus::Failed, Some(7)), |req, _| {
        assert_eq!(param(req, "follow").as_deref(), Some("true"));
        ndjson(&[out_line(0, "42\n"), line(1, LogStream::Stderr, "oops\n")])
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&run_args(&[], &["python", "-c", "print(6*7)"]));
    assert_eq!(out.code, 7, "{out:?}");
    assert_eq!(out.stdout, "42\n");
    // The job id first, then its stderr line between the state changes, and the status line last.
    assert!(out.stderr.starts_with(&id.to_string()), "{}", out.stderr);
    assert!(out.stderr.contains("oops\n"), "{}", out.stderr);
    assert!(
        out.stderr.trim_end().ends_with("job failed with exit code 7"),
        "{}",
        out.stderr
    );
}

#[test]
fn run_resumes_a_dropped_log_without_repeating_lines() {
    let id = JobId::generate();
    let server = run_server(id, fixtures::job(id, JobStatus::Succeeded, Some(0)), |req, n| match n {
        0 => ndjson(&[out_line(0, "one\n"), out_line(1, "two\n")]).cut(),
        1 => {
            assert_eq!(param(req, "since_seq").as_deref(), Some("2"));
            ndjson(&[out_line(1, "two\n"), out_line(2, "three\n")])
        }
        _ => ndjson_since(&[out_line(2, "three\n")], req),
    });
    let out = Cli::new().with_server(&server).run(&run_args(&[], &["true"]));
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, "one\ntwo\nthree\n");
}

#[test]
fn run_exit_codes_follow_the_spec_when_the_job_cannot_run_or_is_cancelled() {
    for (status, exit_code, error, expected) in [
        (JobStatus::Failed, None, Some("image_pull_failed"), 125),
        (JobStatus::Cancelled, None, None, 130),
        (JobStatus::TimedOut, None, None, 124),
        (JobStatus::Lost, None, None, 75),
        (JobStatus::Succeeded, Some(0), None, 0),
    ] {
        let id = JobId::generate();
        let mut done = fixtures::job(id, status, exit_code);
        done.error = error.map(str::to_string);
        let server = run_server(id, done, |_, _| ndjson(&[out_line(0, "x\n")]));
        let out = Cli::new().with_server(&server).run(&run_args(&[], &["true"]));
        assert_eq!(out.code, expected, "{status}: {out:?}");
        assert_eq!(out.stdout, "x\n", "{status}");
    }
}

#[test]
fn run_on_a_terminal_cannot_be_driven_by_the_job_either() {
    let id = JobId::generate();
    let server = run_server(id, fixtures::job(id, JobStatus::Succeeded, Some(0)), |_, _| {
        ndjson(&[
            out_line(0, "\u{1b}]52;c;eA==\u{7}hi\rbye\n"),
            line(1, LogStream::Stderr, "\u{1b}[2J\n"),
        ])
    });
    let out = Cli::new()
        .with_server(&server)
        .with_terminal_output()
        .run(&run_args(&[], &["true"]));
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, "\\x1b]52;c;eA==\\x07hi\\rbye\n");
    assert!(out.stderr.contains("\\x1b[2J"), "{}", out.stderr);
    for text in [&out.stdout, &out.stderr] {
        assert!(text.chars().all(|c| !c.is_control() || c == '\n'), "{text:?}");
    }
}

#[test]
fn run_with_json_streams_the_log_records_and_ends_with_the_final_job() {
    let id = JobId::generate();
    let finished = fixtures::job(id, JobStatus::Succeeded, Some(0));
    let server = run_server(id, finished.clone(), |_, _| ndjson(&[out_line(0, "hi\n")]));
    let out = Cli::new().with_server(&server).run(&run_args(&["--json"], &["true"]));
    assert_eq!(out.code, 0, "{out:?}");
    let lines: Vec<Value> = out.stdout.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 2, "{}", out.stdout);
    assert_eq!(lines[0]["data"], "hi\n");
    assert_eq!(lines[1], json_of(&finished));
}

#[test]
fn ctrl_c_during_the_live_follow_detaches_and_says_how_to_follow_again_and_to_cancel() {
    let id = JobId::generate();
    let ctrl_c = Arc::new(tokio::sync::Notify::new());
    let running = json_of(&fixtures::job(id, JobStatus::Running, None));
    let server = {
        let (ctrl_c, running) = (ctrl_c.clone(), running.clone());
        MockServer::start(move |req| match req.route().as_str() {
            "POST /v1/jobs" => MockResponse::json(201, &running),
            r if r.ends_with("/logs") => {
                ctrl_c.notify_one();
                ndjson(&[out_line(0, "working\n")]).cut()
            }
            r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &running),
            _ => not_found(),
        })
    };
    let out = Cli::new()
        .with_server(&server)
        .interrupted_on(ctrl_c)
        .run(&run_args(&[], &["sleep", "600"]));
    assert_eq!(out.code, 130, "{out:?}");
    assert!(
        out.stderr.contains(&format!("p2pc logs --follow {id}")),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains(&format!("p2pc cancel {id}")), "{}", out.stderr);
    assert!(
        server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty(),
        "Ctrl-C must not cancel"
    );
}

/// T11b2 review: `p2pc run … | head -1` closes stdout while the job goes on spending units. It must not leave without a
/// word: it says how to follow the job again and how to stop it, like Ctrl-C does, and it does not cancel (spec §7).
#[test]
fn a_closed_stdout_detaches_with_the_same_hint_as_ctrl_c_and_does_not_cancel() {
    let id = JobId::generate();
    // The job is still running when the pipe closes.
    let server = run_server(id, fixtures::job(id, JobStatus::Running, None), |_, _| {
        ndjson(&[out_line(0, "first\n"), out_line(1, "second\n")])
    });
    let out = Cli::new()
        .with_server(&server)
        .with_closed_stdout()
        .run(&run_args(&[], &["yes"]));
    assert_eq!(out.code, 130, "{out:?}");
    assert!(
        out.stderr.contains(&format!("p2pc logs --follow {id}")),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains(&format!("p2pc cancel {id}")), "{}", out.stderr);
    assert!(
        !out.stderr.contains("error:"),
        "a closed pipe is not an error: {}",
        out.stderr
    );
    assert!(
        server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty(),
        "a closed pipe must not cancel"
    );
}

/// T11b3 review: a short job's whole log arrives in the final read. If the pipe closes then, the job has ended: saying
/// that it "keeps running" would be false, and a job that succeeded would exit 130. `run` looks at the job's state first.
#[test]
fn a_closed_stdout_after_the_job_ended_returns_the_jobs_own_code_without_a_detach_hint() {
    for (done, code, said) in [
        (JobStatus::Succeeded, Some(0), "job succeeded"),
        (JobStatus::Failed, Some(7), "job failed with exit code 7"),
    ] {
        let id = JobId::generate();
        let server = run_server(id, fixtures::job(id, done, code), |_, _| ndjson(&[out_line(0, "x\n")]));
        let out = Cli::new()
            .with_server(&server)
            .with_closed_stdout()
            .run(&run_args(&[], &["true"]));
        assert_eq!(i32::from(out.code), code.unwrap(), "{done}: {out:?}");
        assert!(out.stderr.contains(said), "{done}: {}", out.stderr);
        assert!(!out.stderr.contains("detached"), "{done}: {}", out.stderr);
        assert!(!out.stderr.contains("keeps running"), "{done}: {}", out.stderr);
        assert!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty());
    }
}

/// T11b3 review: with `--json` the job's final record is written after the follow ended. If the reader is gone by then
/// the write fails too: the job's own code must survive it (spec §7), not become 0.
#[test]
fn a_closed_stdout_before_the_final_json_record_returns_the_jobs_own_code() {
    for (done, code) in [(JobStatus::Succeeded, Some(0)), (JobStatus::Failed, Some(7))] {
        let id = JobId::generate();
        // No log lines: the final record is the first thing written to stdout.
        let server = run_server(id, fixtures::job(id, done, code), |_, _| ndjson(&[]));
        let out = Cli::new()
            .with_server(&server)
            .with_closed_stdout()
            .run(&run_args(&["--json"], &["true"]));
        assert_eq!(i32::from(out.code), code.unwrap(), "{done}: {out:?}");
        assert!(!out.stderr.contains("detached"), "{done}: {}", out.stderr);
        assert!(!out.stderr.contains("error:"), "{done}: {}", out.stderr);
    }
}

#[test]
fn a_closed_stdout_with_json_while_the_job_runs_detaches_with_the_hint() {
    let id = JobId::generate();
    let server = run_server(id, fixtures::job(id, JobStatus::Running, None), |_, _| {
        ndjson(&[out_line(0, "first\n")])
    });
    let out = Cli::new()
        .with_server(&server)
        .with_closed_stdout()
        .run(&run_args(&["--json"], &["yes"]));
    assert_eq!(out.code, 130, "{out:?}");
    assert!(
        out.stderr.contains(&format!("p2pc logs --follow {id}")),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains(&format!("p2pc cancel {id}")), "{}", out.stderr);
    assert!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty());
}

/// A write error that is not a closed pipe (a full disk) is an error: 125, after saying what became of the job.
#[test]
fn another_write_error_on_stdout_is_an_error_after_saying_what_became_of_the_job() {
    // Still running: the detach hint, then the error.
    let id = JobId::generate();
    let server = run_server(id, fixtures::job(id, JobStatus::Running, None), |_, _| {
        ndjson(&[out_line(0, "x\n")])
    });
    let out = Cli::new()
        .with_server(&server)
        .with_failing_stdout(std::io::ErrorKind::Other)
        .run(&run_args(&[], &["yes"]));
    assert_eq!(out.code, 125, "{out:?}");
    assert!(
        out.stderr.contains(&format!("p2pc logs --follow {id}")),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("error:"), "{}", out.stderr);
    assert!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty());

    // Already over: the outcome line, not the hint, then the error.
    let id = JobId::generate();
    let server = run_server(id, fixtures::job(id, JobStatus::Failed, Some(7)), |_, _| {
        ndjson(&[out_line(0, "x\n")])
    });
    let out = Cli::new()
        .with_server(&server)
        .with_failing_stdout(std::io::ErrorKind::Other)
        .run(&run_args(&[], &["false"]));
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("job failed with exit code 7"), "{}", out.stderr);
    assert!(!out.stderr.contains("keeps running"), "{}", out.stderr);
    assert!(out.stderr.contains("error:"), "{}", out.stderr);
    assert!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty());
}

/// T11b3 review: a closed stderr must not turn an outcome into 0 (`app::run` maps `BrokenPipe` to success).
#[test]
fn a_closed_stderr_keeps_ctrl_c_at_130_and_a_follow_error_at_125() {
    // Ctrl-C while following.
    let id = JobId::generate();
    let ctrl_c = Arc::new(tokio::sync::Notify::new());
    let running = json_of(&fixtures::job(id, JobStatus::Running, None));
    let server = {
        let (ctrl_c, running) = (ctrl_c.clone(), running.clone());
        MockServer::start(move |req| match req.route().as_str() {
            "POST /v1/jobs" => MockResponse::json(201, &running),
            r if r.ends_with("/logs") => {
                ctrl_c.notify_one();
                ndjson(&[out_line(0, "working\n")]).cut()
            }
            r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &running),
            _ => not_found(),
        })
    };
    let out = Cli::new()
        .with_server(&server)
        .with_failing_stderr(std::io::ErrorKind::BrokenPipe)
        .interrupted_on(ctrl_c)
        .run(&run_args(&[], &["sleep", "600"]));
    assert_eq!(out.code, 130, "{out:?}");
    assert!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty());

    // A permanent error while following (the job cannot be found).
    let created = json_of(&fixtures::job(id, JobStatus::Running, None));
    let server = MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &created),
        _ => MockResponse::problem(404, "job_not_found", "no such job"),
    });
    let out = Cli::new()
        .with_server(&server)
        .with_failing_stderr(std::io::ErrorKind::BrokenPipe)
        .run(&run_args(&[], &["true"]));
    assert_eq!(out.code, 125, "{out:?}");

    // Ctrl-C during the submission.
    let server = MockServer::start(|_| not_found());
    let out = Cli::new()
        .with_server(&server)
        .with_failing_stderr(std::io::ErrorKind::BrokenPipe)
        .interrupted()
        .run(&run_args(&[], &["true"]));
    assert_eq!(out.code, 130, "{out:?}");
}

/// T11b3 review: the job's stderr lines go to our stderr. If that stream is closed (`2>&-`, `2>/dev/full`) the follow must
/// go on: stdout keeps flowing and the exit code is the job's own, not 130 (a detach) or 125.
#[test]
fn a_closed_stderr_does_not_end_the_follow_and_stdout_keeps_flowing() {
    let make_server = |id: JobId| {
        run_server(id, fixtures::job(id, JobStatus::Failed, Some(3)), |_, _| {
            ndjson(&[
                out_line(0, "one\n"),
                line(1, LogStream::Stderr, "warning\n"),
                out_line(2, "two\n"),
                line(3, LogStream::Stderr, "again\n"),
                out_line(4, "three\n"),
            ])
        })
    };
    let closed = [
        Cli::new().with_failing_stderr(std::io::ErrorKind::BrokenPipe),
        Cli::new().with_invalid_stderr(),
    ];
    for cli in closed {
        let id = JobId::generate();
        let server = make_server(id);
        let out = cli.with_server(&server).run(&run_args(&[], &["false"]));
        assert_eq!(out.code, 3, "the job's own code: {out:?}");
        assert_eq!(out.stdout, "one\ntwo\nthree\n", "{out:?}");
        assert!(server.requests_to(&format!("POST /v1/jobs/{id}/cancel")).is_empty());
    }
    // `p2pc logs --follow` and a page of the log too.
    let id = JobId::generate();
    let server = follow_server(id, fixtures::job(id, JobStatus::Failed, Some(3)), |_, _| {
        ndjson(&[
            out_line(0, "one\n"),
            line(1, LogStream::Stderr, "warning\n"),
            out_line(2, "two\n"),
        ])
    });
    for args in [vec!["logs", "--follow"], vec!["logs"]] {
        let id_text = id.to_string();
        let mut argv = vec![args[0], id_text.as_str()];
        argv.extend_from_slice(&args[1..]);
        let out = Cli::new().with_server(&server).with_invalid_stderr().run(&argv);
        assert_eq!(out.code, 0, "{args:?}: {out:?}");
        assert_eq!(out.stdout, "one\ntwo\n", "{args:?}: {out:?}");
    }
}

/// The follower already knew the job had ended (the final read is the one that failed): even if the server cannot be
/// asked again, the job it carried decides.
#[test]
fn a_closed_stdout_uses_the_job_the_follow_already_knew_when_the_server_cannot_be_asked() {
    let id = JobId::generate();
    let created = json_of(&fixtures::job(id, JobStatus::Running, None));
    let done = json_of(&fixtures::job(id, JobStatus::Failed, Some(7)));
    let (reads, gets) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let server = MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &created),
        // The first read is empty (the job was still running when it began); the one after the job ended has the log.
        r if r.ends_with("/logs") => {
            if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                ndjson(&[])
            } else {
                ndjson(&[out_line(0, "x\n")])
            }
        }
        // The follow sees the job over once; every later question fails.
        r if r.starts_with("GET /v1/jobs/") && gets.fetch_add(1, Ordering::SeqCst) == 0 => {
            MockResponse::json(200, &done)
        }
        _ => MockResponse::text(500, "down"),
    });
    let out = Cli::new()
        .with_server(&server)
        .with_closed_stdout()
        .run(&run_args(&[], &["false"]));
    assert_eq!(out.code, 7, "{out:?}");
    assert!(!out.stderr.contains("keeps running"), "{}", out.stderr);
}

// ---------------------------------------------------------------------------------------------------------------
// p2pc results
// ---------------------------------------------------------------------------------------------------------------

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn output(path: &str, bytes: &[u8]) -> OutputFile {
    OutputFile {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

/// A server with `files` (path, content) as the outputs of any job.
fn outputs_server(files: Vec<(&'static str, &'static [u8])>) -> MockServer {
    let listing = json!({
        "items": files.iter().map(|(p, c)| json_of(&output(p, c))).collect::<Vec<_>>(),
        "next_cursor": null,
    });
    MockServer::start(move |req| {
        if req.path.ends_with("/outputs") {
            return MockResponse::json(200, &listing);
        }
        let rest = req.path.split("/outputs/").nth(1).unwrap_or_default();
        match files.iter().find(|(p, _)| *p == rest) {
            Some((_, content)) => MockResponse {
                status: 200,
                headers: vec![],
                body: content.to_vec(),
            },
            None => MockResponse::problem(404, "output_not_found", "no such output"),
        }
    })
}

#[test]
fn results_download_everything_verify_it_and_summarise() {
    let id = JobId::generate();
    let server = outputs_server(vec![("a.txt", b"hello"), ("deep/er/b.csv", b"1,2,3\n")]);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("out");
    let out = Cli::new()
        .with_server(&server)
        .run(&["results", &id.to_string(), "--out", target.to_str().unwrap()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"hello");
    assert_eq!(std::fs::read(target.join("deep/er/b.csv")).unwrap(), b"1,2,3\n");
    assert!(out.stdout.contains("2 files"), "{}", out.stdout);
    assert!(out.stdout.contains("11 B"), "{}", out.stdout);
    assert!(out.stdout.contains("sha256 verified"), "{}", out.stdout);
    // No temporary file is left behind.
    let leftovers: Vec<_> = walk(&target).into_iter().filter(|p| p.contains(".p2pc-part")).collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

fn walk(dir: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path.display().to_string());
        }
    }
    found
}

#[test]
fn the_default_directory_is_p2pc_results_slash_the_job_id() {
    let id = JobId::generate();
    assert_eq!(
        p2pc_cli::commands::results::default_dir(&id),
        std::path::PathBuf::from("p2pc-results").join(id.to_string())
    );
}

#[test]
fn results_with_file_download_only_those_and_attempt_goes_on_every_request() {
    let id = JobId::generate();
    let server = outputs_server(vec![("a.txt", b"hello"), ("b.txt", b"world")]);
    let dir = tempfile::tempdir().unwrap();
    let out = Cli::new().with_server(&server).run(&[
        "results",
        &id.to_string(),
        "--out",
        dir.path().to_str().unwrap(),
        "--file",
        "b.txt",
        "--attempt",
        "2",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(!dir.path().join("a.txt").exists());
    assert_eq!(std::fs::read(dir.path().join("b.txt")).unwrap(), b"world");
    assert!(out.stdout.contains("1 file,"), "{}", out.stdout);
    for req in server.requests() {
        assert_eq!(param(&req, "attempt").as_deref(), Some("2"), "{}", req.path);
    }
}

#[test]
fn results_for_a_file_the_job_did_not_produce_download_nothing() {
    let id = JobId::generate();
    let server = outputs_server(vec![("a.txt", b"hello")]);
    let dir = tempfile::tempdir().unwrap();
    let out = Cli::new().with_server(&server).run(&[
        "results",
        &id.to_string(),
        "--out",
        dir.path().to_str().unwrap(),
        "--file",
        "nope.txt",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("nope.txt"), "{}", out.stderr);
    assert_eq!(walk(dir.path()).len(), 0);
}

#[test]
fn results_never_overwrite_an_existing_file_without_force() {
    let id = JobId::generate();
    let server = outputs_server(vec![("a.txt", b"new!"), ("b.txt", b"new!")]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"mine").unwrap();
    let args = ["results", &id.to_string(), "--out", dir.path().to_str().unwrap()];
    let out = Cli::new().with_server(&server).run(&args);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(
        out.stderr.contains("a.txt") && out.stderr.contains("--force"),
        "{}",
        out.stderr
    );
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"mine");
    // Nothing at all was downloaded, not even the file that was free.
    assert!(!dir.path().join("b.txt").exists());
    assert_eq!(server.requests_to(&format!("GET /v1/jobs/{id}/outputs/b.txt")).len(), 0);

    // With --force it is replaced.
    let mut forced: Vec<&str> = args.to_vec();
    forced.push("--force");
    let out = Cli::new().with_server(&server).run(&forced);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"new!");
    assert_eq!(std::fs::read(dir.path().join("b.txt")).unwrap(), b"new!");
}

#[cfg(unix)]
#[test]
fn results_do_not_write_through_a_symlink_that_is_in_the_way() {
    let id = JobId::generate();
    let server = outputs_server(vec![("a.txt", b"new!")]);
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("victim"), b"keep").unwrap();
    std::os::unix::fs::symlink(elsewhere.path().join("victim"), dir.path().join("a.txt")).unwrap();
    let out = Cli::new()
        .with_server(&server)
        .run(&["results", &id.to_string(), "--out", dir.path().to_str().unwrap()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert_eq!(std::fs::read(elsewhere.path().join("victim")).unwrap(), b"keep");
}

#[test]
fn results_check_the_sha256_and_keep_nothing_of_a_file_that_fails() {
    let id = JobId::generate();
    let listing = json!({"items": [json_of(&output("a.txt", b"expected"))], "next_cursor": null});
    let server = MockServer::start(move |req| {
        if req.path.ends_with("/outputs") {
            MockResponse::json(200, &listing)
        } else {
            // Same size, different content.
            MockResponse::text(200, "tampered")
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let out = Cli::new()
        .with_server(&server)
        .run(&["results", &id.to_string(), "--out", dir.path().to_str().unwrap()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("SHA-256"), "{}", out.stderr);
    assert!(!out.stdout.contains("sha256 verified"), "{}", out.stdout);
    assert_eq!(walk(dir.path()).len(), 0, "nothing of the failed file is kept");
}

#[test]
fn results_refuse_a_path_that_would_leave_the_directory() {
    let id = JobId::generate();
    let hostile = ["../escape.txt", "/etc/cron.d/evil", "a/../../b", "a//b", "x\u{1b}[2J"];
    for path in hostile {
        let listing = json!({"items": [{"path": path, "size": 1, "sha256": digest(b"x")}], "next_cursor": null});
        let server = MockServer::start(move |req| {
            if req.path.ends_with("/outputs") {
                MockResponse::json(200, &listing)
            } else {
                MockResponse::text(200, "x")
            }
        });
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("results");
        let out = Cli::new().with_server(&server).run(&[
            "results",
            &id.to_string(),
            "--out",
            dir.to_str().unwrap(),
            "--force",
        ]);
        assert_eq!(out.code, 125, "{path:?}: {out:?}");
        assert!(!out.stderr.contains('\u{1b}'), "{path:?}: {:?}", out.stderr);
        assert!(walk(parent.path()).is_empty(), "{path:?}: nothing was written");
        // And no download request was made for it.
        assert_eq!(server.requests().len(), 1, "{path:?}: only the list was asked for");
    }
}

#[test]
fn results_of_expired_outputs_say_so_with_a_clear_message() {
    let id = JobId::generate();
    let dir = tempfile::tempdir().unwrap();
    // `410` on a download, after a list that still names the file (the entry shows `expired: true`).
    let listing = json!({"items": [{"path": "a.txt", "size": 5, "sha256": digest(b"hello"), "expired": true}], "next_cursor": null});
    let gone = MockServer::start(move |req| {
        if req.path.ends_with("/outputs") {
            MockResponse::json(200, &listing)
        } else {
            MockResponse::problem(410, "outputs_expired", "the outputs were deleted")
        }
    });
    let out = Cli::new()
        .with_server(&gone)
        .run(&["results", &id.to_string(), "--out", dir.path().to_str().unwrap()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("expired"), "{}", out.stderr);
    assert!(out.stderr.contains(&id.to_string()), "{}", out.stderr);
    assert_eq!(walk(dir.path()).len(), 0);

    // `410` on the list itself.
    let gone = MockServer::start(|_| MockResponse::problem(410, "outputs_expired", "gone"));
    let out = Cli::new()
        .with_server(&gone)
        .run(&["results", &id.to_string(), "--out", dir.path().to_str().unwrap()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("expired"), "{}", out.stderr);
    // With --json the error says what it is.
    let out = Cli::new().with_server(&gone).run(&[
        "results",
        &id.to_string(),
        "--out",
        dir.path().to_str().unwrap(),
        "--json",
    ]);
    let err: Value = serde_json::from_str(out.stderr.trim()).unwrap();
    assert_eq!(err["error"]["kind"], "outputs_expired", "{err}");
}

#[test]
fn results_of_a_missing_job_are_a_404() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::problem(404, "job_not_found", "no such job"));
    let dir = tempfile::tempdir().unwrap();
    let out = Cli::new()
        .with_server(&server)
        .run(&["results", &id.to_string(), "--out", dir.path().to_str().unwrap()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("no such job"), "{}", out.stderr);
}

#[test]
fn results_of_a_job_without_outputs_say_so() {
    let id = JobId::generate();
    let server = outputs_server(vec![]);
    let dir = tempfile::tempdir().unwrap();
    let out = Cli::new()
        .with_server(&server)
        .run(&["results", &id.to_string(), "--out", dir.path().to_str().unwrap()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stderr.contains("no output files"), "{}", out.stderr);
    assert_eq!(walk(dir.path()).len(), 0);
}

#[test]
fn results_with_json_describe_what_was_saved() {
    let id = JobId::generate();
    let server = outputs_server(vec![("a.txt", b"hello")]);
    let dir = tempfile::tempdir().unwrap();
    let out = Cli::new().with_server(&server).run(&[
        "results",
        &id.to_string(),
        "--out",
        dir.path().to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    let v: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["job_id"], id.to_string());
    assert_eq!(v["bytes"], 5);
    assert_eq!(v["files"][0]["path"], "a.txt");
    assert_eq!(v["files"][0]["sha256"], digest(b"hello").to_string());
}

// ---------------------------------------------------------------------------------------------------------------
// p2pc usage
// ---------------------------------------------------------------------------------------------------------------

fn totals(key: Option<&str>, attempts: u64, units_milli: u64, estimated: u64) -> UsageTotals {
    UsageTotals {
        key: key.map(String::from),
        attempts,
        units: Units::from_milli(units_milli),
        reserved_cpu_ms: attempts * 3_600_000,
        used_cpu_ms: attempts * 1_800_000,
        estimated_attempts: estimated,
        ..UsageTotals::default()
    }
}

fn report(by: UsageGroupBy, items: Vec<UsageTotals>, next: Option<&str>) -> UsageReport {
    let mut total = totals(None, 3, 3000, 1);
    total.reserved_gpu_ms = 90_000;
    let mut r = UsageReport::new(fixtures::t0(), fixtures::t0() + time::Duration::days(1), by, total);
    r.items = items;
    r.next_cursor = next.map(String::from);
    r
}

#[test]
fn usage_shows_a_table_and_marks_what_the_server_estimated() {
    let server = MockServer::start(|_| {
        MockResponse::json(
            200,
            &json_of(&report(
                UsageGroupBy::Job,
                vec![
                    totals(Some("job_exact"), 2, 2000, 0),
                    totals(Some("job_lost"), 1, 1000, 1),
                ],
                None,
            )),
        )
    });
    let out = Cli::new().with_server(&server).run(&["usage"]);
    assert_eq!(out.code, 0, "{out:?}");
    let rows: Vec<&str> = out.stdout.lines().collect();
    assert!(rows[0].contains("2023-11-14T22:13:20Z"), "{}", out.stdout);
    for header in [
        "JOB",
        "ATTEMPTS",
        "UNITS",
        "CPU RESERVED",
        "CPU USED",
        "GPU RESERVED",
        "ESTIMATED",
    ] {
        assert!(rows[1].contains(header), "{header}: {}", out.stdout);
    }
    let exact = rows.iter().find(|r| r.starts_with("job_exact")).unwrap();
    let lost = rows.iter().find(|r| r.starts_with("job_lost")).unwrap();
    let total = rows.iter().find(|r| r.starts_with("TOTAL")).unwrap();
    // "≈" only where the estimated attempts are above zero.
    assert!(!exact.contains('≈'), "{exact}");
    assert!(lost.contains("≈1.000") && lost.trim_end().ends_with("≈1"), "{lost}");
    assert!(total.contains("≈3.000") && total.contains("1m 30s"), "{total}");
    assert!(exact.contains("2.000") && exact.contains("2h 0m"), "{exact}");
    assert!(out.stderr.contains('≈'), "the footnote explains it: {}", out.stderr);
}

#[test]
fn usage_without_estimates_has_no_marks_and_no_footnote() {
    let server = MockServer::start(|_| {
        let mut r = report(UsageGroupBy::Job, vec![totals(Some("job_a"), 3, 3000, 0)], None);
        r.total.estimated_attempts = 0;
        MockResponse::json(200, &json_of(&r))
    });
    let out = Cli::new().with_server(&server).run(&["usage"]);
    assert!(!out.stdout.contains('≈') && !out.stderr.contains('≈'), "{out:?}");
}

#[test]
fn usage_defaults_to_today_in_utc_in_whole_seconds() {
    let server = MockServer::start(|_| MockResponse::json(200, &json_of(&report(UsageGroupBy::Job, vec![], None))));
    // The harness clock is 2023-11-14T22:13:20.123456789Z.
    let out = Cli::new().with_server(&server).run(&["usage"]);
    assert_eq!(out.code, 0, "{out:?}");
    let req = &server.requests()[0];
    assert_eq!(req.path, "/v1/usage");
    assert_eq!(param(req, "from").as_deref(), Some("2023-11-14T00:00:00Z"));
    assert_eq!(param(req, "to").as_deref(), Some("2023-11-15T00:00:00Z"));
    assert_eq!(param(req, "group_by").as_deref(), Some("job"));
}

#[test]
fn usage_sends_dates_by_group_and_walks_every_page() {
    let pages = Arc::new(Mutex::new(Vec::new()));
    let seen = pages.clone();
    let server = MockServer::start(move |req| {
        seen.lock().unwrap().push(param(req, "cursor"));
        match param(req, "cursor").as_deref() {
            None => MockResponse::json(
                200,
                &json_of(&report(
                    UsageGroupBy::Node,
                    vec![totals(Some("node_a"), 1, 1000, 0)],
                    Some("c2"),
                )),
            ),
            Some("c2") => MockResponse::json(
                200,
                &json_of(&report(
                    UsageGroupBy::Node,
                    vec![totals(Some("node_b"), 2, 2000, 0)],
                    None,
                )),
            ),
            Some(other) => panic!("cursor {other}"),
        }
    });
    let out = Cli::new().with_server(&server).run(&[
        "usage",
        "--from",
        "2023-11-01",
        "--to",
        "2023-11-08T12:30:00.987+02:00",
        "--by",
        "node",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stdout.contains("node_a") && out.stdout.contains("node_b"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.lines().nth(1).unwrap().starts_with("NODE"), "{}", out.stdout);
    let first = &server.requests()[0];
    assert_eq!(param(first, "from").as_deref(), Some("2023-11-01T00:00:00Z"));
    assert_eq!(param(first, "to").as_deref(), Some("2023-11-08T10:30:00Z"));
    assert_eq!(param(first, "group_by").as_deref(), Some("node"));
    assert_eq!(*pages.lock().unwrap(), vec![None, Some("c2".to_string())]);
}

#[test]
fn usage_with_json_prints_the_report_as_it_is() {
    let expected = report(UsageGroupBy::Key, vec![totals(Some("k1"), 1, 1000, 1)], None);
    let body = json_of(&expected);
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let out = Cli::new().with_server(&server).run(&["usage", "--by", "key", "--json"]);
    assert_eq!(out.code, 0, "{out:?}");
    let got: UsageReport = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(got, expected);
    assert_eq!(got.items[0].estimated_attempts, 1);
}

#[test]
fn usage_rejects_what_it_cannot_read_before_asking() {
    let server = MockServer::start(|_| not_found());
    for args in [
        ["usage", "--from", "yesterday"],
        ["usage", "--by", "colour"],
        ["usage", "--to", "2023-13-40"],
    ] {
        let out = Cli::new().with_server(&server).run(&args);
        assert_eq!(out.code, 125, "{args:?}: {out:?}");
    }
    assert!(server.requests().is_empty());
}

#[test]
fn usage_passes_a_refused_range_through() {
    let server = MockServer::start(|_| MockResponse::problem(422, "validation_failed", "from must be before to"));
    let out = Cli::new()
        .with_server(&server)
        .run(&["usage", "--from", "2023-11-08", "--to", "2023-11-01"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("from must be before to"), "{}", out.stderr);
}

// ---------------------------------------------------------------------------------------------------------------
// status: the command is shown as a shell would read it
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn status_shows_the_command_shell_quoted() {
    let id = JobId::generate();
    let mut job = fixtures::job(id, JobStatus::Succeeded, Some(0));
    job.spec.command = vec![
        "python".into(),
        "-c".into(),
        "print(6*7)".into(),
        "it's a \"test\"".into(),
    ];
    let body = json_of(&job);
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let out = Cli::new().with_server(&server).run(&["status", &id.to_string()]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        out.stdout.contains(r#"python -c 'print(6*7)' 'it'\''s a "test"'"#),
        "{}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------------------------------------------
// A fast job: its log must not be lost to a 404 or an empty answer that came before it was written
// ---------------------------------------------------------------------------------------------------------------

/// A job on its first attempt, `assigned` for the first `running_gets` reads of `GET job` and `succeeded` after. Its log
/// answers `first_log` the first time it is asked (before the job wrote anything), and `lines` after that.
fn fast_job_server(id: JobId, running_gets: usize, first_log: fn() -> MockResponse, lines: Vec<LogLine>) -> MockServer {
    let assigned = json_of(&fixtures::job(id, JobStatus::Assigned, None));
    let done = json_of(&fixtures::job(id, JobStatus::Succeeded, Some(0)));
    let (gets, logs) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &assigned),
        r if r.ends_with("/logs") => match logs.fetch_add(1, Ordering::SeqCst) {
            0 => first_log(),
            _ => ndjson_since(&lines, req),
        },
        r if r.starts_with("GET /v1/jobs/") => {
            if gets.fetch_add(1, Ordering::SeqCst) < running_gets {
                MockResponse::json(200, &assigned)
            } else {
                MockResponse::json(200, &done)
            }
        }
        _ => not_found(),
    })
}

fn log_not_found() -> MockResponse {
    MockResponse::problem(404, "job_not_found", "no such job")
}

fn log_empty() -> MockResponse {
    ndjson(&[])
}

#[test]
fn a_fast_jobs_output_is_not_lost_to_a_404_or_an_empty_answer_before_it_was_written() {
    let lines = vec![out_line(0, "42\n"), out_line(1, "43\n")];
    for (name, first_log) in [("404", log_not_found as fn() -> MockResponse), ("empty 200", log_empty)] {
        // `p2pc logs --follow`, with and without --attempt: queued -> assigned (no log yet) -> succeeded (with a log).
        for extra in [&[][..], &["--attempt", "1"][..]] {
            let id = JobId::generate();
            let server = fast_job_server(id, 1, first_log, lines.clone());
            let mut args = vec!["logs", "--follow"];
            args.extend_from_slice(extra);
            let id_text = id.to_string();
            args.insert(1, &id_text);
            let out = Cli::new().with_server(&server).run(&args);
            assert_eq!(out.code, 0, "{name} {extra:?}: {out:?}");
            assert_eq!(out.stdout, "42\n43\n", "{name} {extra:?}");
            // The last read began after the job was seen final, and it is the one that found the lines.
            let reads = server.requests_to(&format!("GET /v1/jobs/{id}/logs"));
            assert_eq!(reads.len(), 2, "{name} {extra:?}");
        }
        // `p2pc run`: the job is already final when it is first read.
        let id = JobId::generate();
        let server = fast_job_server(id, 0, first_log, lines.clone());
        let out = Cli::new()
            .with_server(&server)
            .run(&run_args(&[], &["python", "-c", "print(6*7)"]));
        assert_eq!(out.code, 0, "{name}: {out:?}");
        assert_eq!(out.stdout, "42\n43\n", "{name}");
    }
}

#[test]
fn a_404_after_the_job_was_seen_final_is_conclusive() {
    let id = JobId::generate();
    let done = json_of(&fixtures::job(id, JobStatus::Failed, None));
    let server = MockServer::start(move |req| {
        if req.path.ends_with("/logs") {
            log_not_found()
        } else {
            MockResponse::json(200, &done)
        }
    });
    // Following the latest attempt: a job that never wrote a log simply ends.
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--follow"]);
    assert_eq!((out.code, out.stdout.as_str()), (0, ""), "{out:?}");
    assert_eq!(server.requests_to(&format!("GET /v1/jobs/{id}/logs")).len(), 1);
    // Asking for an attempt that has no log: the error.
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--follow", "--attempt", "1"]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("no such job"), "{out:?}");
}

/// T11b3 review: two separate outages, with a good read between them. Each is announced, and the follow ends normally.
#[test]
fn follow_goes_through_two_separate_outages_and_ends_normally() {
    let id = JobId::generate();
    let running = json_of(&fixtures::job(id, JobStatus::Running, None));
    let done = json_of(&fixtures::job(id, JobStatus::Succeeded, Some(0)));
    let gets = Arc::new(AtomicUsize::new(0));
    let server = MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => ndjson(&[out_line(0, "hi\n")]),
        r if r.starts_with("GET /v1/jobs/") => match gets.fetch_add(1, Ordering::SeqCst) {
            0 => MockResponse::json(200, &running),
            // The first outage: more failures in a row than the client's own three retries.
            1..=4 => MockResponse::text(502, "bad gateway"),
            // A good answer in between.
            5 => MockResponse::json(200, &running),
            // The second outage.
            6..=9 => MockResponse::text(502, "bad gateway"),
            _ => MockResponse::json(200, &done),
        },
        _ => not_found(),
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["logs", &id.to_string(), "--follow"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, "hi\n");
    assert_eq!(out.stderr.matches("reconnecting…").count(), 2, "{}", out.stderr);
}

/// Same, one level down, to see the waits: after a good answer the next outage starts again at 1 s, not where the first
/// one stopped (1, 2, 4 s).
#[test]
fn the_wait_of_an_outage_starts_again_after_a_good_answer() {
    use p2pc_cli::follow::{FollowError, Followed, LogSink, PollSchedule, Progress, Sleeper, StreamFollower};
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct Instant(Arc<Mutex<Vec<Duration>>>);
    impl Sleeper for Instant {
        async fn sleep(&mut self, d: Duration) {
            self.0.lock().unwrap().push(d);
        }
    }
    #[derive(Default)]
    struct Count(u32);
    impl Progress for Count {
        fn on_status(&mut self, _: &Job) {}
        fn on_reconnecting(&mut self, _: &p2pc_client::Error) {
            self.0 += 1;
        }
    }
    impl LogSink for Count {
        fn line(&mut self, _: &LogLine) -> std::io::Result<()> {
            Ok(())
        }
    }

    // The job waits in the queue, so nothing but its state is asked: a good log read would end the outage by itself.
    let id = JobId::generate();
    let queued = json_of(&fixtures::job(id, JobStatus::Queued, None));
    let mut over = fixtures::job(id, JobStatus::Succeeded, Some(0));
    over.attempt = 1;
    let over = json_of(&over);
    let gets = Arc::new(AtomicUsize::new(0));
    let server = MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => ndjson(&[]),
        r if r.starts_with("GET /v1/jobs/") => match gets.fetch_add(1, Ordering::SeqCst) {
            // Three failures (waits 1, 2, 4 s), a good answer, one failure, then the job is over.
            0..=2 | 4 => MockResponse::text(502, "bad gateway"),
            3 => MockResponse::json(200, &queued),
            _ => MockResponse::json(200, &over),
        },
        _ => not_found(),
    });
    // One request per call: the client's own retries would blur which failure is which.
    let client = p2pc_client::Client::builder(server.url(), p2pc_proto::auth::ApiKey::generate())
        .retry(p2pc_client::RetryPolicy::immediate(0))
        .build()
        .unwrap();
    let waits = Instant::default();
    let mut events = Count::default();
    let followed = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(
            StreamFollower::new(PollSchedule::default(), waits.clone(), 0, None).follow(
                &client,
                {
                    let mut job = fixtures::job(id, JobStatus::Queued, None);
                    job.attempt = 0;
                    job
                },
                &mut events,
                std::future::pending(),
            ),
        );
    assert!(
        matches!(followed, Ok(Followed::Finished(_))),
        "{:?}",
        followed.err().map(|e| matches!(e, FollowError::Sink(..)))
    );
    assert_eq!(events.0, 2, "two outages, each announced once");
    // 1, 2, 4 s for the first outage; 1 s for the poll after the good answer; and the second outage starts at 1 s again.
    let secs: Vec<u64> = waits.0.lock().unwrap().iter().map(Duration::as_secs).collect();
    assert_eq!(secs, [1, 2, 4, 1, 1]);
}

/// A clock that tests move by hand, so that nothing here depends on real time: the follower's waits advance it instead of
/// sleeping, and a line delivered by the mock server advances it by `per_line` (a stream that lasted that long).
#[derive(Clone, Default)]
struct VirtualClock(Arc<std::sync::atomic::AtomicU64>);

impl VirtualClock {
    fn advance(&self, by: std::time::Duration) {
        self.0
            .fetch_add(u64::try_from(by.as_nanos()).unwrap(), Ordering::SeqCst);
    }

    fn offset(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

/// How a follow played out, in virtual time.
struct Played {
    followed: Result<p2pc_cli::follow::Followed, p2pc_cli::follow::FollowError>,
    /// When each "reconnecting…" was announced.
    announced: Vec<std::time::Duration>,
    /// The virtual time at the end.
    ended: std::time::Duration,
    waits: Vec<std::time::Duration>,
}

/// Follows `id` against `server` with the default schedule (5 min per outage, waits of 1 to 30 s) on a virtual clock.
/// Every line the server delivers takes `per_line` of virtual time.
fn follow_on_virtual_time(id: JobId, server: &MockServer, per_line: std::time::Duration) -> Played {
    use p2pc_cli::follow::{LogSink, PollSchedule, Progress, Sleeper, StreamFollower};
    use std::time::Duration;

    #[derive(Clone)]
    struct Sleep(VirtualClock, Arc<Mutex<Vec<Duration>>>);
    impl Sleeper for Sleep {
        async fn sleep(&mut self, d: Duration) {
            self.1.lock().unwrap().push(d);
            self.0.advance(d);
        }
        fn now(&self) -> tokio::time::Instant {
            tokio::time::Instant::now() + self.0.offset()
        }
    }
    struct Events {
        clock: VirtualClock,
        per_line: Duration,
        announced: Vec<Duration>,
        /// The real time is part of the follower's clock too (virtual offset + real time), so it is part of ours.
        begun: std::time::Instant,
    }
    impl Progress for Events {
        fn on_status(&mut self, _: &Job) {}
        fn on_reconnecting(&mut self, _: &p2pc_client::Error) {
            self.announced.push(self.clock.offset() + self.begun.elapsed());
        }
    }
    impl LogSink for Events {
        fn line(&mut self, _: &LogLine) -> std::io::Result<()> {
            self.clock.advance(self.per_line);
            Ok(())
        }
    }

    // One request per call: the client's own retries would blur which failure is which.
    let client = p2pc_client::Client::builder(server.url(), p2pc_proto::auth::ApiKey::generate())
        .retry(p2pc_client::RetryPolicy::immediate(0))
        .build()
        .unwrap();
    let clock = VirtualClock::default();
    let waits = Arc::new(Mutex::new(Vec::new()));
    let mut events = Events {
        clock: clock.clone(),
        per_line,
        announced: Vec::new(),
        begun: std::time::Instant::now(),
    };
    // Bounded in real time, so that a follow that never ends fails the test instead of hanging it.
    let followed = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(60),
                StreamFollower::new(PollSchedule::default(), Sleep(clock.clone(), waits.clone()), 0, None).follow(
                    &client,
                    fixtures::job(id, JobStatus::Running, None),
                    &mut events,
                    std::future::pending(),
                ),
            )
            .await
        })
        .expect("the follow ends");
    let waits = waits.lock().unwrap().clone();
    Played {
        followed,
        announced: events.announced,
        ended: clock.offset() + events.begun.elapsed(),
        waits,
    }
}

fn finished(played: &Played) -> bool {
    matches!(played.followed, Ok(p2pc_cli::follow::Followed::Finished(_)))
}

fn over_job(id: JobId) -> Value {
    let mut over = fixtures::job(id, JobStatus::Succeeded, Some(0));
    over.attempt = 1;
    json_of(&over)
}

const SIX_MINUTES: std::time::Duration = std::time::Duration::from_secs(360);

/// Spec §7: an outage of a route has no gap longer than 30 s between two of its requests. A `404` (no log yet), one
/// failed job check, a stream that lasts longer than the 5-minute budget, one more failed job check: two short
/// outages of the job route, not one of six minutes. It fails with 125 if they are joined.
#[test]
fn two_failed_job_checks_around_a_long_stream_are_two_outages() {
    let id = JobId::generate();
    let over = over_job(id);
    let (reads, gets) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let server = MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => match reads.fetch_add(1, Ordering::SeqCst) {
            0 => not_found(),
            // The long stream: its one line takes six minutes of virtual time.
            1 => ndjson(&[out_line(0, "a\n")]),
            _ => ndjson(&[]),
        },
        r if r.starts_with("GET /v1/jobs/") => match gets.fetch_add(1, Ordering::SeqCst) {
            0 | 1 => MockResponse::text(502, "bad gateway"),
            _ => MockResponse::json(200, &over),
        },
        _ => not_found(),
    });
    let played = follow_on_virtual_time(id, &server, SIX_MINUTES);
    assert!(finished(&played), "{:?}", played.followed.as_ref().map(|_| ()));
    assert_eq!(played.announced.len(), 2, "two outages: {:?}", played.announced);
    assert!(played.ended >= SIX_MINUTES);
}

/// A job check that keeps failing after the logs have ended gives up five minutes after its first failure (spec §7):
/// the log reads in between are healthy work, but they are short, and no gap between two checks passes 30 s.
#[test]
fn a_job_route_that_keeps_failing_gives_up_five_minutes_after_its_first_failure() {
    use std::time::Duration;
    let id = JobId::generate();
    let reads = Arc::new(AtomicUsize::new(0));
    let server = MockServer::start(move |req| match req.route().as_str() {
        // One line (a minute of virtual time), then nothing more.
        r if r.ends_with("/logs") => {
            if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                ndjson(&[out_line(0, "a\n")])
            } else {
                ndjson(&[])
            }
        }
        r if r.starts_with("GET /v1/jobs/") => MockResponse::text(502, "bad gateway"),
        _ => not_found(),
    });
    let played = follow_on_virtual_time(id, &server, Duration::from_secs(60));
    assert!(
        matches!(&played.followed, Err(p2pc_cli::follow::FollowError::Client(e)) if e.status() == Some(502)),
        "the outage error ends the follow: {:?}",
        played.followed.as_ref().map(|_| ())
    );
    assert_eq!(played.announced.len(), 1, "announced once: {:?}", played.announced);
    let lasted = played.ended - played.announced[0];
    assert!(
        lasted >= Duration::from_secs(299) && lasted < Duration::from_secs(301),
        "about five minutes after the first failure: {lasted:?}"
    );
    // The waits grow 1, 2, 4, 8, 16, 30 s and stay there.
    let secs: Vec<u64> = played.waits.iter().map(Duration::as_secs).collect();
    assert_eq!(secs[..7], [1, 2, 4, 8, 16, 30, 30], "{secs:?}");
}

/// T11b3 review: the log route's outage ends with a success of the log route. The logs fail past `LogFollow`'s budget (an
/// outage), then recover and stream for longer than the budget; one failed job check after that is a new, short outage
/// of the other route, not the old one come back.
#[test]
fn a_log_outage_that_ended_does_not_make_a_later_job_check_failure_fatal() {
    let id = JobId::generate();
    let over = over_job(id);
    let (reads, gets) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let server = MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => match reads.fetch_add(1, Ordering::SeqCst) {
            // The first request and `LogFollow`'s 8 reconnects fail: it gives up.
            0..=8 => MockResponse::text(503, "unavailable"),
            // Then it works, for a long time.
            9 => ndjson(&[out_line(0, "a\n")]),
            _ => ndjson(&[]),
        },
        r if r.starts_with("GET /v1/jobs/") => {
            // The first check after the long stream fails once.
            if gets.fetch_add(1, Ordering::SeqCst) == 0 {
                MockResponse::text(502, "bad gateway")
            } else {
                MockResponse::json(200, &over)
            }
        }
        _ => not_found(),
    });
    let played = follow_on_virtual_time(id, &server, SIX_MINUTES);
    assert!(finished(&played), "{:?}", played.followed.as_ref().map(|_| ()));
    // The log outage and the job-check outage, each announced once.
    assert_eq!(played.announced.len(), 2);
}

/// The same for a later outage of the log route itself: after a recovery and a long stream, a second burst of failures is
/// a new outage with its own 5 minutes, not the first one still running.
#[test]
fn a_later_log_outage_is_a_new_one_after_the_logs_recovered() {
    let id = JobId::generate();
    let over = over_job(id);
    let reads = Arc::new(AtomicUsize::new(0));
    let server = MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => match reads.fetch_add(1, Ordering::SeqCst) {
            0..=8 => MockResponse::text(503, "unavailable"),
            9 => ndjson(&[out_line(0, "a\n")]),
            // A second burst, long after the first one began.
            10..=18 => MockResponse::text(503, "unavailable"),
            _ => ndjson(&[]),
        },
        r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &over),
        _ => not_found(),
    });
    let played = follow_on_virtual_time(id, &server, SIX_MINUTES);
    assert!(finished(&played), "{:?}", played.followed.as_ref().map(|_| ()));
    assert_eq!(
        played.announced.len(),
        2,
        "two outages of the log route, each announced once"
    );
}

/// T13h (T11b3 review): the gap between two requests of a route does not count the wait the follower scheduled, only the
/// time spent on the other route's work. Every log read takes 2 s here, so with waits of 30 s the time from one failed
/// job check to the next is 32 s; that is no gap (the work in between is 2 s), and the outage goes on to its 5 minutes.
#[test]
fn slow_log_reads_do_not_restart_the_outage_of_a_job_route_that_keeps_failing() {
    use std::time::Duration;
    let id = JobId::generate();
    let reads = Arc::new(AtomicUsize::new(0));
    let server = MockServer::start(move |req| match req.route().as_str() {
        // A new line at every read, so that each read takes its 2 s of virtual time.
        r if r.ends_with("/logs") => ndjson(&[out_line(reads.fetch_add(1, Ordering::SeqCst) as u64, "a\n")]),
        r if r.starts_with("GET /v1/jobs/") => MockResponse::text(502, "bad gateway"),
        _ => not_found(),
    });
    let played = follow_on_virtual_time(id, &server, Duration::from_secs(2));
    assert!(
        matches!(&played.followed, Err(p2pc_cli::follow::FollowError::Client(e)) if e.status() == Some(502)),
        "the outage error ends the follow: {:?}",
        played.followed.as_ref().map(|_| ())
    );
    assert_eq!(
        played.announced.len(),
        1,
        "one outage, announced once: {:?}",
        played.announced
    );
    let lasted = played.ended - played.announced[0];
    assert!(
        lasted >= Duration::from_secs(299) && lasted < Duration::from_secs(305),
        "about five minutes after the first failure: {lasted:?}"
    );
}

/// T13h (T11b3 review): a log outage is dated from `LogFollow`'s first failed request, not from when it gives up. The
/// log route is black-holed (it accepts the connection and never answers), so `LogFollow` reconnects 8 times, each
/// request ending at the client's 30 s timeout, before it returns the error. The follow gives up about 5 minutes after
/// the first of those requests began, not 5 minutes after `LogFollow` gave up. Runs on Tokio's paused clock.
#[tokio::test(start_paused = true)]
async fn a_black_holed_log_route_gives_up_five_minutes_after_its_first_failure() {
    use p2pc_cli::follow::{FollowError, LogSink, PollSchedule, Progress, StreamFollower, TokioSleeper};
    use std::time::Duration;
    use tokio::time::Instant;

    struct Events(u32);
    impl Progress for Events {
        fn on_status(&mut self, _: &Job) {}
        fn on_reconnecting(&mut self, _: &p2pc_client::Error) {
            self.0 += 1;
        }
    }
    impl LogSink for Events {
        fn line(&mut self, _: &LogLine) -> std::io::Result<()> {
            Ok(())
        }
    }

    // A server that takes every connection and says nothing.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    let client = p2pc_client::Client::builder(url, p2pc_proto::auth::ApiKey::generate())
        .request_timeout(Duration::from_secs(30))
        .retry(p2pc_client::RetryPolicy::none())
        .build()
        .unwrap();
    let id = JobId::generate();
    let mut events = Events(0);
    let started = Instant::now();
    let followed = StreamFollower::new(PollSchedule::default(), TokioSleeper, 0, None)
        .follow(
            &client,
            fixtures::job(id, JobStatus::Running, None),
            &mut events,
            std::future::pending(),
        )
        .await;
    let lasted = started.elapsed();
    holder.abort();
    assert!(matches!(followed, Err(FollowError::Client(_))), "{followed:?}");
    assert_eq!(events.0, 1, "announced once");
    assert!(
        lasted >= Duration::from_secs(300) && lasted < Duration::from_secs(340),
        "five minutes after the first failed request, counting LogFollow's reconnects: {lasted:?}"
    );
}

/// A stream that delivered a line is a success of the log route even if it then breaks and the reconnects fail past the
/// budget: the earlier outage is over, and the new one starts from there.
#[test]
fn a_stream_that_delivered_before_it_broke_ends_the_log_outage() {
    let id = JobId::generate();
    let over = over_job(id);
    let reads = Arc::new(AtomicUsize::new(0));
    let server = MockServer::start(move |req| match req.route().as_str() {
        r if r.ends_with("/logs") => match reads.fetch_add(1, Ordering::SeqCst) {
            0..=8 => MockResponse::text(503, "unavailable"),
            // A line after a long time, then the connection breaks and the reconnects fail past the budget again.
            9 => ndjson(&[out_line(0, "a\n")]).cut(),
            10..=26 => MockResponse::text(503, "unavailable"),
            _ => ndjson(&[]),
        },
        r if r.starts_with("GET /v1/jobs/") => MockResponse::json(200, &over),
        _ => not_found(),
    });
    let played = follow_on_virtual_time(id, &server, SIX_MINUTES);
    assert!(
        finished(&played),
        "the old outage must not count against the new one: {:?}",
        played.followed.as_ref().map(|_| ())
    );
    assert_eq!(played.announced.len(), 2, "two outages of the log route");
}

/// A stream that the server ends while the job runs is not the end of the log: it is opened again from `next_seq`.
#[test]
fn a_stream_that_ends_early_is_reopened_from_the_next_seq() {
    use p2pc_cli::follow::{FollowError, Followed, LogSink, PollSchedule, Progress, Sleeper, StreamFollower};

    #[derive(Clone, Default)]
    struct Instant(Arc<Mutex<Vec<std::time::Duration>>>);
    impl Sleeper for Instant {
        async fn sleep(&mut self, d: std::time::Duration) {
            self.0.lock().unwrap().push(d);
        }
    }
    #[derive(Default)]
    struct Collect(Vec<u64>);
    impl Progress for Collect {
        fn on_status(&mut self, _: &Job) {}
    }
    impl LogSink for Collect {
        fn line(&mut self, l: &LogLine) -> std::io::Result<()> {
            self.0.push(l.seq);
            Ok(())
        }
    }

    let id = JobId::generate();
    let (running, done) = (
        json_of(&fixtures::job(id, JobStatus::Running, None)),
        json_of(&fixtures::job(id, JobStatus::Succeeded, Some(0))),
    );
    let gets = Arc::new(AtomicUsize::new(0));
    let all = vec![out_line(0, "a\n"), out_line(1, "b\n"), out_line(2, "c\n")];
    let server = MockServer::start(move |req| match req.route().as_str() {
        // Every stream ends after one line, whatever is left.
        r if r.ends_with("/logs") => {
            let mut page = ndjson_since(&all, req);
            let first = page.body.split(|b| *b == b'\n').next().unwrap_or_default().to_vec();
            page.body = if first.is_empty() {
                first
            } else {
                [first, b"\n".to_vec()].concat()
            };
            page
        }
        // Running for three reads, then final.
        r if r.starts_with("GET /v1/jobs/") => {
            if gets.fetch_add(1, Ordering::SeqCst) < 3 {
                MockResponse::json(200, &running)
            } else {
                MockResponse::json(200, &done)
            }
        }
        _ => not_found(),
    });
    let client = p2pc_client::Client::builder(server.url(), p2pc_proto::auth::ApiKey::generate())
        .build()
        .unwrap();
    let waits = Instant::default();
    let mut events = Collect::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let followed = runtime.block_on(
        StreamFollower::new(PollSchedule::default(), waits.clone(), 0, None).follow(
            &client,
            fixtures::job(id, JobStatus::Running, None),
            &mut events,
            std::future::pending(),
        ),
    );
    assert!(
        matches!(followed, Ok(Followed::Finished(_))),
        "{:?}",
        followed.err().map(|e| matches!(e, FollowError::Sink(..)))
    );
    assert_eq!(events.0, vec![0, 1, 2], "every line once, in order");
    // It waited (1 s, growing) between the reopenings while the job ran, and not once it was final.
    let waits = waits.0.lock().unwrap().clone();
    assert!(
        waits.len() >= 2 && waits[0] == std::time::Duration::from_secs(1),
        "{waits:?}"
    );
    let since: Vec<_> = server
        .requests_to(&format!("GET /v1/jobs/{id}/logs"))
        .iter()
        .map(|r| param(r, "since_seq").unwrap())
        .collect();
    assert_eq!(&since[..3], ["0", "1", "2"], "{since:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// --json on a terminal, and the results cap
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn json_logs_on_a_terminal_also_escape_del_c1_and_bidi_and_stay_valid() {
    let id = JobId::generate();
    let lines = vec![out_line(
        0,
        "a\u{7f}b\u{9b}2J\u{9d}52;c;eA==\u{9c}\u{202e}gpj.exe\u{2066}\n",
    )];
    let server = logs_server(lines.clone());
    let terminal = Cli::new()
        .with_server(&server)
        .with_terminal_output()
        .run(&["logs", &id.to_string(), "--json"]);
    assert_eq!(terminal.code, 0, "{terminal:?}");
    assert!(
        terminal
            .stdout
            .chars()
            .all(|c| !p2pc_cli::output::is_terminal_hazard(c) || c == '\n'),
        "{:?}",
        terminal.stdout
    );
    let parsed: Vec<LogLine> = terminal
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(parsed, lines, "the escaped JSON means the same");
    // Piped, or with --raw, the line is exactly what serde wrote.
    for cli in [
        Cli::new().with_server(&server),
        Cli::new().with_server(&server).with_terminal_output(),
    ] {
        let id_text = id.to_string();
        let raw = if cli.out_tty {
            vec!["logs", &id_text, "--json", "--raw"]
        } else {
            vec!["logs", &id_text, "--json"]
        };
        let out = cli.run(&raw);
        assert_eq!(out.stdout, format!("{}\n", serde_json::to_string(&lines[0]).unwrap()));
    }
}

#[test]
fn results_refuse_a_list_longer_than_the_cap_instead_of_cutting_it() {
    let id = JobId::generate();
    let content: &[u8] = b"x";
    let item = |i: usize| json_of(&output(&format!("f{i}.txt"), content));
    let listing = |n: usize| json!({"items": (0..n).map(item).collect::<Vec<_>>(), "next_cursor": null});
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("out");
    let out_arg = out_dir.to_str().unwrap();

    // One over the cap: refused, and nothing is downloaded.
    let over = listing(10_001);
    let server = MockServer::start(move |req| {
        if req.path.ends_with("/outputs") {
            MockResponse::json(200, &over)
        } else {
            MockResponse::text(200, "x")
        }
    });
    let out = Cli::new()
        .with_server(&server)
        .run(&["results", &id.to_string(), "--out", out_arg]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("more than 10000"), "{}", out.stderr);
    assert!(!out_dir.exists());
    assert!(
        server.requests().iter().all(|r| r.path.ends_with("/outputs")),
        "no download"
    );

    // Exactly at the cap is fine.
    let at = listing(10_000);
    let server = MockServer::start(move |req| {
        if req.path.ends_with("/outputs") {
            MockResponse::json(200, &at)
        } else {
            MockResponse::text(200, "x")
        }
    });
    let out =
        Cli::new()
            .with_server(&server)
            .run(&["results", &id.to_string(), "--out", out_arg, "--file", "f9999.txt"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out_dir.join("f9999.txt").exists());
}
