// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The T11b2 additions to the client: following the logs live, the `attempt` selector of the logs and outputs
//! methods, and `GET /v1/usage`. Everything runs against the mock server on `127.0.0.1:0`.

use std::sync::{Arc, Mutex};

use p2pc_client::testing::{MockResponse, MockServer, RecordedRequest, fixtures};
use p2pc_client::{Client, Error, FollowOptions, ListParams, RetryPolicy};
use p2pc_proto::api::{LogLine, LogStream, OutputFile, Sha256Digest, UsageGroupBy, UsageReport, UsageTotals};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::JobId;
use p2pc_proto::units::Units;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::time::Instant;

fn client_for(server: &MockServer) -> Client {
    Client::builder(server.url(), ApiKey::generate())
        .retry(RetryPolicy::immediate(1))
        .build()
        .expect("client")
}

fn line(seq: u64, data: &str) -> LogLine {
    LogLine {
        seq,
        stream: LogStream::Stdout,
        ts: fixtures::t0(),
        data: data.into(),
    }
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

fn query_of(req: &RecordedRequest) -> Vec<(String, String)> {
    url::form_urlencoded::parse(req.query.clone().unwrap_or_default().as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn param(req: &RecordedRequest, name: &str) -> Option<String> {
    query_of(req).into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

async fn drain(follow: &mut p2pc_client::LogFollow) -> Result<Vec<u64>, Error> {
    let mut seqs = Vec::new();
    while let Some(l) = follow.next().await? {
        seqs.push(l.seq);
    }
    Ok(seqs)
}

// ---------------------------------------------------------------------------------------------------------------
// follow_logs
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn follow_asks_for_follow_since_seq_and_the_attempt_and_ends_when_the_server_ends() {
    let id = JobId::generate();
    let server = MockServer::start(|_| ndjson(&[line(7, "a\n"), line(8, "b\n")]));
    let mut follow = client_for(&server).follow_logs(&id, 7, Some(2));
    assert_eq!(drain(&mut follow).await.unwrap(), vec![7, 8]);
    assert_eq!(follow.next_seq(), 9);
    // After the end, it stays ended and makes no new request.
    assert!(follow.next().await.unwrap().is_none());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, format!("/v1/jobs/{id}/logs"));
    assert_eq!(param(&requests[0], "follow").as_deref(), Some("true"));
    assert_eq!(param(&requests[0], "since_seq").as_deref(), Some("7"));
    assert_eq!(param(&requests[0], "attempt").as_deref(), Some("2"));
}

#[tokio::test]
async fn follow_without_an_attempt_leaves_it_to_the_server() {
    let id = JobId::generate();
    let server = MockServer::start(|_| ndjson(&[]));
    let mut follow = client_for(&server).follow_logs(&id, 0, None);
    assert!(drain(&mut follow).await.unwrap().is_empty());
    assert_eq!(param(&server.requests()[0], "attempt"), None);
}

#[tokio::test]
async fn a_dropped_connection_resumes_from_the_last_seq_plus_one_without_repeating_a_line() {
    let id = JobId::generate();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = asked.clone();
    let server = MockServer::start(move |req| {
        let since: u64 = param(req, "since_seq").unwrap().parse().unwrap();
        log.lock().unwrap().push(since);
        match since {
            // The first connection delivers 0 and 1 and breaks.
            0 => ndjson(&[line(0, "zero\n"), line(1, "one\n")]).cut(),
            // The server is off by one on resume (it starts at 1): the client still shows 1 only once.
            2 => ndjson(&[line(1, "one\n"), line(2, "two\n"), line(3, "three\n")]).cut(),
            // The next one is complete.
            4 => ndjson(&[line(4, "four\n")]),
            other => panic!("unexpected since_seq {other}"),
        }
    });
    let mut follow = client_for(&server).follow_logs(&id, 0, None);
    assert_eq!(drain(&mut follow).await.unwrap(), vec![0, 1, 2, 3, 4]);
    assert_eq!(*asked.lock().unwrap(), vec![0, 2, 4]);
}

#[tokio::test]
async fn a_line_split_across_chunks_and_a_last_line_without_newline_are_read() {
    let id = JobId::generate();
    let mut body = serde_json::to_string(&line(0, "a\n")).unwrap();
    body.push('\n');
    body.push_str(&serde_json::to_string(&line(1, "b\n")).unwrap()); // no newline at the end
    let server = MockServer::start(move |_| MockResponse {
        status: 200,
        headers: vec![],
        body: body.clone().into_bytes(),
    });
    let mut follow = client_for(&server).follow_logs(&id, 0, None);
    assert_eq!(drain(&mut follow).await.unwrap(), vec![0, 1]);
}

#[tokio::test]
async fn follow_gives_up_after_too_many_drops_in_a_row_that_deliver_nothing() {
    let id = JobId::generate();
    let server = MockServer::start(|_| ndjson(&[]).cut());
    let mut follow = client_for(&server)
        .follow_logs(&id, 0, None)
        .with_options(FollowOptions {
            max_failures: 3,
            ..FollowOptions::default()
        });
    let err = follow.next().await.unwrap_err();
    assert!(matches!(err, Error::Network(_)), "{err:?}");
    // The first request plus three reconnects.
    assert_eq!(server.requests().len(), 4);
}

#[tokio::test]
async fn drops_that_deliver_lines_do_not_use_up_the_failures() {
    let id = JobId::generate();
    let server = MockServer::start(|req| {
        let since: u64 = param(req, "since_seq").unwrap().parse().unwrap();
        if since < 10 {
            ndjson(&[line(since, "x\n")]).cut()
        } else {
            ndjson(&[line(since, "end\n")])
        }
    });
    let mut follow = client_for(&server)
        .follow_logs(&id, 0, None)
        .with_options(FollowOptions {
            max_failures: 1,
            ..FollowOptions::default()
        });
    assert_eq!(drain(&mut follow).await.unwrap(), (0..=10).collect::<Vec<_>>());
}

/// T11b3: a caller that gets the error can tell a route that never worked from one that worked and then failed (spec §7,
/// "How a follow ends"): a delivered line is a success, even if the reconnects after it fail past the budget.
#[tokio::test]
async fn worked_tells_a_follow_that_delivered_from_one_that_never_did() {
    let id = JobId::generate();
    let options = FollowOptions {
        max_failures: 2,
        ..FollowOptions::default()
    };

    let never = MockServer::start(|_| MockResponse::text(503, "unavailable"));
    let mut follow = client_for(&never).follow_logs(&id, 0, None).with_options(options);
    assert!(follow.next().await.is_err());
    assert!(!follow.worked(), "nothing was ever delivered");

    let delivered = MockServer::start(|req| {
        if param(req, "since_seq").as_deref() == Some("0") {
            ndjson(&[line(0, "x\n")]).cut()
        } else {
            MockResponse::text(503, "unavailable")
        }
    });
    let mut follow = client_for(&delivered).follow_logs(&id, 0, None).with_options(options);
    assert_eq!(follow.next().await.unwrap().map(|l| l.seq), Some(0));
    assert!(follow.next().await.is_err(), "the reconnects fail past the budget");
    assert!(follow.worked(), "but a connection had delivered a line");
}

/// T13h review P3: with the clock paused, the retry waits take measurable (virtual) time, so a `failing_since` that
/// recorded the last request instead of the first would be far from `before`.
#[tokio::test(start_paused = true)]
async fn failing_since_is_the_start_of_the_first_request_not_the_last() {
    let id = JobId::generate();
    let never = MockServer::start(|_| MockResponse::text(503, "unavailable"));
    // Every wait has a ceiling of 1000 s (full jitter), so the retries span far more than a second.
    let client = Client::builder(never.url(), ApiKey::generate())
        .retry(RetryPolicy {
            max_retries: 1,
            base_delay: std::time::Duration::from_secs(1000),
            max_delay: std::time::Duration::from_secs(1000),
        })
        .build()
        .expect("client");
    let before = Instant::now();
    let mut follow = client.follow_logs(&id, 0, None).with_options(FollowOptions {
        max_failures: 2,
        ..FollowOptions::default()
    });
    assert!(follow.next().await.is_err());
    let since = follow.failing_since().expect("the run of failures");
    let one_second = std::time::Duration::from_secs(1);
    assert!(
        Instant::now() - before >= one_second,
        "the retries waited, so the last request is well after the first"
    );
    assert!(since - before < one_second, "the run began with its first request");
}

/// T13h: `failing_since` dates an outage of the log route from the first failed request of the current run of failures,
/// which `LogFollow` retries by itself before it returns the error. A success starts a new run.
#[tokio::test]
async fn failing_since_is_when_the_current_run_of_failures_began() {
    let id = JobId::generate();
    let options = FollowOptions {
        max_failures: 2,
        ..FollowOptions::default()
    };

    // Nothing failed yet; a follow that ends cleanly has no failure either.
    let ok = MockServer::start(|_| ndjson(&[line(0, "x\n")]));
    let mut follow = client_for(&ok).follow_logs(&id, 0, None);
    assert!(follow.failing_since().is_none());
    assert_eq!(drain(&mut follow).await.unwrap(), vec![0]);
    assert!(follow.failing_since().is_none());

    // A failure that never recovers: the run began with its first request, not with the last.
    let before = Instant::now();
    let never = MockServer::start(|_| MockResponse::text(503, "unavailable"));
    let mut follow = client_for(&never).follow_logs(&id, 0, None).with_options(options);
    assert!(follow.next().await.is_err());
    let since = follow.failing_since().expect("the run of failures");
    assert!(since >= before && since <= Instant::now());
    assert_eq!(
        never.requests().len(),
        6,
        "three opens (the first and two reconnects), two sends each"
    );

    // A delivered line is a success: the run that follows began after it, not before.
    let delivered = MockServer::start(|req| {
        if param(req, "since_seq").as_deref() == Some("0") {
            ndjson(&[line(0, "x\n")]).cut()
        } else {
            MockResponse::text(503, "unavailable")
        }
    });
    let mut follow = client_for(&delivered).follow_logs(&id, 0, None).with_options(options);
    assert_eq!(follow.next().await.unwrap().map(|l| l.seq), Some(0));
    assert!(follow.failing_since().is_none(), "the line was a success");
    let after_the_line = Instant::now();
    assert!(follow.next().await.is_err());
    assert!(follow.failing_since().expect("a new run") >= after_the_line);

    // A failure that recovers: the run is over.
    let flaky = {
        let calls = Arc::new(Mutex::new(0));
        MockServer::start(move |_| {
            let mut n = calls.lock().unwrap();
            *n += 1;
            if *n == 1 {
                MockResponse::text(503, "unavailable")
            } else {
                ndjson(&[line(0, "x\n")])
            }
        })
    };
    let mut follow = client_for(&flaky).follow_logs(&id, 0, None);
    assert_eq!(drain(&mut follow).await.unwrap(), vec![0]);
    assert!(follow.failing_since().is_none());
}

/// T13h: `give_up_after` bounds the retries by time too, from the start of the first failed request, so that a caller
/// with a budget (the CLI's 5 minutes per outage) is not kept waiting by a follow that retries for longer.
#[tokio::test]
async fn give_up_after_ends_the_retries_by_time_before_the_count() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::text(503, "unavailable"));
    let mut follow = client_for(&server)
        .follow_logs(&id, 0, None)
        .with_options(FollowOptions {
            give_up_after: Some(std::time::Duration::ZERO),
            ..FollowOptions::default()
        });
    assert_eq!(follow.next().await.unwrap_err().status(), Some(503));
    assert_eq!(
        server.requests().len(),
        2,
        "one request, and its one retry of the client; no reconnect"
    );
}

#[tokio::test]
async fn follow_returns_an_api_error_at_once() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::problem(404, "job_not_found", "no such job"));
    let mut follow = client_for(&server).follow_logs(&id, 0, None);
    let err = follow.next().await.unwrap_err();
    assert_eq!(err.status(), Some(404));
    assert_eq!(server.requests().len(), 1, "a 404 is not retried");
}

#[tokio::test]
async fn follow_refuses_a_line_that_is_not_a_log_record_without_quoting_it() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::text(200, "SECRET-JOB-OUTPUT\n"));
    let mut follow = client_for(&server).follow_logs(&id, 0, None);
    let err = follow.next().await.unwrap_err();
    assert!(!err.to_string().contains("SECRET-JOB-OUTPUT"), "{err}");
}

// ---------------------------------------------------------------------------------------------------------------
// ?attempt=K on the logs and outputs methods
// ---------------------------------------------------------------------------------------------------------------

fn output(path: &str, bytes: &[u8]) -> OutputFile {
    OutputFile {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: Sha256Digest(Sha256::digest(bytes).into()),
    }
}

#[tokio::test]
async fn log_page_outputs_and_downloads_send_the_attempt_when_given_and_only_then() {
    let id = JobId::generate();
    let body = b"hello".to_vec();
    let listing =
        serde_json::json!({"items": [serde_json::to_value(output("a.txt", &body)).unwrap()], "next_cursor": null});
    let server = MockServer::start(move |req| {
        if req.path.ends_with("/logs") {
            ndjson(&[line(0, "x\n")])
        } else if req.path.ends_with("/outputs") {
            MockResponse::json(200, &listing)
        } else {
            MockResponse {
                status: 200,
                headers: vec![],
                body: body.clone(),
            }
        }
    });
    let client = client_for(&server);
    let file = output("a.txt", b"hello");
    for attempt in [None, Some(3)] {
        let before = server.requests().len();
        client.log_page(&id, 0, attempt, 1024).await.unwrap();
        client.list_outputs(&id, attempt, &ListParams::default()).await.unwrap();
        client.list_all_outputs(&id, attempt, 10).await.unwrap();
        client
            .download_output(&id, attempt, &file, &mut Vec::new())
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        client.save_output(&id, attempt, &file, dir.path()).await.unwrap();
        let sent = &server.requests()[before..];
        assert_eq!(sent.len(), 5);
        for req in sent {
            assert_eq!(param(req, "attempt"), attempt.map(|a| a.to_string()), "{}", req.path);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// usage
// ---------------------------------------------------------------------------------------------------------------

fn report(group_by: UsageGroupBy, next: Option<&str>) -> UsageReport {
    let total = UsageTotals {
        attempts: 3,
        units: Units::from_milli(2500),
        estimated_attempts: 1,
        ..UsageTotals::default()
    };
    let mut r = UsageReport::new(
        fixtures::t0(),
        fixtures::t0() + time::Duration::days(1),
        group_by,
        total,
    );
    r.next_cursor = next.map(String::from);
    r
}

#[tokio::test]
async fn usage_sends_whole_seconds_in_utc_and_the_grouping_and_the_cursor() {
    let server = MockServer::start(|_| {
        MockResponse::json(
            200,
            &serde_json::to_value(report(UsageGroupBy::Node, Some("next-page"))).unwrap(),
        )
    });
    // A real clock has a fraction of a second, and any offset.
    let from = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789)
        .unwrap()
        .to_offset(time::UtcOffset::from_hms(5, 30, 0).unwrap());
    let to = OffsetDateTime::from_unix_timestamp_nanos(1_700_086_400_999_999_999).unwrap();
    let got = client_for(&server)
        .usage(Some(from), Some(to), Some(UsageGroupBy::Node), Some("abc"))
        .await
        .unwrap();
    assert_eq!(got.group_by, UsageGroupBy::Node);
    assert_eq!(got.total.attempts, 3);
    assert_eq!(got.total.estimated_attempts, 1);
    assert_eq!(got.next_cursor.as_deref(), Some("next-page"));
    let req = &server.requests()[0];
    assert_eq!(req.path, "/v1/usage");
    assert_eq!(param(req, "from").as_deref(), Some("2023-11-14T22:13:20Z"));
    assert_eq!(param(req, "to").as_deref(), Some("2023-11-15T22:13:20Z"));
    assert_eq!(param(req, "group_by").as_deref(), Some("node"));
    assert_eq!(param(req, "cursor").as_deref(), Some("abc"));
}

#[tokio::test]
async fn usage_with_nothing_given_sends_no_query() {
    let server =
        MockServer::start(|_| MockResponse::json(200, &serde_json::to_value(report(UsageGroupBy::Job, None)).unwrap()));
    client_for(&server).usage(None, None, None, None).await.unwrap();
    assert_eq!(server.requests()[0].query, None);
}

#[tokio::test]
async fn usage_passes_the_api_error_through() {
    let server = MockServer::start(|_| MockResponse::problem(422, "validation_failed", "from must be before to"));
    let err = client_for(&server).usage(None, None, None, None).await.unwrap_err();
    assert_eq!(err.api_code(), Some("validation_failed"));
}
