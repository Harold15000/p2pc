// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The T12 additions to the client: the caller's limits, one page of logs, the outputs list and verified downloads.
//! Everything runs against the mock server on `127.0.0.1:0`.

use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_client::{Client, DownloadError, Error, ListParams, RetryPolicy};
use p2pc_proto::api::{LogLine, LogStream, OutputFile, Scope, Sha256Digest};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::JobId;
use serde_json::json;
use sha2::{Digest, Sha256};

fn client_for(server: &MockServer) -> Client {
    Client::builder(server.url(), ApiKey::generate())
        .retry(RetryPolicy::immediate(1))
        .build()
        .expect("client")
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

fn line(seq: u64, data: &str) -> LogLine {
    LogLine {
        seq,
        stream: LogStream::Stdout,
        ts: fixtures::t0(),
        data: data.into(),
    }
}

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

// ---------------------------------------------------------------------------------------------------------------
// The caller's limits
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn key_limits_tell_a_set_cap_from_a_null_cap_and_a_missing_field() {
    let key = ApiKey::generate();
    // `whoami_legacy` has the four limit members absent, so the cases below say exactly what they add.
    let base = |extra: serde_json::Value| {
        let mut body = fixtures::whoami_legacy(key.key_id(), vec![Scope::JobsWrite]);
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        body
    };
    for (extra, cap, reported) in [
        (
            json!({"daily_unit_cap": 2500, "allowed_images": ["docker.io/library/*"]}),
            Some(2500),
            true,
        ),
        (json!({"daily_unit_cap": null, "allowed_images": null}), None, true),
        (json!({}), None, false),
    ] {
        let body = base(extra);
        let server = MockServer::start(move |_| MockResponse::json(200, &body));
        let limits = client_for(&server).key_limits().await.unwrap();
        assert_eq!(limits.scopes, vec![Scope::JobsWrite]);
        assert_eq!(limits.daily_unit_cap.map(|u| u.milli()), cap);
        assert_eq!(limits.cap_reported, reported);
    }
}

#[tokio::test]
async fn key_limits_reject_an_answer_that_is_not_a_whoami() {
    let server = MockServer::start(|_| MockResponse::json(200, &json!({"hello": "world"})));
    assert!(matches!(
        client_for(&server).key_limits().await,
        Err(Error::Unexpected(_))
    ));
}

// ---------------------------------------------------------------------------------------------------------------
// One page of logs
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn log_page_asks_for_a_page_without_follow_and_returns_the_lines() {
    let id = JobId::generate();
    let lines = vec![line(5, "five\n"), line(6, "six\n")];
    let server = MockServer::start(move |_| ndjson(&lines));
    let page = client_for(&server).log_page(&id, 5, None, 64 * 1024).await.unwrap();
    assert_eq!(page.lines.iter().map(|l| l.seq).collect::<Vec<_>>(), vec![5, 6]);
    assert!(!page.more);
    let req = &server.requests()[0];
    assert_eq!(req.path, format!("/v1/jobs/{id}/logs"));
    let query = req.query.clone().unwrap();
    assert!(query.contains("since_seq=5"), "{query}");
    assert!(!query.contains("follow"), "{query}");
}

#[tokio::test]
async fn log_page_drops_lines_before_since_seq_even_if_the_server_sends_them() {
    // `since_seq` is inclusive for the client: a server that is off by one cannot make a line show up twice.
    let id = JobId::generate();
    let lines = vec![line(3, "old\n"), line(4, "new\n")];
    let server = MockServer::start(move |_| ndjson(&lines));
    let page = client_for(&server).log_page(&id, 4, None, 64 * 1024).await.unwrap();
    assert_eq!(page.lines.iter().map(|l| l.seq).collect::<Vec<_>>(), vec![4]);
}

#[tokio::test]
async fn log_page_stops_at_the_byte_budget_and_says_there_is_more() {
    let id = JobId::generate();
    let lines: Vec<LogLine> = (0..1000).map(|i| line(i, &"x".repeat(100))).collect();
    let server = MockServer::start(move |_| ndjson(&lines));
    let page = client_for(&server).log_page(&id, 0, None, 4096).await.unwrap();
    assert!(page.more);
    assert!(
        !page.lines.is_empty() && page.lines.len() < 1000,
        "{}",
        page.lines.len()
    );
    // The lines are consecutive from the start, and what was kept fits the budget.
    for (i, l) in page.lines.iter().enumerate() {
        assert_eq!(l.seq, i as u64);
    }
    let kept: usize = page
        .lines
        .iter()
        .map(|l| serde_json::to_string(l).unwrap().len() + 1)
        .sum();
    assert!(kept <= 4096, "{kept}");
}

#[tokio::test]
async fn log_page_always_returns_the_first_line_even_if_it_is_over_the_budget() {
    let id = JobId::generate();
    let lines = vec![line(0, &"y".repeat(10_000)), line(1, "next\n")];
    let server = MockServer::start(move |_| ndjson(&lines));
    let page = client_for(&server).log_page(&id, 0, None, 1024).await.unwrap();
    assert_eq!(page.lines.len(), 1);
    assert!(page.more);
}

#[tokio::test]
async fn log_page_of_a_job_with_no_logs_is_empty() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse {
        status: 200,
        headers: vec![],
        body: Vec::new(),
    });
    let page = client_for(&server).log_page(&id, 0, None, 1024).await.unwrap();
    assert!(page.lines.is_empty() && !page.more);
}

#[tokio::test]
async fn log_page_refuses_a_line_that_is_not_json_and_a_line_without_end() {
    let id = JobId::generate();
    let bad = MockServer::start(|_| MockResponse::text(200, "this is not json\n"));
    assert!(matches!(
        client_for(&bad).log_page(&id, 0, None, 1024).await,
        Err(Error::Unexpected(_))
    ));
    // A single 2 MiB "line" would fill the memory of the agent: it is refused, not buffered.
    let huge = MockServer::start(|_| MockResponse::text(200, &"z".repeat(2 * 1024 * 1024)));
    assert!(matches!(
        client_for(&huge).log_page(&id, 0, None, 1024).await,
        Err(Error::Unexpected(_))
    ));
}

#[tokio::test]
async fn log_page_passes_the_api_error_through() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::problem(404, "job_not_found", "no such job"));
    let err = client_for(&server).log_page(&id, 0, None, 1024).await.unwrap_err();
    assert_eq!(err.api_code(), Some("job_not_found"));
}

// ---------------------------------------------------------------------------------------------------------------
// The outputs list
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn list_outputs_accepts_a_page_and_a_bare_array() {
    let id = JobId::generate();
    let files = vec![output("a.txt", b"a"), output("dir/b.bin", b"bb")];
    let as_page = json!({"items": files, "next_cursor": "c2"});
    let as_array = json!(files);
    for (body, cursor) in [(as_page, Some("c2".to_string())), (as_array, None)] {
        let server = MockServer::start(move |_| MockResponse::json(200, &body));
        let page = client_for(&server)
            .list_outputs(&id, None, &ListParams::default())
            .await
            .unwrap();
        assert_eq!(page.items, files);
        assert_eq!(page.next_cursor, cursor);
        assert_eq!(server.requests()[0].path, format!("/v1/jobs/{id}/outputs"));
    }
}

#[tokio::test]
async fn list_all_outputs_walks_the_pages_and_stops_at_the_limit() {
    let id = JobId::generate();
    let first = vec![output("a", b"1")];
    let second = vec![output("b", b"2")];
    let server = MockServer::start(move |req| match req.query.as_deref() {
        Some(q) if q.contains("cursor=p2") => MockResponse::json(200, &json!({"items": second, "next_cursor": null})),
        _ => MockResponse::json(200, &json!({"items": first, "next_cursor": "p2"})),
    });
    let all = client_for(&server).list_all_outputs(&id, None, 10).await.unwrap();
    assert_eq!(all.iter().map(|o| o.path.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
    let one = client_for(&server).list_all_outputs(&id, None, 1).await.unwrap();
    assert_eq!(one.len(), 1);
}

// ---------------------------------------------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn download_streams_the_file_into_the_sink_after_checking_size_and_sha256() {
    let id = JobId::generate();
    let content = b"hello outputs\n".to_vec();
    let file = output("results/a b.txt", &content);
    let served = content.clone();
    let server = MockServer::start(move |_| MockResponse {
        status: 200,
        headers: vec![],
        body: served.clone(),
    });
    let mut sink = Vec::new();
    client_for(&server)
        .download_output(&id, None, &file, &mut sink)
        .await
        .unwrap();
    assert_eq!(sink, content);
    // The path goes in as segments, each percent-encoded.
    assert_eq!(
        server.requests()[0].path,
        format!("/v1/jobs/{id}/outputs/results/a%20b.txt")
    );
}

#[tokio::test]
async fn download_refuses_content_with_the_wrong_sha256() {
    let id = JobId::generate();
    let file = output("a.txt", b"expected");
    let server = MockServer::start(|_| MockResponse {
        status: 200,
        headers: vec![],
        body: b"tampered".to_vec(), // same length as "expected"
    });
    let mut sink = Vec::new();
    let err = client_for(&server)
        .download_output(&id, None, &file, &mut sink)
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::DigestMismatch { .. }), "{err:?}");
}

#[tokio::test]
async fn download_refuses_more_bytes_than_declared_without_reading_them_all() {
    let id = JobId::generate();
    let file = output("a.txt", b"tiny");
    let server = MockServer::start(|_| MockResponse {
        status: 200,
        headers: vec![],
        body: vec![b'x'; 1_000_000],
    });
    let mut sink = Vec::new();
    let err = client_for(&server)
        .download_output(&id, None, &file, &mut sink)
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::SizeMismatch { .. }), "{err:?}");
    assert!(sink.len() <= 4, "the sink got {} bytes", sink.len());
}

#[tokio::test]
async fn download_refuses_fewer_bytes_than_declared() {
    let id = JobId::generate();
    let file = output("a.txt", b"longer content");
    let server = MockServer::start(|_| MockResponse {
        status: 200,
        headers: vec![],
        body: b"short".to_vec(),
    });
    let mut sink = Vec::new();
    let err = client_for(&server)
        .download_output(&id, None, &file, &mut sink)
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::SizeMismatch { .. }), "{err:?}");
}

#[tokio::test]
async fn download_never_sends_a_request_for_an_unsafe_path() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::empty(200));
    let client = client_for(&server);
    for path in [
        "../x",
        "a/../../x",
        "/etc/passwd",
        "a//b",
        "./a",
        "a\\b",
        "a/\u{0}b",
        "",
    ] {
        let file = output(path, b"x");
        let mut sink = Vec::new();
        let err = client.download_output(&id, None, &file, &mut sink).await.unwrap_err();
        assert!(matches!(err, DownloadError::UnsafePath(_)), "{path:?}: {err:?}");
    }
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn download_passes_the_api_error_through() {
    let id = JobId::generate();
    let server = MockServer::start(|_| MockResponse::problem(404, "output_not_found", "gone"));
    let mut sink = Vec::new();
    let err = client_for(&server)
        .download_output(&id, None, &output("a", b"x"), &mut sink)
        .await
        .unwrap_err();
    match err {
        DownloadError::Request(e) => assert_eq!(e.api_code(), Some("output_not_found")),
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Saving to disk
// ---------------------------------------------------------------------------------------------------------------

fn serving(content: &[u8]) -> MockServer {
    let content = content.to_vec();
    MockServer::start(move |_| MockResponse {
        status: 200,
        headers: vec![],
        body: content.clone(),
    })
}

#[tokio::test]
async fn save_output_writes_under_the_root_and_creates_the_directories() {
    let id = JobId::generate();
    let content = b"col1,col2\n1,2\n";
    let server = serving(content);
    let root = tempfile::tempdir().unwrap();
    let saved = client_for(&server)
        .save_output(&id, None, &output("deep/er/table.csv", content), root.path())
        .await
        .unwrap();
    assert_eq!(saved, root.path().join("deep/er/table.csv"));
    assert_eq!(std::fs::read(&saved).unwrap(), content);
    // No temporary file is left next to it.
    let names: Vec<_> = std::fs::read_dir(root.path().join("deep/er"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
}

#[tokio::test]
async fn save_output_replaces_an_earlier_copy() {
    let id = JobId::generate();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), "old").unwrap();
    let server = serving(b"new!");
    client_for(&server)
        .save_output(&id, None, &output("a.txt", b"new!"), root.path())
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.path().join("a.txt")).unwrap(), b"new!");
}

#[tokio::test]
async fn save_new_output_never_replaces_a_file_that_exists() {
    let id = JobId::generate();
    let server = serving(b"new!");
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), b"mine").unwrap();
    let err = client_for(&server)
        .save_new_output(&id, None, &output("a.txt", b"new!"), root.path())
        .await
        .unwrap_err();
    assert!(
        matches!(err, DownloadError::Exists { ref path } if path == "a.txt"),
        "{err:?}"
    );
    assert_eq!(std::fs::read(root.path().join("a.txt")).unwrap(), b"mine");
    // No temporary file is left behind.
    let names: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    // A file that is not there yet is written, with its directories, and nothing else is left in them.
    let saved = client_for(&server)
        .save_new_output(&id, None, &output("sub/b.txt", b"new!"), root.path())
        .await
        .unwrap();
    assert_eq!(std::fs::read(saved).unwrap(), b"new!");
    assert_eq!(std::fs::read_dir(root.path().join("sub")).unwrap().count(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn save_new_output_does_not_follow_or_replace_a_symlink() {
    let id = JobId::generate();
    let server = serving(b"new!");
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("target"), b"keep").unwrap();
    std::os::unix::fs::symlink(elsewhere.path().join("target"), root.path().join("link.txt")).unwrap();
    // A dangling link is "something that exists" too.
    std::os::unix::fs::symlink(elsewhere.path().join("nowhere"), root.path().join("dangling.txt")).unwrap();
    for name in ["link.txt", "dangling.txt"] {
        let err = client_for(&server)
            .save_new_output(&id, None, &output(name, b"new!"), root.path())
            .await
            .unwrap_err();
        assert!(matches!(err, DownloadError::Exists { .. }), "{name}: {err:?}");
    }
    assert_eq!(std::fs::read(elsewhere.path().join("target")).unwrap(), b"keep");
    assert!(!elsewhere.path().join("nowhere").exists());
}

#[tokio::test]
async fn save_output_leaves_nothing_behind_when_the_digest_is_wrong() {
    let id = JobId::generate();
    let root = tempfile::tempdir().unwrap();
    let server = serving(b"tampered");
    let err = client_for(&server)
        .save_output(&id, None, &output("sub/a.txt", b"expected"), root.path())
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::DigestMismatch { .. }), "{err:?}");
    assert!(!root.path().join("sub/a.txt").exists());
    let left: Vec<_> = std::fs::read_dir(root.path().join("sub"))
        .map(|d| d.map(|e| e.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "{left:?}");
}

#[tokio::test]
async fn save_output_refuses_traversal_without_touching_the_disk_or_the_network() {
    let id = JobId::generate();
    let server = serving(b"x");
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("results");
    std::fs::create_dir(&root).unwrap();
    for path in ["../escape.txt", "a/../../escape.txt", "/abs.txt"] {
        let err = client_for(&server)
            .save_output(&id, None, &output(path, b"x"), &root)
            .await
            .unwrap_err();
        assert!(matches!(err, DownloadError::UnsafePath(_)), "{path}: {err:?}");
    }
    assert!(!parent.path().join("escape.txt").exists());
    assert!(server.requests().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn save_output_does_not_follow_a_symlinked_directory_or_overwrite_through_a_symlinked_file() {
    use std::os::unix::fs::symlink;
    let id = JobId::generate();
    let server = serving(b"x");
    let outside = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    // A directory of the results that is a symlink to somewhere else: refused.
    symlink(outside.path(), root.path().join("link")).unwrap();
    let err = client_for(&server)
        .save_output(&id, None, &output("link/pwned.txt", b"x"), root.path())
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::UnsafePath(_)), "{err:?}");
    assert!(!outside.path().join("pwned.txt").exists());

    // A file that is a symlink: the link is replaced, and what it pointed to is left alone.
    let victim = outside.path().join("victim.txt");
    std::fs::write(&victim, "precious").unwrap();
    symlink(&victim, root.path().join("f.txt")).unwrap();
    client_for(&server)
        .save_output(&id, None, &output("f.txt", b"x"), root.path())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    assert_eq!(std::fs::read(root.path().join("f.txt")).unwrap(), b"x");
    assert!(
        !std::fs::symlink_metadata(root.path().join("f.txt"))
            .unwrap()
            .is_symlink()
    );
}

#[tokio::test]
async fn save_output_refuses_to_replace_a_directory_with_a_file() {
    let id = JobId::generate();
    let server = serving(b"x");
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("a.txt")).unwrap();
    let err = client_for(&server)
        .save_output(&id, None, &output("a.txt", b"x"), root.path())
        .await
        .unwrap_err();
    assert!(
        matches!(err, DownloadError::UnsafePath(_) | DownloadError::Io(_)),
        "{err:?}"
    );
    assert!(root.path().join("a.txt").is_dir());
}

/// T12 review: a `save_output` whose future is dropped mid-download (a timeout, a cancelled tool call) leaves no
/// `.p2pc-part-*` file behind. The server here sends the headers and part of the body, then waits for the test.
#[tokio::test]
async fn a_dropped_save_output_leaves_no_partial_file() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (got_request, request_seen) = tokio::sync::oneshot::channel::<()>();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = tcp.read(&mut buf).await.unwrap();
        tcp.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\npart")
            .await
            .unwrap();
        tcp.flush().await.unwrap();
        got_request.send(()).unwrap();
        let _ = released.await;
    });
    let client = Client::builder(url, ApiKey::generate())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let id = JobId::generate();
    let file = output("sub/a.bin", b"partpart");
    {
        let save = client.save_output(&id, None, &file, root.path());
        tokio::pin!(save);
        tokio::select! {
            r = &mut save => panic!("the download cannot finish: {r:?}"),
            _ = request_seen => {}
        }
        // Let the client take in the bytes that were sent, so a partial file really exists before the drop.
        for _ in 0..50 {
            tokio::select! {
                biased;
                r = &mut save => panic!("the download cannot finish: {r:?}"),
                () = tokio::task::yield_now() => {}
            }
        }
    }
    release.send(()).unwrap();
    server.await.unwrap();
    let left: Vec<_> = std::fs::read_dir(root.path().join("sub"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");
}
