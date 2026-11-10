// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc blobs` and `p2pc run --input` (H2 §7.5, §7.8), in process against the mock server.

mod common;

use std::sync::Mutex;

use common::Cli;
use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_proto::api::{BlobInfo, JobStatus, Sha256Digest};
use p2pc_proto::ids::JobId;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const T: &str = "2023-11-14T22:13:20Z";

fn digest_of(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn file(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path.display().to_string()
}

/// A hub that has the blobs in `have` and accepts uploads of any other.
fn blob_server(have: Vec<Sha256Digest>) -> MockServer {
    MockServer::start(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("HEAD", p) => {
            let wanted = p.trim_start_matches("/v1/blobs/");
            if have.iter().any(|d| d.to_string() == wanted) {
                MockResponse::head(200, 11)
            } else {
                MockResponse::head(404, 0)
            }
        }
        ("POST", "/v1/blobs") => {
            let digest = req.header("x-p2pc-sha256").unwrap_or_default().to_string();
            MockResponse::json(
                201,
                &json!({"sha256": digest, "size": req.body.len(), "created_at": T, "expires_at": null}),
            )
        }
        ("POST", "/v1/jobs") => {
            let job = fixtures::job(JobId::generate(), JobStatus::Queued, None);
            MockResponse::json(201, &serde_json::to_value(job).unwrap())
        }
        ("POST", "/v1/estimate") => MockResponse::json(
            200,
            &json!({"feasible": true, "matching_nodes": 1, "would_queue": false, "units_per_hour": 1000}),
        ),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

fn routes(server: &MockServer) -> Vec<String> {
    server.requests().iter().map(|r| r.route()).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// blobs put
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn put_asks_first_uploads_what_the_hub_lacks_and_prints_the_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "audio.bin", b"hello world");
    let digest = digest_of(b"hello world");
    let server = blob_server(vec![]);
    let out = Cli::new().with_server(&server).run(&["blobs", "put", &path]);
    assert_eq!(out.code, 0, "{out:?}");
    // The digest, as a job spec writes it, alone on stdout: `blob=$(p2pc blobs put f)` works.
    assert_eq!(out.stdout, format!("sha256:{digest}\n"));
    assert_eq!(
        routes(&server),
        [format!("HEAD /v1/blobs/{digest}"), "POST /v1/blobs".to_string()]
    );
    let upload = &server.requests()[1];
    assert_eq!(upload.body, b"hello world");
    assert_eq!(upload.header("x-p2pc-sha256"), Some(digest.to_string().as_str()));
    assert!(out.stderr.contains("uploaded"), "{}", out.stderr);
}

#[test]
fn put_does_not_upload_what_the_hub_already_has() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "audio.bin", b"hello world");
    let digest = digest_of(b"hello world");
    let server = blob_server(vec![digest]);
    let out = Cli::new().with_server(&server).run(&["blobs", "put", &path]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.stdout, format!("sha256:{digest}\n"));
    assert_eq!(routes(&server), [format!("HEAD /v1/blobs/{digest}")]);
    assert!(out.stderr.contains("already"), "{}", out.stderr);
}

#[test]
fn put_json_says_whether_it_uploaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "a", b"hello world");
    let out = Cli::new()
        .with_server(&blob_server(vec![]))
        .run(&["blobs", "put", &path, "--json"]);
    let v: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v["sha256"], format!("sha256:{}", digest_of(b"hello world")));
    assert_eq!(v["size"], 11);
    assert_eq!(v["uploaded"], true);
}

#[test]
fn put_with_a_head_the_hub_refuses_still_gets_the_real_error_from_the_upload() {
    // A `HEAD` answer has no body, so a 403 there says nothing: the upload's own answer does.
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "a", b"hello world");
    let server = MockServer::start(|req| {
        if req.method == "HEAD" {
            MockResponse::head(403, 0)
        } else {
            MockResponse::problem(403, "forbidden", "this device may not upload blobs")
        }
    });
    let out = Cli::new().with_server(&server).run(&["blobs", "put", &path]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(
        out.stderr.contains("this device may not upload blobs"),
        "{}",
        out.stderr
    );
}

#[test]
fn put_shows_the_hubs_quota_and_size_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "a", b"hello world");
    for (status, code) in [(507, "quota_exceeded"), (413, "too_large"), (422, "digest_mismatch")] {
        let server = MockServer::start(move |req| {
            if req.method == "HEAD" {
                MockResponse::head(404, 0)
            } else {
                MockResponse::problem(status, code, "refused by the hub")
            }
        });
        let out = Cli::new().with_server(&server).run(&["blobs", "put", &path]);
        assert_eq!(out.code, 125, "{status}: {out:?}");
        assert!(out.stderr.contains("refused by the hub"), "{status}: {}", out.stderr);
        assert!(
            out.stdout.is_empty(),
            "{status}: no digest for a blob the hub did not take"
        );
    }
}

#[test]
fn put_refuses_a_missing_file_and_a_directory_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let server = blob_server(vec![]);
    let cli = Cli::new().with_server(&server);
    for target in [
        dir.path().join("nope").display().to_string(),
        dir.path().display().to_string(),
    ] {
        let out = cli.run(&["blobs", "put", &target]);
        assert_eq!(out.code, 125, "{target}: {out:?}");
    }
    assert!(server.requests().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// blobs ls and rm
// ---------------------------------------------------------------------------------------------------------------

fn info(bytes: &[u8], referenced_by: u64) -> BlobInfo {
    BlobInfo {
        sha256: digest_of(bytes),
        size: bytes.len() as u64,
        created_at: fixtures::t0(),
        referenced_by,
        expires_at: None,
    }
}

#[test]
fn ls_walks_every_page_and_reports_the_quota() {
    let (a, b) = (info(b"a", 0), info(b"bb", 2));
    let pages = Mutex::new(0);
    let (a2, b2) = (a.clone(), b.clone());
    let server = MockServer::start(move |req| {
        assert_eq!(req.route(), "GET /v1/blobs");
        let mut n = pages.lock().unwrap();
        *n += 1;
        if *n == 1 {
            MockResponse::json(
                200,
                &json!({"items": [a2], "next_cursor": "page2", "total_bytes": 3, "quota_mb": 20480}),
            )
        } else {
            assert!(req.query.as_deref().unwrap().contains("cursor=page2"));
            MockResponse::json(
                200,
                &json!({"items": [b2], "next_cursor": null, "total_bytes": 3, "quota_mb": 20480}),
            )
        }
    });
    let out = Cli::new().with_server(&server).run(&["blobs", "ls"]);
    assert_eq!(out.code, 0, "{out:?}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert!(
        lines[0].starts_with("DIGEST") && lines[0].contains("REFERENCED BY"),
        "{}",
        lines[0]
    );
    assert!(lines[1].contains(&format!("sha256:{}", a.sha256)), "{}", lines[1]);
    assert!(
        lines[2].contains(&format!("sha256:{}", b.sha256)) && lines[2].contains('2'),
        "{}",
        lines[2]
    );
    assert!(out.stderr.contains("20 GiB"), "the quota: {}", out.stderr);
}

#[test]
fn ls_json_is_an_array_of_blobs() {
    let a = info(b"a", 0);
    let body = json!({"items": [a], "next_cursor": null, "total_bytes": 1, "quota_mb": 20480});
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let out = Cli::new().with_server(&server).run(&["blobs", "ls", "--json"]);
    let v: Vec<Value> = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["sha256"], a.sha256.to_string());
}

#[test]
fn rm_takes_a_digest_with_or_without_the_prefix() {
    let digest = digest_of(b"x");
    let server = blob_server(vec![]);
    let server_ok = MockServer::start(|_| MockResponse::empty(204));
    for text in [format!("sha256:{digest}"), digest.to_string()] {
        let out = Cli::new().with_server(&server_ok).run(&["blobs", "rm", &text]);
        assert_eq!(out.code, 0, "{text}: {out:?}");
    }
    assert_eq!(routes(&server_ok), vec![format!("DELETE /v1/blobs/{digest}"); 2]);
    drop(server);
}

#[test]
fn rm_refuses_what_is_not_a_digest_before_any_request() {
    let server = MockServer::start(|_| MockResponse::empty(204));
    for text in ["", "sha256:abc", "../etc", &"G".repeat(64), &"A".repeat(64)] {
        let out = Cli::new().with_server(&server).run(&["blobs", "rm", text]);
        assert_eq!(out.code, 125, "{text:?}: {out:?}");
    }
    assert!(server.requests().is_empty());
}

#[test]
fn rm_shows_why_a_blob_is_kept() {
    let server = MockServer::start(|_| MockResponse::problem(409, "blob_in_use", "a running job uses this blob"));
    let out = Cli::new()
        .with_server(&server)
        .run(&["blobs", "rm", &digest_of(b"x").to_string()]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("a running job uses this blob"), "{}", out.stderr);
}

// ---------------------------------------------------------------------------------------------------------------
// run --input
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn run_input_uploads_the_file_and_adds_the_inputs_entry() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "audio.bin", b"hello world");
    let digest = digest_of(b"hello world");
    let server = blob_server(vec![]);
    let out = Cli::new().with_server(&server).run(&[
        "run",
        "--detach",
        "--image",
        "docker.io/library/python:3.12-slim",
        "--input",
        &format!("{path}:/inputs/audio"),
        "--",
        "true",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(
        routes(&server),
        [
            format!("HEAD /v1/blobs/{digest}"),
            "POST /v1/blobs".to_string(),
            "POST /v1/jobs".to_string()
        ]
    );
    let spec = server.requests()[2].json();
    assert_eq!(
        spec["inputs"],
        json!([{"path": "/inputs/audio", "blob": format!("sha256:{digest}")}])
    );
    // The bytes themselves are not in the job (inline `--file` keeps its own limit).
    assert!(spec.get("files").is_none_or(|f| f.as_array().unwrap().is_empty()));
}

#[test]
fn run_input_without_a_container_path_goes_under_inputs_by_file_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "clip.wav", b"hello world");
    let server = blob_server(vec![digest_of(b"hello world")]);
    let out = Cli::new().with_server(&server).run(&[
        "run",
        "--detach",
        "--image",
        "docker.io/library/python:3.12-slim",
        "--input",
        &path,
        "--",
        "true",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    // The hub has it: only a HEAD, no upload.
    assert_eq!(routes(&server).len(), 2);
    assert_eq!(server.requests()[1].json()["inputs"][0]["path"], "/inputs/clip.wav");
}

#[test]
fn run_input_with_a_missing_file_creates_no_job() {
    let dir = tempfile::tempdir().unwrap();
    let server = blob_server(vec![]);
    let out = Cli::new().with_server(&server).run(&[
        "run",
        "--detach",
        "--image",
        "docker.io/library/python:3.12-slim",
        "--input",
        &dir.path().join("nope").display().to_string(),
        "--",
        "true",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("--input"), "{}", out.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn run_input_that_does_not_fit_the_disk_is_refused_before_a_job_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "a.bin", b"hello world");
    let server = blob_server(vec![digest_of(b"hello world")]);
    // 64 MiB of disk minus the 64 MiB reserve leaves nothing for an input.
    let out = Cli::new().with_server(&server).run(&[
        "run",
        "--detach",
        "--image",
        "docker.io/library/python:3.12-slim",
        "--disk",
        "64",
        "--input",
        &path,
        "--",
        "true",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("inputs"), "{}", out.stderr);
    assert!(!routes(&server).contains(&"POST /v1/jobs".to_string()));
}

#[test]
fn estimate_input_hashes_the_file_but_uploads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "a.bin", b"hello world");
    let digest = digest_of(b"hello world");
    let server = blob_server(vec![]);
    let out = Cli::new().with_server(&server).run(&[
        "estimate",
        "--image",
        "docker.io/library/python:3.12-slim",
        "--input",
        &path,
        "--",
        "true",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(routes(&server), ["POST /v1/estimate"]);
    assert_eq!(
        server.requests()[0].json()["inputs"][0]["blob"],
        format!("sha256:{digest}")
    );
}
