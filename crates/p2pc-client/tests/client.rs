// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The client against a mock server on `127.0.0.1:0`. No real network, no `p2pc-server`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use p2pc_client::testing::{MockResponse, MockServer, fixtures};
use p2pc_client::{Client, Error, IDEMPOTENCY_HEADER, JobListParams, ListParams, NetworkKind, RetryPolicy, fetch_all};
use p2pc_proto::api::{CreateApiKey, JobSpec, JobStatus, Page, Resources, Scope};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{JobId, KeyId, NodeId};
use serde_json::json;

fn client_for(server: &MockServer, key: &ApiKey) -> Client {
    Client::builder(server.url(), key.clone())
        .retry(RetryPolicy::immediate(3))
        .build()
        .expect("client")
}

fn spec() -> JobSpec {
    JobSpec {
        name: None,
        image: "docker.io/library/python:3.12-slim".into(),
        command: vec!["true".into()],
        env: Default::default(),
        files: vec![],
        resources: Resources {
            cpu: 1.0,
            memory_mb: 512,
            gpu: 0,
            disk_mb: 10_240,
        },
        timeout_s: 60,
        egress: Default::default(),
        outputs: Default::default(),
        placement: Default::default(),
        retry: Default::default(),
        idempotency_key: None,
    }
}

#[tokio::test]
async fn whoami_sends_the_bearer_key_and_the_user_agent() {
    let key = ApiKey::generate();
    let who = fixtures::whoami(key.key_id(), vec![Scope::Admin]);
    let body = serde_json::to_value(&who).unwrap();
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let got = client_for(&server, &key).whoami().await.unwrap();
    assert_eq!(got, who);
    let req = &server.requests()[0];
    assert_eq!(req.route(), "GET /v1/whoami");
    assert_eq!(
        req.header("authorization"),
        Some(format!("Bearer {}", key.expose()).as_str())
    );
    assert_eq!(
        req.header("user-agent"),
        Some(format!("p2pc/{}", env!("CARGO_PKG_VERSION")).as_str())
    );
}

#[tokio::test]
async fn problem_json_becomes_an_api_error_with_field_errors() {
    let server = MockServer::start(|_| {
        MockResponse::problem_with(
            422,
            "validation_failed",
            "The request is invalid",
            &json!([{"field": "resources.cpu", "code": "out_of_range", "message": "must be 0.25-256"}]),
        )
    });
    let err = client_for(&server, &ApiKey::generate())
        .create_job(&spec())
        .await
        .unwrap_err();
    let api = err.as_api().expect("an API error");
    assert_eq!(api.status, 422);
    assert_eq!(api.code, "validation_failed");
    assert_eq!(api.detail.as_deref(), Some("The request is invalid"));
    assert_eq!(api.errors.len(), 1);
    assert_eq!(api.errors[0].field, "resources.cpu");
    // A 422 is not retried.
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn a_non_problem_error_page_is_an_unexpected_response() {
    let server = MockServer::start(|_| MockResponse::text(500, "<html>boom</html>"));
    let err = client_for(&server, &ApiKey::generate()).whoami().await.unwrap_err();
    match err {
        Error::Unexpected(u) => {
            assert_eq!(u.status, Some(500));
            assert!(u.message.contains("boom"));
        }
        other => panic!("expected Unexpected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_success_body_of_the_wrong_shape_is_an_unexpected_response() {
    let server = MockServer::start(|_| MockResponse::json(200, &json!({"nope": 1})));
    let err = client_for(&server, &ApiKey::generate()).whoami().await.unwrap_err();
    assert!(matches!(err, Error::Unexpected(_)), "{err:?}");
}

#[tokio::test]
async fn a_refused_connection_is_a_network_error_without_the_url() {
    // Bind and drop a listener to get a port nobody listens on.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let client = Client::builder(format!("http://127.0.0.1:{port}"), ApiKey::generate())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();
    let err = client.whoami().await.unwrap_err();
    match &err {
        Error::Network(n) => {
            assert_eq!(n.kind(), NetworkKind::Connect);
            assert!(!err.to_string().contains(&port.to_string()), "{err}");
        }
        other => panic!("expected Network, got {other:?}"),
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = MockServer::start(|_| MockResponse::empty(301).with_header("Location", "http://example.invalid/"));
    let err = client_for(&server, &ApiKey::generate()).whoami().await.unwrap_err();
    assert!(
        matches!(err, Error::Unexpected(ref u) if u.status == Some(301)),
        "{err:?}"
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn create_job_retries_503_with_the_same_idempotency_key() {
    let calls = Arc::new(AtomicUsize::new(0));
    let job = fixtures::job(JobId::generate(), JobStatus::Queued, None);
    let body = serde_json::to_value(&job).unwrap();
    let server = {
        let calls = Arc::clone(&calls);
        MockServer::start(move |_| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                MockResponse::problem(503, "unavailable", "try again")
            } else {
                MockResponse::json(201, &body)
            }
        })
    };
    let got = client_for(&server, &ApiKey::generate())
        .create_job(&spec())
        .await
        .unwrap();
    assert_eq!(got.id, job.id);
    let posts = server.requests_to("POST /v1/jobs");
    assert_eq!(posts.len(), 2);
    let first = posts[0]
        .header(&IDEMPOTENCY_HEADER.to_ascii_lowercase())
        .unwrap()
        .to_string();
    assert_eq!(posts[1].header("idempotency-key"), Some(first.as_str()));
    assert!(first.len() <= 255 && !first.is_empty());
    // The same key is in the body, which is where the server reads it (§7).
    assert_eq!(posts[0].json()["idempotency_key"], first.as_str());
    assert_eq!(posts[1].json()["idempotency_key"], first.as_str());
}

#[tokio::test]
async fn create_job_keeps_the_callers_key() {
    let job = fixtures::job(JobId::generate(), JobStatus::Queued, None);
    let body = serde_json::to_value(&job).unwrap();
    let server = MockServer::start(move |_| MockResponse::json(201, &body));
    let mut s = spec();
    s.idempotency_key = Some("mine-123".into());
    client_for(&server, &ApiKey::generate()).create_job(&s).await.unwrap();
    assert_eq!(server.requests()[0].header("idempotency-key"), Some("mine-123"));
}

#[tokio::test]
async fn retries_stop_after_three_and_return_the_last_error() {
    let server = MockServer::start(|_| MockResponse::text(502, "bad gateway"));
    let err = client_for(&server, &ApiKey::generate())
        .create_job(&spec())
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(502));
    assert_eq!(server.requests().len(), 4, "the first attempt and three retries");
}

#[tokio::test]
async fn gets_are_retried_on_503_and_504() {
    let calls = Arc::new(AtomicUsize::new(0));
    let who = fixtures::whoami(KeyId::generate(), vec![Scope::JobsRead]);
    let body = serde_json::to_value(&who).unwrap();
    let server = {
        let calls = Arc::clone(&calls);
        MockServer::start(move |_| match calls.fetch_add(1, Ordering::SeqCst) {
            0 => MockResponse::text(503, "x"),
            1 => MockResponse::problem(504, "gateway_timeout", "slow"),
            _ => MockResponse::json(200, &body),
        })
    };
    client_for(&server, &ApiKey::generate()).whoami().await.unwrap();
    assert_eq!(server.requests().len(), 3);
}

#[tokio::test]
async fn other_posts_and_deletes_are_not_retried() {
    let server = MockServer::start(|_| MockResponse::problem(503, "unavailable", "try again"));
    let client = client_for(&server, &ApiKey::generate());
    let node = NodeId::generate();
    assert!(client.cancel_job(&JobId::generate()).await.is_err());
    assert!(client.drain_node(&node).await.is_err());
    assert!(client.estimate(&spec()).await.is_err());
    assert!(
        client
            .create_key(&CreateApiKey {
                label: None,
                scopes: vec![Scope::JobsRead],
                expires_at: None,
                daily_unit_cap: None,
                allowed_images: None,
            })
            .await
            .is_err()
    );
    assert!(client.delete_node(&node).await.is_err());
    assert!(client.revoke_key(&KeyId::generate()).await.is_err());
    assert_eq!(server.requests().len(), 6, "one attempt each, no retries");
}

#[tokio::test]
async fn a_client_error_is_never_retried() {
    let server = MockServer::start(|_| MockResponse::problem(409, "idempotency_conflict", "different body"));
    let err = client_for(&server, &ApiKey::generate())
        .create_job(&spec())
        .await
        .unwrap_err();
    assert_eq!(err.api_code(), Some("idempotency_conflict"));
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn list_jobs_sends_filters_and_paging() {
    let server = MockServer::start(|_| MockResponse::json(200, &json!({"items": [], "next_cursor": null})));
    let node = NodeId::generate();
    let params = JobListParams {
        status: Some(JobStatus::TimedOut),
        node_id: Some(node),
        limit: Some(25),
        cursor: Some("abc def".into()),
    };
    client_for(&server, &ApiKey::generate())
        .list_jobs(&params)
        .await
        .unwrap();
    let q = server.requests()[0].query.clone().unwrap();
    assert!(q.contains("status=timed_out"), "{q}");
    assert!(q.contains(&format!("node_id={node}")), "{q}");
    assert!(q.contains("limit=25"), "{q}");
    assert!(q.contains("cursor=abc+def") || q.contains("cursor=abc%20def"), "{q}");
}

#[tokio::test]
async fn fetch_all_walks_three_pages() {
    let ids: Vec<NodeId> = (0..5).map(|_| NodeId::generate()).collect();
    let pages = {
        let n = |i: usize| serde_json::to_value(fixtures::node(ids[i], &format!("n{i}"))).unwrap();
        vec![
            json!({"items": [n(0), n(1)], "next_cursor": "c1"}),
            json!({"items": [n(2), n(3)], "next_cursor": "c2"}),
            json!({"items": [n(4)], "next_cursor": null}),
        ]
    };
    let server = MockServer::start(move |req| {
        let q = req.query.clone().unwrap_or_default();
        let page = if q.contains("cursor=c2") {
            2
        } else if q.contains("cursor=c1") {
            1
        } else {
            0
        };
        MockResponse::json(200, &pages[page])
    });
    let client = client_for(&server, &ApiKey::generate());
    let nodes = fetch_all(
        |cursor| {
            let client = client.clone();
            async move { client.list_nodes(&ListParams { limit: Some(2), cursor }).await }
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(nodes.iter().map(|n| n.id).collect::<Vec<_>>(), ids);
    assert_eq!(server.requests().len(), 3);
}

#[tokio::test]
async fn fetch_all_stops_at_the_item_limit_and_refuses_a_repeated_cursor() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let looping = fetch_all(
        move |cursor: Option<String>| {
            seen.lock().unwrap().push(cursor);
            async {
                Ok(Page {
                    items: vec![1u8],
                    next_cursor: Some("same".into()),
                })
            }
        },
        None,
    )
    .await;
    assert!(matches!(looping, Err(Error::Unexpected(_))));
    assert_eq!(calls.lock().unwrap().len(), 2);

    let limited = fetch_all(
        |cursor: Option<String>| async move {
            let n = cursor.map_or(0u32, |c| c.parse().unwrap());
            Ok(Page {
                items: vec![n, n],
                next_cursor: Some((n + 1).to_string()),
            })
        },
        Some(3),
    )
    .await
    .unwrap();
    assert_eq!(limited.len(), 3);
}

#[tokio::test]
async fn base_urls_with_a_path_prefix_keep_it() {
    let who = fixtures::whoami(KeyId::generate(), vec![Scope::Admin]);
    let body = serde_json::to_value(&who).unwrap();
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let client = Client::builder(format!("{}/api/", server.url()), ApiKey::generate())
        .build()
        .unwrap();
    client.whoami().await.unwrap();
    assert_eq!(server.requests()[0].path, "/api/v1/whoami");
}

#[test]
fn bad_base_urls_are_refused() {
    for url in [
        "not a url",
        "ftp://example.invalid",
        "p2pc_srv_abc",
        "https://user:pw@example.invalid",
        "https://example.invalid/?x=1",
    ] {
        assert!(Client::builder(url, ApiKey::generate()).build().is_err(), "{url}");
    }
}

#[test]
fn debug_output_never_contains_the_key() {
    let key = ApiKey::generate();
    let secret = key.expose();
    let secret_part = secret.rsplit('_').next().unwrap().to_string();
    let client = Client::builder("https://example.invalid", key.clone()).build().unwrap();
    for text in [
        format!("{client:?}"),
        format!("{client:#?}"),
        format!("{key:?}"),
        format!("{key}"),
    ] {
        assert!(!text.contains(&secret), "{text}");
        assert!(!text.contains(&secret_part), "{text}");
    }
}

#[tokio::test]
async fn errors_never_contain_the_key() {
    let key = ApiKey::generate();
    let secret_part = key.expose().rsplit('_').next().unwrap().to_string();
    let server = MockServer::start(|_| MockResponse::problem(401, "unauthorized", "invalid credentials"));
    let err = client_for(&server, &key).whoami().await.unwrap_err();
    assert!(!format!("{err} {err:?}").contains(&secret_part));
}

#[tokio::test]
async fn a_decoding_error_on_a_secret_response_does_not_quote_it() {
    // A new-key response whose `key` has the wrong type: the message must not echo the body.
    let server = MockServer::start(|_| MockResponse::json(201, &json!({"key": "p2pc_sk_aaaaaaaaaaaa_SECRETSECRET"})));
    let err = client_for(&server, &ApiKey::generate())
        .create_key(&CreateApiKey {
            label: None,
            scopes: vec![Scope::JobsRead],
            expires_at: None,
            daily_unit_cap: None,
            allowed_images: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Unexpected(_)));
    assert!(!format!("{err} {err:?}").contains("SECRETSECRET"));
}

#[tokio::test]
async fn responses_over_the_size_limit_are_refused() {
    let server = MockServer::start(|_| {
        let mut r = MockResponse::json(200, &json!({}));
        r.body = vec![b' '; p2pc_client::MAX_RESPONSE_BYTES + 1];
        r
    });
    let err = client_for(&server, &ApiKey::generate()).whoami().await.unwrap_err();
    assert!(
        matches!(err, Error::Unexpected(ref u) if u.message.contains("larger")),
        "{err:?}"
    );
}

/// T11a review: a request that cannot even be built here (a header value with a newline) is a local error, sent
/// zero times and never retried as if the network had failed.
#[tokio::test]
async fn a_request_that_cannot_be_built_is_a_local_error_and_is_not_retried() {
    let server = MockServer::start(|_| MockResponse::empty(201));
    let mut s = spec();
    s.idempotency_key = Some("bad\nkey".into());
    let err = client_for(&server, &ApiKey::generate())
        .create_job(&s)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Local(_)), "{err:?}");
    assert_eq!(err.status(), None);
    assert!(server.requests().is_empty(), "nothing reaches the server");
}

/// Real-run bug (T11b1): the server refuses a timestamp with a fraction of a second. The client sends whole seconds,
/// in UTC, whatever it is given, and the mock server enforces the rule as the real one does.
#[tokio::test]
async fn timestamps_are_sent_in_whole_seconds_utc() {
    let server = MockServer::start(|_| MockResponse::problem(500, "unexpected", "the request got through"));
    let at = time::OffsetDateTime::from_unix_timestamp_nanos(1_800_000_000_987_654_321)
        .unwrap()
        .to_offset(time::UtcOffset::from_hms(2, 0, 0).unwrap());
    let request = CreateApiKey {
        label: Some("ci".into()),
        scopes: vec![Scope::JobsRead],
        expires_at: Some(at),
        daily_unit_cap: None,
        allowed_images: None,
    };
    let err = client_for(&server, &ApiKey::generate())
        .create_key(&request)
        .await
        .unwrap_err();
    // It reached the handler, so the mock's whole-seconds check passed.
    assert_eq!(err.api_code(), Some("unexpected"), "{err:?}");
    assert_eq!(server.requests()[0].json()["expires_at"], "2027-01-15T08:00:00Z");
}

/// The mock refuses what the real server refuses, so this class of bug fails a test.
#[tokio::test]
async fn the_mock_server_refuses_fractional_timestamps_like_the_real_one() {
    let server = MockServer::start(|_| MockResponse::empty(201));
    let (status, body) = raw_post(&server.url(), r#"{"expires_at":"2027-01-15T08:00:00.5Z","x":[1]}"#).await;
    assert_eq!(status, 422, "{body}");
    assert!(body.contains("whole number of seconds"), "{body}");
    assert!(body.contains("expires_at"), "{body}");
    let (status, _) = raw_post(&server.url(), r#"{"expires_at":"2027-01-15T08:00:00Z"}"#).await;
    assert_eq!(status, 201);
    // Only the accepted request reached the handler.
    assert_eq!(server.requests().len(), 1);
}

/// A raw POST, so that a fractional timestamp reaches the mock exactly as written.
async fn raw_post(base: &str, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base.trim_start_matches("http://");
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /v1/keys HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    // The mock keeps the connection for keep-alive: read the head and the declared body only.
    let mut buf = [0u8; 4096];
    loop {
        let n = tcp.read(&mut buf).await.unwrap();
        out.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&out).to_string();
        if let Some((head, rest)) = text.split_once("\r\n\r\n") {
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if rest.len() >= len || n == 0 {
                let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
                return (status, rest.to_string());
            }
        }
        if n == 0 {
            panic!("connection closed early: {text}");
        }
    }
}
