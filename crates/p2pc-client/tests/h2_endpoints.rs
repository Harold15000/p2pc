// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! The H2 endpoints of the client (H2 spec §7.3, §7.4, §7.8) against the mock server. No real network and no
//! `p2pc-server`.

use p2pc_client::testing::{MockResponse, MockServer};
use p2pc_client::{Client, Error, JobListParams, ListParams, RetryPolicy, TemplateLaunch};
use p2pc_proto::api::{
    BlobInfo, BlobList, CreatePairingTicket, DeviceInfo, JobKind, LaunchTemplate, PairingTicketCreated, Principal,
    Scope, Sha256Digest, TemplateList, VolumeInfo,
};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{DeviceId, JobId, KeyId, NodeId, PairingTicketId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn client_for(server: &MockServer) -> Client {
    Client::builder(server.url(), ApiKey::generate())
        .retry(RetryPolicy::immediate(3))
        .build()
        .expect("client")
}

fn digest_of(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

const T: &str = "2023-11-14T22:13:20Z";

// ---------------------------------------------------------------------------------------------------------------
// jobs
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_job_list_filters_by_kind() {
    let server = MockServer::start(|_| MockResponse::json(200, &json!({"items": [], "next_cursor": null})));
    let params = JobListParams {
        kind: Some(JobKind::Service),
        ..JobListParams::default()
    };
    client_for(&server).list_jobs(&params).await.unwrap();
    assert_eq!(server.requests()[0].query.as_deref(), Some("kind=service"));
}

// ---------------------------------------------------------------------------------------------------------------
// nodes
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn approving_a_node_posts_to_its_approve_route_and_is_not_retried() {
    let id = NodeId::generate();
    let server = MockServer::start(|_| MockResponse::problem(503, "unavailable", "try later"));
    let err = client_for(&server).approve_node(&id).await.unwrap_err();
    assert!(err.as_api().is_some(), "{err:?}");
    // One attempt: an approval is a decision, not something to repeat behind the user's back.
    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.requests()[0].route(), format!("POST /v1/nodes/{id}/approve"));
}

#[tokio::test]
async fn approving_a_node_accepts_an_empty_answer() {
    let id = NodeId::generate();
    let server = MockServer::start(|_| MockResponse::empty(204));
    client_for(&server).approve_node(&id).await.unwrap();
}

// ---------------------------------------------------------------------------------------------------------------
// blobs
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn head_blob_reads_the_size_from_content_length_and_maps_404_to_none() {
    let digest = digest_of(b"abc");
    let wanted = format!("HEAD /v1/blobs/{digest}");
    let server = MockServer::start(move |req| {
        if req.route() == wanted {
            MockResponse::head(200, 3_000_000_000)
        } else {
            MockResponse::problem(404, "not_found", "x")
        }
    });
    let client = client_for(&server);
    assert_eq!(client.head_blob(&digest).await.unwrap(), Some(3_000_000_000));
    assert_eq!(client.head_blob(&digest_of(b"other")).await.unwrap(), None);
}

#[tokio::test]
async fn head_blob_treats_a_bodyless_404_as_absent() {
    let server = MockServer::start(|_| MockResponse::head(404, 0));
    assert_eq!(client_for(&server).head_blob(&digest_of(b"x")).await.unwrap(), None);
}

#[tokio::test]
async fn head_blob_passes_other_errors_on_with_their_status() {
    // A `HEAD` answer has no body, so there is no problem document: the status is all there is.
    let server = MockServer::start(|_| MockResponse::head(403, 0));
    let err = client_for(&server).head_blob(&digest_of(b"x")).await.unwrap_err();
    match err {
        Error::Unexpected(u) => assert_eq!(u.status, Some(403)),
        other => panic!("expected the bare status, got {other:?}"),
    }
}

#[tokio::test]
async fn put_blob_streams_the_file_with_its_digest_and_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.bin");
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &bytes).unwrap();
    let digest = digest_of(&bytes);
    let answer = json!({"sha256": digest.to_string(), "size": bytes.len(), "created_at": T, "expires_at": null});
    let server = MockServer::start(move |_| MockResponse::json(201, &answer));

    let up = client_for(&server)
        .put_blob(&path, &digest, bytes.len() as u64)
        .await
        .unwrap();
    assert_eq!(up.sha256, digest);
    assert_eq!(up.size, bytes.len() as u64);

    let req = &server.requests()[0];
    assert_eq!(req.route(), "POST /v1/blobs");
    assert_eq!(req.header("x-p2pc-sha256"), Some(digest.to_string().as_str()));
    assert_eq!(req.header("content-length"), Some(bytes.len().to_string().as_str()));
    assert_eq!(req.header("content-type"), Some("application/octet-stream"));
    assert_eq!(req.body, bytes);
}

#[tokio::test]
async fn put_blob_refuses_a_file_that_is_not_the_announced_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.bin");
    std::fs::write(&path, b"12345").unwrap();
    let server = MockServer::start(|_| MockResponse::empty(500));
    let err = client_for(&server)
        .put_blob(&path, &digest_of(b"12345"), 99)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Local(_)), "{err:?}");
    // Nothing was sent for a file that changed under us.
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn blobs_are_listed_and_removed_by_digest() {
    let digest = digest_of(b"abc");
    let list = BlobList {
        items: vec![BlobInfo {
            sha256: digest,
            size: 3,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            referenced_by: 2,
            expires_at: None,
        }],
        next_cursor: None,
        total_bytes: 3,
        quota_mb: 20_480,
    };
    let body = serde_json::to_value(&list).unwrap();
    let server = MockServer::start(move |req| match req.method.as_str() {
        "GET" => MockResponse::json(200, &body),
        _ => MockResponse::empty(204),
    });
    let client = client_for(&server);
    let got = client
        .list_blobs(&ListParams {
            limit: Some(50),
            cursor: Some("c1".into()),
        })
        .await
        .unwrap();
    assert_eq!(got, list);
    assert_eq!(server.requests()[0].query.as_deref(), Some("limit=50&cursor=c1"));
    client.delete_blob(&digest).await.unwrap();
    assert_eq!(server.requests()[1].route(), format!("DELETE /v1/blobs/{digest}"));
}

// ---------------------------------------------------------------------------------------------------------------
// volumes
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn volumes_are_listed_in_pages() {
    let node = NodeId::generate();
    let volume = VolumeInfo {
        name: "tpl:private-chat/models".into(),
        node_id: node,
        size_mb: 2_500,
        max_mb: 20_480,
        last_used_at: None,
        in_use_by: None,
    };
    let body = json!({"items": [volume], "next_cursor": null});
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let page = client_for(&server).list_volumes(&ListParams::default()).await.unwrap();
    assert_eq!(page.items, vec![volume]);
    assert_eq!(server.requests()[0].route(), "GET /v1/volumes");
}

#[tokio::test]
async fn a_template_volume_name_is_one_percent_encoded_path_segment() {
    let node = NodeId::generate();
    let server = MockServer::start(|_| MockResponse::empty(204));
    let client = client_for(&server);
    client.delete_volume(&node, "tpl:private-chat/models").await.unwrap();
    client.delete_volume(&node, "scratch.v1").await.unwrap();
    let reqs = server.requests();
    // The raw request target, exactly as the spec writes it (§7.3): the `:` and the `/` are escaped, nothing twice.
    assert_eq!(
        reqs[0].route(),
        format!("DELETE /v1/volumes/{node}/tpl%3Aprivate-chat%2Fmodels")
    );
    assert_eq!(reqs[1].route(), format!("DELETE /v1/volumes/{node}/scratch.v1"));
}

#[tokio::test]
async fn a_hostile_volume_name_cannot_leave_its_segment() {
    let node = NodeId::generate();
    let server = MockServer::start(|_| MockResponse::empty(204));
    client_for(&server)
        .delete_volume(&node, "../../keys/x?a=b#c %")
        .await
        .unwrap();
    let path = server.requests()[0].path.clone();
    assert_eq!(path, format!("/v1/volumes/{node}/..%2F..%2Fkeys%2Fx%3Fa%3Db%23c%20%25"));
    assert_eq!(server.requests()[0].query, None);
}

// ---------------------------------------------------------------------------------------------------------------
// templates
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn templates_are_listed_with_their_bundle_version() {
    let server = MockServer::start(|_| {
        MockResponse::json(
            200,
            &json!({"bundle_version": 7, "templates": [], "bundle_error": null}),
        )
    });
    let list: TemplateList = client_for(&server).list_templates().await.unwrap();
    assert_eq!(list.bundle_version, Some(7));
    assert_eq!(server.requests()[0].route(), "GET /v1/templates");
}

fn job_json(id: JobId) -> Value {
    json!({
        "id": id, "project_id": p2pc_proto::ids::ProjectId::generate(), "status": "queued", "attempt": 0,
        "spec": {"image": "x", "command": ["a"], "resources": {"cpu": 1.0, "memory_mb": 128}, "timeout_s": 60},
        "estimated_units": 0, "created_at": T,
    })
}

#[tokio::test]
async fn a_template_launch_tells_a_new_job_from_the_running_singleton() {
    let id = JobId::generate();
    let body = job_json(id);
    let server = MockServer::start(move |req| {
        let status = if req.query.as_deref() == Some("again") {
            200
        } else {
            201
        };
        MockResponse::json(status, &body)
    });
    let client = client_for(&server);
    let mut launch = LaunchTemplate::default();
    launch
        .params
        .insert("model".into(), p2pc_proto::api::ParamValue::Text("small".into()));
    let created: TemplateLaunch = client.launch_template("private-chat", &launch).await.unwrap();
    assert_eq!(created.job.id, id);
    assert!(!created.existing);
    let req = &server.requests()[0];
    assert_eq!(req.route(), "POST /v1/templates/private-chat/launch");
    let sent = req.json();
    assert_eq!(sent["params"]["model"], "small");
    // A retry-safe launch: the client always sends a key, like a job submission.
    assert!(sent["idempotency_key"].as_str().is_some_and(|k| k.starts_with("p2pc-")));
}

#[tokio::test]
async fn a_200_launch_is_the_instance_that_was_already_running() {
    let id = JobId::generate();
    let body = job_json(id);
    let server = MockServer::start(move |_| MockResponse::json(200, &body));
    let got = client_for(&server)
        .launch_template("private-chat", &LaunchTemplate::default())
        .await
        .unwrap();
    assert!(got.existing);
}

#[tokio::test]
async fn a_launch_is_retried_with_the_same_idempotency_key() {
    let id = JobId::generate();
    let body = job_json(id);
    let n = std::sync::atomic::AtomicUsize::new(0);
    let server = MockServer::start(move |_| {
        if n.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            MockResponse::problem(503, "unavailable", "x")
        } else {
            MockResponse::json(201, &body)
        }
    });
    client_for(&server)
        .launch_template("private-chat", &LaunchTemplate::default())
        .await
        .unwrap();
    let reqs = server.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].json()["idempotency_key"], reqs[1].json()["idempotency_key"]);
}

#[tokio::test]
async fn a_template_id_cannot_leave_its_segment() {
    let server = MockServer::start(|_| MockResponse::problem(404, "unknown_template", "x"));
    let _ = client_for(&server)
        .launch_template("../keys", &LaunchTemplate::default())
        .await;
    assert_eq!(server.requests()[0].path, "/v1/templates/..%2Fkeys/launch");
}

// ---------------------------------------------------------------------------------------------------------------
// devices and pairing tickets
// ---------------------------------------------------------------------------------------------------------------

fn device(id: DeviceId) -> DeviceInfo {
    DeviceInfo::new(
        id,
        "iOS Safari",
        vec![Scope::TemplatesLaunch],
        time::OffsetDateTime::UNIX_EPOCH,
        Principal::Key(KeyId::generate()),
    )
}

#[tokio::test]
async fn devices_are_listed_fetched_and_revoked() {
    let id = DeviceId::generate();
    let info = device(id);
    let (list, one) = (
        json!({"items": [info], "next_cursor": null}),
        serde_json::to_value(&info).unwrap(),
    );
    let server = MockServer::start(move |req| match req.method.as_str() {
        "DELETE" => MockResponse::empty(204),
        _ if req.path == "/v1/devices" => MockResponse::json(200, &list),
        _ => MockResponse::json(200, &one),
    });
    let client = client_for(&server);
    assert_eq!(
        client.list_devices(&ListParams::default()).await.unwrap().items,
        vec![info.clone()]
    );
    assert_eq!(client.get_device(&id).await.unwrap(), info);
    client.revoke_device(&id).await.unwrap();
    let routes: Vec<String> = server.requests().iter().map(|r| r.route()).collect();
    assert_eq!(
        routes,
        [
            "GET /v1/devices".to_string(),
            format!("GET /v1/devices/{id}"),
            format!("DELETE /v1/devices/{id}")
        ]
    );
}

#[tokio::test]
async fn a_pairing_ticket_is_created_once_and_never_retried() {
    let ticket = "p2pc_pair_FAKEFAKEFAKE"; // gitleaks:allow
    let created = json!({
        "id": PairingTicketId::generate(), "ticket": ticket,
        "url": format!("https://app.example.invalid/pair#{ticket}"), "expires_at": T,
    });
    let n = std::sync::atomic::AtomicUsize::new(0);
    let server = MockServer::start(move |_| {
        if n.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            MockResponse::json(201, &created)
        } else {
            MockResponse::problem(503, "unavailable", "x")
        }
    });
    let client = client_for(&server);
    let request = CreatePairingTicket {
        daily_unit_cap: Some(p2pc_proto::units::Units::from_milli(2_500)),
        allowed_images: Some(vec!["docker.io/library/*".into()]),
        ..CreatePairingTicket::default()
    };
    let got: PairingTicketCreated = client.create_pairing_ticket(&request).await.unwrap();
    assert_eq!(got.ticket, ticket);
    let req = &server.requests()[0];
    assert_eq!(req.route(), "POST /v1/devices/pairing-tickets");
    assert_eq!(req.json()["daily_unit_cap"], 2_500);
    assert_eq!(req.json()["allowed_images"][0], "docker.io/library/*");
    // The scopes were left to the hub's phone profile.
    assert!(req.json().get("scopes").is_none());
    // A second call fails once and is not repeated.
    assert!(client.create_pairing_ticket(&request).await.is_err());
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn a_failed_pairing_ticket_never_quotes_the_secret() {
    let server = MockServer::start(|_| MockResponse::json(201, &json!({"ticket": "p2pc_pair_SECRETSECRET"}))); // gitleaks:allow
    let err = client_for(&server)
        .create_pairing_ticket(&CreatePairingTicket::default())
        .await
        .unwrap_err();
    assert!(!format!("{err} {err:?}").contains("SECRETSECRET"));
}

#[tokio::test]
async fn pairing_tickets_are_listed_and_revoked() {
    let id = PairingTicketId::generate();
    let server = MockServer::start(|req| match req.method.as_str() {
        "DELETE" => MockResponse::empty(204),
        _ => MockResponse::json(200, &json!({"items": [], "next_cursor": null})),
    });
    let client = client_for(&server);
    client.list_pairing_tickets(&ListParams::default()).await.unwrap();
    client.revoke_pairing_ticket(&id).await.unwrap();
    let routes: Vec<String> = server.requests().iter().map(|r| r.route()).collect();
    assert_eq!(
        routes,
        [
            "GET /v1/devices/pairing-tickets".to_string(),
            format!("DELETE /v1/devices/pairing-tickets/{id}")
        ]
    );
}

// ---------------------------------------------------------------------------------------------------------------
// service ports (H2 §7.4)
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_port_connection_upgrades_and_carries_raw_bytes() {
    let job = JobId::generate();
    let server = MockServer::start(|_| MockResponse::upgrade_echo());
    let mut stream = client_for(&server).open_port(&job, 11434, false).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");

    let req = &server.requests()[0];
    assert_eq!(req.route(), format!("POST /v1/jobs/{job}/ports/11434/connect"));
    assert_eq!(req.query, None);
    assert_eq!(req.header("upgrade"), Some("p2pc-port/1"));
    assert!(
        req.header("connection")
            .is_some_and(|c| c.to_ascii_lowercase().contains("upgrade"))
    );
    assert!(req.header("authorization").is_some_and(|a| a.starts_with("Bearer ")));
}

#[tokio::test]
async fn a_port_connection_can_wait_for_the_service_to_be_ready() {
    let server = MockServer::start(|_| MockResponse::upgrade_echo());
    client_for(&server)
        .open_port(&JobId::generate(), 80, true)
        .await
        .unwrap();
    assert_eq!(server.requests()[0].query.as_deref(), Some("wait_ready=true"));
}

#[tokio::test]
async fn a_refused_port_connection_is_the_hubs_error() {
    let server = MockServer::start(|_| MockResponse::problem(409, "service_not_running", "the service is not running"));
    let err = client_for(&server)
        .open_port(&JobId::generate(), 80, false)
        .await
        .expect_err("an error");
    let api = err.as_api().expect("an API error");
    assert_eq!((api.status, api.code.as_str()), (409, "service_not_running"));
    // A refused upgrade is not retried blindly: 409 is final, and a 5xx is a new connection the user asked for.
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn an_answer_that_is_not_an_upgrade_is_not_a_port_connection() {
    // A proxy that answers 200 with a page must not be treated as a raw stream into a service.
    let server = MockServer::start(|_| MockResponse::json(200, &json!({"ok": true})));
    let err = client_for(&server)
        .open_port(&JobId::generate(), 80, false)
        .await
        .expect_err("an error");
    assert!(matches!(err, Error::Unexpected(_)), "{err:?}");
}
