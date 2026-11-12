// SPDX-License-Identifier: Apache-2.0

// Unix only, like the upload directory itself: elsewhere `p2pc_blob_put` refuses every call.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `p2pc_blob_put` and the `inputs` of `p2pc_run` (H2 §7.8, SI-H2-21): an in-process MCP client talks to the server,
//! which talks to a mock hub on `127.0.0.1:0`. Every refusal is checked for the tool error `path_not_allowed` and for
//! what reached the hub: nothing is uploaded.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use p2pc_cli::mcp::{McpConfig, McpServer, UploadDir};
use p2pc_client::testing::{MockResponse, MockServer, RecordedRequest, fixtures};
use p2pc_client::{Client, RetryPolicy};
use p2pc_proto::api::{JobStatus, ServerInfo};
use p2pc_proto::auth::{ApiKey, ServerAddress};
use p2pc_proto::ids::JobId;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const T: &str = "2023-11-14T22:13:20Z";

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn server_info(max_blob_mb: u64) -> Value {
    let address = ServerAddress::new(
        "a".repeat(64),
        vec![url::Url::parse("https://relay.example.invalid/").unwrap()],
    );
    let mut info = ServerInfo::new(address, "0.1.0");
    info.max_blob_mb = Some(max_blob_mb);
    serde_json::to_value(info).unwrap()
}

/// A hub that has the blobs in `have`, takes any other upload, and runs `on_head` when it is asked about a blob (the
/// file is then between its first read and its second).
fn hub(
    max_blob_mb: u64,
    have: Vec<String>,
    on_head: Option<Arc<dyn Fn() + Send + Sync>>,
) -> impl Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static {
    move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/server") => MockResponse::json(200, &server_info(max_blob_mb)),
        ("HEAD", p) => {
            if let Some(hook) = &on_head {
                hook();
            }
            let wanted = p.trim_start_matches("/v1/blobs/");
            if have.iter().any(|d| d.trim_start_matches("sha256:") == wanted) {
                MockResponse::head(200, 11)
            } else {
                MockResponse::head(404, 0)
            }
        }
        ("POST", "/v1/blobs") => {
            let sha = req.header("x-p2pc-sha256").unwrap_or_default().to_string();
            MockResponse::json(
                201,
                &json!({"sha256": sha, "size": req.body.len(), "created_at": T, "expires_at": null}),
            )
        }
        ("POST", "/v1/jobs") => {
            let job = fixtures::job(JobId::generate(), JobStatus::Queued, None);
            MockResponse::json(201, &serde_json::to_value(job).unwrap())
        }
        _ => MockResponse::problem(404, "not_found", "no such route"),
    }
}

struct Session {
    mcp: RunningService<RoleClient, ()>,
    rest: MockServer,
    /// The user's directories: `uploads`, `config` and a file outside both.
    root: tempfile::TempDir,
    uploads: PathBuf,
}

#[derive(Debug)]
struct Reply {
    is_error: bool,
    value: Value,
    text: String,
}

async fn session_with(
    handler: impl Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static,
    with_upload_dir: bool,
) -> Session {
    let rest = MockServer::start(handler);
    let key = ApiKey::generate();
    let root = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(root.path()).unwrap();
    let config_dir = base.join("config");
    std::fs::create_dir(&config_dir).unwrap();
    let uploads = base.join("uploads");
    let mut config = McpConfig::new(base.join("results"));
    config.poll_interval = Duration::from_millis(1);
    if with_upload_dir {
        config = config.with_upload_dir(UploadDir::prepare(&uploads, Some(&base), &config_dir).unwrap());
    }
    let client = Client::builder(rest.url(), key.clone())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();
    let server = McpServer::new(client, &key, config);
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let running = server.serve(server_io).await.expect("serve");
        let _ = running.waiting().await;
    });
    let mcp = ().serve(client_io).await.expect("client handshake");
    Session {
        mcp,
        rest,
        root,
        uploads,
    }
}

async fn session(handler: impl Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static) -> Session {
    session_with(handler, true).await
}

impl Session {
    async fn call(&self, tool: &str, args: Value) -> Reply {
        let params = CallToolRequestParams::new(tool.to_string()).with_arguments(args.as_object().cloned().unwrap());
        let result: CallToolResult = self.mcp.call_tool(params).await.expect("a tool result");
        let text = result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join("\n");
        Reply {
            is_error: result.is_error.unwrap_or(false),
            value: result.structured_content.expect("structured content"),
            text,
        }
    }

    async fn put(&self, path: &str) -> Reply {
        self.call("p2pc_blob_put", json!({"path": path})).await
    }

    /// A file outside the upload directory, which the agent must never reach.
    fn outside(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::fs::canonicalize(self.root.path()).unwrap().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn routes(&self) -> Vec<String> {
        self.rest.requests().iter().map(RecordedRequest::route).collect()
    }

    /// The tool error is `path_not_allowed`, nothing reached the hub, and the secret is nowhere in the answer.
    fn assert_refused(&self, reply: &Reply, what: &str) {
        assert!(reply.is_error, "{what}: {reply:?}");
        assert_eq!(reply.value["error"]["kind"], "path_not_allowed", "{what}: {reply:?}");
        assert!(
            self.rest.requests_to("POST /v1/blobs").is_empty(),
            "{what}: something was uploaded"
        );
        assert!(
            !reply.text.contains("TOPSECRET"),
            "{what}: the contents leaked: {}",
            reply.text
        );
    }
}

fn write_in(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
}

// ---------------------------------------------------------------------------------------------------------------
// The tool and its schema
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_tool_list_has_p2pc_blob_put_with_a_path_and_run_takes_inputs_by_digest() {
    let s = session(|_| MockResponse::empty(404)).await;
    let tools = s.mcp.list_all_tools().await.unwrap();
    let put = tools
        .iter()
        .find(|t| t.name == "p2pc_blob_put")
        .expect("p2pc_blob_put is listed");
    let schema = serde_json::to_value(&*put.input_schema).unwrap();
    assert_eq!(schema["required"], json!(["path"]));
    assert_eq!(schema["additionalProperties"], false);
    assert!(
        put.description
            .as_deref()
            .unwrap_or_default()
            .contains("daily unit cap")
    );
    // No service tools in H2 (§7.8): eight tools in all.
    assert_eq!(tools.len(), 8);
    assert!(!tools.iter().any(|t| t.name.contains("service")));
    for name in ["p2pc_run", "p2pc_estimate"] {
        let tool = tools.iter().find(|t| t.name == name).unwrap();
        let schema = serde_json::to_value(&*tool.input_schema).unwrap();
        let inputs = &schema["properties"]["inputs"];
        assert_eq!(inputs["items"]["required"], json!(["path", "blob"]), "{name}");
        assert_eq!(
            inputs["items"]["properties"]["blob"]["pattern"], "^sha256:[0-9a-f]{64}$",
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// What is uploaded
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_file_in_the_upload_directory_is_hashed_and_uploaded_and_its_contents_are_not_returned() {
    let s = session(hub(2048, vec![], None)).await;
    write_in(&s.uploads, "data/a.bin", b"hello world");
    let r = s.put("data/a.bin").await;
    assert!(!r.is_error, "{r:?}");
    let blob = digest(b"hello world");
    assert_eq!(r.value, json!({"blob": blob, "size": 11, "uploaded": true}));
    assert!(!r.text.contains("hello world"));
    let hash = blob.trim_start_matches("sha256:");
    assert_eq!(
        s.routes(),
        [
            "GET /v1/server".to_string(),
            format!("HEAD /v1/blobs/{hash}"),
            "POST /v1/blobs".to_string()
        ]
    );
    let upload = &s.rest.requests()[2];
    assert_eq!(upload.body, b"hello world");
    assert_eq!(upload.header("x-p2pc-sha256"), Some(hash));
}

#[tokio::test]
async fn an_absolute_path_under_the_directory_is_taken_as_its_relative_rest() {
    let s = session(hub(2048, vec![], None)).await;
    write_in(&s.uploads, "a.txt", b"hello world");
    let r = s.put(&format!("{}/a.txt", s.uploads.display())).await;
    assert!(!r.is_error, "{r:?}");
    assert_eq!(r.value["blob"], digest(b"hello world"));
}

#[tokio::test]
async fn a_blob_the_hub_already_has_is_not_uploaded_again() {
    let s = session(hub(2048, vec![digest(b"hello world")], None)).await;
    write_in(&s.uploads, "a.txt", b"hello world");
    let r = s.put("a.txt").await;
    assert!(!r.is_error, "{r:?}");
    assert_eq!(r.value["uploaded"], false);
    assert!(s.rest.requests_to("POST /v1/blobs").is_empty());
}

#[tokio::test]
async fn without_an_upload_directory_the_tool_refuses_every_call() {
    let s = session_with(hub(2048, vec![], None), false).await;
    let r = s.put("a.txt").await;
    s.assert_refused(&r, "no upload directory");
    assert!(s.rest.requests().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// SI-H2-21: each of these is refused with `path_not_allowed` and nothing is uploaded
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn traversal_and_paths_outside_the_directory_are_refused_without_a_request() {
    let s = session(hub(2048, vec![], None)).await;
    s.outside("outside.txt", b"TOPSECRET");
    write_in(&s.uploads, "sub/a.txt", b"x");
    let credentials = s.root.path().join("config/credentials.toml");
    std::fs::write(&credentials, b"api_key = \"TOPSECRET\"").unwrap(); // gitleaks:allow
    for path in [
        "../outside.txt".to_string(),
        "sub/../../outside.txt".to_string(),
        "sub/../sub/a.txt".to_string(),
        "/etc/passwd".to_string(),
        credentials.display().to_string(),
        s.root.path().join("outside.txt").display().to_string(),
    ] {
        let r = s.put(&path).await;
        s.assert_refused(&r, &path);
    }
    // Refused before the hub was asked anything.
    assert!(s.rest.requests().is_empty(), "{:?}", s.routes());
}

#[tokio::test]
async fn hidden_files_and_files_under_hidden_directories_are_refused() {
    let s = session(hub(2048, vec![], None)).await;
    write_in(&s.uploads, ".env", b"TOPSECRET");
    write_in(&s.uploads, ".ssh/id_ed25519", b"TOPSECRET");
    write_in(&s.uploads, "ok/.hidden", b"TOPSECRET");
    for path in [".env", ".ssh/id_ed25519", "ok/.hidden"] {
        let r = s.put(path).await;
        s.assert_refused(&r, path);
    }
    assert!(s.rest.requests().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn symbolic_links_are_refused_wherever_they_are() {
    use std::os::unix::fs::symlink;
    let s = session(hub(2048, vec![], None)).await;
    let secret = s.outside("outside.txt", b"TOPSECRET");
    let outdir = s.root.path().join("outdir");
    std::fs::create_dir(&outdir).unwrap();
    std::fs::write(outdir.join("inner.txt"), b"TOPSECRET").unwrap();
    // To a file outside, as the last component.
    symlink(&secret, s.uploads.join("link.txt")).unwrap();
    // To a directory outside, as a middle component.
    symlink(&outdir, s.uploads.join("linkdir")).unwrap();
    for path in ["link.txt", "linkdir/inner.txt"] {
        let r = s.put(path).await;
        s.assert_refused(&r, path);
    }
    assert!(s.rest.requests().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn the_upload_directory_replaced_by_a_link_is_refused() {
    use std::os::unix::fs::symlink;
    let s = session(hub(2048, vec![], None)).await;
    write_in(&s.uploads, "a.txt", b"TOPSECRET");
    // The user's directory is moved aside and a link to it put in its place after `p2pc mcp` started.
    let moved = s.root.path().join("moved");
    std::fs::rename(&s.uploads, &moved).unwrap();
    symlink(&moved, &s.uploads).unwrap();
    let r = s.put("a.txt").await;
    s.assert_refused(&r, "link in place of the directory");
    assert!(s.rest.requests().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a_fifo_does_not_block_the_call_and_is_refused() {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    let s = session(hub(2048, vec![], None)).await;
    mknodat(CWD, s.uploads.join("pipe"), FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
    // Nobody writes to the FIFO: opening it for reading would block forever. The call must return.
    let r = tokio::time::timeout(Duration::from_secs(30), s.put("pipe"))
        .await
        .expect("the call blocked on the FIFO");
    s.assert_refused(&r, "fifo");
    assert!(s.rest.requests().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a_directory_a_device_and_a_socket_are_refused() {
    use rustix::fs::{CWD, FileType, Mode, makedev, mknodat};
    let s = session(hub(2048, vec![], None)).await;
    std::fs::create_dir(s.uploads.join("adir")).unwrap();
    let r = s.put("adir").await;
    s.assert_refused(&r, "directory");
    // A device node needs privilege to be created, and a restricted sandbox may forbid a socket: each is covered
    // when the environment lets it be made (the type check is the one that refuses the FIFO and the directory).
    if mknodat(
        CWD,
        s.uploads.join("null"),
        FileType::CharacterDevice,
        Mode::RUSR | Mode::WUSR,
        makedev(1, 3),
    )
    .is_ok()
    {
        let r = s.put("null").await;
        s.assert_refused(&r, "device");
    }
    if let Ok(_listener) = std::os::unix::net::UnixListener::bind(s.uploads.join("sock")) {
        let r = s.put("sock").await;
        s.assert_refused(&r, "socket");
    }
    assert!(s.rest.requests().is_empty());
}

#[tokio::test]
async fn a_sparse_file_over_the_hubs_max_blob_mb_is_refused_without_being_read() {
    let s = session(hub(1, vec![], None)).await;
    // 2 MiB of hole: it costs no disk, and reading it would be work the hub's limit says not to do.
    let file = std::fs::File::create(s.uploads.join("big.bin")).unwrap();
    file.set_len(2 * 1024 * 1024).unwrap();
    let r = s.put("big.bin").await;
    s.assert_refused(&r, "sparse file over max_blob_mb");
    assert!(r.value["error"]["message"].as_str().unwrap().contains("1 MiB"), "{r:?}");
    // Only the hub's limit was asked; no blob was hashed or sent.
    assert_eq!(s.routes(), ["GET /v1/server"]);
    // A file within the limit is fine.
    write_in(&s.uploads, "small.bin", b"hello world");
    assert!(!s.put("small.bin").await.is_error);
}

#[tokio::test]
async fn a_file_that_grows_before_the_upload_is_refused_and_nothing_is_uploaded() {
    let dir: Arc<std::sync::OnceLock<PathBuf>> = Arc::default();
    let grow = {
        let dir = Arc::clone(&dir);
        Arc::new(move || {
            // The hub is asked about the blob after the hash: the agent's own process appends to the file now.
            let path = dir.get().unwrap().join("log.txt");
            let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
            std::io::Write::write_all(&mut file, b" and then some").unwrap();
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let s = session(hub(2048, vec![], Some(grow))).await;
    dir.set(s.uploads.clone()).unwrap();
    write_in(&s.uploads, "log.txt", b"hello world");
    let r = s.put("log.txt").await;
    s.assert_refused(&r, "file that grew");
    assert!(
        r.value["error"]["message"].as_str().unwrap().contains("longer"),
        "{r:?}"
    );
}

#[tokio::test]
async fn a_file_rewritten_in_place_between_the_hash_and_the_upload_is_refused() {
    let dir: Arc<std::sync::OnceLock<PathBuf>> = Arc::default();
    let rewrite = {
        let dir = Arc::clone(&dir);
        Arc::new(move || {
            std::fs::write(dir.get().unwrap().join("a.txt"), b"HELLO WORLD").unwrap();
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let s = session(hub(2048, vec![], Some(rewrite))).await;
    dir.set(s.uploads.clone()).unwrap();
    write_in(&s.uploads, "a.txt", b"hello world");
    let r = s.put("a.txt").await;
    assert!(r.is_error, "{r:?}");
    assert!(
        s.rest.requests_to("POST /v1/blobs").is_empty(),
        "the rewritten bytes were uploaded"
    );
}

#[tokio::test]
async fn the_refusal_names_the_rule_and_a_bad_call_is_an_invalid_argument() {
    let s = session(hub(2048, vec![], None)).await;
    let r = s.put("../x").await;
    assert!(r.value["error"]["message"].as_str().unwrap().contains("`..`"), "{r:?}");
    for args in [json!({}), json!({"path": 1}), json!({"path": "a", "extra": true})] {
        let r = s.call("p2pc_blob_put", args).await;
        assert!(r.is_error);
        assert_eq!(r.value["error"]["kind"], "invalid_arguments");
    }
    assert!(s.rest.requests().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// `p2pc_run` inputs
// ---------------------------------------------------------------------------------------------------------------

fn run_with_inputs(inputs: Value) -> Value {
    json!({"image": "python:3.12-slim", "command": ["python", "/inputs/main.py"], "inputs": inputs})
}

#[tokio::test]
async fn run_sends_blob_inputs_by_digest() {
    let s = session(hub(2048, vec![], None)).await;
    let blob = digest(b"hello world");
    let r = s
        .call(
            "p2pc_run",
            run_with_inputs(json!([{"path": "/inputs/data.bin", "blob": blob}])),
        )
        .await;
    assert!(!r.is_error, "{r:?}");
    let create = &s.rest.requests_to("POST /v1/jobs")[0];
    let body: Value = serde_json::from_slice(&create.body).unwrap();
    assert_eq!(body["inputs"], json!([{"path": "/inputs/data.bin", "blob": blob}]));
}

#[tokio::test]
async fn run_never_takes_a_local_path_as_an_input() {
    let s = session(hub(2048, vec![], None)).await;
    let secret = s.outside("outside.txt", b"TOPSECRET");
    let home_key = "/home/user/.ssh/id_ed25519";
    for blob in [
        secret.display().to_string(),
        home_key.to_string(),
        "file:///etc/passwd".to_string(),
        "../outside.txt".to_string(),
        "sha256:xyz".to_string(),
        String::new(),
        // A digest that is not lowercase hex of the right length.
        format!("sha256:{}", "A".repeat(64)),
    ] {
        for tool in ["p2pc_run", "p2pc_estimate"] {
            let r = s
                .call(
                    tool,
                    run_with_inputs(json!([{"path": "/inputs/data.bin", "blob": blob}])),
                )
                .await;
            assert!(r.is_error, "{tool} {blob:?}: {r:?}");
            assert_eq!(r.value["error"]["kind"], "invalid_arguments", "{blob:?}");
            assert!(!r.text.contains("TOPSECRET"));
        }
    }
    // An input that names a file instead of a blob is not a field either.
    let r = s
        .call(
            "p2pc_run",
            run_with_inputs(json!([{"path": "/inputs/x", "file": "/etc/passwd"}])),
        )
        .await;
    assert!(r.is_error);
    assert!(s.rest.requests().is_empty(), "{:?}", s.routes());
}
