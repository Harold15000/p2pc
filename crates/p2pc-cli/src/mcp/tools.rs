// SPDX-License-Identifier: Apache-2.0

//! The seven tools: what each one asks of the API, and how the answer is shaped for an agent.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use p2pc_client::{Client, DownloadError, Error, ListParams, fetch_all};
#[cfg(unix)]
use p2pc_proto::api::{BLOB_REF_PREFIX, DEFAULT_MAX_BLOB_MB, Sha256Digest};
use p2pc_proto::api::{
    BlobInput, BlobRef, DEFAULT_DISK_MB, DEFAULT_TIMEOUT_S, Egress, InputFile, Job, JobSpec, LogLine, MAX_PAGE_LIMIT,
    Node, OutputFile, Outputs, Placement, REDACTED, Resources, Retry,
};
use p2pc_proto::ids::JobId;
use p2pc_proto::validate::{FieldError, ValidationErrors};
use rmcp::model::JsonObject;
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[cfg(unix)]
use super::upload::{ReadError, read_exact_hashed};
use super::{
    MAX_INLINE_FILE_BYTES, MAX_INLINE_TOTAL_BYTES, MAX_LOG_BYTES, MAX_WAIT_S, McpConfig, Scrubber, UNTRUSTED_NOTE,
};
use crate::commands::run::local_limits;

/// Most output files one `p2pc_results` call fetches. The rest are counted in `omitted`.
const MAX_RESULT_FILES: usize = 200;
/// Most output files read from the list. The list is paged by the server; this only bounds a runaway answer.
const MAX_LISTED_OUTPUTS: usize = 1000;
/// Most machines listed.
const MAX_MACHINES: usize = 200;
/// Most entries in the `paths` argument of `p2pc_results` (the schema's `maxItems`).
const MAX_RESULT_PATHS: usize = 200;
/// The longest a single poll of `p2pc_run`'s wait may take. The whole wait is bounded by `wait_s` too.
const WAIT_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// A tool answer: one JSON document, and whether it reports a failure.
#[derive(Debug, Clone)]
pub struct Reply {
    pub value: Value,
    pub is_error: bool,
}

impl Reply {
    fn ok(value: Value) -> Self {
        Self { value, is_error: false }
    }
}

/// Why a tool could not do what it was asked. It becomes an MCP tool error (`isError`), never a crash.
#[derive(Debug)]
pub struct ToolError(Value);

impl ToolError {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self(json!({"error": {"kind": kind, "message": message.into()}}))
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_arguments", message)
    }

    fn validation(errors: ValidationErrors) -> Self {
        let fields: Vec<FieldError> = errors.into_vec();
        Self(json!({"error": {
            "kind": "validation",
            "message": "the job is not valid; nothing was sent. Fix the fields listed in `errors`.",
            "errors": fields,
        }}))
    }

    /// An error of the client. `scope` is the scope the tool needs, for the hint of a `403`.
    fn client(e: &Error, scope: &str) -> Self {
        let mut error = match e {
            Error::Api(api) => {
                let mut body = json!({
                    "kind": "api", "status": api.status, "code": api.code, "title": api.title,
                    "detail": api.detail, "errors": api.errors,
                });
                if let Some(hint) = hint(api.status, scope) {
                    body["hint"] = Value::String(hint);
                }
                body
            }
            Error::Network(_) => json!({
                "kind": "network", "message": e.to_string(),
                "hint": "p2pc could not reach the server. Check that it is up and retry later.",
            }),
            Error::Unexpected(u) => json!({"kind": "unexpected_response", "status": u.status, "message": u.message}),
            Error::Local(_) => json!({
                "kind": "invalid_request", "message": e.to_string(),
                "hint": "p2pc could not build this request; nothing was sent. Retrying the same call will not help.",
            }),
        };
        if let Some(map) = error.as_object_mut()
            && map.get("errors").and_then(Value::as_array).is_some_and(Vec::is_empty)
        {
            map.remove("errors");
        }
        Self(json!({ "error": error }))
    }

    fn download(e: &DownloadError, scope: &str) -> Self {
        match e {
            DownloadError::Request(inner) => Self::client(inner, scope),
            DownloadError::UnsafePath(why) => Self::new("unsafe_path", format!("the output was not fetched: {why}")),
            DownloadError::SizeMismatch { .. } => Self::new("size_mismatch", e.to_string()),
            // Not `e.to_string()`: it quotes the output's path, which the job chose. The path is in the entry, under
            // `untrusted_job_output`.
            DownloadError::DigestMismatch { .. } => Self::new(
                "digest_mismatch",
                "the SHA-256 of the output does not match the one the job listed; it was not kept",
            ),
            // `p2pc_results` replaces files; the variant exists for `p2pc results`. Not `e.to_string()`: it quotes the path.
            DownloadError::Exists { .. } => Self::new("exists", "a file is already there; it was not replaced"),
            DownloadError::Io(_) => Self::new("io", e.to_string()),
        }
    }

    fn into_value(self) -> Value {
        self.0
    }
}

impl From<ValidationErrors> for ToolError {
    fn from(e: ValidationErrors) -> Self {
        Self::validation(e)
    }
}

/// An `idempotency_conflict` (`409`) from `POST /v1/jobs` means the `idempotency_key` was already used for a different
/// job: say how to go on. Any other `409` gets no such hint.
fn conflict_hint(mut error: ToolError, cause: &Error) -> ToolError {
    if matches!(cause, Error::Api(api) if api.status == 409 && api.code == "idempotency_conflict")
        && let Some(map) = error.0.get_mut("error").and_then(Value::as_object_mut)
    {
        map.insert(
            "hint".into(),
            json!(
                "idempotency_key conflict: this idempotency_key was already used for a different job. To retry the \
                 same call, send exactly the same job; for a new job, use a new idempotency_key."
            ),
        );
    }
    error
}

/// What to tell the agent about an HTTP status, so that it does not retry blindly.
fn hint(status: u16, scope: &str) -> Option<String> {
    match status {
        401 => Some(
            "The API key was rejected: it may be revoked or expired. Ask the owner for a new key \
             (`p2pc keys create --label agent --scope jobs:write --scope jobs:read --cap <UNITS>`)."
                .into(),
        ),
        402 => Some(
            "The key's daily unit cap would be exceeded. Use a smaller job or a shorter timeout, wait for the next \
             UTC day, or ask the owner to raise the cap."
                .into(),
        ),
        403 => Some(format!(
            "This key may not do that: it may lack the `{scope}` scope, or the image may not be on its allowlist. \
             Ask the owner to create a key with `--scope {scope}`."
        )),
        422 => Some("The server refused the job. Fix the fields listed in `errors` and try again.".into()),
        500..=599 => Some("The server failed. Retrying later may work.".into()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------------------------------------------

fn parse_args<T: for<'de> Deserialize<'de>>(args: JsonObject) -> Result<T, ToolError> {
    match serde_json::from_value::<T>(Value::Object(args.clone())) {
        Ok(parsed) => Ok(parsed),
        Err(e) => {
            let message = e.to_string();
            // serde names a missing or unknown field but not the field of a wrong type: find it, so that the agent
            // knows what to fix.
            let culprit = (!message.contains("field `"))
                .then(|| args.keys().find(|k| removing_fixes::<T>(&args, k)).cloned())
                .flatten();
            Err(ToolError::invalid(match culprit {
                Some(field) => format!("the argument `{field}` is not valid: {message}"),
                None => message,
            }))
        }
    }
}

/// Whether the arguments parse once `key` is left out (a field that then goes missing counts: the rest was fine).
fn removing_fixes<T: for<'de> Deserialize<'de>>(args: &JsonObject, key: &str) -> bool {
    let mut rest = args.clone();
    rest.remove(key);
    match serde_json::from_value::<T>(Value::Object(rest)) {
        Ok(_) => true,
        Err(e) => e.to_string().starts_with("missing field"),
    }
}

fn one() -> f64 {
    1.0
}
fn default_memory_mb() -> u64 {
    2048
}
fn default_disk_mb() -> u64 {
    DEFAULT_DISK_MB
}
fn default_timeout() -> u32 {
    DEFAULT_TIMEOUT_S
}

/// The input of `p2pc_run` and `p2pc_estimate`: `JobSpec` with the defaults of the schema.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobInput {
    name: Option<String>,
    image: String,
    command: Vec<String>,
    #[serde(default = "one")]
    cpu: f64,
    #[serde(default = "default_memory_mb")]
    memory_mb: u64,
    #[serde(default)]
    gpu: u32,
    #[serde(default = "default_disk_mb")]
    disk_mb: u64,
    #[serde(default = "default_timeout")]
    timeout_s: u32,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    files: Vec<FileInput>,
    /// Blobs by digest (H2 §7.8). Never a local path: a file reaches a job only through `p2pc_blob_put`.
    #[serde(default)]
    inputs: Vec<BlobInputArg>,
    #[serde(default)]
    egress: EgressInput,
    #[serde(default)]
    wait_s: u64,
    /// `p2pc_run` only. Sent to the API as `mcp:<key>`.
    idempotency_key: Option<String>,
}

/// The longest `idempotency_key` an agent may give.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;

/// The key as the API gets it: the agent's own, prefixed `mcp:` (spec §7, "No duplicate jobs").
fn api_idempotency_key(key: &str) -> Result<String, ToolError> {
    let valid = !key.is_empty()
        && key.len() <= MAX_IDEMPOTENCY_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if valid {
        Ok(format!("mcp:{key}"))
    } else {
        Err(ToolError::invalid(format!(
            "idempotency_key must be 1 to {MAX_IDEMPOTENCY_KEY_LEN} characters of A-Z a-z 0-9 . _ : - ; \
             nothing was sent"
        )))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInput {
    path: String,
    content: Option<String>,
    content_b64: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobInputArg {
    path: String,
    /// `sha256:<64 lowercase hex>`; anything else (a path, a URL) is refused when the job is built.
    blob: String,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressInput {
    #[serde(default)]
    allow: Vec<String>,
}

impl JobInput {
    fn into_spec(self) -> Result<JobSpec, ToolError> {
        if self.wait_s > MAX_WAIT_S {
            return Err(ToolError::invalid(format!(
                "wait_s must be at most {MAX_WAIT_S}; use p2pc_status and p2pc_logs for longer jobs"
            )));
        }
        let idempotency_key = self.idempotency_key.as_deref().map(api_idempotency_key).transpose()?;
        let mut files = Vec::with_capacity(self.files.len());
        for file in self.files {
            let content_b64 = match (file.content, file.content_b64) {
                (Some(text), None) => data_encoding::BASE64.encode(text.as_bytes()),
                (None, Some(b64)) => {
                    // Decode once to refuse what is not base64 here, with a clear message.
                    if data_encoding::BASE64.decode(b64.as_bytes()).is_err() {
                        return Err(ToolError::invalid(format!(
                            "files: content_b64 of {} is not valid padded base64",
                            file.path
                        )));
                    }
                    b64
                }
                _ => {
                    return Err(ToolError::invalid(format!(
                        "files: give exactly one of content or content_b64 for {}",
                        file.path
                    )));
                }
            };
            files.push(InputFile {
                path: file.path,
                content_b64,
            });
        }
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for input in self.inputs {
            let blob = BlobRef::from_str(&input.blob).map_err(|_| {
                ToolError::invalid(format!(
                    "inputs: `blob` of {} must be a digest `sha256:<64 lowercase hex>`, as p2pc_blob_put returns it; \
                     a local path is never accepted here. nothing was sent",
                    input.path
                ))
            })?;
            inputs.push(BlobInput { path: input.path, blob });
        }
        let spec = JobSpec {
            name: self.name,
            image: self.image,
            command: self.command,
            env: self.env,
            files,
            resources: Resources {
                cpu: self.cpu,
                memory_mb: self.memory_mb,
                gpu: self.gpu,
                disk_mb: self.disk_mb,
            },
            timeout_s: self.timeout_s,
            egress: Egress {
                allow: self
                    .egress
                    .allow
                    .iter()
                    .map(|d| d.trim().to_ascii_lowercase())
                    .collect(),
            },
            outputs: Outputs::default(),
            placement: Placement::default(),
            retry: Retry::default(),
            idempotency_key,
            kind: p2pc_proto::api::JobKind::Batch,
            service: None,
            volumes: Vec::new(),
            inputs,
            template: None,
        };
        // The same checks as the server's, minus the registry policy that only the server knows.
        spec.validate(&local_limits())?;
        Ok(spec)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobIdInput {
    job_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogsInput {
    job_id: String,
    #[serde(default)]
    since_seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultsInput {
    job_id: String,
    paths: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoInput {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobPutInput {
    /// Relative to the upload directory (an absolute path under it is accepted too).
    path: String,
}

fn parse_job_id(text: &str) -> Result<JobId, ToolError> {
    JobId::from_str(text)
        .map_err(|_| ToolError::invalid("job_id must be a job ID such as `job_01…`, as p2pc_run returned it"))
}

// ---------------------------------------------------------------------------------------------------------------
// The tools
// ---------------------------------------------------------------------------------------------------------------

/// The state the tools share.
#[derive(Debug)]
pub struct Tools {
    client: Client,
    config: McpConfig,
    scrubber: Scrubber,
}

/// How to fix a job that ended with `error="disk_limit"`, in the words of this tool's arguments.
const DISK_FIX: &str = "a larger `disk_mb` argument";

/// A job as an agent needs it right after submitting or cancelling it. The job's `error` text can come from what the
/// job or its image did, so it goes under `untrusted_job_output`, with the note.
fn job_summary(job: &Job) -> Value {
    let mut map = Map::new();
    map.insert("job_id".into(), json!(job.id));
    map.insert("status".into(), json!(job.status));
    map.insert("finished".into(), json!(job.status.is_terminal()));
    map.insert("attempt".into(), json!(job.attempt));
    if let Some(code) = job.exit_code {
        map.insert("exit_code".into(), json!(code));
    }
    if let Some(error) = &job.error {
        map.insert("note".into(), json!(UNTRUSTED_NOTE));
        map.insert("untrusted_job_output".into(), json!({ "error": error }));
    }
    if let Some(hint) = crate::outcome::disk_limit_hint(job, DISK_FIX) {
        map.insert("hint".into(), json!(hint));
    }
    Value::Object(map)
}

impl Tools {
    pub fn new(client: Client, config: McpConfig, scrubber: Scrubber) -> Self {
        Self {
            client,
            config,
            scrubber,
        }
    }

    pub fn scrubber(&self) -> &Scrubber {
        &self.scrubber
    }

    /// Runs the tool `name`. The JSON-RPC request ID plays no part: a retry always carries a new one.
    pub async fn call(&self, name: &str, args: JsonObject) -> Option<Reply> {
        let outcome = match name {
            "p2pc_estimate" => self.estimate(args).await,
            "p2pc_run" => self.run(args).await,
            "p2pc_status" => self.status(args).await,
            "p2pc_logs" => self.logs(args).await,
            "p2pc_results" => self.results(args).await,
            "p2pc_cancel" => self.cancel(args).await,
            "p2pc_machines" => self.machines(args).await,
            "p2pc_blob_put" => self.blob_put(args).await,
            _ => return None,
        };
        Some(match outcome {
            Ok(reply) => reply,
            Err(e) => Reply {
                value: e.into_value(),
                is_error: true,
            },
        })
    }

    async fn estimate(&self, args: JsonObject) -> Result<Reply, ToolError> {
        let spec = parse_args::<JobInput>(args)?.into_spec()?;
        let estimate = self
            .client
            .estimate(&spec)
            .await
            .map_err(|e| ToolError::client(&e, "jobs:read"))?;
        Ok(Reply::ok(json!(estimate)))
    }

    async fn run(&self, args: JsonObject) -> Result<Reply, ToolError> {
        let input = parse_args::<JobInput>(args)?;
        let wait_s = input.wait_s;
        let spec = input.into_spec()?;
        let job = self
            .client
            .create_job(&spec)
            .await
            .map_err(|e| conflict_hint(ToolError::client(&e, "jobs:write"), &e))?;
        let mut summary = job_summary(&job);
        if wait_s > 0 && !job.status.is_terminal() {
            let (job, wait_error) = self.wait(job, wait_s).await;
            summary = job_summary(&job);
            if let Some(error) = wait_error {
                summary["wait_error"] = Value::String(error);
            }
        }
        if summary["finished"] == Value::Bool(false) {
            summary["hint"] =
                json!("The job is still going. Use p2pc_status, p2pc_logs and p2pc_cancel with this job_id.");
        }
        Ok(Reply::ok(summary))
    }

    /// Polls the job until it ends or `wait_s` passes. `wait_s` is a hard bound on the whole wait (a slow or stalled
    /// server cannot stretch it), and each poll also has its own short timeout. A failed poll ends the wait with the
    /// last known job: the job exists, and its ID must not be lost.
    async fn wait(&self, job: Job, wait_s: u64) -> (Job, Option<String>) {
        let mut last = job;
        let polling = async {
            while !last.status.is_terminal() {
                tokio::time::sleep(self.config.poll_interval).await;
                match tokio::time::timeout(WAIT_POLL_TIMEOUT, self.client.get_job(&last.id)).await {
                    Ok(Ok(fresh)) => last = fresh,
                    Ok(Err(e)) => return Some(format!("could not check the job while waiting: {e}")),
                    Err(_) => return Some("the server did not answer in time while waiting".to_string()),
                }
            }
            None
        };
        let outcome = tokio::time::timeout(Duration::from_secs(wait_s), polling).await;
        // Out of time: the job as it was last seen, which is still running.
        (last, outcome.unwrap_or(None))
    }

    async fn status(&self, args: JsonObject) -> Result<Reply, ToolError> {
        let id = parse_job_id(&parse_args::<JobIdInput>(args)?.job_id)?;
        let mut job = self
            .client
            .get_job(&id)
            .await
            .map_err(|e| ToolError::client(&e, "jobs:read"))?;
        // The server redacts the env. Do it again: a value must never get out through this tool, whatever sent it.
        for value in job.spec.env.values_mut() {
            *value = REDACTED.to_string();
        }
        let hint = crate::outcome::disk_limit_hint(&job, DISK_FIX);
        let error = job.error.take();
        let mut value = json!(job);
        if let (Some(hint), Some(map)) = (hint, value.as_object_mut()) {
            map.insert("hint".into(), json!(hint));
        }
        if let (Some(error), Some(map)) = (error, value.as_object_mut()) {
            // The error text may come from what the job or its image did: it is data, not instructions.
            map.remove("error");
            map.insert("note".into(), json!(UNTRUSTED_NOTE));
            map.insert("untrusted_job_output".into(), json!({ "error": error }));
        }
        Ok(Reply::ok(value))
    }

    async fn cancel(&self, args: JsonObject) -> Result<Reply, ToolError> {
        let id = parse_job_id(&parse_args::<JobIdInput>(args)?.job_id)?;
        let job = self
            .client
            .cancel_job(&id)
            .await
            .map_err(|e| ToolError::client(&e, "jobs:write"))?;
        Ok(Reply::ok(job_summary(&job)))
    }

    async fn machines(&self, args: JsonObject) -> Result<Reply, ToolError> {
        parse_args::<NoInput>(args)?;
        let nodes = fetch_all(
            |cursor| async move {
                self.client
                    .list_nodes(&ListParams {
                        limit: Some(MAX_PAGE_LIMIT),
                        cursor,
                    })
                    .await
            },
            Some(MAX_MACHINES),
        )
        .await
        .map_err(|e| ToolError::client(&e, "nodes:read"))?;
        let machines: Vec<Value> = nodes.iter().map(machine).collect();
        Ok(Reply::ok(json!({"machines": machines})))
    }

    /// `p2pc_blob_put` (H2 §7.8, SI-H2-21): uploads a file of the upload directory as a blob.
    ///
    /// The path rules and the safe open come first, before the hub is asked anything. The size from `fstat` is held
    /// against the hub's `max_blob_mb`; the hash reads the descriptor; and, if the hub lacks the blob, the descriptor
    /// is read again into a private temporary copy that is what the client uploads (the client opens the file it
    /// uploads by path, which must never be a path the agent named). Both reads stop at the size that was checked,
    /// and the second must give the same hash: a file that changes while it is read is refused. The answer never
    /// holds file contents.
    #[cfg(unix)]
    async fn blob_put(&self, args: JsonObject) -> Result<Reply, ToolError> {
        let input = parse_args::<BlobPutInput>(args)?;
        let Some(dir) = self.config.upload_dir.clone() else {
            return Err(ToolError::new(
                "path_not_allowed",
                "no upload directory is configured: start `p2pc mcp` with --upload-dir",
            ));
        };
        let opened = blocking(move || dir.open(&input.path))
            .await?
            .map_err(|e| ToolError::new("path_not_allowed", e.0))?;
        let size = opened.size;
        let max_mb = self
            .client
            .server_info()
            .await
            .map_err(|e| ToolError::client(&e, "blobs:write"))?
            .max_blob_mb
            .unwrap_or(DEFAULT_MAX_BLOB_MB);
        if size > max_mb.saturating_mul(1024 * 1024) {
            return Err(ToolError::new(
                "path_not_allowed",
                format!("the file is larger than the hub's limit for a blob ({max_mb} MiB); nothing was uploaded"),
            ));
        }

        let mut file = opened.file;
        let (file, digest) = blocking(move || {
            let digest = read_exact_hashed(&mut file, size, None::<&mut std::fs::File>)?;
            Ok::<_, ReadError>((file, digest))
        })
        .await?
        .map_err(read_failure)?;
        let blob = format!("{BLOB_REF_PREFIX}{digest}");

        let present = match self.client.head_blob(&digest).await {
            Ok(found) => found.is_some(),
            // A `HEAD` answer has no body: a refusal there says nothing, and the upload's own answer does.
            Err(Error::Unexpected(u)) if u.status.is_some_and(|s| (400..500).contains(&s)) => false,
            Err(e) => return Err(ToolError::client(&e, "blobs:write")),
        };
        if !present {
            let copy = blocking(move || stage(file, size, &digest))
                .await?
                .map_err(read_failure)?;
            self.client
                .put_blob(&copy.path, &digest, size)
                .await
                .map_err(|e| ToolError::client(&e, "blobs:write"))?;
        }
        Ok(Reply::ok(json!({"blob": blob, "size": size, "uploaded": !present})))
    }

    /// `p2pc_blob_put` where there is no safe open of a file below a directory (not Unix): it refuses every call. The
    /// arguments are still checked, so a malformed call gets the same `invalid_arguments` as everywhere.
    #[cfg(not(unix))]
    async fn blob_put(&self, args: JsonObject) -> Result<Reply, ToolError> {
        parse_args::<BlobPutInput>(args)?;
        Err(ToolError::new(
            "path_not_allowed",
            "uploads from MCP are not supported on this platform yet; nothing was uploaded. Upload the file with \
             `p2pc blobs put` yourself and pass its digest in `inputs`.",
        ))
    }

    async fn logs(&self, args: JsonObject) -> Result<Reply, ToolError> {
        let input = parse_args::<LogsInput>(args)?;
        let id = parse_job_id(&input.job_id)?;
        // Ask for the job first: if it has ended before the logs are read, no line can still be added after them.
        let job = self
            .client
            .get_job(&id)
            .await
            .map_err(|e| ToolError::client(&e, "jobs:read"))?;
        let page = self
            .client
            .log_page(&id, input.since_seq, None, MAX_LOG_BYTES)
            .await
            .map_err(|e| ToolError::client(&e, "jobs:read"))?;
        let total = page.lines.len();
        let (entries, kept) = bounded_log_entries(&page.lines, MAX_LOG_BYTES);
        let next_seq = page.lines[..kept]
            .last()
            .map_or(input.since_seq, |l| l.seq.saturating_add(1));
        let more = page.more || kept < total;
        Ok(Reply::ok(json!({
            "job_id": id,
            "status": job.status,
            "since_seq": input.since_seq,
            "next_seq": next_seq,
            "done": job.status.is_terminal() && !more,
            "more": more,
            "note": UNTRUSTED_NOTE,
            "untrusted_job_output": entries,
        })))
    }

    async fn results(&self, args: JsonObject) -> Result<Reply, ToolError> {
        let input = parse_args::<ResultsInput>(args)?;
        let id = parse_job_id(&input.job_id)?;
        if input.paths.as_ref().is_some_and(|p| p.len() > MAX_RESULT_PATHS) {
            return Err(ToolError::invalid(format!(
                "paths may list at most {MAX_RESULT_PATHS} outputs; ask in several calls"
            )));
        }
        let listed = self
            .client
            .list_all_outputs(&id, None, MAX_LISTED_OUTPUTS)
            .await
            .map_err(|e| ToolError::client(&e, "jobs:read"))?;

        let mut not_found = Vec::new();
        let files: Vec<OutputFile> = match &input.paths {
            None => listed,
            Some(wanted) => {
                let present: HashSet<&str> = listed.iter().map(|f| f.path.as_str()).collect();
                not_found = wanted
                    .iter()
                    .filter(|w| !present.contains(w.as_str()))
                    .cloned()
                    .collect();
                let wanted: HashSet<&str> = wanted.iter().map(String::as_str).collect();
                listed
                    .into_iter()
                    .filter(|f| wanted.contains(f.path.as_str()))
                    .collect()
            }
        };
        let omitted = files.len().saturating_sub(MAX_RESULT_FILES);

        let job_dir = absolute(&self.config.results_dir.join(id.to_string()));
        let mut inline_used = 0usize;
        let mut entries = Vec::new();
        let mut failed = false;
        for file in files.iter().take(MAX_RESULT_FILES) {
            // The path is chosen by the job, and so is everything derived from it: they go under
            // `untrusted_job_output`. Only the size and the digest are outside.
            let mut entry = json!({
                "size": file.size,
                "sha256": file.sha256.to_string(),
                "untrusted_job_output": {"path": file.path},
            });
            match self.fetch_output(&id, file, &job_dir, &mut inline_used).await {
                Ok(Fetched::Inline(text)) => entry["untrusted_job_output"]["content"] = Value::String(text),
                Ok(Fetched::Saved(path)) => {
                    entry["untrusted_job_output"]["saved_to"] = Value::String(path.display().to_string());
                }
                Err(e) => {
                    failed = true;
                    entry["error"] = ToolError::download(&e, "jobs:read").into_value()["error"].clone();
                }
            }
            entries.push(entry);
        }

        let mut value = json!({
            "job_id": id,
            "note": UNTRUSTED_NOTE,
            "directory": job_dir.display().to_string(),
            "files": entries,
        });
        if omitted > 0 {
            value["omitted"] = json!(omitted);
            value["omitted_hint"] = json!("Ask for the rest with `paths`.");
        }
        if input.paths.is_some() {
            value["not_found"] = json!(not_found);
        }
        Ok(Reply {
            value,
            is_error: failed,
        })
    }

    /// One output file: inline if it is small text and the answer has room, saved to disk otherwise.
    async fn fetch_output(
        &self,
        id: &JobId,
        file: &OutputFile,
        job_dir: &Path,
        inline_used: &mut usize,
    ) -> Result<Fetched, DownloadError> {
        let size = usize::try_from(file.size).unwrap_or(usize::MAX);
        if size <= MAX_INLINE_FILE_BYTES && inline_used.saturating_add(size) <= MAX_INLINE_TOTAL_BYTES {
            let mut bytes = Vec::with_capacity(size);
            // Verified here: the size and the SHA-256 match the listing.
            self.client.download_output(id, None, file, &mut bytes).await?;
            return match as_text(bytes) {
                Ok(text) => {
                    *inline_used += text.len();
                    Ok(Fetched::Inline(text))
                }
                // Small, but not text: the bytes already in memory go to disk, with the same path checks as a
                // download (no second request).
                Err(bytes) => Ok(Fetched::Saved(save_verified(job_dir, file, bytes).await?)),
            };
        }
        let saved = self.client.save_output(id, None, file, job_dir).await?;
        Ok(Fetched::Saved(saved))
    }
}

/// Runs blocking work (file reads) off the async threads.
#[cfg(unix)]
async fn blocking<T, F>(work: F) -> Result<T, ToolError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ToolError::new("io", "reading the file was interrupted"))
}

/// A private temporary copy of the upload, removed when dropped.
#[cfg(unix)]
struct StagedCopy {
    path: PathBuf,
    // Removes the directory (and the copy) on drop.
    _dir: tempfile::TempDir,
}

/// Copies the descriptor to a new file in a private (0700) temporary directory, from its start, and checks that the
/// copy has the hash that was announced: the bytes uploaded are the bytes that were hashed.
#[cfg(unix)]
fn stage(mut file: std::fs::File, size: u64, digest: &Sha256Digest) -> Result<StagedCopy, ReadError> {
    use std::io::{Seek, SeekFrom, Write};

    let dir = tempfile::Builder::new().prefix("p2pc-blob-").tempdir()?;
    let path = dir.path().join("blob");
    let mut out = std::fs::File::create(&path)?;
    file.seek(SeekFrom::Start(0))?;
    let again = read_exact_hashed(&mut file, size, Some(&mut out))?;
    out.flush()?;
    if &again != digest {
        // Same length, other bytes: the file was rewritten between the two reads.
        return Err(ReadError::Io(std::io::Error::other(
            "the file changed while it was read",
        )));
    }
    Ok(StagedCopy { path, _dir: dir })
}

/// A file that changed or could not be read is `path_not_allowed` (the file may not be uploaded as it is) or `io`.
#[cfg(unix)]
fn read_failure(e: ReadError) -> ToolError {
    match e {
        ReadError::Shrank | ReadError::Grew => ToolError::new(
            "path_not_allowed",
            format!("{e}; nothing was uploaded. Write the file completely, then ask again."),
        ),
        ReadError::Io(io) => ToolError::new("io", format!("the file could not be read: {io}")),
    }
}

/// Saves bytes that were already downloaded and verified, through the client's safe path (SI-9).
async fn save_verified(job_dir: &Path, file: &OutputFile, bytes: Vec<u8>) -> Result<PathBuf, DownloadError> {
    p2pc_client::save_verified_output(job_dir, file, &bytes).await
}

enum Fetched {
    Inline(String),
    Saved(PathBuf),
}

/// The text of a small output file, or the bytes back if it is binary: text is valid UTF-8 without control
/// characters other than newline, carriage return and tab.
fn as_text(bytes: Vec<u8>) -> Result<String, Vec<u8>> {
    let text = String::from_utf8(bytes).map_err(std::string::FromUtf8Error::into_bytes)?;
    if text.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) {
        Ok(text)
    } else {
        Err(text.into_bytes())
    }
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn machine(node: &Node) -> Value {
    json!({
        "id": node.id,
        "name": node.name,
        "state": node.state,
        "draining": node.draining,
        "platform": node.inventory.platform,
        "cpu_cores": node.inventory.cpu.cores,
        "memory_mb": node.inventory.memory_mb,
        "gpus": node.inventory.gpus.iter().map(|g| &g.name).collect::<Vec<_>>(),
        "offered": node.inventory.offered,
        "free": node.free,
        "last_seen": node.last_seen.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
    })
}

/// The log lines as JSON, as many as fit in `max_bytes` once serialized as an array. Returns them and how many lines
/// were used. The first line is always used: if it alone is over the budget, its text is cut (`"truncated": true`),
/// so that the cursor can move past it.
fn bounded_log_entries(lines: &[LogLine], max_bytes: usize) -> (Vec<Value>, usize) {
    let mut entries = Vec::new();
    // The brackets of the array.
    let mut used = 2usize;
    for (i, line) in lines.iter().enumerate() {
        let mut entry = json!(line);
        // The entry and its comma, which overcounts the last one by a byte: the bound is never exceeded.
        let size = entry.to_string().len() + 1;
        if used + size <= max_bytes {
            used += size;
            entries.push(entry);
            continue;
        }
        if i == 0 {
            // Measure what the entry costs without its text, and give the text what is left.
            let mut bare = entry.clone();
            bare["data"] = Value::String(String::new());
            bare["truncated"] = Value::Bool(true);
            let overhead = bare.to_string().len() + 1;
            let room = max_bytes.saturating_sub(used + overhead);
            entry["data"] = Value::String(cut_to_json_len(&line.data, room));
            entry["truncated"] = Value::Bool(true);
            entries.push(entry);
        }
        break;
    }
    let kept = entries.len();
    (entries, kept)
}

/// The longest prefix of `text` (on a character boundary) whose JSON-escaped form is at most `max` bytes.
fn cut_to_json_len(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for c in text.chars() {
        let cost = match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if c.is_control() => 6,
            c => c.len_utf8(),
        };
        if used + cost > max {
            break;
        }
        used += cost;
        out.push(c);
    }
    out
}
