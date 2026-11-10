// SPDX-License-Identifier: Apache-2.0

//! The typed REST client (spec §7).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use p2pc_proto::api::{
    ApiKeyInfo, AuditEvent, BlobList, BlobUploaded, CreateApiKey, CreateJoinToken, CreatePairingTicket, DeviceInfo,
    Estimate, Job, JobKind, JobSpec, JobStatus, JoinTokenInfo, JoinTokenResponse, LaunchTemplate, NewApiKey, Node,
    OutputFile, Page, PairingTicketCreated, PairingTicketInfo, ServerInfo, Sha256Digest, TemplateList, UsageGroupBy,
    UsageReport, VolumeInfo, WhoAmI,
};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{DeviceId, JobId, JoinTokenId, KeyId, NodeId, PairingTicketId};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;

use crate::error::{ApiError, BuildError, Error, LocalError, NetworkError, UnexpectedResponse, excerpt};
use crate::logs::LogFollow;
use crate::retry::{RetryPolicy, is_retryable_status};
use crate::transfer::{DownloadError, KeyLimits, LogPage, LogSplitter, prepare_destination, validate_remote_path};

/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default timeout of a whole request.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest response body the client reads. A job page is at most a few hundred KiB, so this only stops a
/// misbehaving server from filling the client's memory.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// The header that carries the idempotency key of `POST /v1/jobs`, next to the `idempotency_key` field of the body.
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";
/// The whole-request timeout of an output download. Outputs are up to 1 GiB, so the default 60 s does not apply; a
/// stalled connection is still detected by the per-read timeout of the client.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(3600);
/// The whole-request timeout of a followed log: a day, because a job runs for at most 24 h (spec §7).
pub const FOLLOW_TIMEOUT: Duration = Duration::from_secs(25 * 3600);
/// The slowest upload the server tolerates (H2 §7.5: a floor of 16 KiB/s averaged over a minute). The whole-request
/// timeout of a blob upload is its size at this rate, so a slow link is not cut off by the client before the server
/// would cut it off.
pub const UPLOAD_FLOOR_BYTES_PER_S: u64 = 16 * 1024;
/// The shortest whole-request timeout of a blob upload.
pub const UPLOAD_MIN_TIMEOUT: Duration = Duration::from_secs(600);
/// The longest whole-request timeout of a blob upload: 2 GiB at the floor is 36 hours.
pub const UPLOAD_MAX_TIMEOUT: Duration = Duration::from_secs(48 * 3600);

/// Filters and paging of `GET /v1/jobs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobListParams {
    /// Only jobs in this state.
    pub status: Option<JobStatus>,
    /// Only jobs that ran on this node.
    pub node_id: Option<NodeId>,
    /// Only `batch` or only `service` jobs (H2 §7.2).
    pub kind: Option<JobKind>,
    /// Page size, at most 100.
    pub limit: Option<u32>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// Paging of the other list endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListParams {
    /// Page size, at most 100.
    pub limit: Option<u32>,
    /// The `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// Where a [`ClientBuilder`] sends requests.
#[derive(Debug)]
enum BuilderTarget {
    /// An `http://` or `https://` base URL.
    Url(String),
    /// A server address, through the `p2pc/http/1` tunnel.
    #[cfg(feature = "tunnel")]
    Tunnel(crate::tunnel::Tunnel),
}

/// Builds a [`Client`].
#[derive(Debug)]
pub struct ClientBuilder {
    target: BuilderTarget,
    api_key: ApiKey,
    connect_timeout: Duration,
    request_timeout: Duration,
    retry: RetryPolicy,
    user_agent: String,
}

impl ClientBuilder {
    /// A builder for the server at `base_url` (`https://…` or `http://…`, a path prefix is kept) and `api_key`.
    pub fn new(base_url: impl Into<String>, api_key: ApiKey) -> Self {
        Self {
            target: BuilderTarget::Url(base_url.into()),
            api_key,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            retry: RetryPolicy::default(),
            user_agent: default_user_agent(),
        }
    }

    /// A builder for the server behind `tunnel` (spec §10, option B). Requests, retries, caps and errors are the
    /// same as over TCP; each request goes over its own QUIC stream of the tunnel's one connection. The connect
    /// timeout is the tunnel's own ([`crate::tunnel::TUNNEL_CONNECT_TIMEOUT`]).
    #[cfg(feature = "tunnel")]
    pub fn tunnel(tunnel: crate::tunnel::Tunnel, api_key: ApiKey) -> Self {
        Self {
            target: BuilderTarget::Tunnel(tunnel),
            ..Self::new(String::new(), api_key)
        }
    }

    /// The connect timeout. Default 10 s.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// The timeout of a whole request. Default 60 s.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// The retry policy of repeatable requests. Default: 3 retries with backoff and jitter.
    #[must_use]
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// The `User-Agent`. Default `p2pc/<version>`.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Builds the client.
    pub fn build(self) -> Result<Client, BuildError> {
        let (transport, base) = match self.target {
            BuilderTarget::Url(text) => {
                let base = parse_base_url(&text)?;
                let builder = |read_timeout: bool| -> Result<reqwest::Client, BuildError> {
                    let mut builder = reqwest::Client::builder()
                        .tls_backend_preconfigured(tls_config()?)
                        .user_agent(self.user_agent.clone())
                        .connect_timeout(self.connect_timeout)
                        .timeout(self.request_timeout)
                        // A redirect would re-send the request, and a downgrade from https to http would send the
                        // key in clear text. The server never redirects, so a redirect means a wrong URL: say so
                        // instead of following it.
                        .redirect(reqwest::redirect::Policy::none());
                    if read_timeout {
                        // A stalled body is noticed even for a download that overrides the total timeout.
                        builder = builder.read_timeout(self.request_timeout);
                    }
                    builder
                        .build()
                        .map_err(|e| BuildError::Tls(e.without_url().to_string()))
                };
                // A blob upload waits for the answer for as long as the upload takes; the read timeout of the other
                // calls would cut it off after a minute. Its own whole-request timeout bounds it instead.
                let http = builder(true)?;
                let bulk = builder(false)?;
                (Transport::Http { http, bulk }, base)
            }
            #[cfg(feature = "tunnel")]
            BuilderTarget::Tunnel(tunnel) => (Transport::Tunnel(tunnel), crate::tunnel::base_url()),
        };
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", self.api_key.expose()))
            .map_err(|_| BuildError::Tls("the API key is not a valid header value".into()))?;
        auth.set_sensitive(true);
        let user_agent = HeaderValue::from_str(&self.user_agent)
            .map_err(|_| BuildError::InvalidUrl("the user agent is not a valid header value".into()))?;
        Ok(Client {
            transport,
            base,
            auth,
            user_agent,
            api_key: self.api_key,
            retry: self.retry,
            request_timeout: self.request_timeout,
        })
    }
}

fn default_user_agent() -> String {
    format!("p2pc/{}", env!("CARGO_PKG_VERSION"))
}

fn parse_base_url(text: &str) -> Result<Url, BuildError> {
    let url = Url::parse(text).map_err(|_| BuildError::InvalidUrl("it is not a valid URL".into()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(BuildError::InvalidUrl("it must be an http:// or https:// URL".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        // Credentials in a URL end up in logs and process listings: the key has its own place.
        return Err(BuildError::InvalidUrl(
            "it must not contain a user name or password".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(BuildError::InvalidUrl(
            "it must not contain a query or a fragment".into(),
        ));
    }
    Ok(url)
}

/// rustls with the `ring` provider and the operating system's certificate store.
///
/// No `aws-lc-rs` (it needs CMake and NASM on Windows) and no OpenSSL. The platform verifier reads the OS store, so
/// a server behind a reverse proxy with a private CA works once that CA is installed on the machine.
fn tls_config() -> Result<rustls::ClientConfig, BuildError> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| BuildError::Tls(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| BuildError::Tls(e.to_string()))?
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// How requests reach the server.
#[derive(Clone)]
enum Transport {
    /// HTTP(S) over TCP, with reqwest: `http` for the API, `bulk` for blob uploads.
    Http {
        http: reqwest::Client,
        bulk: reqwest::Client,
    },
    /// HTTP/1.1 over a QUIC stream of the `p2pc/http/1` tunnel.
    #[cfg(feature = "tunnel")]
    Tunnel(crate::tunnel::Tunnel),
}

/// A typed client of the P2PC REST API.
///
/// `Debug` never prints the key or the `Authorization` header (SI-6). Cloning is cheap: the HTTP connection pool, or
/// the tunnel's one connection, is shared.
#[derive(Clone)]
pub struct Client {
    transport: Transport,
    base: Url,
    auth: HeaderValue,
    /// Sent by the tunnel transport; reqwest has its own copy.
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code, reason = "read by the tunnel transport"))]
    user_agent: HeaderValue,
    api_key: ApiKey,
    retry: RetryPolicy,
    /// The tunnel transport's whole-request and read timeout; reqwest has its own copy.
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code, reason = "read by the tunnel transport"))]
    request_timeout: Duration,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Client");
        match &self.transport {
            Transport::Http { .. } => d.field("base", &self.base.as_str()),
            #[cfg(feature = "tunnel")]
            Transport::Tunnel(t) => d.field("tunnel", t),
        };
        d.field("api_key", &self.api_key)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

/// A response whose headers are in and whose body is read as it arrives, from either transport.
pub(crate) struct Response {
    status: StatusCode,
    content_length: Option<u64>,
    /// The `Content-Length` header, whatever the body: the size a `HEAD` answer announces.
    declared_length: Option<u64>,
    body: ResponseBody,
}

enum ResponseBody {
    Http(reqwest::Response),
    #[cfg(feature = "tunnel")]
    Tunnel(crate::tunnel::TunnelBody),
}

impl Response {
    fn from_reqwest(response: reqwest::Response) -> Self {
        let declared_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        Self {
            status: response.status(),
            content_length: response.content_length(),
            declared_length,
            body: ResponseBody::Http(response),
        }
    }

    #[cfg(feature = "tunnel")]
    pub(crate) fn from_tunnel(
        status: StatusCode,
        content_length: Option<u64>,
        body: crate::tunnel::TunnelBody,
    ) -> Self {
        Self {
            status,
            content_length,
            declared_length: content_length,
            body: ResponseBody::Tunnel(body),
        }
    }

    fn status(&self) -> StatusCode {
        self.status
    }

    fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    fn declared_length(&self) -> Option<u64> {
        self.declared_length
    }

    /// The next piece of the body, `None` at its end.
    pub(crate) async fn chunk(&mut self) -> Result<Option<Bytes>, Error> {
        match &mut self.body {
            ResponseBody::Http(r) => r
                .chunk()
                .await
                .map_err(|e| Error::Network(NetworkError::from_reqwest(e))),
            #[cfg(feature = "tunnel")]
            ResponseBody::Tunnel(b) => b.chunk().await.map_err(Error::Network),
        }
    }
}

/// One request, before it is sent.
struct Call<'a> {
    method: Method,
    segments: &'a [&'a str],
    query: Vec<(&'static str, String)>,
    body: Option<Vec<u8>>,
    idempotency_key: Option<&'a str>,
    /// Whether the request may be sent again after a connection error or a `502`/`503`/`504`.
    repeatable: bool,
    /// The response may carry a secret (a new key, a join token): decoding errors never quote it.
    secret_response: bool,
    /// Replaces the client's whole-request timeout (a download streams for longer than a JSON request).
    timeout: Option<Duration>,
    /// The segments are already percent-encoded, one each: they are appended as they are, not encoded again.
    raw_segments: bool,
    /// A file sent as the body, streamed.
    upload: Option<Upload>,
    /// Headers besides the usual ones.
    extra_headers: Vec<(HeaderName, HeaderValue)>,
}

/// A file to stream as a request body.
struct Upload {
    path: PathBuf,
    len: u64,
}

impl<'a> Call<'a> {
    fn get(segments: &'a [&'a str]) -> Self {
        Self {
            method: Method::GET,
            segments,
            query: Vec::new(),
            body: None,
            idempotency_key: None,
            repeatable: true,
            secret_response: false,
            timeout: None,
            raw_segments: false,
            upload: None,
            extra_headers: Vec::new(),
        }
    }

    fn head(segments: &'a [&'a str]) -> Self {
        Self {
            method: Method::HEAD,
            ..Self::get(segments)
        }
    }

    fn post(segments: &'a [&'a str]) -> Self {
        Self {
            method: Method::POST,
            repeatable: false,
            ..Self::get(segments)
        }
    }

    fn delete(segments: &'a [&'a str]) -> Self {
        Self {
            method: Method::DELETE,
            repeatable: false,
            ..Self::get(segments)
        }
    }

    fn json_body<B: Serialize>(mut self, body: &B) -> Result<Self, Error> {
        let bytes = serde_json::to_vec(body)
            .map_err(|_| Error::Unexpected(UnexpectedResponse::new(None, "the request could not be encoded")))?;
        self.body = Some(bytes);
        Ok(self)
    }

    fn query(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.query.push((name, value.into()));
        self
    }

    /// `?attempt=K`, when one is asked for.
    fn attempt(self, attempt: Option<u32>) -> Self {
        match attempt {
            Some(k) => self.query("attempt", k.to_string()),
            None => self,
        }
    }

    fn page(self, limit: Option<u32>, cursor: Option<&str>) -> Self {
        let mut call = self;
        if let Some(limit) = limit {
            call = call.query("limit", limit.to_string());
        }
        if let Some(cursor) = cursor {
            call = call.query("cursor", cursor);
        }
        call
    }
}

impl Client {
    /// A builder for the server at `base_url`.
    pub fn builder(base_url: impl Into<String>, api_key: ApiKey) -> ClientBuilder {
        ClientBuilder::new(base_url, api_key)
    }

    /// A builder for the server behind `tunnel` (spec §10, option B).
    #[cfg(feature = "tunnel")]
    pub fn builder_tunnel(tunnel: crate::tunnel::Tunnel, api_key: ApiKey) -> ClientBuilder {
        ClientBuilder::tunnel(tunnel, api_key)
    }

    /// `GET /v1/whoami`: who the key is.
    pub async fn whoami(&self) -> Result<WhoAmI, Error> {
        self.fetch(Call::get(&["v1", "whoami"])).await
    }

    /// `GET /v1/server`: the server's NodeId, relays, address `p2pc_srv_…` and version.
    pub async fn server_info(&self) -> Result<ServerInfo, Error> {
        self.fetch(Call::get(&["v1", "server"])).await
    }

    /// `POST /v1/jobs`. Always sends an idempotency key: the spec's own, or a generated one. A transient failure is
    /// retried with the **same** key, so a retry never creates a second job.
    pub async fn create_job(&self, spec: &JobSpec) -> Result<Job, Error> {
        let mut spec = spec.clone();
        let key = spec
            .idempotency_key
            .get_or_insert_with(generate_idempotency_key)
            .clone();
        let mut call = Call::post(&["v1", "jobs"]).json_body(&spec)?;
        call.idempotency_key = Some(&key);
        call.repeatable = true;
        self.fetch(call).await
    }

    /// `GET /v1/jobs/{id}`.
    pub async fn get_job(&self, id: &JobId) -> Result<Job, Error> {
        self.fetch(Call::get(&["v1", "jobs", &id.to_string()])).await
    }

    /// `GET /v1/jobs`: one page.
    pub async fn list_jobs(&self, params: &JobListParams) -> Result<Page<Job>, Error> {
        let mut call = Call::get(&["v1", "jobs"]);
        if let Some(status) = params.status {
            call = call.query("status", status.as_str());
        }
        if let Some(node) = &params.node_id {
            call = call.query("node_id", node.to_string());
        }
        if let Some(kind) = params.kind {
            call = call.query("kind", kind.as_str());
        }
        self.fetch(call.page(params.limit, params.cursor.as_deref())).await
    }

    /// `POST /v1/jobs/{id}/cancel`. Idempotent on the server; not retried by the client.
    pub async fn cancel_job(&self, id: &JobId) -> Result<Job, Error> {
        self.fetch(Call::post(&["v1", "jobs", &id.to_string(), "cancel"])).await
    }

    /// `POST /v1/estimate`: can the job run, and what does it reserve? The body is the job spec.
    pub async fn estimate(&self, spec: &JobSpec) -> Result<Estimate, Error> {
        self.fetch(Call::post(&["v1", "estimate"]).json_body(spec)?).await
    }

    /// `GET /v1/nodes`: one page.
    pub async fn list_nodes(&self, params: &ListParams) -> Result<Page<Node>, Error> {
        self.fetch(Call::get(&["v1", "nodes"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `GET /v1/nodes/{id}`.
    pub async fn get_node(&self, id: &NodeId) -> Result<Node, Error> {
        self.fetch(Call::get(&["v1", "nodes", &id.to_string()])).await
    }

    /// `POST /v1/nodes/{id}/drain`: the node accepts no new jobs. Returns the node.
    pub async fn drain_node(&self, id: &NodeId) -> Result<Node, Error> {
        self.fetch(Call::post(&["v1", "nodes", &id.to_string(), "drain"])).await
    }

    /// `POST /v1/nodes/{id}/resume`: the node accepts jobs again. Returns the node.
    pub async fn resume_node(&self, id: &NodeId) -> Result<Node, Error> {
        self.fetch(Call::post(&["v1", "nodes", &id.to_string(), "resume"]))
            .await
    }

    /// `DELETE /v1/nodes/{id}`. Not retried.
    pub async fn delete_node(&self, id: &NodeId) -> Result<(), Error> {
        self.send_ignoring_body(Call::delete(&["v1", "nodes", &id.to_string()]))
            .await
    }

    /// `POST /v1/nodes/join-tokens`. The token is shown once. Not retried.
    pub async fn create_join_token(&self, request: &CreateJoinToken) -> Result<JoinTokenResponse, Error> {
        let mut call = Call::post(&["v1", "nodes", "join-tokens"]).json_body(request)?;
        call.secret_response = true;
        self.fetch(call).await
    }

    /// `GET /v1/nodes/join-tokens`: one page.
    pub async fn list_join_tokens(&self, params: &ListParams) -> Result<Page<JoinTokenInfo>, Error> {
        self.fetch(Call::get(&["v1", "nodes", "join-tokens"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `DELETE /v1/nodes/join-tokens/{id}`: revokes an unused token. Not retried.
    pub async fn revoke_join_token(&self, id: &JoinTokenId) -> Result<(), Error> {
        self.send_ignoring_body(Call::delete(&["v1", "nodes", "join-tokens", &id.to_string()]))
            .await
    }

    /// `POST /v1/keys`. The key is shown once. Not retried. `expires_at` is sent in whole seconds, in UTC
    /// ([`whole_seconds`]): the server refuses a fraction of a second.
    pub async fn create_key(&self, request: &CreateApiKey) -> Result<NewApiKey, Error> {
        let mut request = request.clone();
        request.expires_at = request.expires_at.map(whole_seconds);
        let mut call = Call::post(&["v1", "keys"]).json_body(&request)?;
        call.secret_response = true;
        self.fetch(call).await
    }

    /// `GET /v1/keys`: one page.
    pub async fn list_keys(&self, params: &ListParams) -> Result<Page<ApiKeyInfo>, Error> {
        self.fetch(Call::get(&["v1", "keys"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `DELETE /v1/keys/{id}`: revokes the key. Not retried.
    pub async fn revoke_key(&self, id: &KeyId) -> Result<(), Error> {
        self.send_ignoring_body(Call::delete(&["v1", "keys", id.as_str()]))
            .await
    }

    /// `GET /v1/audit`: one page.
    pub async fn list_audit(&self, params: &ListParams) -> Result<Page<AuditEvent>, Error> {
        self.fetch(Call::get(&["v1", "audit"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `GET /v1/whoami`, read for what the key may do: its scopes, its daily cap and its image allowlist.
    ///
    /// Unlike [`Client::whoami`], it tells a cap that is `null` (the key has none) from a server that does not report
    /// the cap at all ([`KeyLimits::cap_reported`]), which `p2pc mcp` needs to refuse both.
    pub async fn key_limits(&self) -> Result<KeyLimits, Error> {
        let value: serde_json::Value = self.fetch(Call::get(&["v1", "whoami"])).await?;
        KeyLimits::from_whoami(&value).map_err(|what| Error::Unexpected(UnexpectedResponse::new(Some(200), what)))
    }

    /// `GET /v1/jobs/{id}/logs?since_seq=N`, without `follow`: **one page** of the job's log lines.
    ///
    /// - `since_seq` is inclusive: the page starts at the first line with `seq >= since_seq`, and lines before it are
    ///   dropped here even if the server sends them.
    /// - Reading stops once the page holds `max_bytes` of NDJSON (the wire size, newlines included). The first line is
    ///   always returned, so a page makes progress even when one line is over the budget. [`LogPage::more`] says
    ///   that the budget cut the page short.
    /// - A single line over 1 MiB is an error, and so is a stream of more than [`MAX_RESPONSE_BYTES`].
    /// - `attempt` is `?attempt=K`; without it the server answers for the latest attempt.
    pub async fn log_page(
        &self,
        id: &JobId,
        since_seq: u64,
        attempt: Option<u32>,
        max_bytes: usize,
    ) -> Result<LogPage, Error> {
        let id_text = id.to_string();
        let segments = ["v1", "jobs", id_text.as_str(), "logs"];
        let call = Call::get(&segments)
            .query("since_seq", since_seq.to_string())
            .attempt(attempt);
        let mut response = self.open(call).await?;
        let mut splitter = LogSplitter::new(since_seq, max_bytes);
        loop {
            let Some(chunk) = response.chunk().await? else { break };
            if splitter.push(&chunk)? {
                return Ok(splitter.finish());
            }
        }
        splitter.end_of_stream()?;
        Ok(splitter.finish())
    }

    /// `GET /v1/jobs/{id}/outputs`: one page of the output files, with their sizes and SHA-256.
    ///
    /// The answer may be a page (`{items, next_cursor}`, like every list) or a bare array; both are read. `attempt`
    /// is `?attempt=K` (default: the latest attempt).
    pub async fn list_outputs(
        &self,
        id: &JobId,
        attempt: Option<u32>,
        params: &ListParams,
    ) -> Result<Page<OutputFile>, Error> {
        let id_text = id.to_string();
        let segments = ["v1", "jobs", id_text.as_str(), "outputs"];
        let call = Call::get(&segments)
            .attempt(attempt)
            .page(params.limit, params.cursor.as_deref());
        let value: serde_json::Value = self.fetch(call).await?;
        let page = match value {
            serde_json::Value::Array(_) => serde_json::from_value::<Vec<OutputFile>>(value).map(|items| Page {
                items,
                next_cursor: None,
            }),
            other => serde_json::from_value::<Page<OutputFile>>(other),
        };
        page.map_err(|e| {
            Error::Unexpected(UnexpectedResponse::new(
                Some(200),
                format!("the outputs list does not have the documented shape: {e}"),
            ))
        })
    }

    /// Every output file of a job (100 per page), at most `max_items`.
    pub async fn list_all_outputs(
        &self,
        id: &JobId,
        attempt: Option<u32>,
        max_items: usize,
    ) -> Result<Vec<OutputFile>, Error> {
        fetch_all(
            |cursor| async move {
                let params = ListParams {
                    limit: Some(p2pc_proto::api::MAX_PAGE_LIMIT),
                    cursor,
                };
                self.list_outputs(id, attempt, &params).await
            },
            Some(max_items),
        )
        .await
    }

    /// `GET /v1/jobs/{id}/outputs/{path}`, streamed into `sink` and **verified**: the number of bytes must be exactly
    /// `file.size` (more is refused as it arrives, before it is written) and their SHA-256 must be `file.sha256`.
    ///
    /// `file.path` is checked first (SI-9: no `..`, no absolute path, no empty segment, no control characters), and no
    /// request is sent for a path that fails. `attempt` is `?attempt=K` (default: the latest attempt). When this returns an error the sink may already hold bytes of an
    /// unverified file: discard them ([`Client::save_output`] does).
    pub async fn download_output<W>(
        &self,
        id: &JobId,
        attempt: Option<u32>,
        file: &OutputFile,
        sink: &mut W,
    ) -> Result<(), DownloadError>
    where
        W: tokio::io::AsyncWrite + Unpin + ?Sized,
    {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;

        validate_remote_path(&file.path)?;
        let id_text = id.to_string();
        let mut segments = vec!["v1", "jobs", id_text.as_str(), "outputs"];
        segments.extend(file.path.split('/'));
        let mut call = Call::get(&segments).attempt(attempt);
        call.timeout = Some(DOWNLOAD_TIMEOUT);
        let mut response = self.open(call).await?;
        if response.content_length().is_some_and(|n| n > file.size) {
            return Err(DownloadError::SizeMismatch { expected: file.size });
        }
        let mut hasher = Sha256::new();
        let mut received: u64 = 0;
        while let Some(chunk) = response.chunk().await.map_err(DownloadError::Request)? {
            received = received.saturating_add(chunk.len() as u64);
            if received > file.size {
                return Err(DownloadError::SizeMismatch { expected: file.size });
            }
            hasher.update(&chunk);
            sink.write_all(&chunk)
                .await
                .map_err(|e| DownloadError::Io(format!("could not write the output: {e}")))?;
        }
        if received != file.size {
            return Err(DownloadError::SizeMismatch { expected: file.size });
        }
        sink.flush()
            .await
            .map_err(|e| DownloadError::Io(format!("could not write the output: {e}")))?;
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != file.sha256.0 {
            return Err(DownloadError::DigestMismatch {
                path: file.path.clone(),
            });
        }
        Ok(())
    }

    /// Downloads an output file to `root/<file.path>` and returns where it went.
    ///
    /// The destination follows SI-9: the path is validated, no directory on the way may be a symbolic link, and the
    /// bytes go to a temporary file next to it that replaces the destination only after the size and SHA-256 check
    /// out (so a failed download leaves nothing, and an earlier copy is replaced as a whole). If the destination is a
    /// symbolic link, the link is replaced, never followed.
    pub async fn save_output(
        &self,
        id: &JobId,
        attempt: Option<u32>,
        file: &OutputFile,
        root: &Path,
    ) -> Result<PathBuf, DownloadError> {
        self.save_output_with(id, attempt, file, root, true).await
    }

    /// Like [`Client::save_output`], but a file that already exists at the destination (a symbolic link too, even a
    /// dangling one) is never replaced: [`DownloadError::Exists`]. The check and the write are one system call.
    pub async fn save_new_output(
        &self,
        id: &JobId,
        attempt: Option<u32>,
        file: &OutputFile,
        root: &Path,
    ) -> Result<PathBuf, DownloadError> {
        self.save_output_with(id, attempt, file, root, false).await
    }

    async fn save_output_with(
        &self,
        id: &JobId,
        attempt: Option<u32>,
        file: &OutputFile,
        root: &Path,
        replace: bool,
    ) -> Result<PathBuf, DownloadError> {
        let destination = prepare_destination(root, &file.path).await?;
        let temp = destination.with_file_name(format!(".p2pc-part-{}", ulid::Ulid::generate()));
        // From here on the temporary file is removed on every way out, including this future being dropped (a
        // timeout, a cancelled tool call), unless it was verified and renamed into place.
        let mut guard = crate::transfer::PartFile::new(temp.clone());
        let mut out = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .await
            .map_err(|e| DownloadError::Io(format!("could not create a file in the results directory: {e}")))?;
        let result = self.download_output(id, attempt, file, &mut out).await;
        drop(out);
        result?;
        if replace {
            crate::transfer::replace_file(&temp, &destination).await?;
            guard.disarm();
        } else {
            // The guard removes the temporary file; the destination is its own link or copy.
            crate::transfer::place_new_file(&temp, &destination, &file.path).await?;
        }
        Ok(destination)
    }

    /// `GET /v1/jobs/{id}/logs?follow=true&since_seq=N[&attempt=K]`, as a stream of [`LogLine`]s: see [`LogFollow`].
    ///
    /// `since_seq` is inclusive, so a follower that has `seq` 41 asks for 42. Nothing is sent until the first
    /// [`LogFollow::next`].
    #[must_use]
    pub fn follow_logs(&self, id: &JobId, since_seq: u64, attempt: Option<u32>) -> LogFollow {
        LogFollow::new(self.clone(), *id, since_seq, attempt)
    }

    /// Opens the live log stream, body unread. The whole-request timeout is lifted to a day (a job runs for at most
    /// 24 h): the stream is meant to stay open, and a stalled one is noticed by the read timeout.
    pub(crate) async fn open_log_stream(
        &self,
        id: &JobId,
        since_seq: u64,
        attempt: Option<u32>,
    ) -> Result<Response, Error> {
        let id_text = id.to_string();
        let segments = ["v1", "jobs", id_text.as_str(), "logs"];
        let mut call = Call::get(&segments)
            .query("follow", "true")
            .query("since_seq", since_seq.to_string())
            .attempt(attempt);
        call.timeout = Some(FOLLOW_TIMEOUT);
        self.open(call).await
    }

    pub(crate) fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// `GET /v1/usage`: the usage of the caller's project for attempts that ended in `[from, to)`, grouped by
    /// `group_by` (the server's default is per job), one page of groups and the total of the whole range.
    ///
    /// `from` and `to` go out in whole seconds, in UTC ([`whole_seconds`]): the server refuses a fraction. Without
    /// them the server answers for the current UTC day. `cursor` is the previous page's `next_cursor`.
    pub async fn usage(
        &self,
        from: Option<time::OffsetDateTime>,
        to: Option<time::OffsetDateTime>,
        group_by: Option<UsageGroupBy>,
        cursor: Option<&str>,
    ) -> Result<UsageReport, Error> {
        let mut call = Call::get(&["v1", "usage"]);
        for (name, at) in [("from", from), ("to", to)] {
            if let Some(at) = at {
                let text = whole_seconds(at)
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|_| Error::Local(LocalError::new("the time cannot be written")))?;
                call = call.query(name, text);
            }
        }
        if let Some(group_by) = group_by {
            call = call.query(
                "group_by",
                match group_by {
                    UsageGroupBy::Job => "job",
                    UsageGroupBy::Node => "node",
                    UsageGroupBy::Key => "key",
                },
            );
        }
        if let Some(cursor) = cursor {
            call = call.query("cursor", cursor);
        }
        self.fetch(call).await
    }

    /// `POST /v1/nodes/{id}/approve` (H2 §5.5, `admin` only): lets a `pending_approval` node get work. Idempotent on
    /// the server, but not retried by the client: an approval is a decision the user confirmed once. The answer's body,
    /// if any, is not read.
    pub async fn approve_node(&self, id: &NodeId) -> Result<(), Error> {
        self.send_ignoring_body(Call::post(&["v1", "nodes", &id.to_string(), "approve"]))
            .await
    }

    /// `HEAD /v1/blobs/{sha256}` (H2 §7.3): the size of the blob if the caller's account has it, `None` if not.
    pub async fn head_blob(&self, digest: &Sha256Digest) -> Result<Option<u64>, Error> {
        let text = digest.to_string();
        let segments = ["v1", "blobs", text.as_str()];
        match self.open(Call::head(&segments)).await {
            // The answer to a `HEAD` has no body to read: only its headers matter.
            Ok(response) => Ok(Some(response.declared_length().ok_or_else(|| {
                Error::Unexpected(UnexpectedResponse::new(
                    Some(response.status().as_u16()),
                    "the answer has no Content-Length",
                ))
            })?)),
            Err(Error::Api(e)) if e.status == 404 => Ok(None),
            // A `HEAD` answer has no problem document: a bare 404 is "not there".
            Err(Error::Unexpected(e)) if e.status == Some(404) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `POST /v1/blobs` (H2 §7.5): uploads the file at `path`, which has `size` bytes and the SHA-256 `digest`.
    ///
    /// The file is streamed, never held in memory. `Content-Length` and `X-P2PC-SHA256` are required by the server
    /// before it reads the body, so the caller measures and hashes the file first; a file that is not `size` bytes
    /// any more is refused here before anything is sent, and one that changes while it is sent is refused by the
    /// server (`422 digest_mismatch`). Not retried.
    pub async fn put_blob(&self, path: &Path, digest: &Sha256Digest, size: u64) -> Result<BlobUploaded, Error> {
        let meta = tokio::fs::metadata(path)
            .await
            .map_err(|e| Error::Local(LocalError::new(format!("cannot read the file: {e}"))))?;
        if !meta.is_file() || meta.len() != size {
            return Err(Error::Local(LocalError::new(
                "the file is not a regular file of the size that was measured; it changed while it was prepared",
            )));
        }
        let mut call = Call::post(&["v1", "blobs"]);
        call.upload = Some(Upload {
            path: path.to_path_buf(),
            len: size,
        });
        let hex = HeaderValue::from_str(&digest.to_string())
            .map_err(|_| Error::Local(LocalError::new("the digest is not a valid header value")))?;
        call.extra_headers
            .push((HeaderName::from_static(p2pc_proto::api::BLOB_SHA256_HEADER), hex));
        let floor = Duration::from_secs(size / UPLOAD_FLOOR_BYTES_PER_S);
        call.timeout = Some(floor.clamp(UPLOAD_MIN_TIMEOUT, UPLOAD_MAX_TIMEOUT));
        self.fetch(call).await
    }

    /// `GET /v1/blobs`: one page of the account's blobs, with its stored total and quota.
    pub async fn list_blobs(&self, params: &ListParams) -> Result<BlobList, Error> {
        self.fetch(Call::get(&["v1", "blobs"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `DELETE /v1/blobs/{sha256}`: removes the caller's claim on the blob. Not retried.
    pub async fn delete_blob(&self, digest: &Sha256Digest) -> Result<(), Error> {
        let text = digest.to_string();
        self.send_ignoring_body(Call::delete(&["v1", "blobs", text.as_str()]))
            .await
    }

    /// `GET /v1/volumes`: one page.
    pub async fn list_volumes(&self, params: &ListParams) -> Result<Page<VolumeInfo>, Error> {
        self.fetch(Call::get(&["v1", "volumes"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `DELETE /v1/volumes/{node_id}/{name}` (H2 §7.3). Not retried.
    ///
    /// `name` is sent as **one** percent-encoded path segment: a template volume `tpl:private-chat/models` goes out
    /// as `tpl%3Aprivate-chat%2Fmodels`, and nothing in a name can add a segment or a query.
    pub async fn delete_volume(&self, node: &NodeId, name: &str) -> Result<(), Error> {
        let (node, name) = (node.to_string(), encode_segment(name));
        let segments = ["v1", "volumes", node.as_str(), name.as_str()];
        let mut call = Call::delete(&segments);
        call.raw_segments = true;
        self.send_ignoring_body(call).await
    }

    /// `GET /v1/templates` (H2 §7.6): the loaded bundle, or an empty list and `bundle_error`.
    pub async fn list_templates(&self) -> Result<TemplateList, Error> {
        self.fetch(Call::get(&["v1", "templates"])).await
    }

    /// `POST /v1/templates/{id}/launch` (H2 §7.6). Like a job submission, it always carries an idempotency key (the
    /// caller's or a generated one), and a transient failure is retried with the same key, so a retry never starts a
    /// second instance.
    pub async fn launch_template(&self, id: &str, launch: &LaunchTemplate) -> Result<TemplateLaunch, Error> {
        let mut launch = launch.clone();
        launch.idempotency_key.get_or_insert_with(generate_idempotency_key);
        let id = encode_segment(id);
        let segments = ["v1", "templates", id.as_str(), "launch"];
        let mut call = Call::post(&segments).json_body(&launch)?;
        call.raw_segments = true;
        call.repeatable = true;
        let (status, job) = self.fetch_with_status(call).await?;
        Ok(TemplateLaunch {
            job,
            existing: status == StatusCode::OK,
        })
    }

    /// `POST /v1/devices/pairing-tickets` (H2 §5.2, `admin` only). The ticket and its URL are shown once. Not retried.
    pub async fn create_pairing_ticket(&self, request: &CreatePairingTicket) -> Result<PairingTicketCreated, Error> {
        let mut call = Call::post(&["v1", "devices", "pairing-tickets"]).json_body(request)?;
        call.secret_response = true;
        self.fetch(call).await
    }

    /// `GET /v1/devices/pairing-tickets`: one page.
    pub async fn list_pairing_tickets(&self, params: &ListParams) -> Result<Page<PairingTicketInfo>, Error> {
        self.fetch(Call::get(&["v1", "devices", "pairing-tickets"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `DELETE /v1/devices/pairing-tickets/{id}`: revokes an unused ticket. Not retried.
    pub async fn revoke_pairing_ticket(&self, id: &PairingTicketId) -> Result<(), Error> {
        self.send_ignoring_body(Call::delete(&["v1", "devices", "pairing-tickets", &id.to_string()]))
            .await
    }

    /// `GET /v1/devices`: one page. For a device that is not `admin`, the page is that device alone.
    pub async fn list_devices(&self, params: &ListParams) -> Result<Page<DeviceInfo>, Error> {
        self.fetch(Call::get(&["v1", "devices"]).page(params.limit, params.cursor.as_deref()))
            .await
    }

    /// `GET /v1/devices/{id}`.
    pub async fn get_device(&self, id: &DeviceId) -> Result<DeviceInfo, Error> {
        self.fetch(Call::get(&["v1", "devices", &id.to_string()])).await
    }

    /// `DELETE /v1/devices/{id}`: revokes the device. Not retried.
    pub async fn revoke_device(&self, id: &DeviceId) -> Result<(), Error> {
        self.send_ignoring_body(Call::delete(&["v1", "devices", &id.to_string()]))
            .await
    }

    /// `POST /v1/jobs/{id}/ports/{port}/connect` (H2 §7.4): an HTTP/1.1 upgrade to `p2pc-port/1`, after which the
    /// connection is a raw, bidirectional byte stream into the service's `port`.
    ///
    /// `wait_ready` adds `?wait_ready=true`: the hub waits up to 30 s for a `starting` service instead of answering
    /// `409 service_not_ready`. A refusal before the upgrade is the hub's error (`404`, `409`, `422`, `429`, `502`); an
    /// answer that is neither a refusal nor `101` is an [`UnexpectedResponse`], never a stream. Not retried: every
    /// call is a connection the user asked for.
    pub async fn open_port(&self, job: &JobId, port: u32, wait_ready: bool) -> Result<PortStream, Error> {
        let (job, port) = (job.to_string(), port.to_string());
        let segments = ["v1", "jobs", job.as_str(), "ports", port.as_str(), "connect"];
        let mut call = Call::post(&segments);
        if wait_ready {
            call = call.query("wait_ready", "true");
        }
        call.extra_headers.push((
            HeaderName::from_static("connection"),
            HeaderValue::from_static("Upgrade"),
        ));
        call.extra_headers.push((
            HeaderName::from_static("upgrade"),
            HeaderValue::from_static(PORT_UPGRADE_PROTOCOL),
        ));
        let url = self.url(&call);
        let headers = self.headers(&call)?;
        let response = match &self.transport {
            Transport::Http { http, .. } => {
                let response = http
                    .request(call.method.clone(), url)
                    .headers(headers)
                    .send()
                    .await
                    .map_err(|e| Error::Network(NetworkError::from_reqwest(e)))?;
                if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                    let upgraded = response
                        .upgrade()
                        .await
                        .map_err(|e| Error::Network(NetworkError::from_reqwest(e)))?;
                    return Ok(PortStream::http(upgraded));
                }
                Response::from_reqwest(response)
            }
            #[cfg(feature = "tunnel")]
            Transport::Tunnel(tunnel) => {
                let mut headers = headers;
                headers.insert(reqwest::header::USER_AGENT, self.user_agent.clone());
                let request = crate::tunnel::TunnelRequest {
                    method: call.method.clone(),
                    path_and_query: &url[url::Position::BeforePath..],
                    headers,
                    body: None,
                    upload: None,
                    timeout: self.request_timeout,
                    read_timeout: self.request_timeout,
                };
                match tunnel.upgrade(request).await? {
                    crate::tunnel::Upgrade::Upgraded(stream) => return Ok(PortStream::tunnel(stream)),
                    crate::tunnel::Upgrade::Refused(response) => response,
                }
            }
        };
        let status = response.status();
        if status.is_success() {
            // A proxy's page, or a hub that does not know the route: not a stream into a service.
            return Err(Error::Unexpected(UnexpectedResponse::new(
                Some(status.as_u16()),
                "the server did not switch protocols; it is not a P2PC hub that serves service ports",
            )));
        }
        let body = read_body(response).await?;
        Err(error_from_response(status, &body))
    }

    async fn fetch<T: DeserializeOwned>(&self, call: Call<'_>) -> Result<T, Error> {
        self.fetch_with_status(call).await.map(|(_, value)| value)
    }

    /// Like [`Client::fetch`], and the status of the `2xx` too (a template launch answers `200` or `201`).
    async fn fetch_with_status<T: DeserializeOwned>(&self, call: Call<'_>) -> Result<(StatusCode, T), Error> {
        let secret = call.secret_response;
        let (status, body) = self.send(call).await?;
        let value = serde_json::from_slice(&body).map_err(|e| {
            let what = if secret {
                // The body holds a secret: say where it went wrong, never what it said.
                format!(
                    "the response does not have the documented shape (line {}, column {})",
                    e.line(),
                    e.column()
                )
            } else {
                format!("the response does not have the documented shape: {e}")
            };
            Error::Unexpected(UnexpectedResponse::new(Some(status.as_u16()), what))
        })?;
        Ok((status, value))
    }

    async fn send_ignoring_body(&self, call: Call<'_>) -> Result<(), Error> {
        self.send(call).await.map(|_| ())
    }

    /// Sends the request, retrying what may be retried, and returns the body of a `2xx`.
    async fn send(&self, call: Call<'_>) -> Result<(StatusCode, Vec<u8>), Error> {
        let url = self.url(&call);
        let max_retries = if call.repeatable { self.retry.max_retries } else { 0 };
        let mut retry = 0;
        loop {
            let outcome = self.send_once(&url, &call).await;
            let retryable = match &outcome {
                Ok((status, _)) => is_retryable_status(status.as_u16()),
                Err(e) => is_retryable_error(e),
            };
            if !retryable || retry >= max_retries {
                return outcome;
            }
            tokio::time::sleep(self.retry.delay(retry)).await;
            retry += 1;
        }
    }

    fn url(&self, call: &Call<'_>) -> Url {
        let mut url = self.base.clone();
        if call.raw_segments {
            // Already encoded, one segment each: `set_path` keeps the `%XX` sequences as they are.
            let mut path = url.path().trim_end_matches('/').to_string();
            for segment in call.segments {
                path.push('/');
                path.push_str(segment);
            }
            url.set_path(&path);
        } else if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty().extend(call.segments);
        }
        if !call.query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(call.query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        url
    }

    async fn send_once(&self, url: &Url, call: &Call<'_>) -> Result<(StatusCode, Vec<u8>), Error> {
        let response = self.start(url, call).await?;
        let status = response.status();
        let body = read_body(response).await?;
        Ok((status, body))
    }

    /// The headers of a request: the key (marked sensitive), what is accepted, and the idempotency key and content
    /// type when there are. A value that cannot be sent is a [`LocalError`], which never quotes it.
    fn headers(&self, call: &Call<'_>) -> Result<HeaderMap, Error> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.auth.clone());
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, application/problem+json"),
        );
        if let Some(key) = call.idempotency_key {
            let value = HeaderValue::from_str(key)
                .map_err(|_| LocalError::new("the idempotency key is not a valid header value"))?;
            headers.insert(HeaderName::from_static("idempotency-key"), value);
        }
        if call.body.is_some() {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        if let Some(upload) = &call.upload {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            headers.insert(reqwest::header::CONTENT_LENGTH, HeaderValue::from(upload.len));
        }
        for (name, value) in &call.extra_headers {
            headers.insert(name.clone(), value.clone());
        }
        Ok(headers)
    }

    /// Sends the request and returns the response of a `2xx`, body unread. A non-`2xx` answer is read (bounded) and
    /// turned into the error it is.
    async fn start(&self, url: &Url, call: &Call<'_>) -> Result<Response, Error> {
        let headers = self.headers(call)?;
        let response = match &self.transport {
            Transport::Http { http, bulk } => {
                let http = if call.upload.is_some() { bulk } else { http };
                let mut request = http.request(call.method.clone(), url.clone()).headers(headers);
                if let Some(timeout) = call.timeout {
                    request = request.timeout(timeout);
                }
                if let Some(body) = &call.body {
                    request = request.body(body.clone());
                }
                if let Some(upload) = &call.upload {
                    request = request.body(reqwest::Body::wrap(open_upload(upload).await?));
                }
                let response = request.send().await.map_err(|e| {
                    if e.is_builder() {
                        // Nothing was sent: retrying cannot help, and it is not the network's fault.
                        Error::Local(LocalError::new("the request is not valid"))
                    } else {
                        Error::Network(NetworkError::from_reqwest(e))
                    }
                })?;
                Response::from_reqwest(response)
            }
            #[cfg(feature = "tunnel")]
            Transport::Tunnel(tunnel) => {
                let mut headers = headers;
                headers.insert(reqwest::header::USER_AGENT, self.user_agent.clone());
                let request = crate::tunnel::TunnelRequest {
                    method: call.method.clone(),
                    path_and_query: &url[url::Position::BeforePath..],
                    headers,
                    body: call.body.clone(),
                    upload: match &call.upload {
                        Some(upload) => Some(open_upload(upload).await?),
                        None => None,
                    },
                    timeout: call.timeout.unwrap_or(self.request_timeout),
                    read_timeout: self.request_timeout,
                };
                tunnel.send(request).await?
            }
        };
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = read_body(response).await?;
        Err(error_from_response(status, &body))
    }

    /// Like [`Client::send`], but hands back the response so that the caller reads the body as it arrives. Retries
    /// the same way (only until the headers of a `2xx` are in).
    async fn open(&self, call: Call<'_>) -> Result<Response, Error> {
        let url = self.url(&call);
        let max_retries = if call.repeatable { self.retry.max_retries } else { 0 };
        let mut retry = 0;
        loop {
            let outcome = self.start(&url, &call).await;
            let retryable = match &outcome {
                Ok(_) => false,
                Err(e) => is_retryable_error(e),
            };
            if !retryable || retry >= max_retries {
                return outcome;
            }
            tokio::time::sleep(self.retry.delay(retry)).await;
            retry += 1;
        }
    }
}

/// Whether a failed attempt may be sent again: a network error, or a `502`/`503`/`504`. A [`LocalError`] never is.
fn is_retryable_error(e: &Error) -> bool {
    match e {
        Error::Network(_) => true,
        Error::Api(e) => is_retryable_status(e.status),
        Error::Unexpected(e) => e.status.is_some_and(is_retryable_status),
        Error::Local(_) => false,
    }
}

/// Reads a whole body, up to [`MAX_RESPONSE_BYTES`].
async fn read_body(mut response: Response) -> Result<Vec<u8>, Error> {
    let status = response.status();
    let declared = response.content_length().and_then(|n| usize::try_from(n).ok());
    if declared.is_some_and(|n| n > MAX_RESPONSE_BYTES) {
        return Err(too_large(status));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(too_large(status));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn too_large(status: StatusCode) -> Error {
    Error::Unexpected(UnexpectedResponse::new(
        Some(status.as_u16()),
        format!("the response is larger than {MAX_RESPONSE_BYTES} bytes"),
    ))
}

/// Turns a non-`2xx` answer into an [`ApiError`] when the body is a problem document, and into an
/// [`UnexpectedResponse`] otherwise (a proxy's HTML page, a redirect).
fn error_from_response(status: StatusCode, body: &[u8]) -> Error {
    if status.is_redirection() {
        return Error::Unexpected(UnexpectedResponse::new(
            Some(status.as_u16()),
            "the server redirected the request; check the server URL (http or https, and the path)",
        ));
    }
    match serde_json::from_slice::<p2pc_proto::api::Problem>(body) {
        Ok(problem) => Error::Api(ApiError::from_problem(status.as_u16(), problem)),
        Err(_) => {
            let shown = excerpt(body);
            let message = if shown.is_empty() {
                "the error has no body".to_string()
            } else {
                format!("the error is not a problem document: {shown}")
            };
            Error::Unexpected(UnexpectedResponse::new(Some(status.as_u16()), message))
        }
    }
}

/// `at` in UTC, without its fraction of a second (rounded down, so an expiry is never later than asked).
///
/// The server stores instants as Unix seconds and refuses a timestamp with a fraction (`422`), so every timestamp the
/// client sends goes through this. A real clock always has a fraction.
#[must_use]
pub fn whole_seconds(at: time::OffsetDateTime) -> time::OffsetDateTime {
    let utc = at.to_offset(time::UtcOffset::UTC);
    utc.replace_nanosecond(0).unwrap_or(utc)
}

/// A fresh idempotency key: `p2pc-` and a ULID. 31 characters, well under the 255 the server accepts.
#[must_use]
pub fn generate_idempotency_key() -> String {
    format!("p2pc-{}", ulid::Ulid::generate())
}

/// The `Upgrade` protocol of a service port connection (H2 §7.4).
pub const PORT_UPGRADE_PROTOCOL: &str = "p2pc-port/1";

/// The answer of [`Client::launch_template`].
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateLaunch {
    /// The job: the instance that was started, or the one that was already running.
    pub job: Job,
    /// `true` when the hub answered `200` with the running instance of a `singleton` template instead of starting a
    /// new one (H2 §7.6).
    pub existing: bool,
}

/// An upgraded connection into a service port: raw bytes both ways (H2 §7.4). Dropping it closes the connection.
pub struct PortStream {
    inner: PortInner,
}

enum PortInner {
    Http(reqwest::Upgraded),
    #[cfg(feature = "tunnel")]
    Tunnel(hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>),
}

impl fmt::Debug for PortStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortStream").finish_non_exhaustive()
    }
}

impl PortStream {
    fn http(upgraded: reqwest::Upgraded) -> Self {
        Self {
            inner: PortInner::Http(upgraded),
        }
    }

    #[cfg(feature = "tunnel")]
    pub(crate) fn tunnel(upgraded: hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>) -> Self {
        Self {
            inner: PortInner::Tunnel(upgraded),
        }
    }
}

impl tokio::io::AsyncRead for PortStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.inner {
            PortInner::Http(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tunnel")]
            PortInner::Tunnel(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for PortStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut self.inner {
            PortInner::Http(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tunnel")]
            PortInner::Tunnel(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.inner {
            PortInner::Http(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tunnel")]
            PortInner::Tunnel(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.inner {
            PortInner::Http(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tunnel")]
            PortInner::Tunnel(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Opens the file of an upload for streaming.
async fn open_upload(upload: &Upload) -> Result<crate::upload::FileBody, Error> {
    let file = tokio::fs::File::open(&upload.path)
        .await
        .map_err(|e| Error::Local(LocalError::new(format!("cannot read the file: {e}"))))?;
    Ok(crate::upload::FileBody::new(file, upload.len))
}

/// Percent-encodes one path segment: everything except the unreserved characters (`A-Z a-z 0-9 - . _ ~`) is
/// written as `%XX`, so a `/`, `?`, `#`, `:` or `%` in a name stays inside its segment. A segment of only dots is
/// encoded too, because `.` and `..` would otherwise mean "this directory" and "the parent".
fn encode_segment(segment: &str) -> String {
    let only_dots = !segment.is_empty() && segment.bytes().all(|b| b == b'.');
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') || (byte == b'.' && !only_dots) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Walks a cursor-paginated list to the end.
///
/// `fetch` gets the cursor of the page to load (`None` for the first) and returns that page. The walk stops after
/// `max_items` items if given, and fails instead of looping when a server hands back a cursor it already gave.
pub async fn fetch_all<T, F, Fut>(mut fetch: F, max_items: Option<usize>) -> Result<Vec<T>, Error>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<Page<T>, Error>>,
{
    /// A list with more pages than this is a broken server, not a big account.
    const MAX_PAGES: usize = 10_000;
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..MAX_PAGES {
        let page = fetch(cursor.clone()).await?;
        items.extend(page.items);
        if let Some(max) = max_items
            && items.len() >= max
        {
            items.truncate(max);
            return Ok(items);
        }
        match page.next_cursor {
            None => return Ok(items),
            Some(next) => {
                if !seen.insert(next.clone()) {
                    return Err(Error::Unexpected(UnexpectedResponse::new(
                        None,
                        "the server returned the same page cursor twice",
                    )));
                }
                cursor = Some(next);
            }
        }
    }
    Err(Error::Unexpected(UnexpectedResponse::new(
        None,
        "the list has too many pages",
    )))
}
