// SPDX-License-Identifier: AGPL-3.0-only

//! `server.toml`: the server configuration.
//!
//! Unknown keys are an error (`deny_unknown_fields`), so a typo never silently falls back to a default. The file is
//! validated as a whole when it is loaded, and every problem is reported at once.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use p2pc_proto::auth::MAX_RELAYS;
use p2pc_proto::net::DirectAddresses;
use p2pc_proto::protocol::{AGENT_LEASE_TTL_MARGIN_S, DEFAULT_HEARTBEAT_INTERVAL_S, DEFAULT_LEASE_TTL_S};
use p2pc_proto::validate::{DEFAULT_ALLOWED_REGISTRIES, ImageRef};
use serde::{Deserialize, Serialize};

/// Name of the config file inside the data dir.
pub const CONFIG_FILE: &str = "server.toml";
/// Name of the SQLite database inside the data dir.
pub const DB_FILE: &str = "p2pc.db";
/// Default listen address: loopback only.
pub const DEFAULT_BIND: &str = "127.0.0.1:7477";
/// Default units charged per GPU-hour (spec §11).
pub const DEFAULT_GPU_HOUR_UNITS: u32 = 10;
/// Largest accepted `gpu_hour_units`.
pub const MAX_GPU_HOUR_UNITS: u32 = 1_000_000;

/// The server configuration (`server.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the REST API listens on.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// Data directory: database, keys, logs and artifacts. Must be absolute.
    pub data_dir: PathBuf,
    /// Registries a job image may come from (spec §7).
    #[serde(default = "default_registries")]
    pub allowed_registries: Vec<String>,
    /// Units charged per GPU-hour (spec §11).
    #[serde(default = "default_gpu_hour_units")]
    pub gpu_hour_units: u32,
    /// The iroh endpoint (spec §10).
    #[serde(default)]
    pub iroh: IrohConfig,
    /// Node liveness and agent compatibility (spec §6).
    #[serde(default)]
    pub nodes: NodesConfig,
    /// The scheduler (spec §8).
    #[serde(default)]
    pub scheduler: SchedulerConfig,
    /// Logging.
    #[serde(default)]
    pub log: LogConfig,
    /// Connection limits for slow clients (spec §10 "Slow clients").
    #[serde(default)]
    pub http: HttpConfig,
    /// Logs and artifacts (spec §12).
    #[serde(default)]
    pub storage: StorageConfig,
}

/// The `[storage]` table: logs and artifacts (spec §12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Days the logs and artifacts of a finished job are kept before the GC deletes them (default 7). The job and
    /// its rows stay.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

/// Default `storage.retention_days` (§12).
pub const DEFAULT_RETENTION_DAYS: u32 = 7;
/// Largest `storage.retention_days` (ten years).
pub const MAX_RETENTION_DAYS: u32 = 3650;

fn default_retention_days() -> u32 {
    DEFAULT_RETENTION_DAYS
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

impl StorageConfig {
    /// The retention period.
    #[must_use]
    pub fn retention(&self) -> time::Duration {
        time::Duration::days(i64::from(self.retention_days))
    }

    fn problems(&self, out: &mut Vec<String>) {
        if !(1..=MAX_RETENTION_DAYS).contains(&self.retention_days) {
            out.push(format!("storage.retention_days must be 1-{MAX_RETENTION_DAYS}"));
        }
    }
}

/// The `[iroh]` table: the server's iroh endpoint (spec §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrohConfig {
    /// Relay URLs. Empty (the default) means n0's public relays, which are meant for development; production sets
    /// its own (`iroh-relay`). They are also the relay hints of join tokens and of the server address.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Which local addresses the endpoint binds and advertises: `"default-route"` (the default), `"none"` (relay
    /// only) or a list of CIDRs. CGNAT, link-local and container or VM bridges are never used (§10).
    #[serde(default)]
    pub direct_addresses: DirectAddresses,
    /// Most `p2pc/http/1` streams at once, in total (§10 "Tunnel budget": 128 by default). Each stream holds one
    /// REST connection, so it must stay **below** `http.max_connections`: anonymous tunnel peers (NodeIds cost
    /// nothing) can then never take every REST slot and lock out local clients.
    #[serde(default = "default_tunnel_max_streams")]
    pub tunnel_max_streams: u32,
}

/// The top-level key T03 had and T05 moved under `[iroh]`.
const LEGACY_RELAYS_KEY: &str = "relays";
/// The error for [`LEGACY_RELAYS_KEY`].
pub const LEGACY_RELAYS_MESSAGE: &str = "`relays` moved under `[iroh]` in T05; move it there";

/// Default `iroh.tunnel_max_streams` (§10 "Tunnel budget").
pub const DEFAULT_TUNNEL_MAX_STREAMS: u32 = 128;

fn default_tunnel_max_streams() -> u32 {
    DEFAULT_TUNNEL_MAX_STREAMS
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            direct_addresses: DirectAddresses::default(),
            tunnel_max_streams: DEFAULT_TUNNEL_MAX_STREAMS,
        }
    }
}

/// The `[nodes]` table: node liveness and agent compatibility (spec §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodesConfig {
    /// A node with no heartbeat for this long becomes `offline` and its leases expire (§6, default 60).
    #[serde(default = "default_lease_ttl_s")]
    pub lease_ttl_s: u32,
    /// How often agents heartbeat (sent in `Welcome`, default 5).
    #[serde(default = "default_heartbeat_interval_s")]
    pub heartbeat_interval_s: u32,
    /// Agents older than this (semver) get `agent_too_old` (default `0.1.0`).
    #[serde(default = "default_min_agent_version")]
    pub min_agent_version: String,
}

/// Default `nodes.min_agent_version`.
pub const DEFAULT_MIN_AGENT_VERSION: &str = "0.1.0";
/// Largest `nodes.lease_ttl_s` (one day).
pub const MAX_LEASE_TTL_S: u32 = 86_400;

fn default_lease_ttl_s() -> u32 {
    DEFAULT_LEASE_TTL_S
}
fn default_heartbeat_interval_s() -> u32 {
    DEFAULT_HEARTBEAT_INTERVAL_S
}
fn default_min_agent_version() -> String {
    DEFAULT_MIN_AGENT_VERSION.to_string()
}

impl Default for NodesConfig {
    fn default() -> Self {
        Self {
            lease_ttl_s: default_lease_ttl_s(),
            heartbeat_interval_s: default_heartbeat_interval_s(),
            min_agent_version: default_min_agent_version(),
        }
    }
}

impl NodesConfig {
    /// The parsed `min_agent_version`. Validated at load, so a loaded config always has one; `0.0.0` otherwise.
    #[must_use]
    pub fn min_agent_version(&self) -> semver::Version {
        semver::Version::parse(&self.min_agent_version).unwrap_or_else(|_| semver::Version::new(0, 0, 0))
    }

    fn problems(&self, out: &mut Vec<String>) {
        if !(1..=3600).contains(&self.heartbeat_interval_s) {
            out.push("nodes.heartbeat_interval_s must be 1-3600".to_string());
        }
        // Two heartbeats at least fit in the TTL, and the agent can keep its SI-13 margin
        // (`agent_lease_ttl_s + 10 <= lease_ttl_s`) with a positive timer of its own.
        let min = (self.heartbeat_interval_s.saturating_mul(2)).max(AGENT_LEASE_TTL_MARGIN_S + 1);
        if !(min..=MAX_LEASE_TTL_S).contains(&self.lease_ttl_s) {
            out.push(format!(
                "nodes.lease_ttl_s must be {min}-{MAX_LEASE_TTL_S} (at least twice heartbeat_interval_s and more \
                 than {AGENT_LEASE_TTL_MARGIN_S})"
            ));
        }
        if semver::Version::parse(&self.min_agent_version).is_err() {
            out.push(format!(
                "nodes.min_agent_version = {:?} is not a semver version such as 0.1.0",
                self.min_agent_version
            ));
        }
    }
}

/// The `[scheduler]` table (spec §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerConfig {
    /// The image pull budget of §8 "Timeouts": a job still `assigned` (accepted, not started) becomes `timed_out`
    /// at `pull_timeout_s + timeout_s + 60` seconds after acceptance (default 600).
    #[serde(default = "default_pull_timeout_s")]
    pub pull_timeout_s: u32,
}

/// Default `scheduler.pull_timeout_s`.
pub const DEFAULT_PULL_TIMEOUT_S: u32 = 600;
/// Largest `scheduler.pull_timeout_s` (one day).
pub const MAX_PULL_TIMEOUT_S: u32 = 86_400;

fn default_pull_timeout_s() -> u32 {
    DEFAULT_PULL_TIMEOUT_S
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            pull_timeout_s: DEFAULT_PULL_TIMEOUT_S,
        }
    }
}

impl SchedulerConfig {
    fn problems(&self, out: &mut Vec<String>) {
        if !(1..=MAX_PULL_TIMEOUT_S).contains(&self.pull_timeout_s) {
            out.push(format!("scheduler.pull_timeout_s must be 1-{MAX_PULL_TIMEOUT_S}"));
        }
    }
}

/// The `[http]` table: limits that keep slow or idle clients from holding the server (spec §10 "Slow clients").
/// Durations are in milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    /// Most connections open at once; further clients wait in the listen backlog.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Time to read a request's headers, counted from its first byte (or from the accept, for a new connection).
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    /// Time to read a request's body.
    #[serde(default = "default_body_read_timeout_ms")]
    pub body_read_timeout_ms: u64,
    /// Time for a whole request, from its headers to its response. Streaming routes (logs, output downloads) opt out
    /// and use `keepalive_idle_ms` as their idle limit instead.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Idle time allowed on a keep-alive connection between two requests.
    #[serde(default = "default_keepalive_idle_ms")]
    pub keepalive_idle_ms: u64,
}

/// Default `http.max_connections` (§10).
pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;
/// Largest `http.max_connections`.
pub const MAX_MAX_CONNECTIONS: u32 = 65_536;
/// Largest value of any `http.*_ms` limit (one hour).
pub const MAX_HTTP_TIMEOUT_MS: u64 = 3_600_000;

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}
fn default_header_read_timeout_ms() -> u64 {
    10_000
}
fn default_body_read_timeout_ms() -> u64 {
    30_000
}
fn default_request_timeout_ms() -> u64 {
    30_000
}
fn default_keepalive_idle_ms() -> u64 {
    60_000
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            header_read_timeout_ms: default_header_read_timeout_ms(),
            body_read_timeout_ms: default_body_read_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            keepalive_idle_ms: default_keepalive_idle_ms(),
        }
    }
}

impl HttpConfig {
    /// The header read limit.
    #[must_use]
    pub fn header_read_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.header_read_timeout_ms)
    }
    /// The body read limit.
    #[must_use]
    pub fn body_read_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.body_read_timeout_ms)
    }
    /// The whole-request limit.
    #[must_use]
    pub fn request_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.request_timeout_ms)
    }
    /// The keep-alive idle limit.
    #[must_use]
    pub fn keepalive_idle(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.keepalive_idle_ms)
    }

    fn problems(&self, out: &mut Vec<String>) {
        if !(1..=MAX_MAX_CONNECTIONS).contains(&self.max_connections) {
            out.push(format!("http.max_connections must be 1-{MAX_MAX_CONNECTIONS}"));
        }
        for (name, ms) in [
            ("http.header_read_timeout_ms", self.header_read_timeout_ms),
            ("http.body_read_timeout_ms", self.body_read_timeout_ms),
            ("http.request_timeout_ms", self.request_timeout_ms),
            ("http.keepalive_idle_ms", self.keepalive_idle_ms),
        ] {
            if !(1..=MAX_HTTP_TIMEOUT_MS).contains(&ms) {
                out.push(format!("{name} must be 1-{MAX_HTTP_TIMEOUT_MS} milliseconds"));
            }
        }
    }
}

/// The `[log]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// A `tracing` filter, for example `info` or `p2pc_server=debug,info`. `RUST_LOG` overrides it.
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 7477))
}

fn default_registries() -> Vec<String> {
    DEFAULT_ALLOWED_REGISTRIES.iter().map(|s| (*s).to_string()).collect()
}

fn default_gpu_hour_units() -> u32 {
    DEFAULT_GPU_HOUR_UNITS
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Why a config cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file cannot be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The file is not valid TOML for a [`Config`].
    #[error("invalid config file {path}: {message}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// What is wrong, from the TOML parser.
        message: String,
    },
    /// The values are not acceptable.
    #[error("invalid config file {path}:\n  - {}", .problems.join("\n  - "))]
    Invalid {
        /// The file.
        path: PathBuf,
        /// Every problem found.
        problems: Vec<String>,
    },
}

impl Config {
    /// The default config for a data dir.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            bind: default_bind(),
            data_dir,
            allowed_registries: default_registries(),
            gpu_hour_units: DEFAULT_GPU_HOUR_UNITS,
            iroh: IrohConfig::default(),
            nodes: NodesConfig::default(),
            scheduler: SchedulerConfig::default(),
            log: LogConfig::default(),
            http: HttpConfig::default(),
            storage: StorageConfig::default(),
        }
    }

    /// Reads, parses and validates a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text, path)
    }

    /// Parses and validates config text. `path` is only used in error messages.
    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        // Unknown keys stay errors. This one gets a precise hint: T05 moved it (nothing was released, so no alias).
        if text
            .parse::<toml::Table>()
            .is_ok_and(|t| t.contains_key(LEGACY_RELAYS_KEY))
        {
            return Err(ConfigError::Parse {
                path: path.to_path_buf(),
                message: LEGACY_RELAYS_MESSAGE.to_string(),
            });
        }
        let config: Config = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: e.message().to_string(),
        })?;
        let problems = config.problems();
        if problems.is_empty() {
            Ok(config)
        } else {
            Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                problems,
            })
        }
    }

    /// The config as TOML text.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Path of the SQLite database.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DB_FILE)
    }

    /// Every problem with the values, as human-readable lines.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.data_dir.is_absolute() {
            out.push(format!("data_dir must be an absolute path, got {:?}", self.data_dir));
        }
        if self.allowed_registries.is_empty() {
            out.push("allowed_registries must list at least one registry".to_string());
        }
        for (i, reg) in self.allowed_registries.iter().enumerate() {
            if !registry_ok(reg) {
                out.push(format!(
                    "allowed_registries[{i}] = {reg:?} is not a registry host (lowercase `host` or `host:port`)"
                ));
            } else if self.allowed_registries[..i].contains(reg) {
                out.push(format!("allowed_registries[{i}] = {reg:?} is listed twice"));
            }
        }
        if !(1..=MAX_GPU_HOUR_UNITS).contains(&self.gpu_hour_units) {
            out.push(format!("gpu_hour_units must be 1-{MAX_GPU_HOUR_UNITS}"));
        }
        if self.iroh.relays.len() > MAX_RELAYS {
            out.push(format!("iroh.relays: at most {MAX_RELAYS} URLs"));
        }
        for (i, relay) in self.iroh.relays.iter().enumerate() {
            if !relay_ok(relay) {
                out.push(format!(
                    "iroh.relays[{i}] = {relay:?} must be an http:// or https:// URL with a host and no credentials"
                ));
            }
        }
        self.nodes.problems(&mut out);
        self.scheduler.problems(&mut out);
        if let Err(e) = tracing_subscriber::EnvFilter::try_new(&self.log.level) {
            out.push(format!("log.level = {:?} is not a valid filter: {e}", self.log.level));
        }
        self.http.problems(&mut out);
        self.storage.problems(&mut out);
        // §10 "Tunnel budget": tunnelled streams always leave REST connections for local clients.
        if self.iroh.tunnel_max_streams == 0 || self.iroh.tunnel_max_streams >= self.http.max_connections {
            out.push(format!(
                "iroh.tunnel_max_streams = {} must be at least 1 and below http.max_connections = {}",
                self.iroh.tunnel_max_streams, self.http.max_connections
            ));
        }
        out
    }
}

/// A registry is valid when an image under it normalizes back to exactly that registry.
fn registry_ok(reg: &str) -> bool {
    !reg.is_empty()
        && !reg.contains('/')
        && ImageRef::parse(&format!("{reg}/p2pc/check:latest")).is_ok_and(|r| r.registry() == reg)
}

fn relay_ok(text: &str) -> bool {
    url::Url::parse(text).is_ok_and(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some_and(|h| !h.is_empty())
            && u.username().is_empty()
            && u.password().is_none()
    }) && text.len() <= p2pc_proto::auth::MAX_RELAY_URL_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("server.toml"))
    }

    #[test]
    fn minimal_config_gets_the_defaults() {
        let c = parse("data_dir = \"/srv/p2pc\"\n").unwrap();
        assert_eq!(c, Config::new(PathBuf::from("/srv/p2pc")));
        assert_eq!(c.bind.to_string(), DEFAULT_BIND);
        assert_eq!(
            c.allowed_registries,
            ["docker.io", "ghcr.io", "quay.io", "nvcr.io", "registry.gitlab.com"]
        );
        assert_eq!(c.gpu_hour_units, 10);
        assert!(c.iroh.relays.is_empty());
        assert_eq!(c.iroh.direct_addresses, DirectAddresses::DefaultRoute);
        assert_eq!(c.nodes, NodesConfig::default());
        assert_eq!((c.nodes.lease_ttl_s, c.nodes.heartbeat_interval_s), (60, 5));
        assert_eq!(c.nodes.min_agent_version(), semver::Version::new(0, 1, 0));
        assert_eq!(c.scheduler.pull_timeout_s, 600);
        assert_eq!(c.log.level, "info");
        assert_eq!(c.db_path(), PathBuf::from("/srv/p2pc/p2pc.db"));
    }

    /// §12: logs and artifacts are kept 7 days by default; the value is bounded.
    #[test]
    fn retention_defaults_to_seven_days_and_is_validated() {
        let c = parse("data_dir = \"/x\"\n").unwrap();
        assert_eq!(c.storage.retention_days, 7);
        assert_eq!(c.storage.retention(), time::Duration::days(7));
        assert_eq!(
            parse("data_dir = \"/x\"\n[storage]\nretention_days = 30\n")
                .unwrap()
                .storage
                .retention_days,
            30
        );
        for bad in [0, 3651] {
            let err = parse(&format!("data_dir = \"/x\"\n[storage]\nretention_days = {bad}\n")).unwrap_err();
            assert!(err.to_string().contains("storage.retention_days"), "{err}");
        }
        assert!(parse("data_dir = \"/x\"\n[storage]\nretention = 1\n").is_err());
    }

    /// §10 "Tunnel budget": the default is accepted, and a budget that reaches the REST cap is refused.
    #[test]
    fn the_tunnel_budget_stays_below_the_rest_cap() {
        let c = parse("data_dir = \"/x\"\n").unwrap();
        assert_eq!(c.iroh.tunnel_max_streams, 128);
        assert!(c.iroh.tunnel_max_streams < c.http.max_connections);
        let at = |streams: u32, conns: u32| {
            parse(&format!(
                "data_dir = \"/x\"\n[iroh]\ntunnel_max_streams = {streams}\n[http]\nmax_connections = {conns}\n"
            ))
        };
        assert!(at(255, 256).is_ok());
        assert!(at(1, 2).is_ok());
        for (streams, conns) in [(256, 256), (300, 256), (128, 128), (0, 256), (128, 64)] {
            let err = at(streams, conns).unwrap_err();
            assert!(
                err.to_string().contains("iroh.tunnel_max_streams"),
                "{streams}/{conns}: {err}"
            );
        }
    }

    #[test]
    fn full_config_round_trips() {
        let mut c = Config::new(PathBuf::from("/srv/p2pc"));
        c.bind = "192.0.2.10:8080".parse().unwrap();
        c.allowed_registries = vec!["registry.example.invalid:5000".into()];
        c.gpu_hour_units = 12;
        c.iroh.relays = vec!["https://relay.example.invalid/".into()];
        c.iroh.direct_addresses = DirectAddresses::Cidrs(vec!["192.0.2.0/24".parse().unwrap()]);
        c.nodes = NodesConfig {
            lease_ttl_s: 90,
            heartbeat_interval_s: 10,
            min_agent_version: "0.2.0-rc.1".into(),
        };
        c.scheduler.pull_timeout_s = 1200;
        c.log.level = "p2pc_server=debug,info".into();
        let text = c.to_toml().unwrap();
        assert_eq!(parse(&text).unwrap(), c);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        for text in [
            "data_dir = \"/srv/p2pc\"\nbindd = \"127.0.0.1:1\"\n",
            "data_dir = \"/srv/p2pc\"\n[log]\nlevel = \"info\"\nformat = \"json\"\n",
        ] {
            let err = parse(text).unwrap_err();
            assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
            assert!(err.to_string().contains("unknown field"), "{err}");
        }
        let err = parse("bind = \"127.0.0.1:1\"\n").unwrap_err();
        assert!(err.to_string().contains("missing field `data_dir`"), "{err}");
    }

    #[test]
    fn bad_values_are_all_reported() {
        let text = r#"
            bind = "127.0.0.1:7477"
            data_dir = "relative/dir"
            allowed_registries = ["Docker.io", "ghcr.io", "ghcr.io", "https://quay.io", ""]
            gpu_hour_units = 0
            [iroh]
            relays = ["ftp://relay.example.invalid/", "https://user:pw@relay.example.invalid/", "nope"]
            [nodes]
            heartbeat_interval_s = 0
            lease_ttl_s = 5
            min_agent_version = "one"
            [scheduler]
            pull_timeout_s = 0
            [log]
            level = "info,[=bad"
        "#;
        let err = parse(text).unwrap_err();
        let ConfigError::Invalid { problems, .. } = &err else {
            panic!("{err}");
        };
        let joined = problems.join("\n");
        for needle in [
            "data_dir must be an absolute path",
            "allowed_registries[0]",
            "allowed_registries[2] = \"ghcr.io\" is listed twice",
            "allowed_registries[3]",
            "allowed_registries[4]",
            "gpu_hour_units must be",
            "iroh.relays[0]",
            "iroh.relays[1]",
            "iroh.relays[2]",
            "nodes.heartbeat_interval_s",
            "nodes.lease_ttl_s",
            "nodes.min_agent_version",
            "scheduler.pull_timeout_s",
            "log.level",
        ] {
            assert!(joined.contains(needle), "{needle} missing in:\n{joined}");
        }
        assert_eq!(problems.len(), 14, "{joined}");
        // A bad bind address is a parse error.
        let err = parse("data_dir = \"/x\"\nbind = \"localhost\"\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    }

    #[test]
    fn direct_addresses_forms() {
        for (text, want) in [
            ("\"default-route\"", DirectAddresses::DefaultRoute),
            ("\"none\"", DirectAddresses::None),
            (
                "[\"192.0.2.0/24\", \"2001:db8::/32\"]",
                DirectAddresses::Cidrs(vec!["192.0.2.0/24".parse().unwrap(), "2001:db8::/32".parse().unwrap()]),
            ),
        ] {
            let c = parse(&format!("data_dir = \"/x\"\n[iroh]\ndirect_addresses = {text}\n")).unwrap();
            assert_eq!(c.iroh.direct_addresses, want, "{text}");
        }
        for bad in ["\"all\"", "[]", "[\"192.0.2.0/33\"]", "5"] {
            let err = parse(&format!("data_dir = \"/x\"\n[iroh]\ndirect_addresses = {bad}\n")).unwrap_err();
            assert!(matches!(err, ConfigError::Parse { .. }), "{bad}: {err}");
        }
        // The old top-level `relays` moved into `[iroh]`: refused, with exactly this hint.
        for text in [
            "data_dir = \"/x\"\nrelays = []\n",
            "relays = [\"https://relay.example.invalid/\"]\ndata_dir = \"/x\"\n",
        ] {
            let err = parse(text).unwrap_err();
            assert!(
                matches!(&err, ConfigError::Parse { message, .. } if message == LEGACY_RELAYS_MESSAGE),
                "{err}"
            );
            assert!(
                err.to_string()
                    .contains("`relays` moved under `[iroh]` in T05; move it there"),
                "{err}"
            );
        }
        // Under `[iroh]` it is fine, and other unknown keys keep the generic error.
        assert!(parse("data_dir = \"/x\"\n[iroh]\nrelays = []\n").is_ok());
        let err = parse("data_dir = \"/x\"\nrelay = []\n").unwrap_err();
        assert!(err.to_string().contains("unknown field `relay`"), "{err}");
    }

    #[test]
    fn lease_ttl_must_leave_room_for_heartbeats_and_the_agent_margin() {
        let at = |ttl: u32, hb: u32| {
            parse(&format!(
                "data_dir = \"/x\"\n[nodes]\nlease_ttl_s = {ttl}\nheartbeat_interval_s = {hb}\n"
            ))
        };
        assert!(at(60, 5).is_ok());
        assert!(at(11, 5).is_ok());
        assert!(
            at(10, 5).is_err(),
            "the agent needs agent_lease_ttl_s + 10 <= lease_ttl_s with a positive timer"
        );
        assert!(at(30, 16).is_err(), "two heartbeats must fit");
        assert!(at(MAX_LEASE_TTL_S + 1, 5).is_err());
    }
}
