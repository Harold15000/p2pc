// SPDX-License-Identifier: Apache-2.0

//! `agent.toml`: where the agent keeps its state, and what the owner lets it offer (U9, spec §8).
//!
//! Lookup order: `--config`, then `$P2PC_AGENT_CONFIG`, then `/etc/p2pc/agent.toml` when running as root, otherwise
//! `~/.config/p2pc-agent/agent.toml`. A missing file at the default path means "all defaults"; a missing file that
//! was named explicitly is an error. Unknown keys are rejected, which catches typos.
//!
//! Validation happens in two steps. [`Config::parse`] checks everything that does not depend on the machine. The
//! share limits are then resolved against the detected hardware with [`Share::resolve`]: they may not exceed it, and
//! an explicitly listed GPU UUID must exist.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use p2pc_proto::api::GpuInfo;
use p2pc_proto::ids::{AccountId, NodeId};
use p2pc_proto::net::DirectAddresses;
use p2pc_proto::validate::{MAX_LABEL_VALUE_LEN, MAX_LABELS, is_label_key};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::parse::is_gpu_uuid;

/// Default `agent_lease_ttl_s` (§6).
pub const DEFAULT_AGENT_LEASE_TTL_S: u64 = 45;
/// Allowed `agent_lease_ttl_s`. The cross-check against the server's `lease_ttl_s` (`+ 10 <=`) happens at
/// `Welcome` (T05b).
pub const AGENT_LEASE_TTL_RANGE: std::ops::RangeInclusive<u64> = 15..=600;
/// Default `detect_timeout_s`: the overall deadline of one inventory detection.
pub const DEFAULT_DETECT_TIMEOUT_S: u64 = 15;
/// Allowed `detect_timeout_s`.
pub const DETECT_TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 1..=300;
/// Default `share.disk_mb`: 50 GiB.
pub const DEFAULT_DISK_MB: u64 = 50 * 1024;
/// `$P2PC_AGENT_SUPERVISED=1`: set by the installers (`install.ps1`, `install-node.sh`), whose Scheduled Task or systemd
/// unit starts the agent. `join` then says so instead of telling the owner to run `p2pc-agent run`.
pub const SUPERVISED_ENV: &str = "P2PC_AGENT_SUPERVISED";
/// The config file when running as root.
pub const ROOT_CONFIG_PATH: &str = "/etc/p2pc/agent.toml";
/// The data dir when running as root (spec §9.0: the WSL2 distro keeps the identity in `/var/lib/p2pc`).
pub const ROOT_DATA_DIR: &str = "/var/lib/p2pc";
/// The environment variable that names the config file.
pub const CONFIG_ENV: &str = "P2PC_AGENT_CONFIG";

/// Why the configuration cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file named by `--config` or `$P2PC_AGENT_CONFIG` does not exist.
    #[error("config file {0} not found")]
    NotFound(PathBuf),
    /// The file exists but cannot be read.
    #[error("cannot read config file {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// Not valid TOML, a wrong type or an unknown key.
    #[error("invalid config file {path}: {message}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// What the TOML parser said, with the line and column.
        message: String,
    },
    /// A value is out of range.
    #[error("invalid config: `{field}` {reason}")]
    Invalid {
        /// The key, for example `share.cpu_cores`.
        field: String,
        /// What is wrong.
        reason: String,
    },
    /// No home directory to derive a default path from.
    #[error("cannot find a home directory: set $HOME or pass --config")]
    NoHome,
}

fn invalid(field: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field: field.into(),
        reason: reason.into(),
    }
}

/// Which GPUs the owner offers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GpuShare {
    /// Every offerable GPU (the default).
    #[default]
    All,
    /// No GPU.
    None,
    /// These GPUs, by UUID.
    List(Vec<String>),
}

impl Serialize for GpuShare {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::All => s.serialize_str("all"),
            Self::None => s.serialize_str("none"),
            Self::List(uuids) => uuids.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for GpuShare {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Word(String),
            List(Vec<String>),
        }
        let expected = "\"all\", \"none\" or a list of GPU UUIDs";
        match Raw::deserialize(d).map_err(|_| serde::de::Error::custom(format!("expected {expected}")))? {
            Raw::Word(w) if w == "all" => Ok(Self::All),
            Raw::Word(w) if w == "none" => Ok(Self::None),
            Raw::Word(w) => Err(serde::de::Error::custom(format!("`{w}`: expected {expected}"))),
            Raw::List(l) => Ok(Self::List(l)),
        }
    }
}

/// The owner's share limits (U9). `None` means "the default".
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    /// vCPUs to offer; fractions allowed. Default: 75 % of the logical cores, rounded down, at least 1 (§8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<f64>,
    /// Memory to offer, in MiB. Default: 75 % of RAM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
    /// GPUs to offer. Default: every offerable GPU.
    #[serde(default)]
    pub gpus: GpuShare,
    /// Disk for job directories, in MiB. Default: 50 GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mb: Option<u64>,
}

/// The OCI runtime for job containers (§9 "Optional gVisor").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    /// crun: the `container` sandbox class.
    #[default]
    Crun,
    /// gVisor: the `container-gvisor` sandbox class.
    Runsc,
}

impl Runtime {
    /// The runtime's program name.
    #[must_use]
    pub fn program(self) -> &'static str {
        match self {
            Self::Crun => "crun",
            Self::Runsc => "runsc",
        }
    }
}

impl fmt::Display for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.program())
    }
}

/// `agent.toml` as written by the owner.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    data_dir: Option<PathBuf>,
    #[serde(default)]
    share: Share,
    agent_lease_ttl_s: Option<u64>,
    detect_timeout_s: Option<u64>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    runtime: Runtime,
    #[serde(default)]
    iroh: IrohConfig,
    server: Option<ServerSection>,
}

/// Most relay URLs in `[iroh] relays` or `[server] relays`.
pub const MAX_RELAYS: usize = 8;

/// `[iroh]`: how the agent's endpoint reaches the network (§10).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrohConfig {
    /// Relay servers. Empty (the default) means the relay hints of the join token, stored in `[server] relays`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<String>,
    /// Which local addresses to bind and advertise: `"default-route"` (the default), `"none"` (relay only) or a
    /// list of CIDRs. The same option as the server's (§10).
    #[serde(default)]
    pub direct_addresses: DirectAddresses,
}

/// `[server]`: the control plane this node joined. Written by `p2pc-agent join` from the token and the `Welcome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// The **server's** iroh NodeId (64 hex characters), from the join token.
    pub node_id: String,
    /// The relay URL hints of the join token.
    #[serde(default)]
    pub relays: Vec<String>,
    /// The account this node is enrolled into, from the `Welcome` of the `Join`: the node's owner. Every lease for
    /// another account is refused (SI-1), and a later `Welcome` with another account is refused too.
    pub account_id: AccountId,
    /// **This node's** ID on the server (`node_…`), from the `Welcome` of the `Join`.
    pub agent_node_id: NodeId,
}

/// The validated agent configuration, with the machine-independent defaults filled in.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Config {
    /// Where the agent keeps its identity and job directories.
    pub data_dir: PathBuf,
    /// The agent's own lease timer (§6, SI-13), in seconds.
    pub agent_lease_ttl_s: u64,
    /// The overall deadline of one inventory detection, in seconds. A tool that has not answered by then is
    /// reported as unknown, with a note, instead of stalling the detection (and the heartbeat behind it).
    pub detect_timeout_s: u64,
    /// The OCI runtime.
    pub runtime: Runtime,
    /// Share limits; the defaults that depend on the hardware stay `None` until [`Share::resolve`].
    pub share: Share,
    /// Node labels, matched against `placement.labels`.
    pub labels: BTreeMap<String, String>,
    /// The agent's iroh endpoint options.
    pub iroh: IrohConfig,
    /// The control plane this node joined; `None` until `p2pc-agent join`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerSection>,
}

/// Where the config came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// `--config`.
    Flag(PathBuf),
    /// `$P2PC_AGENT_CONFIG`.
    Env(PathBuf),
    /// The default path for this user.
    Default(PathBuf),
}

impl ConfigSource {
    /// The file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Flag(p) | Self::Env(p) | Self::Default(p) => p,
        }
    }
}

/// Whether `$P2PC_AGENT_SUPERVISED` (`value`) says an installer starts the agent: exactly `1`.
#[must_use]
pub fn is_supervised(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| v == "1")
}

/// What `join` prints last: where the config was saved, and how the agent gets started.
#[must_use]
pub fn saved_hint(config_path: &Path, supervised: bool) -> String {
    if supervised {
        format!("Saved in {}. The installer starts the agent.", config_path.display())
    } else {
        format!(
            "Saved in {}. Start the agent with `p2pc-agent run`.",
            config_path.display()
        )
    }
}

/// The parts of the process environment that config lookup depends on.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// Whether the agent runs as root (effective UID 0).
    pub root: bool,
    /// `$HOME`.
    pub home: Option<PathBuf>,
    /// `$P2PC_AGENT_CONFIG`.
    pub config_env: Option<OsString>,
    /// `$P2PC_AGENT_SUPERVISED` is `1` ([`is_supervised`]): an installer starts the agent.
    pub supervised: bool,
}

impl Env {
    /// The real process environment. `root` comes from the effective UID.
    #[must_use]
    pub fn system() -> Self {
        Self {
            root: rustix::process::geteuid().is_root(),
            home: std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from),
            config_env: std::env::var_os(CONFIG_ENV).filter(|v| !v.is_empty()),
            supervised: is_supervised(std::env::var_os(SUPERVISED_ENV).as_deref()),
        }
    }

    /// The config file to read.
    pub fn config_source(&self, flag: Option<&Path>) -> Result<ConfigSource, ConfigError> {
        if let Some(path) = flag {
            return Ok(ConfigSource::Flag(path.to_path_buf()));
        }
        if let Some(path) = &self.config_env {
            return Ok(ConfigSource::Env(PathBuf::from(path)));
        }
        if self.root {
            return Ok(ConfigSource::Default(PathBuf::from(ROOT_CONFIG_PATH)));
        }
        let home = self.home.as_ref().ok_or(ConfigError::NoHome)?;
        Ok(ConfigSource::Default(home.join(".config/p2pc-agent/agent.toml")))
    }

    /// The data dir when the config does not set one.
    pub fn default_data_dir(&self) -> Result<PathBuf, ConfigError> {
        if self.root {
            return Ok(PathBuf::from(ROOT_DATA_DIR));
        }
        let home = self.home.as_ref().ok_or(ConfigError::NoHome)?;
        Ok(home.join(".local/share/p2pc-agent"))
    }
}

impl Config {
    /// The overall deadline of one inventory detection.
    #[must_use]
    pub fn detect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.detect_timeout_s)
    }

    /// Reads the config from `source`. A missing file is fine only at the default path.
    pub fn load(source: &ConfigSource, env: &Env) -> Result<Self, ConfigError> {
        let path = source.path();
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match source {
                ConfigSource::Default(_) => String::new(),
                _ => return Err(ConfigError::NotFound(path.to_path_buf())),
            },
            Err(source) => {
                return Err(ConfigError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        Self::parse(&text, env).map_err(|e| match e {
            ConfigError::Parse { message, .. } => ConfigError::Parse {
                path: path.to_path_buf(),
                message,
            },
            other => other,
        })
    }

    /// Parses and validates `agent.toml` text. Errors of the `Parse` kind carry an empty path.
    pub fn parse(text: &str, env: &Env) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: PathBuf::new(),
            message: e.to_string(),
        })?;
        let data_dir = match raw.data_dir {
            Some(dir) => dir,
            None => env.default_data_dir()?,
        };
        if !data_dir.is_absolute() {
            return Err(invalid("data_dir", "must be an absolute path"));
        }
        let agent_lease_ttl_s = raw.agent_lease_ttl_s.unwrap_or(DEFAULT_AGENT_LEASE_TTL_S);
        if !AGENT_LEASE_TTL_RANGE.contains(&agent_lease_ttl_s) {
            return Err(invalid(
                "agent_lease_ttl_s",
                format!(
                    "must be between {} and {} seconds",
                    AGENT_LEASE_TTL_RANGE.start(),
                    AGENT_LEASE_TTL_RANGE.end()
                ),
            ));
        }
        let detect_timeout_s = raw.detect_timeout_s.unwrap_or(DEFAULT_DETECT_TIMEOUT_S);
        if !DETECT_TIMEOUT_RANGE.contains(&detect_timeout_s) {
            return Err(invalid(
                "detect_timeout_s",
                format!(
                    "must be between {} and {} seconds",
                    DETECT_TIMEOUT_RANGE.start(),
                    DETECT_TIMEOUT_RANGE.end()
                ),
            ));
        }
        validate_share(&raw.share)?;
        validate_labels(&raw.labels)?;
        validate_relays("iroh.relays", &raw.iroh.relays)?;
        if let Some(server) = &raw.server {
            validate_server(server)?;
        }
        Ok(Self {
            data_dir,
            agent_lease_ttl_s,
            detect_timeout_s,
            runtime: raw.runtime,
            share: raw.share,
            labels: raw.labels,
            iroh: raw.iroh,
            server: raw.server,
        })
    }

    /// The relays the endpoint uses: `[iroh] relays` when set, otherwise the join token's hints.
    #[must_use]
    pub fn relays(&self) -> Vec<String> {
        if !self.iroh.relays.is_empty() {
            return self.iroh.relays.clone();
        }
        self.server.as_ref().map(|s| s.relays.clone()).unwrap_or_default()
    }
}

fn validate_relays(field: &str, relays: &[String]) -> Result<(), ConfigError> {
    if relays.len() > MAX_RELAYS {
        return Err(invalid(field, format!("at most {MAX_RELAYS} relays")));
    }
    for r in relays {
        let ok = r
            .parse::<iroh::RelayUrl>()
            .is_ok_and(|u| matches!(u.scheme(), "http" | "https"));
        if !ok {
            return Err(invalid(field, format!("`{r}` is not an http(s) relay URL")));
        }
    }
    Ok(())
}

fn validate_server(server: &ServerSection) -> Result<(), ConfigError> {
    if server.node_id.parse::<iroh::EndpointId>().is_err() {
        return Err(invalid(
            "server.node_id",
            "is not an iroh NodeId (64 hex characters); join again",
        ));
    }
    validate_relays("server.relays", &server.relays)
}

/// Writes `[server]` into the config file at `path`, atomically and with mode 0600 (`p2pc-agent join`).
///
/// The rest of the file, comments included, is kept as it is. The new content goes to a temporary file in the same
/// directory (created 0600), is synced, and replaces the old file with a rename, so a crash leaves either the old
/// file or the new one, never half of one. A missing parent directory is created with mode 0700. The result is
/// parsed back before it replaces anything, so a file the agent could not load again is never written.
pub fn write_server_section(path: &Path, server: &ServerSection, env: &Env) -> Result<(), ConfigError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let io = |source: std::io::Error| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(io(e)),
    };
    let mut doc: toml_edit::DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| ConfigError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let mut table = toml_edit::Table::new();
    // Comments just above an existing `[server]` belong to that table: keep them when it is replaced (`--force`).
    let old_prefix = doc
        .get("server")
        .and_then(toml_edit::Item::as_table)
        .and_then(|t| t.decor().prefix())
        .cloned();
    match old_prefix {
        Some(prefix) => table.decor_mut().set_prefix(prefix),
        None => table
            .decor_mut()
            .set_prefix("\n# Written by `p2pc-agent join`: the control plane this node is enrolled with.\n"),
    }
    table["node_id"] = toml_edit::value(server.node_id.as_str());
    let mut relays = toml_edit::Array::new();
    for r in &server.relays {
        relays.push(r.as_str());
    }
    table["relays"] = toml_edit::value(relays);
    table["account_id"] = toml_edit::value(server.account_id.to_string());
    table["agent_node_id"] = toml_edit::value(server.agent_node_id.to_string());
    doc["server"] = toml_edit::Item::Table(table);
    let new_text = doc.to_string();
    // Never write a file that would not load.
    Config::parse(&new_text, env).map_err(|e| match e {
        ConfigError::Parse { message, .. } => ConfigError::Parse {
            path: path.to_path_buf(),
            message,
        },
        other => other,
    })?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    crate::identity::create_private_dirs(&dir).map_err(|e| match e {
        // Name the directory that failed, which may be a parent that was being created.
        crate::identity::IdentityError::Io { path, source, .. } => ConfigError::Io { path, source },
        other => io(std::io::Error::other(other.to_string())),
    })?;
    let name = path
        .file_name()
        .map_or_else(|| "agent.toml".into(), |n| n.to_string_lossy().into_owned());
    let tmp = dir.join(format!(".{name}.{:016x}.tmp", rand::random::<u64>()));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(new_text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(&dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(io)
}

fn validate_share(share: &Share) -> Result<(), ConfigError> {
    if let Some(cpu) = share.cpu_cores
        && !(cpu.is_finite() && cpu > 0.0)
    {
        return Err(invalid("share.cpu_cores", "must be a number greater than 0"));
    }
    if share.memory_mb == Some(0) {
        return Err(invalid("share.memory_mb", "must be greater than 0"));
    }
    if share.disk_mb == Some(0) {
        return Err(invalid("share.disk_mb", "must be greater than 0"));
    }
    if let GpuShare::List(uuids) = &share.gpus {
        for (i, uuid) in uuids.iter().enumerate() {
            if !is_gpu_uuid(uuid) {
                return Err(invalid(
                    "share.gpus",
                    format!("entry {i} is not a GPU UUID (for example GPU-6a3d0a2e-…)"),
                ));
            }
            if uuids[..i].contains(uuid) {
                return Err(invalid("share.gpus", format!("`{uuid}` is listed twice")));
            }
        }
    }
    Ok(())
}

fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    if labels.len() > MAX_LABELS {
        return Err(invalid("labels", format!("at most {MAX_LABELS} labels")));
    }
    for (k, v) in labels {
        if !is_label_key(k) {
            return Err(invalid(
                "labels",
                format!("key `{k}` must match [a-z0-9]([a-z0-9._/-]{{0,61}}[a-z0-9])?"),
            ));
        }
        if v.len() > MAX_LABEL_VALUE_LEN || v.chars().any(char::is_control) {
            return Err(invalid(
                format!("labels.{k}"),
                format!("must be at most {MAX_LABEL_VALUE_LEN} bytes without control characters"),
            ));
        }
    }
    Ok(())
}

/// The machine facts the share limits are checked against.
#[derive(Debug, Clone, Copy)]
pub struct Hardware<'a> {
    /// Logical CPUs.
    pub cores: u32,
    /// RAM in MiB.
    pub memory_mb: u64,
    /// Size of the filesystem holding the data dir, in MiB, if known.
    pub disk_mb: Option<u64>,
    /// The detected GPUs.
    pub gpus: &'a [GpuInfo],
    /// Whether GPU detection itself worked. When it did not, listed UUIDs cannot be checked: they are not offered,
    /// and a warning says so, instead of refusing to start over a transient driver problem.
    pub gpu_detection_ok: bool,
}

/// The share limits with every default applied.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedShare {
    /// vCPUs offered.
    pub cpu_cores: f64,
    /// Memory offered, in MiB.
    pub memory_mb: u64,
    /// The UUIDs of the GPUs offered.
    pub gpus: Vec<String>,
    /// Disk for job directories, in MiB.
    pub disk_mb: u64,
    /// Things the owner should know that do not stop the agent.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// The default vCPU share: 75 % of the logical cores, rounded down, at least 1 (§8).
#[must_use]
pub fn default_cpu_cores(cores: u32) -> f64 {
    f64::from((cores / 4 * 3 + cores % 4 * 3 / 4).max(1))
}

/// The default memory share: 75 % of RAM, rounded down.
#[must_use]
pub fn default_memory_mb(memory_mb: u64) -> u64 {
    memory_mb / 4 * 3 + (memory_mb % 4) * 3 / 4
}

/// What to do with a listed GPU UUID that is not on the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingGpu {
    /// A hard error: at load and in `doctor`, a UUID that matches no GPU is most likely a typo.
    Error,
    /// Skip it with a warning: during periodic re-detection one unplugged eGPU must not stop the whole detection.
    Skip,
}

impl Share {
    /// Applies the defaults and checks the limits against the hardware. A listed UUID that is not on the machine
    /// is an error ([`MissingGpu::Error`]).
    pub fn resolve(&self, hw: &Hardware<'_>) -> Result<ResolvedShare, ConfigError> {
        self.resolve_with(hw, MissingGpu::Error)
    }

    /// Like [`Share::resolve`], with the choice of what a missing GPU UUID does.
    pub fn resolve_with(&self, hw: &Hardware<'_>, missing: MissingGpu) -> Result<ResolvedShare, ConfigError> {
        let cores = f64::from(hw.cores);
        let cpu_cores = self.cpu_cores.unwrap_or_else(|| default_cpu_cores(hw.cores).min(cores));
        if cpu_cores > cores {
            return Err(invalid(
                "share.cpu_cores",
                format!(
                    "is {cpu_cores}, more than the {} logical cores of this machine",
                    hw.cores
                ),
            ));
        }
        let memory_mb = self.memory_mb.unwrap_or_else(|| default_memory_mb(hw.memory_mb));
        if memory_mb > hw.memory_mb {
            return Err(invalid(
                "share.memory_mb",
                format!("is {memory_mb} MiB, more than the {} MiB of RAM", hw.memory_mb),
            ));
        }
        // Only an explicit value is an error: the default adapts to a small disk.
        let disk_mb = match (self.disk_mb, hw.disk_mb) {
            (Some(disk), Some(total)) if disk > total => {
                return Err(invalid(
                    "share.disk_mb",
                    format!("is {disk} MiB, more than the {total} MiB of the data dir's filesystem"),
                ));
            }
            (Some(disk), _) => disk,
            (None, Some(total)) => DEFAULT_DISK_MB.min(total),
            (None, None) => DEFAULT_DISK_MB,
        };
        let mut warnings = Vec::new();
        let gpus = match &self.gpus {
            GpuShare::None => Vec::new(),
            GpuShare::All => hw
                .gpus
                .iter()
                .filter(|g| g.is_offerable())
                .map(|g| g.uuid.clone())
                .collect(),
            GpuShare::List(uuids) => {
                let mut offered = Vec::new();
                for uuid in uuids {
                    match hw.gpus.iter().find(|g| &g.uuid == uuid) {
                        Some(g) if g.is_offerable() => offered.push(uuid.clone()),
                        Some(g) => warnings.push(format!(
                            "GPU {uuid} is not offered: {}",
                            if g.mig {
                                "MIG is enabled (or its state could not be read)"
                            } else {
                                "its VRAM is unknown"
                            }
                        )),
                        None if hw.gpu_detection_ok && missing == MissingGpu::Skip => warnings.push(format!(
                            "GPU {uuid} is not offered: it is not on this machine now (unplugged?)"
                        )),
                        None if hw.gpu_detection_ok => {
                            return Err(invalid(
                                "share.gpus",
                                format!("`{uuid}` is not a GPU of this machine (see `p2pc-agent inventory`)"),
                            ));
                        }
                        None => warnings.push(format!("GPU {uuid} is not offered: GPU detection failed")),
                    }
                }
                offered
            }
        };
        Ok(ResolvedShare {
            cpu_cores,
            memory_mb,
            gpus,
            disk_mb,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env {
            root: false,
            home: Some(PathBuf::from("/home/p2pc")),
            config_env: None,
            ..Default::default()
        }
    }

    /// T10e: under an installer (`P2PC_AGENT_SUPERVISED=1`) the hint does not tell the owner to start the agent.
    #[test]
    fn the_join_hint_depends_on_who_starts_the_agent() {
        use std::ffi::OsStr;
        let path = Path::new("/etc/p2pc/agent.toml");
        assert!(!is_supervised(None));
        assert!(!is_supervised(Some(OsStr::new(""))));
        assert!(!is_supervised(Some(OsStr::new("0"))));
        assert!(!is_supervised(Some(OsStr::new("true"))));
        assert!(is_supervised(Some(OsStr::new("1"))));
        assert_eq!(
            saved_hint(path, false),
            "Saved in /etc/p2pc/agent.toml. Start the agent with `p2pc-agent run`."
        );
        assert_eq!(
            saved_hint(path, true),
            "Saved in /etc/p2pc/agent.toml. The installer starts the agent."
        );
    }

    fn gpu(uuid: &str, vram_mb: Option<u64>, mig: bool) -> GpuInfo {
        GpuInfo {
            uuid: uuid.into(),
            index: 0,
            name: "Example GPU".into(),
            driver_version: "550.54".into(),
            cuda_driver_version: None,
            compute_capability: None,
            vram_mb,
            pci_bdf: None,
            mig,
        }
    }

    fn err_field(r: Result<impl fmt::Debug, ConfigError>) -> String {
        match r {
            Err(ConfigError::Invalid { field, .. }) => field,
            other => panic!("expected an Invalid error, got {other:?}"),
        }
    }

    #[test]
    fn lookup_order() {
        let mut e = env();
        let flag = Path::new("/srv/agent.toml");
        assert_eq!(e.config_source(Some(flag)).unwrap(), ConfigSource::Flag(flag.into()));
        assert_eq!(
            e.config_source(None).unwrap(),
            ConfigSource::Default("/home/p2pc/.config/p2pc-agent/agent.toml".into())
        );
        e.config_env = Some("/opt/agent.toml".into());
        assert_eq!(
            e.config_source(None).unwrap(),
            ConfigSource::Env("/opt/agent.toml".into())
        );
        assert_eq!(e.config_source(Some(flag)).unwrap(), ConfigSource::Flag(flag.into()));
        let root = Env { root: true, ..env() };
        assert_eq!(
            root.config_source(None).unwrap(),
            ConfigSource::Default(ROOT_CONFIG_PATH.into())
        );
        let homeless = Env { home: None, ..env() };
        assert!(matches!(homeless.config_source(None), Err(ConfigError::NoHome)));
    }

    #[test]
    fn defaults() {
        let c = Config::parse("", &env()).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/home/p2pc/.local/share/p2pc-agent"));
        assert_eq!(c.agent_lease_ttl_s, 45);
        assert_eq!(c.runtime, Runtime::Crun);
        assert_eq!(c.share, Share::default());
        assert_eq!(c.share.gpus, GpuShare::All);
        assert!(c.labels.is_empty() && c.server.is_none());
        let root = Env { root: true, ..env() };
        assert_eq!(Config::parse("", &root).unwrap().data_dir, PathBuf::from(ROOT_DATA_DIR));
    }

    #[test]
    fn full_file() {
        let text = r#"
            data_dir = "/var/lib/p2pc"
            agent_lease_ttl_s = 30
            runtime = "runsc"

            [share]
            cpu_cores = 2.5
            memory_mb = 4096
            gpus = ["GPU-00000000-0000-4000-8000-000000000001"]
            disk_mb = 10240

            [labels]
            "gpu.vendor/model" = "rtx 4090"
            zone = "home"

            [iroh]
            relays = ["https://relay.example.invalid/"]
            direct_addresses = ["192.0.2.0/24"]

            [server]
            node_id = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            relays = ["https://relay.example.invalid/"]
            account_id = "acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4"
            agent_node_id = "node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4"
        "#;
        let c = Config::parse(text, &env()).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/p2pc"));
        assert_eq!(c.agent_lease_ttl_s, 30);
        assert_eq!(c.runtime, Runtime::Runsc);
        assert_eq!(c.share.cpu_cores, Some(2.5));
        assert_eq!(c.share.memory_mb, Some(4096));
        assert_eq!(c.share.disk_mb, Some(10_240));
        assert_eq!(
            c.share.gpus,
            GpuShare::List(vec!["GPU-00000000-0000-4000-8000-000000000001".into()])
        );
        assert_eq!(c.labels.len(), 2);
        assert!(c.server.is_some());
        assert_eq!(
            Config::parse("[share]\ngpus = \"none\"\n", &env()).unwrap().share.gpus,
            GpuShare::None
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        for text in [
            "data_dri = \"/x\"\n",
            "[share]\ncpu = 2\n",
            "[share]\ngpus = \"some\"\n",
            "runtime = \"runc\"\n",
            "[share]\ngpus = 1\n",
        ] {
            let e = Config::parse(text, &env()).unwrap_err();
            assert!(matches!(e, ConfigError::Parse { .. }), "{text}: {e:?}");
        }
        let e = Config::parse("[share]\ncpu = 2\n", &env()).unwrap_err().to_string();
        assert!(e.contains("cpu"), "{e}");
    }

    #[test]
    fn values_are_validated() {
        let cases = [
            ("data_dir = \"relative/dir\"", "data_dir"),
            ("agent_lease_ttl_s = 14", "agent_lease_ttl_s"),
            ("agent_lease_ttl_s = 601", "agent_lease_ttl_s"),
            ("[share]\ncpu_cores = 0", "share.cpu_cores"),
            ("[share]\ncpu_cores = -1.5", "share.cpu_cores"),
            ("[share]\ncpu_cores = nan", "share.cpu_cores"),
            ("[share]\ncpu_cores = inf", "share.cpu_cores"),
            ("[share]\nmemory_mb = 0", "share.memory_mb"),
            ("[share]\ndisk_mb = 0", "share.disk_mb"),
            ("[share]\ngpus = [\"\"]", "share.gpus"),
            ("[share]\ngpus = [\"GPU 1\"]", "share.gpus"),
            ("[share]\ngpus = [\"GPU-1\", \"GPU-1\"]", "share.gpus"),
            ("[labels]\n\"Bad Key\" = \"v\"", "labels"),
            ("[labels]\nk = \"a\\nb\"", "labels.k"),
        ];
        for (text, field) in cases {
            assert_eq!(err_field(Config::parse(text, &env())), field, "{text}");
        }
        assert!(Config::parse("agent_lease_ttl_s = 15", &env()).is_ok());
        assert!(Config::parse("agent_lease_ttl_s = 600", &env()).is_ok());
        let many: String = (0..=MAX_LABELS).map(|i| format!("l{i} = \"v\"\n")).collect();
        assert_eq!(err_field(Config::parse(&format!("[labels]\n{many}"), &env())), "labels");
    }

    #[test]
    fn missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("agent.toml");
        let c = Config::load(&ConfigSource::Default(missing.clone()), &env()).unwrap();
        assert_eq!(c, Config::parse("", &env()).unwrap());
        for source in [ConfigSource::Flag(missing.clone()), ConfigSource::Env(missing.clone())] {
            assert!(matches!(Config::load(&source, &env()), Err(ConfigError::NotFound(_))));
        }
        std::fs::write(&missing, "bogus = 1\n").unwrap();
        let e = Config::load(&ConfigSource::Flag(missing.clone()), &env()).unwrap_err();
        assert!(e.to_string().contains(&missing.display().to_string()), "{e}");
    }

    #[test]
    fn default_share_is_75_percent() {
        assert_eq!(default_cpu_cores(16), 12.0);
        assert_eq!(default_cpu_cores(6), 4.0);
        assert_eq!(default_cpu_cores(1), 1.0, "at least 1");
        assert_eq!(default_cpu_cores(2), 1.0);
        assert_eq!(default_memory_mb(32_014), 24_010);
        assert_eq!(default_memory_mb(3), 2);
        let gpus = [
            gpu("GPU-a", Some(8192), false),
            gpu("GPU-mig", Some(40_960), true),
            gpu("GPU-novram", None, false),
        ];
        let hw = Hardware {
            cores: 16,
            memory_mb: 32_014,
            disk_mb: Some(500_000),
            gpus: &gpus,
            gpu_detection_ok: true,
        };
        let r = Share::default().resolve(&hw).unwrap();
        assert_eq!(r.cpu_cores, 12.0);
        assert_eq!(r.memory_mb, 24_010);
        assert_eq!(r.disk_mb, DEFAULT_DISK_MB);
        assert_eq!(r.gpus, ["GPU-a"], "only offerable GPUs");
        assert!(r.warnings.is_empty());
        // A small disk shrinks the default instead of failing.
        let small = Hardware {
            disk_mb: Some(20_000),
            ..hw
        };
        assert_eq!(Share::default().resolve(&small).unwrap().disk_mb, 20_000);
    }

    #[test]
    fn share_cannot_exceed_the_hardware() {
        let gpus = [gpu("GPU-a", Some(8192), false), gpu("GPU-mig", Some(40_960), true)];
        let hw = Hardware {
            cores: 8,
            memory_mb: 16_000,
            disk_mb: Some(100_000),
            gpus: &gpus,
            gpu_detection_ok: true,
        };
        let share = |f: &dyn Fn(&mut Share)| {
            let mut s = Share::default();
            f(&mut s);
            s.resolve(&hw)
        };
        assert_eq!(share(&|s| s.cpu_cores = Some(8.0)).unwrap().cpu_cores, 8.0);
        assert_eq!(share(&|s| s.cpu_cores = Some(0.5)).unwrap().cpu_cores, 0.5);
        assert_eq!(err_field(share(&|s| s.cpu_cores = Some(8.5))), "share.cpu_cores");
        assert_eq!(err_field(share(&|s| s.memory_mb = Some(16_001))), "share.memory_mb");
        assert_eq!(err_field(share(&|s| s.disk_mb = Some(100_001))), "share.disk_mb");
        assert_eq!(
            err_field(share(&|s| s.gpus = GpuShare::List(vec!["GPU-unknown".into()]))),
            "share.gpus"
        );
        assert!(share(&|s| s.gpus = GpuShare::None).unwrap().gpus.is_empty());
        let r = share(&|s| s.gpus = GpuShare::List(vec!["GPU-a".into(), "GPU-mig".into()])).unwrap();
        assert_eq!(r.gpus, ["GPU-a"], "a MIG card is never offered");
        assert_eq!(
            r.warnings,
            ["GPU GPU-mig is not offered: MIG is enabled (or its state could not be read)"]
        );
        // Detection failed: the listed GPU cannot be checked, so it is not offered, with a warning.
        let blind = Hardware {
            gpus: &[],
            gpu_detection_ok: false,
            ..hw
        };
        let s = Share {
            gpus: GpuShare::List(vec!["GPU-a".into()]),
            ..Share::default()
        };
        let r = s.resolve(&blind).unwrap();
        assert!(r.gpus.is_empty());
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn detect_timeout_default_and_range() {
        let parse = |t: &str| Config::parse(t, &env());
        assert_eq!(parse("").unwrap().detect_timeout_s, 15);
        assert_eq!(parse("detect_timeout_s = 60\n").unwrap().detect_timeout_s, 60);
        for bad in ["0", "301"] {
            let e = parse(&format!("detect_timeout_s = {bad}\n")).unwrap_err();
            assert!(e.to_string().contains("detect_timeout_s"), "{e}");
        }
    }

    const SERVER_ID: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn server() -> ServerSection {
        ServerSection {
            node_id: SERVER_ID.into(),
            relays: vec!["https://relay.example.invalid/".into()],
            account_id: AccountId::generate(),
            agent_node_id: NodeId::generate(),
        }
    }

    #[test]
    fn server_and_iroh_sections_are_validated() {
        let cases = [
            (
                "[server]\nnode_id = \"nope\"\naccount_id = \"acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\nagent_node_id = \"node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n",
                "server.node_id",
            ),
            ("[iroh]\nrelays = [\"ftp://relay.example.invalid/\"]\n", "iroh.relays"),
            ("[iroh]\nrelays = [\"not a url\"]\n", "iroh.relays"),
        ];
        for (text, field) in cases {
            assert_eq!(err_field(Config::parse(text, &env())), field, "{text}");
        }
        for text in [
            "[iroh]\ndirect_addresses = \"everything\"\n",
            "[server]\nnode_id = \"x\"\n",
            "[iroh]\nrelay = []\n",
        ] {
            assert!(
                matches!(Config::parse(text, &env()), Err(ConfigError::Parse { .. })),
                "{text}"
            );
        }
        let c = Config::parse("[iroh]\ndirect_addresses = \"none\"\n", &env()).unwrap();
        assert_eq!(c.iroh.direct_addresses, DirectAddresses::None);
        assert_eq!(Config::parse("", &env()).unwrap().iroh, IrohConfig::default());
    }

    #[test]
    fn relays_come_from_iroh_first_then_from_the_token() {
        let mut c = Config::parse("", &env()).unwrap();
        assert!(c.relays().is_empty());
        c.server = Some(server());
        assert_eq!(c.relays(), ["https://relay.example.invalid/"]);
        c.iroh.relays = vec!["https://own-relay.example.invalid/".into()];
        assert_eq!(c.relays(), ["https://own-relay.example.invalid/"]);
    }

    #[test]
    fn the_server_section_is_written_atomically_with_mode_0600_keeping_the_rest() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etc/p2pc/agent.toml");
        // A missing file (and directory) is created.
        let s = server();
        write_server_section(&path, &s, &env()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let loaded = Config::load(&ConfigSource::Flag(path.clone()), &env()).unwrap();
        assert_eq!(loaded.server.as_ref(), Some(&s));
        // An existing file keeps its comments and other keys, and a second write replaces [server].
        std::fs::write(
            &path,
            "# my agent\nagent_lease_ttl_s = 30 # shorter\n\n[labels]\nzone = \"home\"\n\n[server]\nnode_id = \"old\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let s2 = server();
        write_server_section(&path, &s2, &env()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# my agent") && text.contains("# shorter"), "{text}");
        assert!(!text.contains("\"old\""), "{text}");
        assert_eq!(mode(&path), 0o600, "tightened");
        let loaded = Config::load(&ConfigSource::Flag(path.clone()), &env()).unwrap();
        assert_eq!(loaded.server, Some(s2));
        assert_eq!(loaded.agent_lease_ttl_s, 30);
        assert_eq!(loaded.labels["zone"], "home");
        // No temporary file is left behind.
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["agent.toml"]);
        // A file that does not parse is never rewritten.
        std::fs::write(&path, "data_dir = \"relative\"\n").unwrap();
        assert!(write_server_section(&path, &server(), &env()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "data_dir = \"relative\"\n");
    }

    #[test]
    fn effective_config_serializes_as_toml() {
        let c = Config::parse("[labels]\nzone = \"home\"\n", &env()).unwrap();
        let text = toml::to_string(&c).unwrap();
        assert!(
            text.contains("data_dir = \"/home/p2pc/.local/share/p2pc-agent\""),
            "{text}"
        );
        assert!(text.contains("gpus = \"all\""), "{text}");
        assert!(text.contains("zone = \"home\""), "{text}");
    }
}
