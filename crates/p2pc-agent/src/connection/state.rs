// SPDX-License-Identifier: Apache-2.0

//! The small state file that `p2pc-agent run` keeps up to date and `p2pc-agent status` reads, with no network.
//!
//! `<data_dir>/agent-state.json`, mode 0600, replaced atomically on every connection state change. It holds no
//! secret: the connection state and since when, the last `Welcome` time, the server's NodeId and this node's ID on
//! it. The pair of IDs names the enrollment: `join` deletes the file, and `status` shows a file only when both IDs
//! are the current enrollment's (T05b real run, round 2).

use std::fmt::Write as _;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::config::Config;

/// The file name inside the data dir.
pub const STATE_FILE: &str = "agent-state.json";

/// The connection, as `status` shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// Dialling the server, or waiting for its `Welcome`.
    Connecting,
    /// Welcomed: heartbeating.
    Connected,
    /// The last attempt failed or the connection dropped; waiting before the next one.
    BackingOff,
    /// The server's `Welcome` named another account than the enrolled owner: refused (SI-1).
    WrongOwner,
    /// The server said this machine is not enrolled (it was removed).
    NotEnrolled,
    /// The server refuses this agent version.
    AgentTooOld,
    /// `run` stopped (SIGTERM, SIGINT).
    Stopped,
}

impl ConnectionState {
    fn describe(self) -> &'static str {
        match self {
            ConnectionState::Connecting => "connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::BackingOff => "disconnected, reconnecting",
            ConnectionState::WrongOwner => "refused: the server's Welcome named another account than this node's owner",
            ConnectionState::NotEnrolled => "stopped: the server says this machine is not enrolled; join again",
            ConnectionState::AgentTooOld => "stopped: the server refuses this agent version; upgrade the agent",
            ConnectionState::Stopped => "stopped",
        }
    }
}

/// What the file holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentState {
    /// The connection state.
    pub connection: ConnectionState,
    /// Since when.
    #[serde(with = "time::serde::rfc3339")]
    pub since: OffsetDateTime,
    /// The last `Welcome`, if any.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_welcome_at: Option<OffsetDateTime>,
    /// The server's NodeId.
    pub server_node_id: String,
    /// This node's ID on that server (`[server] agent_node_id`). Absent in files written before T10a: such a file is
    /// never taken for the current enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_node_id: Option<String>,
    /// The hub's version from the last `Welcome` (H2 §14.2), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    /// Whether the node waits for approval on the hub PC (H2 §5.5): `Welcome.pending_approval`, then `NodeApproved`.
    /// Absent until the hub said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_approval: Option<bool>,
}

impl AgentState {
    /// A state with no `Welcome` yet.
    #[must_use]
    pub fn new(
        connection: ConnectionState,
        since: OffsetDateTime,
        server_node_id: String,
        agent_node_id: Option<String>,
    ) -> Self {
        Self {
            connection,
            since,
            last_welcome_at: None,
            server_node_id,
            agent_node_id,
            server_version: None,
            pending_approval: None,
        }
    }

    /// Whether this state is of the enrollment with `server_node_id` and `agent_node_id`.
    #[must_use]
    pub fn is_of(&self, server_node_id: &str, agent_node_id: &str) -> bool {
        self.server_node_id == server_node_id && self.agent_node_id.as_deref() == Some(agent_node_id)
    }
}

/// Replaces the file at `path` with `bytes` atomically (a temporary file in the same directory, then a rename), mode
/// 0600.
///
/// # Errors
/// When the file cannot be written; no temporary file is left behind.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let tmp = dir.join(format!(".{name}.{:016x}.tmp", rand::random::<u64>()));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Writes the state file.
#[derive(Debug, Clone)]
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    /// The state file in `data_dir`.
    #[must_use]
    pub fn in_dir(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(STATE_FILE),
        }
    }

    /// Its path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Replaces the file atomically, mode 0600. A failure is logged, never fatal: the agent runs without it.
    pub fn write(&self, state: &AgentState) {
        if let Err(e) = self.try_write(state) {
            tracing::debug!(error = %e, path = %self.path.display(), "cannot write the state file");
        }
    }

    fn try_write(&self, state: &AgentState) -> std::io::Result<()> {
        let json = serde_json::to_vec(state).map_err(std::io::Error::other)?;
        write_atomic(&self.path, &json)
    }

    /// Starts the task that writes this file off the async runtime (T05b review, P3-3): each write runs on the
    /// blocking pool, one at a time and in order, and when states come faster than the disk, the latest wins.
    #[must_use]
    pub fn spawn_writer(self) -> StateWriter {
        let (tx, mut rx) = tokio::sync::watch::channel(None::<AgentState>);
        let tx = std::sync::Arc::new(tx);
        let task = tokio::spawn(async move {
            // `changed()` still reports a value sent just before the sender was dropped, so the last state is written.
            while rx.changed().await.is_ok() {
                let Some(state) = rx.borrow_and_update().clone() else {
                    continue;
                };
                let file = self.clone();
                let _ = tokio::task::spawn_blocking(move || file.write(&state)).await;
            }
        });
        StateWriter { tx, task }
    }

    /// Deletes the file: `join` does it, so nothing of an earlier enrollment is shown for the new one.
    ///
    /// # Errors
    /// When the file exists and cannot be deleted.
    pub fn reset(&self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Reads the file; `None` when it is missing or unreadable.
    #[must_use]
    pub fn read(&self) -> Option<AgentState> {
        let text = std::fs::read(&self.path).ok()?;
        serde_json::from_slice(&text).ok()
    }
}

/// The handle of [`StateFile::spawn_writer`].
#[derive(Debug)]
pub struct StateWriter {
    tx: std::sync::Arc<tokio::sync::watch::Sender<Option<AgentState>>>,
    task: tokio::task::JoinHandle<()>,
}

/// Changes one field of the state a [`StateWriter`] holds, from another task (the node's approval, which can change in
/// the middle of a session). Holds the writer weakly: it never keeps the writer from finishing.
#[derive(Debug, Clone)]
pub struct StatePatcher(std::sync::Weak<tokio::sync::watch::Sender<Option<AgentState>>>);

impl StatePatcher {
    /// Records the node's approval, if a state is queued and it says otherwise.
    pub fn set_pending_approval(&self, pending: bool) {
        if let Some(tx) = self.0.upgrade() {
            tx.send_if_modified(|state| match state {
                Some(s) if s.pending_approval != Some(pending) => {
                    s.pending_approval = Some(pending);
                    true
                }
                _ => false,
            });
        }
    }
}

/// How long [`StateWriter::finish`] waits for the last write.
const FINISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

impl StateWriter {
    /// Queues `state`. Never blocks.
    pub fn set(&self, state: AgentState) {
        self.tx.send_replace(Some(state));
    }

    /// A handle that changes single fields of the queued state.
    #[must_use]
    pub fn patcher(&self) -> StatePatcher {
        StatePatcher(std::sync::Arc::downgrade(&self.tx))
    }

    /// Writes what is queued (bounded), then stops.
    pub async fn finish(self) {
        let StateWriter { tx, task } = self;
        drop(tx);
        let _ = tokio::time::timeout(FINISH_TIMEOUT, task).await;
    }
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.unix_timestamp().to_string())
}

/// The text of `p2pc-agent status`: enrolled or not, the server, the last connection state and the last `Welcome`.
#[must_use]
pub fn render_status(config: &Config, state: Option<&AgentState>) -> String {
    let mut out = String::new();
    match &config.server {
        None => {
            let _ = writeln!(out, "Enrolled:      no (run `p2pc-agent join` with a join token)");
        }
        Some(server) => {
            let _ = writeln!(
                out,
                "Enrolled:      yes (node {}, account {})",
                server.agent_node_id, server.account_id
            );
            let _ = writeln!(out, "Server NodeId: {}", server.node_id);
        }
    }
    // The state file may be from an earlier enrollment (another server, or before `join --force` to the same one): only
    // show it when both IDs are this enrollment's (T05b review P3, and the T05b real run, round 2).
    let current = config
        .server
        .as_ref()
        .map(|s| (s.node_id.as_str(), s.agent_node_id.to_string()));
    match state {
        _ if current.is_none() => {
            let _ = writeln!(out, "Connection:    not enrolled");
        }
        None => {
            let _ = writeln!(out, "Connection:    unknown (`p2pc-agent run` has not run yet)");
            let _ = writeln!(out, "Last Welcome:  never");
        }
        Some(s) if !current.as_ref().is_some_and(|(server, node)| s.is_of(server, node)) => {
            let _ = writeln!(out, "Connection:    not run since this enrollment");
            let _ = writeln!(out, "Last Welcome:  never");
        }
        Some(s) => {
            let _ = writeln!(
                out,
                "Connection:    {} (since {})",
                s.connection.describe(),
                rfc3339(s.since)
            );
            let welcome = s.last_welcome_at.map_or_else(|| "never".to_string(), rfc3339);
            let _ = writeln!(out, "Last Welcome:  {welcome}");
        }
    }
    out
}

/// The node phrase of an iroh NodeId (H2 §5.5): six words the owner compares with the hub PC's screen before approving.
#[must_use]
pub fn node_phrase(iroh_node_id: &iroh_base::PublicKey) -> String {
    p2pc_proto::invite::node_phrase(&p2pc_proto::pair::EndpointKey::from_bytes(*iroh_node_id.as_bytes())).to_string()
}

/// The state file, if it is of the current enrollment of `config` (see [`render_status`]).
fn current_state<'a>(config: &Config, state: Option<&'a AgentState>) -> Option<&'a AgentState> {
    let server = config.server.as_ref()?;
    state.filter(|s| s.is_of(&server.node_id, &server.agent_node_id.to_string()))
}

/// The lines `p2pc-agent status` adds for H2 (H2 §5.5, §8.4): the node phrase, the approval and the owner's pause.
#[must_use]
pub fn render_node(config: &Config, state: Option<&AgentState>, iroh_node_id: Option<&iroh_base::PublicKey>) -> String {
    let mut out = String::new();
    if let Some(id) = iroh_node_id {
        let _ = writeln!(out, "Node phrase:   {}", node_phrase(id));
    }
    if let Some(pending) = current_state(config, state).and_then(|s| s.pending_approval) {
        let approval = if pending {
            "waiting for approval on your hub PC (compare the node phrase)"
        } else {
            "approved"
        };
        let _ = writeln!(out, "Approval:      {approval}");
    }
    let sharing = if config.share.paused {
        "paused by the owner (new work is refused; running work continues)"
    } else {
        "on"
    };
    let _ = writeln!(out, "Sharing:       {sharing}");
    out
}

/// `p2pc-agent status --json`, read by the desktop app (H2 §5.4 step 2, §8.4, §8.8, §14.2). Every key is always
/// present, `null` when unknown. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusJson {
    /// This agent's version.
    pub agent_version: String,
    /// This node's iroh NodeId (64 hex characters), also before enrollment (H2 §5.4 step 2); `null` when the identity
    /// cannot be read.
    pub iroh_node_id: Option<String>,
    /// The node phrase of `iroh_node_id` (H2 §5.5).
    pub node_phrase: Option<String>,
    /// Whether `[server]` is set.
    pub enrolled: bool,
    /// This node's ID on the hub.
    pub node_id: Option<String>,
    /// The owner's account.
    pub account_id: Option<String>,
    /// The hub's iroh NodeId.
    pub server_node_id: Option<String>,
    /// Whether `p2pc-agent run` holds the data dir now.
    pub agent_running: bool,
    /// The last connection state of this enrollment.
    pub connection: Option<ConnectionState>,
    /// Since when.
    #[serde(with = "time::serde::rfc3339::option")]
    pub connection_since: Option<OffsetDateTime>,
    /// The last `Welcome`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_welcome_at: Option<OffsetDateTime>,
    /// The hub's version from the last `Welcome` (H2 §14.2).
    pub server_version: Option<String>,
    /// Whether the node waits for approval on the hub PC (H2 §5.5, `join_pending` in §8.8).
    pub pending_approval: Option<bool>,
    /// Whether the owner paused sharing (`owner_paused`, H2 §8.4).
    pub owner_paused: bool,
}

/// Builds [`StatusJson`] from the config, the state file and the identity.
#[must_use]
pub fn status_json(
    config: &Config,
    state: Option<&AgentState>,
    iroh_node_id: Option<&iroh_base::PublicKey>,
    agent_running: bool,
) -> StatusJson {
    let server = config.server.as_ref();
    let state = current_state(config, state);
    StatusJson {
        agent_version: crate::inventory::AGENT_VERSION.to_string(),
        iroh_node_id: iroh_node_id.map(ToString::to_string),
        node_phrase: iroh_node_id.map(node_phrase),
        enrolled: server.is_some(),
        node_id: server.map(|s| s.agent_node_id.to_string()),
        account_id: server.map(|s| s.account_id.to_string()),
        server_node_id: server.map(|s| s.node_id.clone()),
        agent_running,
        connection: state.map(|s| s.connection),
        connection_since: state.map(|s| s.since),
        last_welcome_at: state.and_then(|s| s.last_welcome_at),
        server_version: state.and_then(|s| s.server_version.clone()),
        pending_approval: state.and_then(|s| s.pending_approval),
        owner_paused: config.share.paused,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::config::{Env, ServerSection};

    fn config() -> Config {
        Config::parse(
            "",
            &Env {
                root: false,
                home: Some("/home/p2pc".into()),
                config_env: None,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn the_state_file_round_trips_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let file = StateFile::in_dir(dir.path());
        assert_eq!(file.read(), None);
        let mut state = AgentState::new(
            ConnectionState::Connected,
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            "d75a98".into(),
            Some("node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4".into()),
        );
        state.last_welcome_at = Some(OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap());
        file.write(&state);
        assert_eq!(file.read(), Some(state.clone()));
        let mode = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Replaced, never appended; no temporary file left.
        file.write(&AgentState {
            connection: ConnectionState::BackingOff,
            ..state
        });
        assert_eq!(file.read().unwrap().connection, ConnectionState::BackingOff);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        // `join` deletes it; deleting a missing file is fine.
        file.reset().unwrap();
        assert_eq!(file.read(), None);
        file.reset().unwrap();
    }

    #[tokio::test]
    async fn the_writer_writes_off_the_runtime_and_the_last_state_wins() {
        let dir = tempfile::tempdir().unwrap();
        let file = StateFile::in_dir(dir.path());
        let writer = file.clone().spawn_writer();
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        for connection in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Stopped,
        ] {
            writer.set(AgentState::new(connection, at, "x".into(), None));
        }
        writer.finish().await;
        assert_eq!(file.read().unwrap().connection, ConnectionState::Stopped);
    }

    fn key() -> iroh_base::PublicKey {
        iroh_base::SecretKey::from_bytes(&[7u8; 32]).public()
    }

    fn enrolled(c: &mut Config) -> (String, String) {
        let node = p2pc_proto::ids::NodeId::generate();
        let server = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();
        c.server = Some(ServerSection {
            node_id: server.clone(),
            relays: vec![],
            account_id: p2pc_proto::ids::AccountId::generate(),
            agent_node_id: node,
        });
        (server, node.to_string())
    }

    /// H2 §5.4 step 2, §5.5: before enrollment, `status --json` already gives the iroh NodeId and its node phrase, and
    /// every key is present (`null` when unknown).
    #[test]
    fn status_json_before_enrollment_has_the_node_id_and_the_node_phrase() {
        let c = config();
        let status = status_json(&c, None, Some(&key()), false);
        let v = serde_json::to_value(&status).unwrap();
        assert_eq!(v["iroh_node_id"], key().to_string());
        assert_eq!(v["iroh_node_id"].as_str().unwrap().len(), 64);
        let expected = p2pc_proto::invite::node_phrase(&p2pc_proto::pair::EndpointKey::from_bytes(*key().as_bytes()));
        assert_eq!(v["node_phrase"], expected.to_string());
        assert_eq!(v["node_phrase"].as_str().unwrap().split(' ').count(), 6);
        assert_eq!(v["enrolled"], false);
        assert_eq!(v["owner_paused"], false);
        assert_eq!(v["agent_version"], env!("CARGO_PKG_VERSION"));
        for key in [
            "node_id",
            "account_id",
            "server_node_id",
            "connection",
            "connection_since",
            "last_welcome_at",
            "server_version",
            "pending_approval",
        ] {
            assert!(v.get(key).is_some_and(serde_json::Value::is_null), "{key}: {v}");
        }
        // Nothing secret: the only key material is the public NodeId.
        assert_eq!(v.as_object().unwrap().len(), 14);
    }

    #[test]
    fn status_json_reports_this_enrollments_state_only() {
        let mut c = config();
        let (server, node) = enrolled(&mut c);
        c.share.paused = true;
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut state = AgentState::new(ConnectionState::Connected, at, server, Some(node));
        state.last_welcome_at = Some(at);
        state.server_version = Some("0.2.0".into());
        state.pending_approval = Some(true);
        let v = serde_json::to_value(status_json(&c, Some(&state), Some(&key()), true)).unwrap();
        assert_eq!(v["enrolled"], true);
        assert_eq!(v["agent_running"], true);
        assert_eq!(v["connection"], "connected");
        assert_eq!(v["connection_since"], "2027-01-15T08:00:00Z");
        assert_eq!(v["last_welcome_at"], "2027-01-15T08:00:00Z");
        assert_eq!(v["server_version"], "0.2.0");
        assert_eq!(v["pending_approval"], true);
        assert_eq!(v["owner_paused"], true);
        assert_eq!(v["server_node_id"], c.server.as_ref().unwrap().node_id);
        // A state file of an earlier enrollment says nothing about this one.
        let old = AgentState {
            agent_node_id: Some(p2pc_proto::ids::NodeId::generate().to_string()),
            ..state
        };
        let v = serde_json::to_value(status_json(&c, Some(&old), Some(&key()), false)).unwrap();
        assert!(v["connection"].is_null() && v["pending_approval"].is_null() && v["server_version"].is_null());
    }

    #[test]
    fn status_text_shows_the_node_phrase_the_approval_and_the_pause() {
        let mut c = config();
        let text = render_node(&c, None, Some(&key()));
        assert!(
            text.contains(&format!("Node phrase:   {}", node_phrase(&key()))),
            "{text}"
        );
        assert!(!text.contains("Approval:"), "{text}");
        assert!(text.contains("Sharing:       on"), "{text}");
        assert!(!render_node(&c, None, None).contains("Node phrase"));
        let (server, node) = enrolled(&mut c);
        c.share.paused = true;
        let mut state = AgentState::new(
            ConnectionState::Connected,
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            server,
            Some(node),
        );
        state.pending_approval = Some(true);
        let text = render_node(&c, Some(&state), Some(&key()));
        assert!(
            text.contains("Approval:      waiting for approval on your hub PC"),
            "{text}"
        );
        assert!(text.contains("Sharing:       paused by the owner"), "{text}");
        state.pending_approval = Some(false);
        assert!(render_node(&c, Some(&state), None).contains("Approval:      approved"));
    }

    /// `NodeApproved` comes in the middle of a session: the patcher changes the queued state at once, and never keeps
    /// the writer from finishing.
    #[tokio::test]
    async fn the_patcher_records_the_approval_and_never_outlives_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let file = StateFile::in_dir(dir.path());
        let writer = file.clone().spawn_writer();
        let patcher = writer.patcher();
        // Nothing queued yet: nothing to patch.
        patcher.set_pending_approval(true);
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut state = AgentState::new(ConnectionState::Connected, at, "x".into(), None);
        state.pending_approval = Some(true);
        writer.set(state);
        patcher.set_pending_approval(false);
        let started = tokio::time::Instant::now();
        writer.finish().await;
        assert!(started.elapsed() < FINISH_TIMEOUT, "the patcher kept the writer alive");
        assert_eq!(file.read().unwrap().pending_approval, Some(false));
        // After the writer, a patch does nothing.
        patcher.set_pending_approval(true);
        assert_eq!(file.read().unwrap().pending_approval, Some(false));
    }

    #[test]
    fn status_text() {
        let mut c = config();
        let text = render_status(&c, None);
        assert!(text.contains("Enrolled:      no"), "{text}");
        assert!(text.contains("Connection:    not enrolled"), "{text}");
        let node = p2pc_proto::ids::NodeId::generate();
        c.server = Some(ServerSection {
            node_id: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
            relays: vec![],
            account_id: p2pc_proto::ids::AccountId::generate(),
            agent_node_id: node,
        });
        let state = AgentState::new(
            ConnectionState::Connected,
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
            Some(node.to_string()),
        );
        assert!(render_status(&c, None).contains("has not run yet"));
        let text = render_status(&c, Some(&state));
        assert!(text.contains("Enrolled:      yes (node node_"), "{text}");
        assert!(text.contains("Server NodeId: d75a98"), "{text}");
        assert!(
            text.contains("Connection:    connected (since 2027-01-15T08:00:00Z)"),
            "{text}"
        );
        assert!(text.contains("Last Welcome:  never"), "{text}");
        // A state file from an earlier enrollment (another server) is not this one's connection.
        let old = AgentState {
            server_node_id: "another-server".into(),
            last_welcome_at: Some(OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()),
            ..state.clone()
        };
        let text = render_status(&c, Some(&old));
        assert!(text.contains("Connection:    not run since this enrollment"), "{text}");
        assert!(!text.contains("connected"), "{text}");
        assert!(text.contains("Last Welcome:  never"), "{text}");
        // The same server, but an earlier node: `join --force` to the same server after `p2pc machines rm` (T05b real
        // run, round 2). Also a file from before T10a, with no node ID.
        for agent_node_id in [Some(p2pc_proto::ids::NodeId::generate().to_string()), None] {
            let earlier = AgentState {
                connection: ConnectionState::NotEnrolled,
                agent_node_id,
                last_welcome_at: Some(OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()),
                ..state.clone()
            };
            let text = render_status(&c, Some(&earlier));
            assert!(text.contains("Connection:    not run since this enrollment"), "{text}");
            assert!(!text.contains("not enrolled"), "{text}");
            assert!(text.contains("Last Welcome:  never"), "{text}");
        }
        // Not enrolled: whatever an old state file says.
        c.server = None;
        assert!(render_status(&c, Some(&old)).contains("Connection:    not enrolled"));
    }
}
