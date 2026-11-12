// SPDX-License-Identifier: Apache-2.0

//! `p2pc-agent`: the P2PC node daemon.
//!
//! - T07: the local core: `config show`, `identity`, `inventory` and `doctor`.
//! - T05b: `join` (enrollment with a join token), `run` (the connection to the control plane) and `status`.
//! - T2-23 (H2): `status --json` (with the iroh NodeId before enrollment, the node phrase and the approval),
//!   `share set` (share changes and the owner's pause, H2 §8.4) and `leave` (H2 §6.1, §8.7).

use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use p2pc_agent::config::{Config, ConfigSource, Env, GpuShare, Hardware, ShareUpdate, ShareWatcher};
use p2pc_agent::connection::daemon::Daemon;
use p2pc_agent::connection::endpoint::{IrohConnector, relay_mode, server_addr};
use p2pc_agent::connection::exit;
use p2pc_agent::connection::gate::{GateFile, render_gate};
use p2pc_agent::connection::join::{JoinError, enroll};
use p2pc_agent::connection::load::LoadMeter;
use p2pc_agent::connection::session::{
    Approval, INVENTORY_INTERVAL, LeaveEnd, LeaveRequest, MAX_PENDING_DECISIONS, NodeControls, Shared, leave_node,
};
use p2pc_agent::connection::state::{StateFile, render_node, render_status, status_json};
use p2pc_agent::connection::token::{self, TokenText};
use p2pc_agent::connection::watchdog::Watchdog;
use p2pc_agent::connection::{Connector as _, DetectInventory, Uplink};
use p2pc_agent::doctor::{self, Findings, IdentityState};
use p2pc_agent::executor::SystemClock;
use p2pc_agent::executor::status::{LeasesFile, render_leases};
use p2pc_agent::host::Host;
use p2pc_agent::identity::{IDENTITY_FILE, Identity};
use p2pc_agent::inventory;
use p2pc_agent::node::{self, Node, NodeFacts, lock_data_dir};
use p2pc_agent::runner::SystemRunner;
use p2pc_net::{current_selection, watch_network};

/// P2PC node agent.
#[derive(Debug, Parser)]
#[command(name = "p2pc-agent", version, about)]
struct Cli {
    /// The config file. Default: $P2PC_AGENT_CONFIG, then /etc/p2pc/agent.toml as root, otherwise
    /// ~/.config/p2pc-agent/agent.toml.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the agent daemon: keep a connection to the control plane.
    Run,
    /// Enroll this machine with a control plane using a join token.
    ///
    /// Prefer piping the token on stdin (`-` or no argument): an argument is visible to every user in `ps`.
    Join {
        /// The join token created with `p2pc join-token create`, or `-` to read it from stdin (the default).
        token: Option<String>,
        /// Enroll again even if this machine is already enrolled.
        #[arg(long)]
        force: bool,
    },
    /// Show whether this machine is enrolled and the last connection state. Needs no network.
    Status {
        /// Print JSON for the desktop app: this node's iroh NodeId (created on first use, also before `join`) and node
        /// phrase, the enrollment, the last connection state, the approval and the owner's pause.
        #[arg(long)]
        json: bool,
    },
    /// Change what this machine offers.
    Share {
        #[command(subcommand)]
        action: ShareAction,
    },
    /// Ask the hub to remove this node, then stop (exit code 7 once the hub removed it). Run by the desktop app on
    /// uninstall.
    Leave {
        /// Why, for the hub's audit log.
        #[arg(long, default_value = "leave", value_name = "TEXT")]
        reason: String,
    },
    /// Inspect the configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Print this node's public NodeId, creating the identity key on first use.
    Identity,
    /// Detect what this machine has and what it offers. Changes nothing.
    Inventory {
        /// Print JSON: the wire inventory plus agent-local details.
        #[arg(long)]
        json: bool,
    },
    /// Check that this machine is ready to run jobs, with a fix hint for each problem. Never applies a fix.
    Doctor,
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Print the effective configuration, with defaults filled in.
    Show,
}

#[derive(Debug, Subcommand)]
enum ShareAction {
    /// Change the share limits or pause sharing. Checked against this machine (never above its hardware), written to
    /// agent.toml atomically, and applied by a running agent within seconds. Options left out keep their value.
    Set {
        /// vCPUs to offer; fractions allowed.
        #[arg(long, value_name = "CORES")]
        cpu: Option<f64>,
        /// Memory to offer, in MiB.
        #[arg(long, value_name = "MIB")]
        memory_mb: Option<u64>,
        /// GPUs to offer: `all`, `none`, or GPU UUIDs separated by commas.
        #[arg(long, value_name = "all|none|UUIDS")]
        gpu: Option<GpuShare>,
        /// Disk for job directories, in MiB.
        #[arg(long, value_name = "MIB")]
        disk_mb: Option<u64>,
        /// Disk for persistent volumes, in MiB.
        #[arg(long, value_name = "MIB")]
        volumes_mb: Option<u64>,
        /// Pause sharing (`true`: new work is refused, running work continues) or resume it (`false`).
        #[arg(long, value_name = "true|false")]
        paused: Option<bool>,
    },
}

/// How long `leave` may take in all: the desktop app gives it 10 s (H2 §8.7), detection and dial included.
const LEAVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

fn describe(source: &ConfigSource) -> String {
    let path = source.path().display();
    let origin = match source {
        ConfigSource::Flag(_) => "from --config",
        ConfigSource::Env(_) => "from $P2PC_AGENT_CONFIG",
        ConfigSource::Default(_) => "default path",
    };
    if source.path().exists() {
        format!("{path} ({origin})")
    } else {
        format!("{path} ({origin}; not found: built-in defaults)")
    }
}

fn load(cli: &Cli, env: &Env) -> anyhow::Result<(ConfigSource, Config)> {
    let source = env.config_source(cli.config.as_deref())?;
    let config = Config::load(&source, env)?;
    Ok((source, config))
}

fn block_on<F: std::future::Future>(f: F) -> anyhow::Result<F::Output> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    Ok(rt.block_on(f))
}

fn config_show(cli: &Cli, env: &Env) -> anyhow::Result<ExitCode> {
    let (source, mut config) = load(cli, env)?;
    // Fill the hardware-dependent defaults from /proc only; GPUs are checked by `inventory`, which runs nvidia-smi.
    let host = Host::system();
    let probe_cpu = host
        .read("/proc/cpuinfo")
        .map(|t| p2pc_agent::parse::cpuinfo(&t).logical);
    let cores = probe_cpu.ok().filter(|&n| n > 0).unwrap_or(1);
    let memory_mb = host
        .read("/proc/meminfo")
        .ok()
        .and_then(|t| p2pc_agent::parse::meminfo_total_mb(&t))
        .context("cannot read the RAM size from /proc/meminfo")?;
    let resolved = config.share.resolve(&Hardware {
        cores,
        memory_mb,
        disk_mb: None,
        gpus: &[],
        gpu_detection_ok: false,
    })?;
    config.share.cpu_cores = Some(resolved.cpu_cores);
    config.share.memory_mb = Some(resolved.memory_mb);
    config.share.disk_mb = Some(resolved.disk_mb);
    config.share.volumes_mb = Some(config.share.volumes_mb());
    println!("# Effective p2pc-agent configuration");
    println!("# source: {}", describe(&source));
    println!("# GPU UUIDs and the disk size are checked against the hardware by `p2pc-agent inventory`.");
    print!("{}", toml::to_string(&config).context("cannot render the config")?);
    Ok(ExitCode::SUCCESS)
}

fn identity(cli: &Cli, env: &Env) -> anyhow::Result<ExitCode> {
    let (_, config) = load(cli, env)?;
    let id = Identity::load_or_create(&config.data_dir)?;
    println!("{}", id.node_id());
    Ok(ExitCode::SUCCESS)
}

fn inventory_cmd(cli: &Cli, env: &Env, json: bool) -> anyhow::Result<ExitCode> {
    let (_, config) = load(cli, env)?;
    let report = block_on(inventory::detect(&Host::system(), &SystemRunner::default(), &config))??;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", doctor::inventory_text(&report));
    }
    Ok(ExitCode::SUCCESS)
}

fn doctor_cmd(cli: &Cli, env: &Env) -> anyhow::Result<ExitCode> {
    let source = env.config_source(cli.config.as_deref())?;
    let (config, config_error) = match Config::load(&source, env) {
        Ok(c) => (c, None),
        Err(e) => (Config::parse("", env)?, Some(e.to_string())),
    };
    let identity = if config.data_dir.join(IDENTITY_FILE).exists() {
        match Identity::load(&config.data_dir) {
            Ok(id) => IdentityState::Ok(id.node_id().to_string()),
            Err(e) => IdentityState::Refused(e.to_string()),
        }
    } else {
        IdentityState::Missing
    };
    let probe = block_on(inventory::probe(
        &Host::system(),
        &SystemRunner::default(),
        config.runtime,
        &config.data_dir,
        config.detect_timeout(),
    ))?;
    let report = probe.clone().report(&config);
    // Skipped (and said so) on a fresh machine with no data dir yet, and when doctor runs as another user than the
    // data dir's owner (`sudo p2pc-agent doctor`).
    let egress_socket = doctor::check_egress_socket(&config.data_dir);
    let (text, ready) = doctor::render(&Findings {
        config_source: describe(&source),
        config_error,
        identity,
        probe: &probe,
        report: &report,
        egress_socket,
    });
    print!("{text}");
    Ok(if ready { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

/// `p2pc-agent join`. Never prints or logs the token (SI-6).
fn join_cmd(cli: &Cli, env: &Env, token: Option<&str>, force: bool) -> anyhow::Result<ExitCode> {
    let (source, config) = load(cli, env)?;
    if let Some(server) = &config.server
        && !force
    {
        eprintln!(
            "error: this machine is already enrolled (node {}, server {}). Run `p2pc-agent join --force` to enroll it \
             again; delete the old node on its server with `p2pc machines`.",
            server.agent_node_id, server.node_id
        );
        return Ok(ExitCode::from(exit::ALREADY_ENROLLED));
    }
    if token::in_argv(token) {
        // Compatible, but the token was in argv, visible to every user in `ps` (T14b2 review). Never echo it.
        eprintln!("warning: {}", token::ARGV_WARNING);
    }
    let token = match TokenText::from_arg_or_stdin(token).and_then(|t| t.decode()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(ExitCode::from(exit::INVALID_TOKEN));
        }
    };
    if p2pc_agent::connection::join::expired_locally(&token, time::OffsetDateTime::now_utc()) {
        eprintln!("error: {}", JoinError::Expired);
        return Ok(ExitCode::from(exit::TOKEN_EXPIRED));
    }
    // Like `run` (T10a review, P3-4): the identity and the config are replaced under the data dir's lock, so a running
    // agent is never left with a new key beneath it (T10c). Held until `join` returns.
    let _lock = match lock_data_dir(&config.data_dir) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(ExitCode::from(exit::FAILURE));
        }
    };
    let rt = runtime()?;
    let result = rt.block_on(async {
        let id = Identity::load_or_create(&config.data_dir)?;
        let report = inventory::detect(&Host::system(), &SystemRunner::default(), &config).await?;
        let relays = if config.iroh.relays.is_empty() {
            token.relays.iter().map(ToString::to_string).collect()
        } else {
            config.iroh.relays.clone()
        };
        let connector = IrohConnector::new(
            id.secret_key().clone(),
            relay_mode(&relays)?,
            server_addr(&token.server, &relays)?,
            current_selection(&config.iroh.direct_addresses).await,
        );
        let hostname = report.inventory.hostname.clone();
        match enroll(
            &connector,
            &token,
            report.inventory,
            source.path(),
            env,
            &config.data_dir,
        )
        .await
        {
            Ok((joined, section)) => {
                println!(
                    "Enrolled: node {} (hostname {hostname}; the server names the node after it).",
                    joined.node_id
                );
                println!("Server:   {} (version {})", section.node_id, joined.server_version);
                println!("Owner:    account {}", joined.account_id);
                println!("{}", p2pc_agent::config::saved_hint(source.path(), env.supervised));
                anyhow::Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("error: {e}");
                anyhow::Ok(ExitCode::from(e.exit_code()))
            }
        }
    });
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

/// `p2pc-agent run`.
fn run_cmd(cli: &Cli, env: &Env) -> anyhow::Result<ExitCode> {
    let (source, config) = load(cli, env)?;
    let env = env.clone();
    let Some(server) = config.server.clone() else {
        eprintln!("error: this machine is not enrolled yet; run `p2pc-agent join` with a join token first");
        return Ok(ExitCode::from(exit::NOT_JOINED));
    };
    init_logging();
    // One agent per data dir (T10a review, P3-4), before anything touches it.
    let _lock = match lock_data_dir(&config.data_dir) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(ExitCode::from(exit::FAILURE));
        }
    };
    let rt = runtime()?;
    let result = rt.block_on(async move {
        let id = Identity::load(&config.data_dir)?;
        let relays = config.relays();
        let bind = current_selection(&config.iroh.direct_addresses).await;
        let connector = IrohConnector::new(
            id.secret_key().clone(),
            relay_mode(&relays)?,
            server_addr(&server.node_id, &relays)?,
            bind.clone(),
        );
        // What the gate says goes to `p2pc-agent status` (T10l): a file from an earlier run is not this run's.
        let gate_file = GateFile::in_dir(&config.data_dir);
        gate_file.reset();
        tokio::spawn(gate_file.keep(connector.egress_report(), time::OffsetDateTime::now_utc));
        let host = Host::system();
        let ttl = std::time::Duration::from_secs(config.agent_lease_ttl_s);
        // The lease executor (T10a): the sandbox driver as this node can build it now, the executor on top of it, the
        // leftovers of an earlier process swept before the first Hello (no checkpointing in v0.1, §9).
        let uplink = Uplink::new();
        let facts = NodeFacts::detect(&host, &config).await;
        let Node {
            executor,
            offers,
            ingress,
            volumes,
        } = node::build(
            &config,
            facts,
            server.account_id,
            uplink.clone(),
            connector.public_addrs(),
            connector.egress_ready(),
            Arc::new(SystemClock),
        );
        executor.startup().await;
        let _leases = executor.spawn_status_writer(LeasesFile::in_dir(&config.data_dir));
        let executor = Arc::new(executor);
        // `p2pc-agent share set` runs as another process: the share in force follows agent.toml (H2 §8.4).
        let (share, _share_watcher) = ShareWatcher::new(source, env, config.share.clone()).spawn();
        // Volume upkeep (H2 §11.3): retries the removal of containers that still hold a volume, and expires unused
        // volumes.
        tokio::spawn(node::keep_volumes(executor.clone()));
        let shared = Shared {
            owner: server.account_id,
            agent_lease_ttl: ttl,
            watchdog: Watchdog::new(ttl),
            supervisor: executor.clone(),
            handler: executor,
            inventory: Arc::new(DetectInventory {
                host: host.clone(),
                config: config.clone(),
                offers: Some(offers),
                live_share: Some(share.clone()),
            }),
            load: Arc::new(LoadMeter::new(host)),
            inventory_interval: INVENTORY_INTERVAL,
            decisions: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_DECISIONS)),
            uplink,
            // The hub's port streams go through the driver's ingress bridge (H2 §6.1, §11.2).
            ports: Some(Arc::new(ingress)),
            // The owner's pause and share changes, and the node's approval (H2 §5.5, §8.4).
            node: Some(NodeControls {
                share,
                approval: Approval::new(),
            }),
            // `VolumeReport` and `VolumeDelete` (H2 §6.1), when the node offers volume space.
            volumes,
        };
        let daemon = Daemon {
            shared,
            connector: Arc::new(connector),
            backoff_seed: rand::random(),
            state_file: Some(StateFile::in_dir(&config.data_dir)),
            server_node_id: server.node_id.clone(),
            agent_node_id: server.agent_node_id.to_string(),
        };
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            wait_for_signal().await;
            tracing::info!("stopping");
            let _ = stop_tx.send(true);
        });
        let (net_tx, net_rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(watch_network(config.iroh.direct_addresses.clone(), bind, net_tx));
        tracing::info!(node_id = %id.node_id(), server = %server.node_id, "p2pc-agent running");
        anyhow::Ok(ExitCode::from(daemon.run(stop_rx, net_rx).await.code()))
    });
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

/// SIGTERM or SIGINT.
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("P2PC_AGENT_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,iroh=warn,noq=warn,netwatch=warn"));
    let ansi = use_ansi(std::io::stderr().is_terminal(), std::env::var_os("NO_COLOR").as_deref());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .try_init();
}

/// Whether the agent's own log carries ANSI colour codes: only on a terminal, and never when `NO_COLOR` is set to
/// a non-empty value (<https://no-color.org>). Under systemd, stderr is the journal, and the codes would be
/// literal bytes in every line.
fn use_ansi(stderr_is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    stderr_is_terminal && no_color.is_none_or(|v| v.is_empty())
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")
}

/// `p2pc-agent status`: local files only. With `--json`, the identity is created when missing, so the desktop app gets
/// this node's iroh NodeId before `join` (H2 §5.4 step 2); the plain text only reads it.
fn status_cmd(cli: &Cli, env: &Env, json: bool) -> anyhow::Result<ExitCode> {
    let (_, config) = load(cli, env)?;
    let state = StateFile::in_dir(&config.data_dir).read();
    if json {
        // The key is created only before enrollment (H2 §5.4 step 2). On an enrolled node a missing key is a lost
        // identity, never replaced by a new one here: `run` would dial with an unknown NodeId and stop as removed
        // (review P3 of T2-23). A key that cannot be read is reported as `null`.
        let identity = if config.server.is_none() {
            Identity::load_or_create(&config.data_dir)
        } else {
            Identity::load(&config.data_dir)
        };
        let identity = identity
            .inspect_err(|e| eprintln!("warning: cannot read this node's identity: {e}"))
            .ok();
        let running = p2pc_agent::node::agent_running(&config.data_dir);
        let node_id = identity.as_ref().map(Identity::node_id);
        let status = status_json(&config, state.as_ref(), node_id.as_ref(), running);
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(ExitCode::SUCCESS);
    }
    let identity = if config.data_dir.join(IDENTITY_FILE).exists() {
        Identity::load(&config.data_dir).ok()
    } else {
        None
    };
    print!("{}", render_status(&config, state.as_ref()));
    print!(
        "{}",
        render_node(
            &config,
            state.as_ref(),
            identity.as_ref().map(Identity::node_id).as_ref()
        )
    );
    if config.server.is_some() {
        let running = p2pc_agent::node::agent_running(&config.data_dir);
        print!(
            "{}",
            render_gate(GateFile::in_dir(&config.data_dir).read().as_ref(), running)
        );
        let leases = LeasesFile::in_dir(&config.data_dir).read();
        print!("{}", render_leases(leases.as_ref(), time::OffsetDateTime::now_utc()));
    }
    Ok(ExitCode::SUCCESS)
}

/// `p2pc-agent share set` (H2 §8.4): the new share is checked against this machine with a full detection (as `run` does
/// at start: never above the hardware, listed GPUs must exist), then only the keys given are written into agent.toml,
/// atomically. A running agent applies it within seconds ([`ShareWatcher`]).
fn share_set_cmd(cli: &Cli, env: &Env, update: &ShareUpdate) -> anyhow::Result<ExitCode> {
    if update.is_empty() {
        eprintln!(
            "error: nothing to change: give at least one of --cpu, --memory-mb, --gpu, --disk-mb, --volumes-mb, --paused"
        );
        return Ok(ExitCode::from(exit::FAILURE));
    }
    let (source, mut config) = load(cli, env)?;
    config.share = update.apply(&config.share);
    // Pausing and resuming change nothing that is offered, so they never wait on (or fail on) the hardware check: an
    // owner must be able to pause even when the share in force no longer matches the machine (review P3 of T2-23).
    if let Some(paused) = update.only_pause() {
        p2pc_agent::config::write_share_update(source.path(), update, env)?;
        println!(
            "Sharing {}. Saved in {}.",
            if paused {
                "paused: new work is refused, running work continues"
            } else {
                "resumed"
            },
            source.path().display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let report = match block_on(inventory::detect(&Host::system(), &SystemRunner::default(), &config))? {
        Ok(report) => report,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(ExitCode::from(exit::FAILURE));
        }
    };
    p2pc_agent::config::write_share_update(source.path(), update, env)?;
    let share = &report.local.share;
    println!(
        "Share: {} vCPU, {} MiB RAM, {} GPU(s), {} MiB disk for jobs, {} MiB for volumes{}.",
        share.cpu_cores,
        share.memory_mb,
        share.gpus.len(),
        share.disk_mb,
        config.share.volumes_mb(),
        if config.share.paused { "; paused" } else { "" }
    );
    for warning in &share.warnings {
        println!("warning: {warning}");
    }
    println!("Saved in {}.", source.path().display());
    Ok(ExitCode::SUCCESS)
}

/// `p2pc-agent leave` (H2 §6.1, §8.7): its own connection to the hub, `Leave`, and exit 7 once the hub removed the node.
/// A running agent's connection is replaced by this one; when it reconnects it is told `not_enrolled` and exits 7 too.
fn leave_cmd(cli: &Cli, env: &Env, reason: &str) -> anyhow::Result<ExitCode> {
    let (_, config) = load(cli, env)?;
    let Some(server) = config.server.clone() else {
        eprintln!("error: this machine is not enrolled");
        return Ok(ExitCode::from(exit::NOT_JOINED));
    };
    let leave = p2pc_proto::protocol::Leave {
        reason: reason.to_string(),
    };
    if let Err(e) = leave.validate() {
        eprintln!("error: --reason: {e}");
        return Ok(ExitCode::from(exit::FAILURE));
    }
    let rt = runtime()?;
    let result = rt.block_on(async move {
        let id = Identity::load(&config.data_dir)?;
        let relays = config.relays();
        let connector = IrohConnector::new(
            id.secret_key().clone(),
            relay_mode(&relays)?,
            server_addr(&server.node_id, &relays)?,
            current_selection(&config.iroh.direct_addresses).await,
        );
        // The leases a running agent holds go into Hello, so the hub's reconciliation does not take them for lost if
        // the Leave never lands. Without a running agent, nothing runs: the leases file is an earlier run's.
        let running = if p2pc_agent::node::agent_running(&config.data_dir) {
            LeasesFile::in_dir(&config.data_dir)
                .read()
                .map(|s| {
                    s.leases
                        .iter()
                        .map(|l| p2pc_proto::protocol::RunningLease::new(l.lease_id, l.epoch))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // The detection is inside the 10 s budget too (review P3 of T2-23).
        let detect = async {
            inventory::detect_periodic(&Host::system(), &SystemRunner::default(), &config)
                .await
                .map(|report| report.inventory)
                .map_err(|e| e.to_string())
        };
        let request = LeaveRequest {
            owner: server.account_id,
            running,
            leave,
        };
        let end = leave_node(&connector, detect, request, LEAVE_DEADLINE).await;
        connector.shutdown().await;
        anyhow::Ok(match end {
            LeaveEnd::Left | LeaveEnd::NotEnrolled => {
                println!("This node was removed from its cloud.");
                ExitCode::from(exit::NOT_ENROLLED)
            }
            other => {
                eprintln!("error: {}", leave_failure(&other));
                ExitCode::from(exit::FAILURE)
            }
        })
    });
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

/// What `leave` says when the node was not removed.
fn leave_failure(end: &LeaveEnd) -> String {
    match end {
        LeaveEnd::Left | LeaveEnd::NotEnrolled => "the node was removed".into(),
        LeaveEnd::Unsupported => "the hub does not support leaving; remove this node from the hub instead".into(),
        LeaveEnd::WrongOwner => "the hub's Welcome named another account than this node's owner (SI-1)".into(),
        LeaveEnd::AgentTooOld => "the hub refuses this agent version".into(),
        LeaveEnd::Refused(code) => format!("the hub refused: {code}"),
        LeaveEnd::Lost => "the connection to the hub ended before the request was sent".into(),
        LeaveEnd::TimedOut => format!("no answer from the hub within {} s", LEAVE_DEADLINE.as_secs()),
        LeaveEnd::Unconfirmed => format!(
            "the request was sent, but the hub did not confirm the removal within {} s; check the node list on the \
             hub",
            LEAVE_DEADLINE.as_secs()
        ),
        LeaveEnd::Failed(e) => e.clone(),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let env = Env::system();
    let result = match &cli.command {
        Command::Join { token, force } => join_cmd(&cli, &env, token.as_deref(), *force),
        Command::Run => run_cmd(&cli, &env),
        Command::Status { json } => status_cmd(&cli, &env, *json),
        Command::Share {
            action:
                ShareAction::Set {
                    cpu,
                    memory_mb,
                    gpu,
                    disk_mb,
                    volumes_mb,
                    paused,
                },
        } => share_set_cmd(
            &cli,
            &env,
            &ShareUpdate {
                cpu_cores: *cpu,
                memory_mb: *memory_mb,
                gpus: gpu.clone(),
                disk_mb: *disk_mb,
                volumes_mb: *volumes_mb,
                paused: *paused,
            },
        ),
        Command::Leave { reason } => leave_cmd(&cli, &env, reason),
        Command::Config {
            action: ConfigAction::Show,
        } => config_show(&cli, &env),
        Command::Identity => identity(&cli, &env),
        Command::Inventory { json } => inventory_cmd(&cli, &env, *json),
        Command::Doctor => doctor_cmd(&cli, &env),
    };
    result.unwrap_or_else(|e| {
        eprintln!("error: {e:#}");
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn join_takes_the_token_from_argv_or_stdin() {
        let parse = |args: &[&str]| Cli::try_parse_from(args).map(|c| c.command);
        assert!(matches!(
            parse(&["p2pc-agent", "join"]),
            Ok(Command::Join {
                token: None,
                force: false
            })
        ));
        assert!(matches!(
            parse(&["p2pc-agent", "join", "-", "--force"]),
            Ok(Command::Join { token: Some(t), force: true }) if t == "-"
        ));
        assert!(matches!(
            parse(&["p2pc-agent", "join", "p2pc_join_example"]),
            Ok(Command::Join { token: Some(t), .. }) if t == "p2pc_join_example"
        ));
    }

    #[test]
    fn colour_codes_only_on_a_terminal_and_without_no_color() {
        use std::ffi::OsStr;
        assert!(use_ansi(true, None));
        assert!(use_ansi(true, Some(OsStr::new(""))), "an empty NO_COLOR does not count");
        assert!(!use_ansi(true, Some(OsStr::new("1"))));
        assert!(!use_ansi(false, None), "stderr is a file or the journal");
        assert!(!use_ansi(false, Some(OsStr::new("1"))));
    }

    #[test]
    fn subcommands_parse() {
        let parse = |args: &[&str]| Cli::try_parse_from(args).map(|c| (c.config, c.command));
        assert!(matches!(
            parse(&["p2pc-agent", "inventory", "--json"]),
            Ok((None, Command::Inventory { json: true }))
        ));
        assert!(matches!(
            parse(&["p2pc-agent", "doctor", "--config", "/etc/x.toml"]),
            Ok((Some(p), Command::Doctor)) if p.as_os_str() == "/etc/x.toml"
        ));
        assert!(matches!(
            parse(&["p2pc-agent", "config", "show"]),
            Ok((
                None,
                Command::Config {
                    action: ConfigAction::Show
                }
            ))
        ));
        assert!(parse(&["p2pc-agent", "config"]).is_err());
        assert!(matches!(
            parse(&["p2pc-agent", "status", "--json"]),
            Ok((None, Command::Status { json: true }))
        ));
        assert!(matches!(
            parse(&["p2pc-agent", "status"]),
            Ok((None, Command::Status { json: false }))
        ));
        assert!(matches!(
            parse(&["p2pc-agent", "leave"]),
            Ok((None, Command::Leave { reason })) if reason == "leave"
        ));
        assert!(matches!(
            parse(&["p2pc-agent", "leave", "--reason", "uninstall"]),
            Ok((None, Command::Leave { reason })) if reason == "uninstall"
        ));
    }

    /// H2 §8.4: the desktop app's command lines.
    #[test]
    fn share_set_parses_the_apps_options() {
        let parse = |args: &[&str]| Cli::try_parse_from(args).map(|c| c.command);
        let Ok(Command::Share {
            action:
                ShareAction::Set {
                    cpu,
                    memory_mb,
                    gpu,
                    disk_mb,
                    volumes_mb,
                    paused,
                },
        }) = parse(&[
            "p2pc-agent",
            "share",
            "set",
            "--cpu",
            "2.5",
            "--memory-mb",
            "4096",
            "--gpu",
            "none",
            "--disk-mb",
            "10240",
            "--volumes-mb",
            "20480",
            "--paused",
            "true",
        ])
        else {
            panic!("share set does not parse");
        };
        assert_eq!(cpu, Some(2.5));
        assert_eq!(memory_mb, Some(4096));
        assert_eq!(gpu, Some(GpuShare::None));
        assert_eq!(disk_mb, Some(10_240));
        assert_eq!(volumes_mb, Some(20_480));
        assert_eq!(paused, Some(true));
        assert!(matches!(
            parse(&["p2pc-agent", "share", "set", "--paused", "false"]),
            Ok(Command::Share {
                action: ShareAction::Set {
                    paused: Some(false),
                    cpu: None,
                    ..
                }
            })
        ));
        for bad in [
            &["p2pc-agent", "share", "set", "--paused", "maybe"][..],
            &["p2pc-agent", "share", "set", "--gpu", "GPU 1"],
            &["p2pc-agent", "share", "set", "--memory-mb", "-1"],
            &["p2pc-agent", "share"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
