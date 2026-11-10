// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-server`: the P2PC control plane.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use p2pc_proto::api::Scope;
use p2pc_proto::ids::{DeviceId, ProjectId};
use p2pc_server::clock::SystemClock;
use p2pc_server::config::{CONFIG_FILE, Config};
use p2pc_server::gateway::ServerIdentity;
use p2pc_server::{datadir, identity, init, logging, recover, serve};

/// P2PC control plane.
#[derive(Debug, Parser)]
#[command(name = "p2pc-server", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the control plane.
    Serve {
        /// Config file. Default: `server.toml` in the data dir ($P2PC_DATA_DIR, $XDG_DATA_HOME/p2pc-server or
        /// ~/.local/share/p2pc-server).
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// Print the server's iroh NodeId and server address (`p2pc_srv_…`).
    Info {
        /// Config file. Default: `server.toml` in the data dir.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// Initialise the data dir and print the admin API key once. With `--owner-device`, register that device as the
    /// owner instead, and print no API key.
    Init {
        /// Data dir. $P2PC_DATA_DIR takes precedence over this flag.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
        /// REST listen address written to `server.toml` (`bind`). Default: 127.0.0.1:7477.
        #[arg(long, value_name = "ADDR")]
        bind: Option<SocketAddr>,
        /// The iroh NodeId of the owner device (the desktop app's own device key): it gets the `admin` scope, and no
        /// API key is created.
        #[arg(long, value_name = "NODE_ID")]
        owner_device: Option<String>,
        /// Label of the owner device.
        #[arg(long, value_name = "TEXT", requires = "owner_device")]
        label: Option<String>,
    },
    /// Offline device management (needs local access to the data dir; works while the server runs).
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
    /// Offline key management (needs local access to the data dir).
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
}

#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Create a new unrestricted admin key and print it once. For an owner who lost every admin key; works while the
    /// server runs.
    Recover {
        /// Data dir. $P2PC_DATA_DIR takes precedence over this flag.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum DevicesCommand {
    /// Register a device by its iroh NodeId, audited as `device_added_offline`.
    Add {
        /// Data dir. $P2PC_DATA_DIR takes precedence over this flag.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
        /// The device's iroh NodeId (64 lowercase hex characters).
        #[arg(long, value_name = "NODE_ID")]
        node_id: String,
        /// Comma-separated scopes, for example `admin` or `nodes:read,templates:launch`.
        #[arg(long, value_name = "LIST", value_parser = parse_scopes)]
        scopes: std::vec::Vec<Scope>,
        /// The device's label.
        #[arg(long, value_name = "TEXT")]
        label: String,
        /// The project (`prj_…`). Default: the `default` project.
        #[arg(long, value_name = "PROJECT_ID")]
        project: Option<ProjectId>,
    },
    /// Revoke a device, audited as `device_revoked_offline`. A running server closes its connections within 5 s.
    Revoke {
        /// Data dir. $P2PC_DATA_DIR takes precedence over this flag.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
        /// The device ID (`dev_…`).
        #[arg(long, value_name = "DEVICE_ID")]
        id: DeviceId,
    },
}

/// A comma-separated scope list (`admin`, `nodes:read,templates:launch`).
fn parse_scopes(text: &str) -> Result<std::vec::Vec<Scope>, String> {
    text.split(',')
        .map(|s| {
            serde_json::from_value(serde_json::Value::String(s.trim().to_string()))
                .map_err(|_| format!("unknown scope {:?}", s.trim()))
        })
        .collect()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli.command)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Init {
            data_dir,
            bind,
            owner_device: Some(node_id),
            label,
        } => {
            logging::init("warn");
            let dir = datadir::resolve_from_env(data_dir.as_deref())?;
            let options = init::OwnerDeviceOptions { bind, node_id, label };
            let out = init::init_owner_device(&dir, &options, &SystemClock).await?;
            eprintln!("Initialised {}", out.data_dir.display());
            eprintln!("Config: {}", out.config_path.display());
            // Nothing secret: the device proves itself with its own key, which never leaves it.
            println!("OWNER DEVICE: {}", out.device_id);
            println!("SERVER ADDRESS: {}", out.server.address());
            Ok(())
        }
        Command::Init {
            data_dir,
            bind,
            owner_device: None,
            ..
        } => {
            logging::init("warn");
            let dir = datadir::resolve_from_env(data_dir.as_deref())?;
            let out = init::init_with(&dir, &init::InitOptions { bind }, &SystemClock).await?;
            eprintln!("Initialised {}", out.data_dir.display());
            eprintln!("Config: {}", out.config_path.display());
            // The only place the full key is ever written: stdout, once.
            println!("ADMIN API KEY (shown once): {}", out.admin_key.expose());
            // Not a secret: how `p2pc login` and agents reach this server over iroh (§10).
            println!("SERVER ADDRESS: {}", out.server.address());
            Ok(())
        }
        Command::Info { config } => {
            logging::init("warn");
            let path = match config {
                Some(p) => p,
                None => datadir::resolve_from_env(None)?.join(CONFIG_FILE),
            };
            let config = Config::load(&path)?;
            let key = identity::load(&config.data_dir)?;
            let server = ServerIdentity::new(key, &config.iroh.relays);
            println!("NODE ID: {}", server.node_id());
            println!("SERVER ADDRESS: {}", server.address());
            for relay in server.relays() {
                println!("RELAY: {relay}");
            }
            Ok(())
        }
        Command::Keys {
            command: KeysCommand::Recover { data_dir },
        } => {
            logging::init("warn");
            let dir = datadir::resolve_from_env(data_dir.as_deref())?;
            let out = recover::recover(&dir, &SystemClock).await?;
            eprintln!("Recovered an unrestricted admin key for {}", out.account_id);
            println!("ADMIN API KEY (shown once): {}", out.admin_key.expose());
            Ok(())
        }
        Command::Devices {
            command:
                DevicesCommand::Add {
                    data_dir,
                    node_id,
                    scopes,
                    label,
                    project,
                },
        } => {
            logging::init("warn");
            let dir = datadir::resolve_from_env(data_dir.as_deref())?;
            let add = recover::AddDevice {
                node_id,
                scopes,
                label: Some(label),
                project_id: project,
            };
            let row = recover::devices_add(&dir, &add, &SystemClock).await?;
            println!("DEVICE: {}", row.device_id);
            Ok(())
        }
        Command::Devices {
            command: DevicesCommand::Revoke { data_dir, id },
        } => {
            logging::init("warn");
            let dir = datadir::resolve_from_env(data_dir.as_deref())?;
            recover::devices_revoke(&dir, id, &SystemClock).await?;
            eprintln!("Revoked {id}");
            Ok(())
        }
        Command::Serve { config } => {
            let path = match config {
                Some(p) => p,
                None => datadir::resolve_from_env(None)?.join(CONFIG_FILE),
            };
            let config = Config::load(&path)?;
            logging::init(&config.log.level);
            logging::install_panic_hook();
            serve::serve(config).await
        }
    }
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
    fn parses_known_subcommands() {
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "serve"]).map(|c| c.command),
            Ok(Command::Serve { config: None })
        ));
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "serve", "--config", "/etc/p2pc/server.toml"]).map(|c| c.command),
            Ok(Command::Serve { config: Some(_) })
        ));
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "init", "--data-dir", "/srv/p2pc"]).map(|c| c.command),
            Ok(Command::Init {
                data_dir: Some(_),
                bind: None,
                owner_device: None,
                label: None,
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "init", "--bind", "192.0.2.1:7477"]).map(|c| c.command),
            Ok(Command::Init {
                data_dir: None,
                bind: Some(_),
                ..
            })
        ));
        let node = "ab".repeat(32);
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "init", "--owner-device", &node, "--label", "hub PC"])
                .map(|c| c.command),
            Ok(Command::Init {
                owner_device: Some(_),
                label: Some(_),
                ..
            })
        ));
        // A label without an owner device makes no sense.
        assert!(Cli::try_parse_from(["p2pc-server", "init", "--label", "x"]).is_err());
        let add = Cli::try_parse_from([
            "p2pc-server",
            "devices",
            "add",
            "--node-id",
            &node,
            "--scopes",
            "nodes:read, templates:launch",
            "--label",
            "phone",
        ])
        .map(|c| c.command);
        assert!(matches!(
            add,
            Ok(Command::Devices {
                command: DevicesCommand::Add { ref scopes, project: None, .. }
            }) if scopes == &[Scope::NodesRead, Scope::TemplatesLaunch]
        ));
        assert!(
            Cli::try_parse_from([
                "p2pc-server",
                "devices",
                "add",
                "--node-id",
                &node,
                "--scopes",
                "root",
                "--label",
                "x"
            ])
            .is_err()
        );
        assert!(matches!(
            Cli::try_parse_from([
                "p2pc-server",
                "devices",
                "revoke",
                "--id",
                "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV"
            ])
            .map(|c| c.command),
            Ok(Command::Devices {
                command: DevicesCommand::Revoke { .. }
            })
        ));
        assert!(Cli::try_parse_from(["p2pc-server", "devices", "revoke", "--id", "nope"]).is_err());
        assert!(Cli::try_parse_from(["p2pc-server", "init", "--bind", "not-an-address"]).is_err());
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "keys", "recover", "--data-dir", "/srv/p2pc"]).map(|c| c.command),
            Ok(Command::Keys {
                command: KeysCommand::Recover { data_dir: Some(_) }
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "info"]).map(|c| c.command),
            Ok(Command::Info { config: None })
        ));
        assert!(Cli::try_parse_from(["p2pc-server", "keys"]).is_err());
        assert!(Cli::try_parse_from(["p2pc-server", "bogus"]).is_err());
    }
}
