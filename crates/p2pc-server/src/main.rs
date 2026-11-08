// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-server`: the P2PC control plane.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
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
    /// Initialise the data dir and print the admin API key once.
    Init {
        /// Data dir. $P2PC_DATA_DIR takes precedence over this flag.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
        /// REST listen address written to `server.toml` (`bind`). Default: 127.0.0.1:7477.
        #[arg(long, value_name = "ADDR")]
        bind: Option<SocketAddr>,
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
        Command::Init { data_dir, bind } => {
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
                bind: None
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["p2pc-server", "init", "--bind", "192.0.2.1:7477"]).map(|c| c.command),
            Ok(Command::Init {
                data_dir: None,
                bind: Some(_)
            })
        ));
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
