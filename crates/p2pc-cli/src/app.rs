// SPDX-License-Identifier: Apache-2.0

//! The application: how a command line becomes requests, output and an exit code.
//!
//! Everything the process touches comes in through [`Host`] (environment, stdin, stdout, stderr, the clock, the
//! Ctrl-C signal), so the whole CLI is tested in process, against a mock server, with no real terminal.

use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use clap::{CommandFactory, Parser};
use p2pc_client::tunnel::{Tunnel, TunnelError, TunnelOptions};
use p2pc_client::{BuildError, Client, RetryPolicy};
use p2pc_proto::auth::{ApiKey, ServerAddress};
use p2pc_proto::net::DirectAddresses;
use p2pc_proto::validate::{FieldError, ValidationErrors};
use serde::Serialize;
use time::OffsetDateTime;

use crate::cli::{Cli, Command};
use crate::commands;
use crate::config::{ConfigError, Env, Flags, Os, Server, Store, config_dir, resolve_target};
use crate::outcome::{EXIT_CANNOT_RUN, EXIT_OK};

/// The Ctrl-C signal, as a future that completes when it arrives.
pub type Interrupt<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

/// Asks for a secret without echoing it. The argument is the prompt.
pub type SecretPrompt<'a> = &'a dyn Fn(&str) -> io::Result<String>;

/// Everything outside the process that a command can touch.
pub struct Host<'a> {
    /// Environment variables.
    pub env: Env<'a>,
    /// Standard output: results.
    pub out: &'a mut dyn Write,
    /// Standard error: progress, warnings and errors.
    pub err: &'a mut dyn Write,
    /// Standard input.
    pub stdin: &'a mut dyn BufRead,
    /// Whether standard input is a terminal (so that a person can answer a question).
    pub stdin_is_tty: bool,
    /// Whether standard output is a terminal. A job's output is untrusted: on a terminal it is shown with its control
    /// characters escaped (`p2pc logs`, `p2pc run`).
    pub stdout_is_tty: bool,
    /// Whether standard error is a terminal (the job's stderr lines go there).
    pub stderr_is_tty: bool,
    /// The hidden prompt of `p2pc login`.
    pub prompt_secret: SecretPrompt<'a>,
    /// Completes on Ctrl-C (SIGINT). `p2pc run` detaches when it does, `p2pc proxy` stops with 130. `None` means it
    /// never fires.
    pub interrupt: Option<Interrupt<'a>>,
    /// Completes on SIGTERM (a service manager's stop). `p2pc proxy` stops cleanly with 0 (spec §7). `None` means it
    /// never fires.
    pub terminate: Option<Interrupt<'a>>,
    /// The current time, taken once per run.
    pub now: OffsetDateTime,
    /// The retry policy of the HTTP client.
    pub retry: RetryPolicy,
    /// How the tunnel to a server address is set up. The default is the spec's; tests bind loopback.
    pub tunnel: TunnelSettings,
}

/// How the iroh endpoint of a tunnel binds, and what it knows of the server beyond its address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelSettings {
    /// The local addresses to bind and advertise (§10). Default: the default-route interface's.
    pub bind: DirectAddresses,
    /// Direct addresses of the server, if known. Default: none, the relay introduces the two ends.
    pub server_addrs: Vec<SocketAddr>,
    /// The timeout of a connection attempt. Default: [`p2pc_client::tunnel::TUNNEL_CONNECT_TIMEOUT`] (15 s).
    pub connect_timeout: Option<Duration>,
}

impl std::fmt::Debug for Host<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("stdin_is_tty", &self.stdin_is_tty)
            .field("stdout_is_tty", &self.stdout_is_tty)
            .field("stderr_is_tty", &self.stderr_is_tty)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a command failed. Every kind exits with 125 ("p2pc could not run the command").
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Configuration or credentials.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The server's answer, or its absence.
    #[error(transparent)]
    Client(#[from] p2pc_client::Error),
    /// The HTTP client could not be built (a bad server URL).
    #[error(transparent)]
    Build(#[from] BuildError),
    /// The tunnel to a server address could not be set up.
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
    /// The input is not valid. The message says what to change.
    #[error("{0}")]
    Usage(String),
    /// The job spec failed local validation.
    #[error("the job is not valid")]
    Validation(Vec<FieldError>),
    /// Reading or writing a stream failed.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The job's output files were deleted after their retention period (`410 Gone`).
    #[error("{0}")]
    Expired(String),
}

impl From<ValidationErrors> for CliError {
    fn from(e: ValidationErrors) -> Self {
        CliError::Validation(e.into_vec())
    }
}

impl CliError {
    /// A [`CliError::Usage`] from anything printable.
    pub fn usage(message: impl Into<String>) -> Self {
        CliError::Usage(message.into())
    }
}

/// The state shared by every command.
#[derive(Debug)]
pub struct Ctx<'a, 'h> {
    /// The process's surroundings.
    pub host: &'a mut Host<'h>,
    /// `--json`.
    pub json: bool,
    /// `--profile` and `--server`.
    pub flags: Flags,
    /// The tunnels opened by this run, closed when it ends so the server frees their slots at once.
    pub tunnels: Vec<Tunnel>,
}

impl Ctx<'_, '_> {
    /// The configuration store, in the directory the environment selects.
    pub fn store(&self) -> Result<Store, ConfigError> {
        Ok(Store::new(config_dir(Os::current(), self.host.env)?))
    }

    /// A client for the selected profile, or the error that says what is missing.
    pub fn client(&mut self) -> Result<Client, CliError> {
        Ok(self.client_with_key()?.0)
    }

    /// Like [`Ctx::client`], and the key too, for the one command that must keep it out of what it sends (`p2pc mcp`).
    pub fn client_with_key(&mut self) -> Result<(Client, ApiKey), CliError> {
        let target = resolve_target(&self.flags, self.host.env, &self.store()?)?;
        let client = self.client_for(&target.server, target.api_key.clone())?;
        Ok((client, target.api_key))
    }

    /// A client for `server` (a URL, or a server address reached through the tunnel) with `key`.
    pub fn client_for(&mut self, server: &str, key: ApiKey) -> Result<Client, CliError> {
        let builder = match Server::parse(server)? {
            Server::Url(url) => {
                self.warn_if_cleartext(&url);
                Client::builder(url, key)
            }
            Server::Address(address) => Client::builder_tunnel(self.tunnel(address)?, key),
        };
        Ok(builder.retry(self.host.retry).build()?)
    }

    /// For a long-running command (`p2pc proxy`, `p2pc mcp`): watches the network for every tunnel of this run, so a
    /// tunnel binds a new endpoint when the machine's addresses change (spec §10). Dropping the handles stops it.
    pub async fn watch_networks(&self) -> Vec<p2pc_client::tunnel::NetworkWatch> {
        let mut watches = Vec::with_capacity(self.tunnels.len());
        for tunnel in &self.tunnels {
            watches.push(tunnel.watch_network().await);
        }
        watches
    }

    /// The tunnel to `address`, with the host's settings. Closed when the run ends.
    pub fn tunnel(&mut self, address: ServerAddress) -> Result<Tunnel, CliError> {
        let tunnel = Tunnel::new(TunnelOptions {
            bind: self.host.tunnel.bind.clone(),
            server_addrs: self.host.tunnel.server_addrs.clone(),
            connect_timeout: self
                .host
                .tunnel
                .connect_timeout
                .unwrap_or(p2pc_client::tunnel::TUNNEL_CONNECT_TIMEOUT),
            ..TunnelOptions::new(address)
        })?;
        self.tunnels.push(tunnel.clone());
        Ok(tunnel)
    }

    /// Warns that an `http://` URL on another machine sends the key unencrypted.
    pub fn warn_if_cleartext(&mut self, server: &str) {
        let Ok(url) = url::Url::parse(server) else { return };
        let local = match url.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if url.scheme() == "http" && !local {
            let _ = writeln!(
                self.host.err,
                "warning: {server} is an http:// URL: your API key travels unencrypted. Use https:// unless the \
                 network is trusted."
            );
        }
    }

    /// Prints a value as pretty JSON on stdout.
    pub fn print_json<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CliError> {
        let text =
            serde_json::to_string_pretty(value).map_err(|_| CliError::usage("could not encode the output as JSON"))?;
        writeln!(self.host.out, "{text}")?;
        Ok(())
    }
}

/// Runs `p2pc` with `args` (including the program name) and returns its exit code.
pub async fn run(args: &[OsString], host: &mut Host<'_>) -> u8 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            // `--help` and `--version` are not errors. A usage error is "p2pc could not run the command".
            let text = e.render().to_string();
            let code = if e.exit_code() == 0 { EXIT_OK } else { EXIT_CANNOT_RUN };
            let _ = if e.use_stderr() {
                write!(host.err, "{text}")
            } else {
                write!(host.out, "{text}")
            };
            return code;
        }
    };
    let json = cli.json;
    let mut ctx = Ctx {
        host,
        json,
        flags: Flags {
            profile: cli.profile,
            server: cli.server,
        },
        tunnels: Vec::new(),
    };
    let result = dispatch(&mut ctx, cli.command).await;
    for tunnel in std::mem::take(&mut ctx.tunnels) {
        // Best effort: a server that is gone must not keep the process from ending.
        let _ = tokio::time::timeout(Duration::from_secs(1), tunnel.close()).await;
    }
    match result {
        Ok(code) => code,
        Err(CliError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => EXIT_OK,
        Err(e) => {
            let _ = render_error(ctx.host.err, &e, json);
            EXIT_CANNOT_RUN
        }
    }
}

async fn dispatch(ctx: &mut Ctx<'_, '_>, command: Command) -> Result<u8, CliError> {
    match command {
        Command::Login(a) => commands::auth::login(ctx, a).await,
        Command::Logout => commands::auth::logout(ctx),
        Command::Whoami => commands::auth::whoami(ctx).await,
        Command::Run(a) => commands::run::run(ctx, a).await,
        Command::Estimate(a) => commands::run::estimate(ctx, a).await,
        Command::Jobs(a) => commands::jobs::list(ctx, a).await,
        Command::Status(a) => commands::jobs::status(ctx, a).await,
        Command::Cancel(a) => commands::jobs::cancel(ctx, a).await,
        Command::Machines(a) => commands::machines::run(ctx, a).await,
        Command::JoinToken(a) => commands::tokens::run(ctx, a).await,
        Command::Keys(a) => commands::keys::run(ctx, a).await,
        Command::Audit(a) => commands::audit::run(ctx, a).await,
        Command::Volumes(a) => commands::volumes::run(ctx, a).await,
        Command::Completion(a) => commands::completion(ctx, a),
        Command::Logs(a) => commands::logs::run(ctx, a).await,
        Command::Results(a) => commands::results::run(ctx, a).await,
        Command::Usage(a) => commands::usage::run(ctx, a).await,
        Command::Proxy(a) => commands::proxy::run(ctx, a).await,
        Command::Mcp(a) => commands::mcp::run(ctx, a).await,
    }
}

/// Writes an error to stderr: text for people, or a JSON object with `--json`. The text may quote the server (an
/// error detail, a machine name), so it is made safe for a terminal first.
fn render_error(err: &mut dyn Write, error: &CliError, json: bool) -> io::Result<()> {
    if json {
        return writeln!(err, "{}", error_json(error));
    }
    let mut text = format!("error: {error}\n");
    match error {
        CliError::Validation(fields) => {
            for f in fields {
                text.push_str(&format!("  {}: {} ({})\n", f.field, f.message, f.code));
            }
        }
        CliError::Client(p2pc_client::Error::Api(api)) => {
            for f in &api.errors {
                text.push_str(&format!("  {}: {} ({})\n", f.field, f.message, f.code));
            }
            if api.status == 401 {
                text.push_str("hint: check the API key; `p2pc login` stores a new one\n");
            }
        }
        _ => {}
    }
    write!(err, "{}", crate::output::printable(&text))
}

/// The error as one JSON object, for `--json`: `{"error": {"kind": …, "message": …, …}}`.
fn error_json(error: &CliError) -> String {
    use serde_json::{Value, json};
    let body = match error {
        CliError::Client(p2pc_client::Error::Api(api)) => json!({
            "kind": "api", "status": api.status, "code": api.code, "title": api.title,
            "detail": api.detail, "errors": api.errors,
        }),
        CliError::Client(p2pc_client::Error::Network(_)) => json!({"kind": "network", "message": error.to_string()}),
        CliError::Client(p2pc_client::Error::Unexpected(u)) => {
            json!({"kind": "unexpected_response", "status": u.status, "message": u.message})
        }
        CliError::Validation(fields) => json!({"kind": "validation", "message": error.to_string(), "errors": fields}),
        CliError::Expired(_) => json!({"kind": "outputs_expired", "message": error.to_string()}),
        _ => json!({"kind": "error", "message": error.to_string()}),
    };
    Value::Object(serde_json::Map::from_iter([("error".to_string(), body)])).to_string()
}

/// The CLI definition, for the completion generator.
pub(crate) fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use p2pc_proto::validate::ErrorCode;

    use super::*;

    fn field(f: &str) -> FieldError {
        FieldError {
            field: f.into(),
            code: ErrorCode::OutOfRange,
            message: "must be in range".into(),
        }
    }

    #[test]
    fn validation_errors_list_every_field_path() {
        let mut out = Vec::new();
        render_error(
            &mut out,
            &CliError::Validation(vec![field("resources.cpu"), field("timeout_s")]),
            false,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("resources.cpu: must be in range (out_of_range)"),
            "{text}"
        );
        assert!(text.contains("timeout_s"), "{text}");
    }

    #[test]
    fn error_text_from_the_server_cannot_inject_escape_sequences() {
        let api = p2pc_client::ApiError {
            status: 500,
            code: "boom".into(),
            title: "t".into(),
            detail: Some("\u{1b}[2Jgone".into()),
            errors: vec![],
        };
        let mut out = Vec::new();
        render_error(&mut out, &CliError::Client(api.into()), false).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains('\u{1b}'));
    }

    #[test]
    fn json_errors_are_one_object_on_one_line() {
        let mut out = Vec::new();
        render_error(&mut out, &CliError::Validation(vec![field("resources.cpu")]), true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["error"]["kind"], "validation");
        assert_eq!(v["error"]["errors"][0]["field"], "resources.cpu");
    }

    #[test]
    fn warns_only_for_cleartext_urls_on_other_machines() {
        let env = |_: &str| None;
        let prompt = |_: &str| Ok(String::new());
        for (url, warns) in [
            ("http://127.0.0.1:7477", false),
            ("http://localhost:7477", false),
            ("http://[::1]:7477", false),
            ("https://p2pc.example.invalid", false),
            ("http://p2pc.example.invalid", true),
            ("http://192.0.2.7:7477", true),
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let mut stdin = io::empty();
            let mut host = Host {
                env: &env,
                out: &mut out,
                err: &mut err,
                stdin: &mut stdin,
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
                prompt_secret: &prompt,
                interrupt: None,
                terminate: None,
                now: OffsetDateTime::UNIX_EPOCH,
                retry: RetryPolicy::none(),
                tunnel: TunnelSettings::default(),
            };
            {
                let mut ctx = Ctx {
                    host: &mut host,
                    json: false,
                    flags: Flags::default(),
                    tunnels: Vec::new(),
                };
                ctx.warn_if_cleartext(url);
            }
            drop(host);
            assert_eq!(!err.is_empty(), warns, "{url}");
        }
    }
}
