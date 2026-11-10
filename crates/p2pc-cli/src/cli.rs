// SPDX-License-Identifier: Apache-2.0

//! The command line, as clap derives. There is **no `--key` flag anywhere**: a key on the command line ends up in the
//! shell history and in `ps` (spec §7). `p2pc login` reads it from a hidden prompt or from stdin.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use p2pc_proto::api::{JobStatus, Scope};
use p2pc_proto::ids::{JobId, JoinTokenId, KeyId, NodeId};
use p2pc_proto::units::Units;

use crate::parse;

/// Run jobs on the machines you own.
#[derive(Debug, Parser)]
#[command(name = "p2pc", version, about, propagate_version = true)]
pub struct Cli {
    /// The profile to use (default: P2PC_PROFILE, then `default_profile` of config.toml, then `default`).
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    /// Print the API's JSON instead of tables and text. Lists are JSON arrays.
    #[arg(long, global = true)]
    pub json: bool,
    /// The server: its URL, or its address `p2pc_srv_…` to go through the tunnel (default: P2PC_SERVER, then the
    /// profile's `server`).
    #[arg(long, global = true, value_name = "URL|ADDRESS")]
    pub server: Option<String>,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check an API key against the server and store it in the profile.
    ///
    /// The key is read from a hidden prompt, or from stdin with --key-stdin. It is never a command-line argument.
    Login(LoginArgs),
    /// Remove the profile's API key.
    Logout,
    /// Show who the API key is: account, project, key ID and scopes.
    Whoami,
    /// Submit a job and follow it until it ends.
    ///
    /// The exit code is the job's: 0 if it succeeded, its own code if it failed, 75 if it was lost, 124 if it timed
    /// out, 130 if it was cancelled, and 125 if p2pc could not run it.
    Run(RunArgs),
    /// Ask the server whether a job could run and what it would reserve, without submitting it.
    Estimate(JobArgs),
    /// List jobs.
    Jobs(JobsArgs),
    /// Show a job.
    Status(JobIdArg),
    /// Cancel a job.
    Cancel(JobIdArg),
    /// List machines, or show, approve, drain, resume and remove one. Also `p2pc nodes`.
    #[command(visible_alias = "nodes")]
    Machines(MachinesArgs),
    /// Create, list and revoke join tokens for new machines.
    #[command(name = "join-token")]
    JoinToken(JoinTokenArgs),
    /// Create, list and revoke API keys.
    Keys(KeysArgs),
    /// Show the audit log.
    Audit(AuditArgs),
    /// List the persistent volumes of the machines, or remove one.
    Volumes(VolumesArgs),
    /// Print a shell completion script.
    Completion(CompletionArgs),
    /// Show a job's logs, or follow them live.
    ///
    /// The job's stdout goes to stdout and its stderr to stderr. Its output is untrusted: on a terminal, control
    /// characters are shown (as `\x1b`) instead of acted on; piped, the bytes are written as stored.
    Logs(LogsArgs),
    /// Download a job's output files, checking each one's SHA-256.
    ///
    /// They go to ./p2pc-results/<job_id>/ unless you say --out. A file that already exists is never overwritten
    /// without --force.
    Results(ResultsArgs),
    /// Show reserved and used compute, today in UTC unless you say otherwise.
    Usage(UsageArgs),
    /// Serve the REST API of a server address (`p2pc_srv_…`) on a local port, through the iroh tunnel.
    ///
    /// Each local TCP connection goes over its own stream of one tunnel connection. Clients send their own API key:
    /// the proxy never adds one. It listens on loopback unless --allow-non-loopback.
    Proxy(ProxyArgs),
    /// Serve the MCP protocol over stdio, so that an AI agent can run jobs with its own capped key.
    ///
    /// For example `claude mcp add p2pc -- p2pc mcp --profile agent`. It refuses a key that has the `admin` scope or
    /// no daily cap, unless you say otherwise. Logs go to stderr; stdout carries only the protocol.
    Mcp(McpArgs),
}

/// `p2pc volumes`.
#[derive(Debug, Args)]
pub struct VolumesArgs {
    /// What to do.
    #[command(subcommand)]
    pub command: VolumesCommand,
}

/// `p2pc volumes <subcommand>`.
#[derive(Debug, Subcommand)]
pub enum VolumesCommand {
    /// List the volumes: name, machine, size, limit, last use and the job that holds each one now.
    #[command(visible_alias = "list")]
    Ls,
    /// Remove a volume from a machine (admin only). Its data is deleted and cannot be recovered.
    ///
    /// The machine must be online and the volume must not be in use. A template's volume is named
    /// `tpl:<template>/<name>`, for example `tpl:private-chat/models`.
    Rm(VolumeRm),
}

/// `p2pc volumes rm`.
#[derive(Debug, Args)]
pub struct VolumeRm {
    /// The machine that holds the volume: its name or ID.
    #[arg(value_name = "NODE")]
    pub node: String,
    /// The volume's name, as `p2pc volumes ls` shows it.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Do not ask for confirmation. Required when there is no terminal.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// `p2pc logs`.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// The job ID, `job_…`.
    #[arg(value_name = "JOB_ID")]
    pub id: JobId,
    /// Keep the log open and print lines as the job writes them, until the job ends. Ctrl-C stops following and
    /// does not cancel the job.
    #[arg(long, short = 'f')]
    pub follow: bool,
    /// An attempt of the job (default: the latest). A job that lost its machine is retried as a new attempt.
    #[arg(long, value_name = "K", value_parser = clap::value_parser!(u32).range(1..))]
    pub attempt: Option<u32>,
    /// Start at this line number (`seq`, counted from 0), inclusive.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub since_seq: u64,
    /// On a terminal, write the job's output as stored too. A job can then move your cursor, change the window
    /// title or write to your clipboard: use it only for output you trust.
    #[arg(long)]
    pub raw: bool,
}

/// `p2pc results`.
#[derive(Debug, Args)]
pub struct ResultsArgs {
    /// The job ID, `job_…`.
    #[arg(value_name = "JOB_ID")]
    pub id: JobId,
    /// An attempt of the job (default: the latest).
    #[arg(long, value_name = "K", value_parser = clap::value_parser!(u32).range(1..))]
    pub attempt: Option<u32>,
    /// Where to put the files (default: ./p2pc-results/<job_id>/).
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
    /// Only this output file, by its path as `p2pc results` lists it. Repeatable.
    #[arg(long = "file", value_name = "PATH")]
    pub files: Vec<String>,
    /// Replace files that already exist.
    #[arg(long)]
    pub force: bool,
}

/// `p2pc usage`.
#[derive(Debug, Args)]
pub struct UsageArgs {
    /// Start of the range, inclusive: a date (`2026-11-01`, midnight UTC) or an RFC 3339 time. Default: the start of
    /// today (UTC), or a day before --to.
    #[arg(long, value_parser = parse::parse_when, value_name = "DATE")]
    pub from: Option<time::OffsetDateTime>,
    /// End of the range, exclusive, like --from. Default: the end of today (UTC).
    #[arg(long, value_parser = parse::parse_when, value_name = "DATE")]
    pub to: Option<time::OffsetDateTime>,
    /// How to group the rows: job (default), node or key.
    #[arg(long = "by", value_enum, default_value_t = UsageBy::Job, value_name = "job|node|key")]
    pub by: UsageBy,
}

/// What `p2pc usage --by` groups on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UsageBy {
    /// Per job.
    Job,
    /// Per machine.
    Node,
    /// Per API key.
    Key,
}

/// `p2pc mcp`.
#[derive(Debug, Args)]
pub struct McpArgs {
    /// Serve a key that has the `admin` scope (it can create keys and enroll machines). A warning is printed.
    #[arg(long)]
    pub allow_admin: bool,
    /// Serve a key that has no daily unit cap, or whose cap the server did not report. A warning is printed.
    #[arg(long)]
    pub allow_uncapped: bool,
    /// Where `p2pc_results` saves files that are too big or not text: `<DIR>/<job_id>/<path>`.
    #[arg(long, value_name = "DIR", default_value = crate::mcp::DEFAULT_RESULTS_DIR)]
    pub results_dir: PathBuf,
}

/// `p2pc login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Read the API key from stdin (one line) instead of asking for it.
    #[arg(long)]
    pub key_stdin: bool,
    /// Log in at the --server URL, ask it for its address (GET /v1/server), check the key again through the tunnel,
    /// and store the address: the profile then works from any network.
    #[arg(long)]
    pub via_tunnel: bool,
}

/// `p2pc proxy`.
#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// Where to listen. A non-loopback address needs --allow-non-loopback.
    #[arg(long, default_value = "127.0.0.1:7477", value_name = "ADDR:PORT")]
    pub listen: std::net::SocketAddr,
    /// Allow a --listen address that is not loopback. This exposes the server's API to that network: anyone who can
    /// reach the port can try API keys against it.
    #[arg(long)]
    pub allow_non_loopback: bool,
}

/// A job ID.
#[derive(Debug, Args)]
pub struct JobIdArg {
    /// The job ID, `job_…`.
    #[arg(value_name = "JOB_ID")]
    pub id: JobId,
}

/// `p2pc run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// What to run.
    #[command(flatten)]
    pub job: JobArgs,
    /// Print only the job ID, on stdout, and return at once.
    #[arg(long, short = 'd')]
    pub detach: bool,
}

/// What a job is: the flags of `p2pc run` and `p2pc estimate`.
#[derive(Debug, Args)]
pub struct JobArgs {
    /// The OCI image, for example `python:3.12-slim`.
    #[arg(long, value_name = "IMAGE")]
    pub image: String,
    /// vCPUs, 0.25 to 256.
    #[arg(long, default_value_t = 1.0, value_name = "N")]
    pub cpu: f64,
    /// Memory: `512M`, `4G`, `4GiB`. A bare number is MiB.
    #[arg(long, default_value = "2G", value_parser = parse::parse_size_mib, value_name = "SIZE")]
    pub mem: u64,
    /// Whole GPUs: 0 or 1.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(0..=1), value_name = "0|1")]
    pub gpu: u32,
    /// Disk for outputs and the writable layer, like --mem (default 2G).
    #[arg(long, value_parser = parse::parse_size_mib, value_name = "SIZE")]
    pub disk: Option<u64>,
    /// An environment variable: `KEY=VALUE`, or `KEY` to take the value from your environment. Repeatable.
    #[arg(long = "env", value_name = "KEY[=VALUE]")]
    pub env: Vec<String>,
    /// A file of `KEY=VALUE` lines. Repeatable. `--env` wins over it.
    #[arg(long, value_name = "PATH")]
    pub env_file: Vec<PathBuf>,
    /// A local file to put in the job: `LOCAL` goes to `/inputs/<name>`, `LOCAL:/inputs/PATH` to PATH. Repeatable.
    #[arg(long = "file", value_name = "LOCAL[:/inputs/PATH]")]
    pub files: Vec<String>,
    /// Domains the job may reach, comma separated. Without it the job has no network.
    #[arg(long, value_delimiter = ',', value_name = "DOMAIN,DOMAIN")]
    pub egress: Vec<String>,
    /// The longest the job may run: `90s`, `2h` (default 1h).
    #[arg(long, value_parser = parse::parse_duration_secs, value_name = "DURATION")]
    pub timeout: Option<u32>,
    /// A label for the job.
    #[arg(long)]
    pub name: Option<String>,
    /// Run only on this machine (its ID, `node_…`).
    #[arg(long, value_name = "NODE_ID")]
    pub node: Option<NodeId>,
    /// Only machines with this label: `key=value`. Repeatable.
    #[arg(long = "label", value_parser = parse::parse_label, value_name = "KEY=VALUE")]
    pub labels: Vec<(String, String)>,
    /// How many times the job may be retried after its machine is lost, 0 to 4 (default 1). Only losing the machine
    /// triggers a retry: a job that fails by itself is never retried.
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..=4), value_name = "N")]
    pub retries: Option<u32>,
    /// Makes the submission idempotent: the same key and body never create a second job. Generated if not given.
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: Option<String>,
    /// The command to run, after `--`. It is an argv: there is no shell unless you run one.
    #[arg(last = true, required = true, num_args = 1.., value_name = "CMD")]
    pub command: Vec<String>,
}

/// `p2pc jobs`.
#[derive(Debug, Args)]
pub struct JobsArgs {
    /// Only jobs in this state: queued, assigned, running, succeeded, failed, timed_out, cancelled or lost.
    #[arg(long, value_parser = parse_status, value_name = "STATE")]
    pub status: Option<JobStatus>,
    /// Only jobs that ran on this machine (its ID).
    #[arg(long, value_name = "NODE_ID")]
    pub node: Option<NodeId>,
    /// How many jobs to show, 1 to 100.
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=100), conflicts_with = "all")]
    pub limit: u32,
    /// Fetch every page.
    #[arg(long)]
    pub all: bool,
}

fn parse_status(text: &str) -> Result<JobStatus, String> {
    serde_json::from_value(serde_json::Value::String(text.to_string()))
        .map_err(|_| format!("{text:?} is not a job state"))
}

fn parse_scope(text: &str) -> Result<Scope, String> {
    serde_json::from_value(serde_json::Value::String(text.to_string()))
        .map_err(|_| format!("{text:?} is not a scope: use admin, jobs:write, jobs:read, nodes:read or nodes:write"))
}

/// `p2pc machines`.
#[derive(Debug, Args)]
pub struct MachinesArgs {
    /// What to do with a machine. Without it, the machines are listed.
    #[command(subcommand)]
    pub command: Option<MachinesCommand>,
}

/// `p2pc machines <subcommand>`.
#[derive(Debug, Subcommand)]
pub enum MachinesCommand {
    /// List the machines, with whether each one is approved (the same as giving no subcommand).
    #[command(visible_alias = "list")]
    Ls,
    /// Show one machine's inventory and state.
    Show(MachineArg),
    /// Approve a machine that waits for approval (admin only): print its node phrase and ask for confirmation.
    ///
    /// A machine enrolled with a token that a phone or a developer device minted gets no job until an admin approves
    /// it. Compare the phrase with the one the machine itself shows (`p2pc-agent status`, or the PC's app) before you
    /// say yes: it proves that the machine you approve is the machine you are looking at.
    Approve(MachineApprove),
    /// Stop sending new jobs to a machine. Running jobs finish.
    Drain(MachineArg),
    /// Send jobs to a drained machine again.
    Resume(MachineArg),
    /// Remove a machine. Its agent must join again with a new token.
    Rm(MachineRm),
}

/// A machine, by name or ID.
#[derive(Debug, Args)]
pub struct MachineArg {
    /// The machine's name or ID (`node_…`).
    #[arg(value_name = "ID_OR_NAME")]
    pub target: String,
}

/// `p2pc nodes approve`.
#[derive(Debug, Args)]
pub struct MachineApprove {
    /// The machine's name or ID.
    #[arg(value_name = "ID_OR_NAME")]
    pub target: String,
    /// Do not ask for confirmation (the phrase is still printed). Required when there is no terminal.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// `p2pc machines rm`.
#[derive(Debug, Args)]
pub struct MachineRm {
    /// The machine's name or ID.
    #[arg(value_name = "ID_OR_NAME")]
    pub target: String,
    /// Do not ask for confirmation. Required when there is no terminal.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// `p2pc join-token`.
#[derive(Debug, Args)]
pub struct JoinTokenArgs {
    /// What to do.
    #[command(subcommand)]
    pub command: JoinTokenCommand,
}

/// `p2pc join-token <subcommand>`.
#[derive(Debug, Subcommand)]
pub enum JoinTokenCommand {
    /// Create a single-use token and print the command to run on the new machine.
    Create {
        /// How long the token is valid, up to 24h (default 15m).
        #[arg(long, value_parser = parse::parse_duration, value_name = "DURATION")]
        expires: Option<Duration>,
        /// A label, shown when tokens are listed.
        #[arg(long)]
        label: Option<String>,
        /// Print only the token and a newline, for a script: `p2pc join-token create --token-only > token.txt`.
        #[arg(long)]
        token_only: bool,
    },
    /// List join tokens.
    List,
    /// Revoke an unused join token.
    Revoke {
        /// The token's ID, `jtk_…` (not the token itself).
        #[arg(value_name = "ID")]
        id: JoinTokenId,
    },
}

/// `p2pc keys`.
#[derive(Debug, Args)]
pub struct KeysArgs {
    /// What to do.
    #[command(subcommand)]
    pub command: KeysCommand,
}

/// `p2pc keys <subcommand>`.
#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Create an API key. It is printed once, on stdout: store it now.
    Create {
        /// A label for the key.
        #[arg(long)]
        label: String,
        /// A scope: admin, jobs:write, jobs:read, nodes:read or nodes:write. Repeatable.
        #[arg(long = "scope", required = true, value_parser = parse_scope, value_name = "SCOPE")]
        scopes: Vec<Scope>,
        /// Daily cap in compute units (1 unit = 1 vCPU-hour reserved), for example `10` or `2.5`.
        #[arg(long = "cap", value_parser = parse::parse_units, value_name = "UNITS")]
        cap: Option<Units>,
        /// An image the key may run, as a glob on the normalized reference, for example `docker.io/library/python:*`.
        /// Repeatable. Without any, every image is allowed.
        #[arg(long = "image", value_name = "PATTERN")]
        images: Vec<String>,
        /// When the key expires: `30d`, `12h`.
        #[arg(long, value_parser = parse::parse_duration, value_name = "DURATION")]
        expires: Option<Duration>,
    },
    /// List API keys.
    List,
    /// Revoke an API key.
    Revoke {
        /// The key's ID (the 12 characters after `p2pc_sk_`), not the key itself.
        #[arg(value_name = "ID")]
        id: KeyId,
    },
}

/// `p2pc audit`.
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// How many events to show, 1 to 100.
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=100), conflicts_with = "all")]
    pub limit: u32,
    /// Fetch every page.
    #[arg(long)]
    pub all: bool,
}

/// The shells that completion scripts exist for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// Bash.
    Bash,
    /// Zsh.
    Zsh,
    /// Fish.
    Fish,
    /// PowerShell.
    Powershell,
}

/// `p2pc completion`.
#[derive(Debug, Args)]
pub struct CompletionArgs {
    /// The shell.
    #[arg(value_enum)]
    pub shell: Shell,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    /// Every command and subcommand, as the path of names that reaches it.
    fn all_paths(cmd: &clap::Command, prefix: &[String], out: &mut Vec<Vec<String>>) {
        for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
            let mut path = prefix.to_vec();
            path.push(sub.get_name().to_string());
            out.push(path.clone());
            all_paths(sub, &path, out);
        }
    }

    #[test]
    fn no_command_has_a_key_argument() {
        let root = Cli::command();
        let mut paths = vec![Vec::new()];
        all_paths(&root, &[], &mut paths);
        assert!(paths.len() > 20, "walked the whole tree: {}", paths.len());
        for path in paths {
            let mut cmd = &root;
            for name in &path {
                cmd = cmd.find_subcommand(name).expect("subcommand");
            }
            for arg in cmd.get_arguments() {
                assert_ne!(arg.get_long(), Some("key"), "{path:?} has --key");
                assert_ne!(arg.get_id().as_str(), "key", "{path:?} has an argument named key");
                assert_ne!(arg.get_short(), Some('k'), "{path:?} has -k");
            }
        }
    }

    #[test]
    fn run_takes_its_command_after_double_dash() {
        let cli = Cli::try_parse_from([
            "p2pc",
            "run",
            "--image",
            "python:3.12",
            "--cpu",
            "2",
            "--mem",
            "4GiB",
            "--",
            "python",
            "-c",
            "print(1)",
        ])
        .unwrap();
        let Command::Run(run) = cli.command else { panic!("run") };
        assert_eq!(run.job.mem, 4096);
        assert_eq!(run.job.command, ["python", "-c", "print(1)"]);
        assert!(!run.detach);
    }

    #[test]
    fn run_requires_an_image_and_a_command() {
        assert!(Cli::try_parse_from(["p2pc", "run", "--", "true"]).is_err());
        assert!(Cli::try_parse_from(["p2pc", "run", "--image", "x"]).is_err());
    }

    #[test]
    fn gpu_is_zero_or_one() {
        assert!(Cli::try_parse_from(["p2pc", "run", "--image", "x", "--gpu", "2", "--", "true"]).is_err());
        assert!(Cli::try_parse_from(["p2pc", "run", "--image", "x", "--gpu", "1", "--", "true"]).is_ok());
    }

    #[test]
    fn global_flags_work_before_and_after_the_subcommand() {
        let a = Cli::try_parse_from(["p2pc", "--json", "--profile", "p", "jobs"]).unwrap();
        let b = Cli::try_parse_from(["p2pc", "jobs", "--json", "--profile", "p"]).unwrap();
        assert!(a.json && b.json);
        assert_eq!((a.profile.as_deref(), b.profile.as_deref()), (Some("p"), Some("p")));
    }

    #[test]
    fn mcp_defaults_to_the_safe_choices() {
        let Command::Mcp(a) = Cli::try_parse_from(["p2pc", "mcp"]).unwrap().command else {
            panic!("not the mcp command");
        };
        assert!(!a.allow_admin && !a.allow_uncapped);
        assert_eq!(a.results_dir, PathBuf::from("p2pc-results"));
        let Command::Mcp(a) = Cli::try_parse_from([
            "p2pc",
            "--profile",
            "agent",
            "mcp",
            "--allow-admin",
            "--allow-uncapped",
            "--results-dir",
            "/tmp/out",
        ])
        .unwrap()
        .command
        else {
            panic!("not the mcp command");
        };
        assert!(a.allow_admin && a.allow_uncapped);
        assert_eq!(a.results_dir, PathBuf::from("/tmp/out"));
    }

    #[test]
    fn keys_create_needs_a_label_and_a_scope() {
        assert!(Cli::try_parse_from(["p2pc", "keys", "create", "--scope", "jobs:read"]).is_err());
        assert!(Cli::try_parse_from(["p2pc", "keys", "create", "--label", "x"]).is_err());
        assert!(Cli::try_parse_from(["p2pc", "keys", "create", "--label", "x", "--scope", "root"]).is_err());
        assert!(
            Cli::try_parse_from([
                "p2pc",
                "keys",
                "create",
                "--label",
                "x",
                "--scope",
                "jobs:read",
                "--scope",
                "nodes:read",
                "--cap",
                "2.5",
                "--image",
                "docker.io/library/*",
                "--expires",
                "30d"
            ])
            .is_ok()
        );
    }

    #[test]
    fn jobs_all_conflicts_with_limit() {
        assert!(Cli::try_parse_from(["p2pc", "jobs", "--all", "--limit", "5"]).is_err());
    }
}
