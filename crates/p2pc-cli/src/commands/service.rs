// SPDX-License-Identifier: Apache-2.0

//! `service`: run, reach, list and stop long-lived services (H2 §7.2, §7.4, §7.8).

use std::sync::Arc;
use std::time::Duration;

use p2pc_client::{Client, Error, JobListParams, PortStream};
use p2pc_proto::api::{Job, JobKind, JobStatus, ServiceHealth, ServiceSpec, VolumeSpec};
use p2pc_proto::ids::JobId;
use serde_json::json;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::collect;
use super::proxy::signal_or_never;
use super::run::{draft_spec, local_limits};
use crate::app::{CliError, Ctx};
use crate::cli::{RestartArg, ServiceArgs, ServiceCommand, ServiceConnectArgs, ServiceListArgs, ServiceRunArgs};
use crate::follow::{PollSchedule, is_transient};
use crate::outcome::{EXIT_CANNOT_RUN, EXIT_INTERRUPTED, EXIT_OK, describe, exit_code};
use crate::output::{Table, fmt_age, fmt_time, or_dash, printable, wire_name};
use crate::parse::parse_size_mib;

/// Local connections forwarded at once. The hub allows 16 per principal and service (H2 §7.4), so the 17th waits in the
/// listen backlog instead of being refused.
pub const MAX_CONNECTIONS: usize = 16;

/// The size of a volume that `--volume NAME:MOUNT` does not give, in MiB: 1 GiB.
pub const DEFAULT_VOLUME_MB: u64 = 1024;

/// `p2pc service <run|connect|stop|list>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: ServiceArgs) -> Result<u8, CliError> {
    match args.command {
        ServiceCommand::Run(a) => start(ctx, *a).await,
        ServiceCommand::Connect(a) => connect(ctx, a).await,
        ServiceCommand::Stop(a) => super::jobs::cancel(ctx, a).await,
        ServiceCommand::List(a) => list(ctx, a).await,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------------------------------------------

/// `--port PORT[:NAME]`.
fn parse_port(text: &str) -> Result<(u32, String), String> {
    let (number, name) = match text.split_once(':') {
        Some((number, name)) => (number, Some(name)),
        None => (text, None),
    };
    let port: u32 = number
        .parse()
        .map_err(|_| format!("--port {text:?}: {number:?} is not a port number; use --port 8080 or --port 8080:web"))?;
    Ok((port, name.map_or_else(|| format!("port-{port}"), str::to_string)))
}

/// `--volume NAME:MOUNT[:SIZE]`. The mount starts with `/`, so a size is whatever follows the last `:`.
fn parse_volume(text: &str) -> Result<(String, String, u64), String> {
    let bad = || format!("--volume {text:?} is not NAME:MOUNT[:SIZE], for example --volume data:/volumes/data:4G");
    let (name, rest) = text.split_once(':').ok_or_else(bad)?;
    if name.is_empty() || !rest.starts_with('/') {
        return Err(bad());
    }
    let (mount, max_mb) = match rest.rsplit_once(':') {
        Some((mount, size)) => (
            mount,
            parse_size_mib(size).map_err(|e| format!("--volume {text:?}: the size: {e}"))?,
        ),
        None => (rest, DEFAULT_VOLUME_MB),
    };
    Ok((name.to_string(), mount.to_string(), max_mb))
}

/// The spec of `p2pc service run`: the job flags, as a `service`, with its ports, health check, idle limit, restart
/// policy and volumes. Validated here with the whole spec's rules; the hub stays the authority.
fn build_service_spec(args: &ServiceRunArgs, env: crate::config::Env) -> Result<p2pc_proto::api::JobSpec, CliError> {
    let mut spec = draft_spec(&args.job, env, JobKind::Service)?;

    let mut ports = Vec::new();
    for text in &args.ports {
        let (port, name) = parse_port(text).map_err(CliError::Usage)?;
        ports.push(json!({"port": port, "name": name}));
    }
    // The health check goes to the first port. Everything else of it, and of the service, takes the defaults of the
    // spec, which only the deserializer of `p2pc-proto` knows (CONTRIBUTING rule 7).
    let first_port = ports.first().and_then(|p| p.get("port")).cloned().unwrap_or(json!(0));
    let mut service = json!({"ports": ports});
    if let Some(path) = &args.health_http {
        service["health"] = json!({"http_get": path, "port": first_port});
    } else if args.health_tcp {
        service["health"] = json!({"tcp": true, "port": first_port});
    }
    if args.no_idle {
        service["idle_timeout_s"] = serde_json::Value::Null;
    } else if let Some(idle) = args.idle {
        service["idle_timeout_s"] = json!(idle);
    }
    if let Some(restart) = args.restart {
        service["restart"] = json!(match restart {
            RestartArg::Never => "never",
            RestartArg::OnNodeLoss => "on_node_loss",
        });
    }
    let service: ServiceSpec =
        serde_json::from_value(service).map_err(|_| CliError::usage("could not build the service from the flags"))?;
    spec.service = Some(service);

    for text in &args.volumes {
        let (name, mount, max_mb) = parse_volume(text).map_err(CliError::Usage)?;
        let volume: VolumeSpec = serde_json::from_value(json!({"name": name, "mount": mount, "max_mb": max_mb}))
            .map_err(|_| CliError::usage("could not build the volume from the flags"))?;
        spec.volumes.push(volume);
    }
    spec.validate(&local_limits())?;
    Ok(spec)
}

/// `p2pc service run`: submits the service and prints its job ID; with `--wait-ready`, waits until it is healthy.
async fn start(ctx: &mut Ctx<'_, '_>, args: ServiceRunArgs) -> Result<u8, CliError> {
    let mut spec = build_service_spec(&args, ctx.host.env)?;
    let client = ctx.client()?;
    // Fixed here so that it can be printed if the submission is interrupted, as `p2pc run` does.
    let key = spec
        .idempotency_key
        .get_or_insert_with(p2pc_client::generate_idempotency_key)
        .clone();
    let interrupt = ctx.host.interrupt.take();
    let mut interrupt = std::pin::pin!(signal_or_never(interrupt));
    let job = tokio::select! {
        biased;
        () = &mut interrupt => {
            let _ = writeln!(
                ctx.host.err,
                "\ninterrupted while submitting the service: it may or may not have been created."
            );
            let _ = writeln!(
                ctx.host.err,
                "Its idempotency key is {key}. Run the same command with --idempotency-key {key} to get that job \
                 without creating a second one, or look for it with `p2pc service list`."
            );
            return Ok(EXIT_INTERRUPTED);
        }
        job = client.create_job(&spec) => job?,
    };
    if ctx.json {
        ctx.print_json(&job)?;
    } else {
        // Alone on stdout, so that `id=$(p2pc service run …)` works, and before any waiting: the service exists now.
        writeln!(ctx.host.out, "{}", job.id)?;
    }
    if !args.wait_ready {
        return Ok(EXIT_OK);
    }
    let _ = writeln!(ctx.host.err, "waiting for {} to become healthy…", job.id);
    let mut poller = Poller::new(ctx.host.poll);
    let id = job.id;
    let ended = loop {
        let state = tokio::select! {
            biased;
            () = &mut interrupt => {
                // Ctrl-C stops waiting and never stops the service (spec §7).
                let _ = writeln!(
                    ctx.host.err,
                    "\nstopped waiting: {id} keeps running. To stop it: p2pc service stop {id}"
                );
                return Ok(EXIT_INTERRUPTED);
            }
            state = poller.poll(&client, &id) => state?,
        };
        if state.status.is_terminal() {
            break state;
        }
        if state.service.as_ref().and_then(|s| s.health) == Some(ServiceHealth::Healthy) {
            let _ = writeln!(ctx.host.err, "{id} is healthy");
            return Ok(EXIT_OK);
        }
    };
    let _ = writeln!(
        ctx.host.err,
        "the service ended before it became healthy: {}",
        describe_service(&ended)
    );
    // It exited by itself before it was ever healthy: that is not "ready", whatever its code was.
    Ok(match ended.status {
        JobStatus::Succeeded => EXIT_CANNOT_RUN,
        _ => exit_code(&ended),
    })
}

/// How a service ended, for stderr: the job's own description, and the reason the hub gave, if any.
fn describe_service(job: &Job) -> String {
    let mut text = describe(job);
    if let Some(reason) = &job.reason {
        text.push_str(&format!(" ({})", printable(reason)));
    }
    text
}

// ---------------------------------------------------------------------------------------------------------------
// polling a job
// ---------------------------------------------------------------------------------------------------------------

/// Asks for a job's state on a schedule (`Host::poll`): the wait grows while nothing changes, and a transient failure
/// is retried for up to `give_up_after`. The wait is a deadline, so a poll that a `select!` drops and starts again does
/// not push the next one back.
struct Poller {
    schedule: PollSchedule,
    wait: Duration,
    next_at: Instant,
    failing_since: Option<Instant>,
    last: Option<(JobStatus, Option<ServiceHealth>)>,
}

impl Poller {
    fn new(schedule: PollSchedule) -> Self {
        Self {
            schedule,
            wait: schedule.initial,
            next_at: Instant::now(),
            failing_since: None,
            last: None,
        }
    }

    /// The job's state, once it is time to ask. An error that is not transient, or a transient one that lasted too
    /// long, ends the watch.
    async fn poll(&mut self, client: &Client, id: &JobId) -> Result<Job, CliError> {
        loop {
            tokio::time::sleep_until(self.next_at).await;
            match client.get_job(id).await {
                Ok(job) => {
                    self.failing_since = None;
                    let key = (job.status, job.service.as_ref().and_then(|s| s.health));
                    self.wait = if self.last == Some(key) {
                        (self.wait + self.wait / 2).min(self.schedule.max)
                    } else {
                        self.schedule.initial
                    };
                    self.last = Some(key);
                    self.next_at = Instant::now() + self.wait;
                    return Ok(job);
                }
                Err(e) if is_transient(&e) => {
                    let since = *self.failing_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= self.schedule.give_up_after {
                        return Err(e.into());
                    }
                    self.next_at =
                        Instant::now() + self.schedule.reconnect_max.min(self.wait.max(self.schedule.initial));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------------------------------------------

async fn list(ctx: &mut Ctx<'_, '_>, args: ServiceListArgs) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let jobs = collect(args.all, args.limit, &mut *ctx.host.err, |limit, cursor| {
        let client = client.clone();
        async move {
            client
                .list_jobs(&JobListParams {
                    kind: Some(JobKind::Service),
                    limit: Some(limit),
                    cursor,
                    ..JobListParams::default()
                })
                .await
        }
    })
    .await?;
    if ctx.json {
        ctx.print_json(&jobs)?;
    } else if jobs.is_empty() {
        writeln!(ctx.host.err, "No services.")?;
    } else {
        write!(ctx.host.out, "{}", service_table(&jobs, ctx.host.now).render())?;
    }
    Ok(0)
}

/// `8080(web),9090(port-9090)`: the ports of a service, from its spec.
fn ports_text(job: &Job) -> String {
    let ports = job
        .spec
        .service
        .as_ref()
        .map(|s| s.ports.as_slice())
        .unwrap_or_default();
    or_dash((!ports.is_empty()).then(|| {
        ports
            .iter()
            .map(|p| format!("{}({})", p.port, printable(&p.name)))
            .collect::<Vec<_>>()
            .join(",")
    }))
}

fn service_table(jobs: &[Job], now: OffsetDateTime) -> Table {
    let mut table = Table::new(["ID", "NAME", "STATUS", "HEALTH", "PORTS", "CONNECTIONS", "CREATED"]);
    for job in jobs {
        let view = job.service.as_ref();
        table.row([
            job.id.to_string(),
            or_dash(job.name.as_deref().map(printable)),
            job.status.to_string(),
            or_dash(view.and_then(|v| v.health).map(|h| wire_name(&h))),
            ports_text(job),
            view.map_or_else(|| "-".to_string(), |v| v.open_connections.to_string()),
            fmt_age(now, job.created_at),
        ]);
    }
    table
}

/// The rows `p2pc status` adds for a service (H2 §7.2).
pub(crate) fn service_rows(job: &Job, now: OffsetDateTime) -> Vec<(&'static str, String)> {
    let Some(view) = &job.service else { return Vec::new() };
    let when = |at: Option<OffsetDateTime>| or_dash(at.map(|at| format!("{} ({})", fmt_time(at), fmt_age(now, at))));
    let mut rows = vec![
        ("health", or_dash(view.health.map(|h| wire_name(&h)))),
        ("ports", ports_text(job)),
        ("connections", view.open_connections.to_string()),
        ("idle deadline", when(view.idle_deadline)),
        ("deadline", when(view.deadline)),
        ("restarts (24h)", view.restarts_24h.to_string()),
    ];
    if let Some(setup) = &view.setup {
        rows.push((
            "model pull",
            format!(
                "{} ({} of {} MiB)",
                wire_name(&setup.state),
                setup.completed_mb,
                setup.total_mb.map_or_else(|| "?".to_string(), |t| t.to_string())
            ),
        ));
    }
    rows
}

// ---------------------------------------------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------------------------------------------

/// The exit code of `p2pc service connect` for a service in its final state (H2 §7.8): stopping a service, or its clean
/// exit, is not a failure; the others are the codes of `p2pc run`.
fn connect_exit_code(job: &Job) -> u8 {
    match job.status {
        JobStatus::Cancelled | JobStatus::Succeeded => EXIT_OK,
        _ => exit_code(job),
    }
}

/// `p2pc service connect <job> --port <p> [--listen <addr>]`.
async fn connect(ctx: &mut Ctx<'_, '_>, args: ServiceConnectArgs) -> Result<u8, CliError> {
    if !args.listen.ip().is_loopback() && !args.allow_non_loopback {
        return Err(CliError::usage(format!(
            "--listen {} is not a loopback address: it would let that network reach the service. Pass \
             --allow-non-loopback if that is what you want.",
            args.listen
        )));
    }
    let client = ctx.client()?;
    let id = args.id;
    let port = u32::from(args.port);

    // Look before listening: a job that is not a service, a port it does not expose and a service that is already over
    // each have a clearer answer here than a refused connection later.
    let job = client.get_job(&id).await?;
    if job.spec.kind != JobKind::Service {
        return Err(CliError::usage(format!("{id} is not a service (it is a batch job)")));
    }
    if job.status.is_terminal() {
        writeln!(ctx.host.err, "{id} has ended: {}", describe_service(&job))?;
        return Ok(connect_exit_code(&job));
    }
    let exposed: Vec<u32> = job
        .spec
        .service
        .as_ref()
        .map(|s| s.ports.iter().map(|p| p.port).collect())
        .unwrap_or_default();
    if !exposed.contains(&port) {
        let list: Vec<String> = exposed.iter().map(u32::to_string).collect();
        return Err(CliError::usage(format!(
            "{id} does not expose port {port} (it exposes: {})",
            list.join(", ")
        )));
    }
    if !args.listen.ip().is_loopback() {
        writeln!(
            ctx.host.err,
            "warning: listening on {}, which is not loopback: that network can reach the service.",
            args.listen
        )?;
    }
    // Tunnels are watched like `p2pc proxy` does, so that a laptop that changes network keeps working (§10).
    let _network_watch = ctx.watch_networks().await;
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| CliError::usage(format!("cannot listen on {}: {e}", args.listen)))?;
    let local = listener.local_addr()?;
    writeln!(
        ctx.host.err,
        "p2pc service connect: listening on {local} for port {port} of {id}. Stop with Ctrl-C."
    )?;
    ctx.host.err.flush()?;

    let (interrupt, terminate) = (ctx.host.interrupt.take(), ctx.host.terminate.take());
    let mut interrupt = std::pin::pin!(signal_or_never(interrupt));
    let mut terminate = std::pin::pin!(signal_or_never(terminate));
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let (notes, mut notes_rx) = mpsc::unbounded_channel::<String>();
    let mut connections = JoinSet::new();
    let mut poller = Poller::new(ctx.host.poll);
    let code = loop {
        tokio::select! {
            biased;
            () = &mut interrupt => break EXIT_INTERRUPTED,
            () = &mut terminate => break EXIT_OK,
            Some(note) = notes_rx.recv() => {
                let _ = writeln!(ctx.host.err, "p2pc service connect: {note}");
            }
            // Reap finished connection tasks so the set does not grow.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            state = poller.poll(&client, &id) => match state {
                Ok(job) if job.status.is_terminal() => {
                    let _ = writeln!(ctx.host.err, "p2pc service connect: {id} has ended: {}", describe_service(&job));
                    break connect_exit_code(&job);
                }
                Ok(_) => {}
                Err(e) => {
                    connections.shutdown().await;
                    return Err(e);
                }
            },
            accepted = accept(&listener, &slots) => match accepted {
                Ok((tcp, permit)) => {
                    let (client, notes) = (client.clone(), notes.clone());
                    connections.spawn(async move {
                        let _permit = permit;
                        forward(client, id, port, tcp, notes).await;
                    });
                }
                Err(e) => {
                    let _ = writeln!(ctx.host.err, "p2pc service connect: accept failed: {e}");
                    // Out of file descriptors, for example: do not spin.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    };
    connections.shutdown().await;
    Ok(code)
}

/// Waits for a free slot, then for a connection.
async fn accept(
    listener: &TcpListener,
    slots: &Arc<Semaphore>,
) -> std::io::Result<(tokio::net::TcpStream, tokio::sync::OwnedSemaphorePermit)> {
    let permit = slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| std::io::Error::other("shutting down"))?;
    let (tcp, _) = listener.accept().await?;
    Ok((tcp, permit))
}

/// One local connection: an upgraded connection to the service's port, then bytes both ways until either side closes.
/// A refusal is reported once, with the hub's reason and without the request, and the local connection is dropped.
async fn forward(
    client: Client,
    id: JobId,
    port: u32,
    mut tcp: tokio::net::TcpStream,
    notes: mpsc::UnboundedSender<String>,
) {
    // A service that is still starting is waited for by the hub (up to 30 s) instead of refusing the connection.
    let mut stream: PortStream = match client.open_port(&id, port, true).await {
        Ok(stream) => stream,
        Err(e) => {
            let _ = notes.send(format!("could not open port {port}: {}", describe_error(&e)));
            return;
        }
    };
    // An end that closes ends the other: the result is the byte counts or the error of a connection that broke, and
    // neither is worth a line.
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
}

/// An error for a line on stderr: the hub's code and reason, safe for a terminal.
fn describe_error(e: &Error) -> String {
    printable(&e.to_string())
}
