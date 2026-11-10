// SPDX-License-Identifier: Apache-2.0

//! `p2pc run` and `p2pc estimate`: turning flags into a job spec, submitting it and following it.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use p2pc_client::Client;
use p2pc_proto::api::{
    BlobInput, DEFAULT_DISK_MB, DEFAULT_MAX_ATTEMPTS, DEFAULT_TIMEOUT_S, Egress, InputFile, Job, JobSpec, Outputs,
    Placement, Resources, Retry,
};
use p2pc_proto::ids::JobId;
use p2pc_proto::validate::{H2Features, Limits};

use crate::app::{CliError, Ctx};
use crate::cli::{JobArgs, RunArgs};
use crate::commands::logs::{Live, LogWriter};
use crate::config::Env;
use crate::follow::{FollowError, Followed, PollSchedule, StreamFollower, TokioSleeper};
use crate::outcome::{EXIT_INTERRUPTED, describe, exit_code};
use crate::output::{fmt_cpu, render_kv};
use crate::parse::{parse_env_arg, parse_env_file, parse_file_arg, parse_input_arg};

/// The limits applied before sending: the §7 table without the registry policy, which only the server knows (it may
/// allow more registries than the default list). The server stays the authority on everything.
///
/// The H2 job features are on: the CLI only sends `service`, `volumes` or `inputs` when the user asked for them, and the
/// hub decides whether it serves them.
pub(crate) fn local_limits() -> Limits {
    Limits {
        allowed_registries: None,
        h2: H2Features::ALL,
        ..Limits::default()
    }
}

/// What `--input` did for one file.
#[derive(Debug, Clone)]
pub(crate) struct InputReport {
    /// Where the job sees it.
    pub path: String,
    /// Its size in bytes.
    pub size: u64,
    /// Whether it was uploaded now (`false`: the hub had it, or this is an estimate and nothing is uploaded).
    pub uploaded: bool,
}

/// Turns every `--input` into a blob input of the spec: hashes the file, uploads it unless the hub has it (`upload`),
/// adds the `inputs` entry and checks the result again, with the disk rule of §7.1 and the real size of the blobs.
///
/// `upload` is `false` for `p2pc estimate`, which must have no side effect: it hashes the file and names the blob, and
/// the hub says whether it could run such a job.
pub(crate) async fn attach_inputs(
    client: &Client,
    spec: &mut JobSpec,
    args: &JobArgs,
    upload: bool,
) -> Result<Vec<InputReport>, CliError> {
    let mut reports = Vec::new();
    let mut total: u64 = 0;
    for arg in &args.inputs {
        let input = parse_input_arg(arg).map_err(CliError::Usage)?;
        let remote = match input.remote {
            Some(remote) => remote,
            None => format!("/inputs/{}", file_name(&input.local)?),
        };
        let measured = crate::commands::blobs::measure(&input.local)
            .await
            .map_err(|e| CliError::usage(format!("--input {e}")))?;
        let uploaded = if upload {
            crate::commands::blobs::upload_if_missing(client, &input.local, measured).await?
        } else {
            false
        };
        total = total.saturating_add(measured.size);
        // Built through serde: a `BlobInput` is a type of `p2pc-proto`, which may grow fields (CONTRIBUTING rule 7).
        let entry: BlobInput = serde_json::from_value(serde_json::json!({
            "path": remote,
            "blob": crate::commands::blobs::blob_ref(&measured.digest),
        }))
        .map_err(|_| CliError::usage("--input: could not build the input"))?;
        spec.inputs.push(entry);
        reports.push(InputReport {
            path: remote,
            size: measured.size,
            uploaded,
        });
    }
    if !reports.is_empty() {
        let limits = local_limits();
        spec.validate(&limits)?;
        spec.check_inputs_fit_disk(total)?;
    }
    Ok(reports)
}

/// Uploads the inputs and submits the job: the whole of what Ctrl-C interrupts in `p2pc run`.
async fn submit(client: &Client, spec: &mut JobSpec, args: &JobArgs) -> Result<(Job, Vec<InputReport>), CliError> {
    let reports = attach_inputs(client, spec, args, true).await?;
    Ok((client.create_job(spec).await?, reports))
}

/// Builds and validates the job spec from the flags. `env` answers `--env KEY`; files are read from disk.
pub fn build_spec(args: &JobArgs, env: Env) -> Result<JobSpec, CliError> {
    let limits = local_limits();

    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    for path in &args.env_file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CliError::usage(format!("--env-file {}: {e}", path.display())))?;
        let entries =
            parse_env_file(&text).map_err(|e| CliError::usage(format!("--env-file {}: {e}", path.display())))?;
        vars.extend(entries);
    }
    for arg in &args.env {
        let (name, value) = parse_env_arg(arg, env).map_err(CliError::Usage)?;
        vars.insert(name, value);
    }

    let mut files = Vec::new();
    let mut total = 0usize;
    for arg in &args.files {
        let file = parse_file_arg(arg).map_err(CliError::Usage)?;
        let remote = match file.remote {
            Some(remote) => remote,
            None => format!("/inputs/{}", file_name(&file.local)?),
        };
        // Check the size before reading: a mistaken `--file /dev/zero` or a huge file must not fill the memory.
        let meta = std::fs::metadata(&file.local)
            .map_err(|e| CliError::usage(format!("--file {}: {e}", file.local.display())))?;
        if !meta.is_file() {
            return Err(CliError::usage(format!(
                "--file {}: not a regular file",
                file.local.display()
            )));
        }
        total = total.saturating_add(usize::try_from(meta.len()).unwrap_or(usize::MAX));
        if total > limits.max_files_bytes {
            return Err(CliError::usage(format!(
                "--file: inline inputs are limited to {} KiB in total; fetch bigger data from inside the job with --egress",
                limits.max_files_bytes / 1024
            )));
        }
        let bytes =
            std::fs::read(&file.local).map_err(|e| CliError::usage(format!("--file {}: {e}", file.local.display())))?;
        files.push(InputFile {
            path: remote,
            content_b64: data_encoding::BASE64.encode(&bytes),
        });
    }

    let spec = JobSpec {
        name: args.name.clone(),
        image: args.image.clone(),
        command: args.command.clone(),
        env: vars,
        files,
        resources: Resources {
            cpu: args.cpu,
            memory_mb: args.mem,
            gpu: args.gpu,
            disk_mb: args.disk.unwrap_or(DEFAULT_DISK_MB),
        },
        timeout_s: args.timeout.unwrap_or(DEFAULT_TIMEOUT_S),
        egress: Egress {
            // Domains are lowercase in the API; accept what people type.
            allow: args.egress.iter().map(|d| d.trim().to_ascii_lowercase()).collect(),
        },
        outputs: Outputs::default(),
        placement: Placement {
            node_id: args.node,
            labels: args.labels.iter().cloned().collect(),
            ..Placement::default()
        },
        retry: Retry {
            max_attempts: args.retries.map_or(DEFAULT_MAX_ATTEMPTS, |n| n.saturating_add(1)),
        },
        idempotency_key: args.idempotency_key.clone(),
        kind: p2pc_proto::api::JobKind::Batch,
        service: None,
        volumes: Vec::new(),
        inputs: Vec::new(),
        template: None,
    };
    spec.validate(&limits)?;
    Ok(spec)
}

fn file_name(path: &Path) -> Result<String, CliError> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            CliError::usage(format!(
                "--file {}: cannot tell the file's name; use LOCAL:/inputs/NAME",
                path.display()
            ))
        })
}

/// How long `p2pc run` waits to learn the job's state after its stdout closed: the command is leaving, and a slow server
/// must not hold it.
const STATE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// `p2pc run`: submit, then follow until the job ends (or detach).
///
/// Ctrl-C is watched from before the submission: during it (or its retries) the command stops with 130 and prints the
/// idempotency key, which makes a second try return the same job instead of a new one.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: RunArgs) -> Result<u8, CliError> {
    let mut spec = build_spec(&args.job, ctx.host.env)?;
    let client = ctx.client()?;
    // Fixed here, not in the client, so that it can be printed if the submission is interrupted.
    let key = spec
        .idempotency_key
        .get_or_insert_with(p2pc_client::generate_idempotency_key)
        .clone();
    let interrupt = ctx.host.interrupt.take();
    let mut interrupt = std::pin::pin!(async move {
        match interrupt {
            Some(signal) => signal.await,
            None => std::future::pending().await,
        }
    });
    let (job, reports) = tokio::select! {
        biased;
        () = &mut interrupt => {
            // Best effort: the exit code says what happened even if stderr is gone.
            let _ = writeln!(
                ctx.host.err,
                "\ninterrupted while submitting the job: it may or may not have been created."
            );
            let _ = writeln!(
                ctx.host.err,
                "Its idempotency key is {key}. Run the same command with --idempotency-key {key} to get that job \
                 (or submit it) without creating a second one, or look for it with `p2pc jobs`."
            );
            return Ok(EXIT_INTERRUPTED);
        }
        submitted = submit(&client, &mut spec, &args.job) => submitted?,
    };
    for report in &reports {
        let _ = writeln!(
            ctx.host.err,
            "input {} ({}): {}",
            crate::output::printable(&report.path),
            crate::output::fmt_bytes(report.size),
            if report.uploaded {
                "uploaded"
            } else {
                "already on the hub"
            }
        );
    }

    if args.detach {
        if ctx.json {
            ctx.print_json(&job)?;
        } else {
            writeln!(ctx.host.out, "{}", job.id)?;
        }
        return Ok(0);
    }

    // Best effort, like every write to stderr from here on: a closed stderr must not stop the job from being followed,
    // or turn the outcome into 0 (`app::run` maps a `BrokenPipe` to success).
    let _ = writeln!(ctx.host.err, "{}", job.id);
    let id = job.id;
    let json = ctx.json;
    let (out_tty, err_tty) = (ctx.host.stdout_is_tty, ctx.host.stderr_is_tty);
    let followed = {
        // The job's stdout goes to stdout and its stderr to stderr (best effort: a closed stderr does not end the
        // follow), escaped on a terminal; the state changes go to stderr between its lines. With --json, stdout is
        // NDJSON: the log lines, then the final job.
        let mut writer = LogWriter::new(&mut *ctx.host.out, &mut *ctx.host.err, out_tty, err_tty, false, json);
        StreamFollower::new(PollSchedule::default(), TokioSleeper, 0, None)
            .follow(
                &client,
                job,
                &mut Live {
                    writer: &mut writer,
                    show_status: true,
                },
                &mut interrupt,
            )
            .await
    };
    match followed {
        Ok(Followed::Finished(job)) => {
            // The job has ended: its code is the command's, whatever happens to the streams now. A closed stdout or
            // stderr (`| head -1`, which may already have left) is not an error (spec §7); `app::run` would turn
            // it into 0, so it is handled here.
            let _ = writeln!(ctx.host.err, "{}", describe(&job));
            if json {
                let line =
                    serde_json::to_string(&job).map_err(|_| CliError::usage("could not encode the job as JSON"))?;
                match writeln!(ctx.host.out, "{line}") {
                    Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e.into()),
                    _ => {}
                }
            }
            Ok(exit_code(&job))
        }
        Ok(Followed::Interrupted(_)) => {
            // Ctrl-C detaches and never cancels (spec §7).
            let _ = detach_hint(ctx.host.err, &id);
            Ok(EXIT_INTERRUPTED)
        }
        Err(FollowError::Client(e)) => {
            // The job exists: say how to find it again.
            let _ = writeln!(
                ctx.host.err,
                "the job was submitted as {id}; check it with `p2pc status {id}` or follow it with `p2pc logs --follow {id}`"
            );
            Err(e.into())
        }
        Err(FollowError::Sink(e, known)) => {
            // stdout stopped taking the log (`p2pc run … | head -1`, a full disk). Say the truth about the job, which
            // may have ended while the last lines were being written: ask once more, briefly, and fall back on what
            // the follow knew. stderr may be gone too, so nothing here may fail the command.
            let job = match tokio::time::timeout(STATE_CHECK_TIMEOUT, client.get_job(&id)).await {
                Ok(Ok(fresh)) => fresh,
                _ => *known,
            };
            let ended = job.status.is_terminal();
            if ended {
                let _ = writeln!(ctx.host.err, "{}", describe(&job));
            } else {
                // Still running and spending units: leave it the way Ctrl-C does (spec §7).
                let _ = detach_hint(ctx.host.err, &id);
            }
            if e.kind() != io::ErrorKind::BrokenPipe {
                return Err(e.into());
            }
            // The reader left on purpose: not an error. The job's own code if it ended, else "detached".
            Ok(if ended { exit_code(&job) } else { EXIT_INTERRUPTED })
        }
    }
}

/// Tells how to follow a job that keeps running after `p2pc run` has left it, and how to stop it.
fn detach_hint(err: &mut dyn Write, id: &JobId) -> io::Result<()> {
    writeln!(
        err,
        "\ndetached: job {id} keeps running. To follow it again or to stop it:"
    )?;
    writeln!(err, "  p2pc logs --follow {id}")?;
    writeln!(err, "  p2pc cancel {id}")
}

/// `p2pc estimate`.
pub async fn estimate(ctx: &mut Ctx<'_, '_>, args: JobArgs) -> Result<u8, CliError> {
    let mut spec = build_spec(&args, ctx.host.env)?;
    let client = ctx.client()?;
    // Nothing is uploaded for an estimate: the file is hashed and named, and the hub says whether it could run.
    attach_inputs(&client, &mut spec, &args, false).await?;
    let estimate = client.estimate(&spec).await?;
    if ctx.json {
        ctx.print_json(&estimate)?;
        return Ok(0);
    }
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_string();
    let mut rows = vec![
        ("feasible", yes_no(estimate.feasible)),
        ("matching machines", estimate.matching_nodes.to_string()),
        ("would queue", yes_no(estimate.would_queue)),
        ("units per hour", estimate.units_per_hour.to_string()),
    ];
    if let Some(reason) = &estimate.reason {
        rows.push(("reason", reason.clone()));
    }
    rows.push((
        "request",
        format!(
            "{} vCPU, {} MiB, {} GPU",
            fmt_cpu(spec.resources.cpu),
            spec.resources.memory_mb,
            spec.resources.gpu
        ),
    ));
    write!(ctx.host.out, "{}", render_kv(&rows))?;
    Ok(0)
}
