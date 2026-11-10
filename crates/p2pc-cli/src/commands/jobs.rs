// SPDX-License-Identifier: Apache-2.0

//! `jobs`, `status` and `cancel`.

use p2pc_client::JobListParams;
use p2pc_proto::api::Job;
use time::OffsetDateTime;

use super::collect;
use crate::app::{CliError, Ctx};
use crate::cli::{JobIdArg, JobsArgs};
use crate::output::{Table, fmt_age, fmt_cpu, fmt_duration_secs, fmt_mib, fmt_time, join_argv, or_dash, render_kv};

/// `p2pc jobs`.
pub async fn list(ctx: &mut Ctx<'_, '_>, args: JobsArgs) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let jobs = collect(args.all, args.limit, &mut *ctx.host.err, |limit, cursor| {
        let client = client.clone();
        let params = JobListParams {
            status: args.status,
            node_id: args.node,
            limit: Some(limit),
            cursor,
            ..JobListParams::default()
        };
        async move { client.list_jobs(&params).await }
    })
    .await?;
    if ctx.json {
        ctx.print_json(&jobs)?;
    } else if jobs.is_empty() {
        writeln!(ctx.host.err, "No jobs.")?;
    } else {
        let now = ctx.host.now;
        write!(ctx.host.out, "{}", job_table(&jobs, now).render())?;
    }
    Ok(0)
}

fn job_table(jobs: &[Job], now: OffsetDateTime) -> Table {
    let mut table = Table::new(["ID", "STATUS", "NAME", "IMAGE", "NODE", "CREATED"]);
    for job in jobs {
        table.row([
            job.id.to_string(),
            job.status.to_string(),
            or_dash(job.name.clone()),
            job.spec.image.clone(),
            or_dash(job.node_id.map(|n| n.to_string())),
            fmt_age(now, job.created_at),
        ]);
    }
    table
}

/// `p2pc status <id>`. The exit code is 0 whatever the job's state: the command worked.
pub async fn status(ctx: &mut Ctx<'_, '_>, args: JobIdArg) -> Result<u8, CliError> {
    let job = ctx.client()?.get_job(&args.id).await?;
    if ctx.json {
        ctx.print_json(&job)?;
    } else {
        let text = job_details(&job, ctx.host.now);
        write!(ctx.host.out, "{text}")?;
    }
    Ok(0)
}

/// `p2pc cancel <id>`.
pub async fn cancel(ctx: &mut Ctx<'_, '_>, args: JobIdArg) -> Result<u8, CliError> {
    let job = ctx.client()?.cancel_job(&args.id).await?;
    if ctx.json {
        ctx.print_json(&job)?;
    } else {
        writeln!(ctx.host.out, "{}: {}", job.id, job.status)?;
    }
    Ok(0)
}

fn job_details(job: &Job, now: OffsetDateTime) -> String {
    let when = |at: OffsetDateTime| format!("{} ({})", fmt_time(at), fmt_age(now, at));
    let r = &job.spec.resources;
    let mut rows = vec![
        ("id", job.id.to_string()),
        ("status", job.status.to_string()),
        ("name", or_dash(job.name.clone())),
        ("image", job.spec.image.clone()),
        ("command", join_argv(&job.spec.command)),
        (
            "resources",
            format!(
                "{} vCPU, {}, {} GPU, disk {}",
                fmt_cpu(r.cpu),
                fmt_mib(r.memory_mb),
                r.gpu,
                fmt_mib(r.disk_mb)
            ),
        ),
        ("timeout", fmt_duration_secs(u64::from(job.spec.timeout_s))),
        ("attempt", format!("{} of {}", job.attempt, job.spec.retry.max_attempts)),
        ("node", or_dash(job.node_id.map(|n| n.to_string()))),
    ];
    if let Some(code) = job.exit_code {
        rows.push(("exit code", code.to_string()));
    }
    if let Some(error) = &job.error {
        rows.push(("error", error.clone()));
    }
    if let Some(hint) = crate::outcome::disk_limit_hint(job, "`--disk <MiB>`") {
        rows.push(("hint", hint));
    }
    rows.extend(crate::commands::service::service_rows(job, now));
    rows.push(("estimated units", job.estimated_units.to_string()));
    rows.push(("created", when(job.created_at)));
    if let Some(at) = job.started_at {
        rows.push(("started", when(at)));
    }
    if let Some(at) = job.finished_at {
        rows.push(("finished", when(at)));
    }
    render_kv(&rows)
}
