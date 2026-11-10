// SPDX-License-Identifier: Apache-2.0

//! `volumes`: list the persistent volumes of the machines, and remove one (H2 §7.3, §7.8).

use p2pc_client::ListParams;
use p2pc_proto::api::VolumeInfo;
use p2pc_proto::validate::VolumeName;
use time::OffsetDateTime;

use super::collect;
use super::machines::resolve;
use crate::app::{CliError, Ctx};
use crate::cli::{VolumeRm, VolumesArgs, VolumesCommand};
use crate::output::{Table, fmt_age, fmt_mib, printable};

/// `p2pc volumes <ls|rm>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: VolumesArgs) -> Result<u8, CliError> {
    match args.command {
        VolumesCommand::Ls => list(ctx).await,
        VolumesCommand::Rm(a) => remove(ctx, a).await,
    }
}

async fn list(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let volumes = collect(true, 100, &mut *ctx.host.err, |limit, cursor| {
        let client = client.clone();
        async move {
            client
                .list_volumes(&ListParams {
                    limit: Some(limit),
                    cursor,
                })
                .await
        }
    })
    .await?;
    if ctx.json {
        ctx.print_json(&volumes)?;
    } else if volumes.is_empty() {
        writeln!(ctx.host.err, "No volumes.")?;
    } else {
        write!(ctx.host.out, "{}", volume_table(&volumes, ctx.host.now).render())?;
    }
    Ok(0)
}

fn volume_table(volumes: &[VolumeInfo], now: OffsetDateTime) -> Table {
    let mut table = Table::new(["NAME", "NODE", "SIZE", "LIMIT", "LAST USED", "IN USE BY"]);
    for v in volumes {
        table.row([
            // A name is a label chosen by a job or a template; the hub validates it, but a terminal is shown only
            // what is safe to show.
            printable(&v.name),
            v.node_id.to_string(),
            fmt_mib(v.size_mb),
            fmt_mib(v.max_mb),
            v.last_used_at
                .map_or_else(|| "never".to_string(), |at| fmt_age(now, at)),
            v.in_use_by.map_or_else(|| "-".to_string(), |job| job.to_string()),
        ]);
    }
    table
}

/// `p2pc volumes rm <node> <name>`: the name goes to the hub as one percent-encoded path segment (`tpl:a/b` as
/// `tpl%3Aa%2Fb`, H2 §7.3), which the client does for any name.
async fn remove(ctx: &mut Ctx<'_, '_>, args: VolumeRm) -> Result<u8, CliError> {
    // The rule of the JobSpec, and of the `{name}` segment once the hub has decoded it: a typo or a path is refused
    // here, before anything is sent.
    if VolumeName::parse(&args.name).is_err() {
        return Err(CliError::usage(format!(
            "{:?} is not a volume name: it must match [a-z0-9][a-z0-9._-]{{0,62}}, or be tpl:<template>/<name>. \
             `p2pc volumes ls` shows the names",
            printable(&args.name)
        )));
    }
    // Decided before any request: with no terminal there is nobody to ask.
    if !args.yes && !ctx.host.stdin_is_tty {
        return Err(CliError::usage(
            "refusing to remove a volume without confirmation: there is no terminal to ask, so pass --yes",
        ));
    }
    let client = ctx.client()?;
    let found = resolve(&client, &args.node).await?;
    if !args.yes {
        write!(
            ctx.host.err,
            "Remove volume {} from machine {}? Its data is deleted and cannot be recovered. [y/N] ",
            args.name, found.id
        )?;
        ctx.host.err.flush()?;
        let mut answer = String::new();
        ctx.host.stdin.read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            writeln!(ctx.host.err, "Not removed.")?;
            return Ok(crate::outcome::EXIT_INTERRUPTED);
        }
    }
    client.delete_volume(&found.id, &args.name).await?;
    if ctx.json {
        ctx.print_json(&serde_json::json!({"removed": args.name, "node_id": found.id}))?;
    } else {
        writeln!(ctx.host.out, "removed volume {} from {}", args.name, found.id)?;
    }
    Ok(0)
}
