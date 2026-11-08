// SPDX-License-Identifier: Apache-2.0

//! `audit`.

use p2pc_client::ListParams;
use p2pc_proto::api::AuditEvent;

use super::collect;
use crate::app::{CliError, Ctx};
use crate::cli::AuditArgs;
use crate::output::{Table, fmt_time, or_dash, wire_name};

/// `p2pc audit`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: AuditArgs) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let events = collect(args.all, args.limit, &mut *ctx.host.err, |limit, cursor| {
        let client = client.clone();
        async move {
            client
                .list_audit(&ListParams {
                    limit: Some(limit),
                    cursor,
                })
                .await
        }
    })
    .await?;
    if ctx.json {
        ctx.print_json(&events)?;
    } else if events.is_empty() {
        writeln!(ctx.host.err, "No audit events.")?;
    } else {
        write!(ctx.host.out, "{}", audit_table(&events).render())?;
    }
    Ok(0)
}

fn audit_table(events: &[AuditEvent]) -> Table {
    let mut table = Table::new(["TIME", "EVENT", "ACTOR KEY", "SUBJECT", "DETAIL"]);
    for e in events {
        let detail = if e.detail.is_empty() {
            "-".to_string()
        } else {
            serde_json::Value::Object(e.detail.clone()).to_string()
        };
        table.row([
            fmt_time(e.at),
            wire_name(&e.kind),
            or_dash(e.actor_key_id.map(|k| k.to_string())),
            or_dash(e.subject_id.clone()),
            detail,
        ]);
    }
    table
}
