// SPDX-License-Identifier: Apache-2.0

//! `keys`: create, list and revoke API keys.

use std::time::Duration;

use p2pc_client::ListParams;
use p2pc_proto::api::{ApiKeyInfo, CreateApiKey, Scope};
use p2pc_proto::units::Units;
use time::OffsetDateTime;

use super::collect;
use crate::app::{CliError, Ctx};
use crate::cli::{KeysArgs, KeysCommand};
use crate::output::{Table, fmt_age, fmt_time, or_dash, wire_name};

/// `p2pc keys <create|list|revoke>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: KeysArgs) -> Result<u8, CliError> {
    match args.command {
        KeysCommand::Create {
            label,
            scopes,
            cap,
            images,
            expires,
        } => create(ctx, label, scopes, cap, images, expires).await,
        KeysCommand::List => list(ctx).await,
        KeysCommand::Revoke { id } => {
            ctx.client()?.revoke_key(&id).await?;
            if ctx.json {
                ctx.print_json(&serde_json::json!({"revoked": id}))?;
            } else {
                writeln!(ctx.host.out, "revoked {id}")?;
            }
            Ok(0)
        }
    }
}

async fn create(
    ctx: &mut Ctx<'_, '_>,
    label: String,
    scopes: Vec<Scope>,
    cap: Option<Units>,
    images: Vec<String>,
    expires: Option<Duration>,
) -> Result<u8, CliError> {
    let now = ctx.host.now;
    let expires_at = expires
        .map(|d| {
            time::Duration::try_from(d)
                .ok()
                .and_then(|d| now.checked_add(d))
                // The server takes whole seconds only (real-run bug: a clock has a fraction).
                .map(p2pc_client::whole_seconds)
                .ok_or_else(|| CliError::usage("--expires is too far in the future"))
        })
        .transpose()?;
    let request = CreateApiKey {
        label: Some(label),
        scopes,
        expires_at,
        daily_unit_cap: cap,
        allowed_images: (!images.is_empty()).then_some(images),
    };
    request.validate(now)?;
    let created = ctx.client()?.create_key(&request).await?;

    // The key goes to stdout exactly once; the warning and the summary go to stderr, so `$(p2pc keys create …)`
    // captures only the key.
    let scopes: Vec<String> = created.info.scopes.iter().map(wire_name).collect();
    writeln!(
        ctx.host.err,
        "Created key {} with scopes {}. Store the key now: it is shown only this once and cannot be recovered.",
        created.info.id,
        scopes.join(", ")
    )?;
    if ctx.json {
        ctx.print_json(&created)?;
    } else {
        writeln!(ctx.host.out, "{}", created.key.expose())?;
    }
    Ok(0)
}

async fn list(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let keys = collect(true, 100, &mut *ctx.host.err, |limit, cursor| {
        let client = client.clone();
        async move {
            client
                .list_keys(&ListParams {
                    limit: Some(limit),
                    cursor,
                })
                .await
        }
    })
    .await?;
    if ctx.json {
        ctx.print_json(&keys)?;
    } else if keys.is_empty() {
        writeln!(ctx.host.err, "No keys.")?;
    } else {
        write!(ctx.host.out, "{}", key_table(&keys, ctx.host.now).render())?;
    }
    Ok(0)
}

fn key_status(k: &ApiKeyInfo, now: OffsetDateTime) -> &'static str {
    if k.revoked_at.is_some() {
        "revoked"
    } else if k.expires_at.is_some_and(|at| at <= now) {
        "expired"
    } else {
        "active"
    }
}

fn key_table(keys: &[ApiKeyInfo], now: OffsetDateTime) -> Table {
    let mut table = Table::new([
        "ID",
        "LABEL",
        "SCOPES",
        "DAILY CAP",
        "IMAGES",
        "EXPIRES",
        "LAST USED",
        "STATUS",
    ]);
    for k in keys {
        let scopes: Vec<String> = k.scopes.iter().map(wire_name).collect();
        table.row([
            k.id.to_string(),
            or_dash(k.label.clone()),
            scopes.join(","),
            k.daily_unit_cap.map_or_else(|| "-".to_string(), |c| c.to_string()),
            k.allowed_images
                .as_ref()
                .map_or_else(|| "any".to_string(), |i| i.join(",")),
            k.expires_at.map_or_else(|| "never".to_string(), fmt_time),
            k.last_used_at
                .map_or_else(|| "never".to_string(), |at| fmt_age(now, at)),
            key_status(k, now).to_string(),
        ]);
    }
    table
}
