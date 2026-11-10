// SPDX-License-Identifier: Apache-2.0

//! `devices`: list, revoke and pair devices (H2 §5.2, §7.3, §7.8).

use p2pc_client::ListParams;
use p2pc_proto::api::{CreatePairingTicket, DeviceInfo};
use time::OffsetDateTime;

use super::collect;
use crate::app::{CliError, Ctx};
use crate::cli::{DevicePair, DeviceRevoke, DevicesArgs, DevicesCommand};
use crate::output::{Table, fmt_age, fmt_time, or_dash, printable, wire_name};

/// `p2pc devices <ls|revoke|pair>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: DevicesArgs) -> Result<u8, CliError> {
    match args.command {
        DevicesCommand::Ls => list(ctx).await,
        DevicesCommand::Revoke(a) => revoke(ctx, a).await,
        DevicesCommand::Pair(a) => pair(ctx, a).await,
    }
}

async fn list(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let devices = collect(true, 100, &mut *ctx.host.err, |limit, cursor| {
        let client = client.clone();
        async move {
            client
                .list_devices(&ListParams {
                    limit: Some(limit),
                    cursor,
                })
                .await
        }
    })
    .await?;
    if ctx.json {
        ctx.print_json(&devices)?;
    } else if devices.is_empty() {
        writeln!(ctx.host.err, "No devices.")?;
    } else {
        write!(ctx.host.out, "{}", device_table(&devices, ctx.host.now).render())?;
    }
    Ok(0)
}

fn device_status(d: &DeviceInfo, now: OffsetDateTime) -> &'static str {
    if d.revoked_at.is_some() {
        "revoked"
    } else if !d.is_live(now) {
        "expired"
    } else {
        "live"
    }
}

fn device_table(devices: &[DeviceInfo], now: OffsetDateTime) -> Table {
    let mut table = Table::new([
        "ID",
        "LABEL",
        "PLATFORM",
        "SCOPES",
        "DAILY CAP",
        "EXPIRES",
        "LAST SEEN",
        "STATUS",
    ]);
    for d in devices {
        let scopes: Vec<String> = d.scopes.iter().map(wire_name).collect();
        table.row([
            d.id.to_string(),
            // The label and the platform are text the device sent when it paired.
            or_dash(d.label.as_deref().map(printable)),
            or_dash((!d.platform.is_empty()).then(|| printable(&d.platform))),
            scopes.join(","),
            d.daily_unit_cap.map_or_else(|| "-".to_string(), |c| c.to_string()),
            d.expires_at.map_or_else(|| "never".to_string(), fmt_time),
            d.last_seen_at
                .map_or_else(|| "never".to_string(), |at| fmt_age(now, at)),
            device_status(d, now).to_string(),
        ]);
    }
    table
}

async fn revoke(ctx: &mut Ctx<'_, '_>, args: DeviceRevoke) -> Result<u8, CliError> {
    ctx.client()?.revoke_device(&args.id).await?;
    if ctx.json {
        ctx.print_json(&serde_json::json!({"revoked": args.id}))?;
    } else {
        writeln!(ctx.host.out, "revoked {}", args.id)?;
    }
    Ok(0)
}

/// `p2pc devices pair`: creates the ticket and prints its URL.
///
/// The URL is a secret (§5.2): it goes to stdout exactly once, alone, so that `url=$(p2pc devices pair)` captures it,
/// and nothing else of this command carries it. The summary goes to stderr. On a terminal, a QR code of the URL follows
/// it on stdout.
async fn pair(ctx: &mut Ctx<'_, '_>, args: DevicePair) -> Result<u8, CliError> {
    let request = CreatePairingTicket {
        scopes: (!args.scopes.is_empty()).then_some(args.scopes),
        daily_unit_cap: args.cap,
        allowed_images: (!args.images.is_empty()).then_some(args.images),
        ..CreatePairingTicket::default()
    };
    request.validate(ctx.host.now)?;
    let created = ctx.client()?.create_pairing_ticket(&request).await?;

    writeln!(
        ctx.host.err,
        "Created pairing ticket {}. Its URL is shown only this once and works for one device until {}: open it on the \
         device, or scan the QR code.",
        created.id,
        fmt_time(created.expires_at)
    )?;
    if ctx.json {
        ctx.print_json(&created)?;
        return Ok(0);
    }
    // The URL comes from the hub: text for the terminal, never terminal commands.
    let url = printable(&created.url);
    writeln!(ctx.host.out, "{url}")?;
    if ctx.host.stdout_is_tty {
        // Drawn from the sanitized text, so that the code and the line above it can never differ.
        match qr(&url) {
            Some(code) => write!(ctx.host.out, "{code}")?,
            None => writeln!(
                ctx.host.err,
                "(the URL is too long for a QR code: type it on the device)"
            )?,
        }
    }
    Ok(0)
}

/// A QR code of `text` for a terminal: two rows of modules per line, light modules as blocks so that it reads on a
/// dark background. `None` if the text does not fit in a code.
fn qr(text: &str) -> Option<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let mut drawn = code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build();
    drawn.push('\n');
    Some(drawn)
}
