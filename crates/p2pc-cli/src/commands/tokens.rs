// SPDX-License-Identifier: Apache-2.0

//! `join-token`: create, list and revoke the single-use tokens that enroll a machine.

use p2pc_client::ListParams;
use p2pc_proto::api::{CreateJoinToken, JoinTokenInfo};
use time::OffsetDateTime;

use super::collect;
use crate::app::{CliError, Ctx};
use crate::cli::{JoinTokenArgs, JoinTokenCommand};
use crate::output::{Table, fmt_age, fmt_time, or_dash};

/// `p2pc join-token <create|list|revoke>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: JoinTokenArgs) -> Result<u8, CliError> {
    match args.command {
        JoinTokenCommand::Create {
            expires,
            label,
            token_only,
        } => create(ctx, expires, label, token_only).await,
        JoinTokenCommand::List => list(ctx).await,
        JoinTokenCommand::Revoke { id } => {
            ctx.client()?.revoke_join_token(&id).await?;
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
    expires: Option<std::time::Duration>,
    label: Option<String>,
    token_only: bool,
) -> Result<u8, CliError> {
    if token_only && ctx.json {
        return Err(CliError::usage(
            "--token-only and --json are two output formats: use one",
        ));
    }
    let ttl_s = expires
        .map(|d| {
            if d.subsec_nanos() != 0 {
                return Err(CliError::usage("--expires must be a whole number of seconds"));
            }
            u32::try_from(d.as_secs()).map_err(|_| CliError::usage("--expires is too long: the maximum is 24h"))
        })
        .transpose()?;
    let request = CreateJoinToken {
        label,
        ttl_s,
        pre_approved: false,
    };
    request.validate()?;
    let response = ctx.client()?.create_join_token(&request).await?;
    if ctx.json {
        ctx.print_json(&response)?;
        return Ok(0);
    }
    let token = response
        .join_token
        .encode()
        .map_err(|_| CliError::usage("the server returned a join token that does not encode"))?;
    if token_only {
        writeln!(ctx.host.out, "{token}")?;
        return Ok(0);
    }
    write!(ctx.host.out, "{}", created_text(&token, &fmt_time(response.expires_at)))?;
    Ok(0)
}

/// What `join-token create` prints: the token once, on a line of its own, then how to use it on the new machine. No
/// command it suggests carries the token: a token in a command line ends up in argv (visible in `ps`) and in the shell
/// history of the new machine, so every installer asks for it instead (hidden input on a terminal, or stdin).
fn created_text(token: &str, expires: &str) -> String {
    format!(
        "Join token (single use, expires {expires}):\n  {token}\n\n\
         On the new machine, paste it when asked:\n\
         \x20 On Linux:   sudo sh install-node.sh --from <dist dir>\n\
         \x20 On Windows: .\\install.ps1 -Join\n\
         \x20 Or, where the agent is already installed: p2pc-agent join   (it asks for the token)\n"
    )
}

async fn list(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let tokens = collect(true, 100, &mut *ctx.host.err, |limit, cursor| {
        let client = client.clone();
        async move {
            client
                .list_join_tokens(&ListParams {
                    limit: Some(limit),
                    cursor,
                })
                .await
        }
    })
    .await?;
    if ctx.json {
        ctx.print_json(&tokens)?;
    } else if tokens.is_empty() {
        writeln!(ctx.host.err, "No join tokens.")?;
    } else {
        write!(ctx.host.out, "{}", token_table(&tokens, ctx.host.now).render())?;
    }
    Ok(0)
}

fn token_status(t: &JoinTokenInfo, now: OffsetDateTime) -> &'static str {
    if t.revoked_at.is_some() {
        "revoked"
    } else if t.consumed_at.is_some() {
        "used"
    } else if t.expires_at <= now {
        "expired"
    } else {
        "unused"
    }
}

fn token_table(tokens: &[JoinTokenInfo], now: OffsetDateTime) -> Table {
    let mut table = Table::new(["ID", "LABEL", "STATUS", "CREATED", "EXPIRES", "MACHINE"]);
    for t in tokens {
        table.row([
            t.id.to_string(),
            or_dash(t.label.clone()),
            token_status(t, now).to_string(),
            fmt_age(now, t.created_at),
            fmt_time(t.expires_at),
            or_dash(t.consumed_by_node_id.map(|n| n.to_string())),
        ]);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    // An obviously fake token: the text only matters for where it appears.
    const TOKEN: &str = "p2pc_join_faketokenforthehinttest"; // gitleaks:allow

    #[test]
    fn the_token_is_printed_once_on_its_own_line() {
        let text = created_text(TOKEN, "2026-11-05T12:15:00Z");
        assert_eq!(text.matches(TOKEN).count(), 1, "{text}");
        assert!(text.lines().any(|l| l == format!("  {TOKEN}")), "{text}");
        assert!(text.starts_with("Join token (single use, expires 2026-11-05T12:15:00Z):\n"));
    }

    #[test]
    fn no_suggested_command_carries_the_token() {
        let text = created_text(TOKEN, "x");
        for line in text.lines().filter(|l| l.contains(TOKEN)) {
            assert_eq!(
                line.trim(),
                TOKEN,
                "the token shares a line with something else: {line}"
            );
        }
        assert!(!text.contains(&format!("join {TOKEN}")));
        assert!(!text.contains(&format!("join - {TOKEN}")));
    }

    #[test]
    fn the_hint_names_the_installers_and_the_agent() {
        let text = created_text(TOKEN, "x");
        assert!(
            text.contains("On Linux:   sudo sh install-node.sh --from <dist dir>"),
            "{text}"
        );
        assert!(text.contains(r"On Windows: .\install.ps1 -Join"), "{text}");
        assert!(text.contains("p2pc-agent join   (it asks for the token)"), "{text}");
        assert!(text.contains("paste it when asked"), "{text}");
    }
}
