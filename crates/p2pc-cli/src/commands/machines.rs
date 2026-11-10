// SPDX-License-Identifier: Apache-2.0

//! `machines`: list, show, drain, resume and remove. Machines are addressed by name or by ID.

use p2pc_client::{Client, ListParams, fetch_all};
use p2pc_proto::api::{MAX_PAGE_LIMIT, Node, NodeState};
use p2pc_proto::ids::NodeId;
use time::OffsetDateTime;

use crate::app::{CliError, Ctx};
use crate::cli::{MachineApprove, MachineArg, MachineRm, MachinesArgs, MachinesCommand};
use crate::output::{Table, fmt_age, fmt_cpu, fmt_mib, fmt_time, or_dash, printable, render_kv, wire_name};

/// `p2pc machines [show|drain|resume|rm]`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: MachinesArgs) -> Result<u8, CliError> {
    match args.command {
        None | Some(MachinesCommand::Ls) => list(ctx).await,
        Some(MachinesCommand::Show(a)) => show(ctx, a).await,
        Some(MachinesCommand::Approve(a)) => approve(ctx, a).await,
        Some(MachinesCommand::Drain(a)) => drain_or_resume(ctx, a, true).await,
        Some(MachinesCommand::Resume(a)) => drain_or_resume(ctx, a, false).await,
        Some(MachinesCommand::Rm(a)) => remove(ctx, a).await,
    }
}

async fn all_nodes(client: &Client) -> Result<Vec<Node>, CliError> {
    Ok(fetch_all(
        |cursor| {
            let client = client.clone();
            async move {
                client
                    .list_nodes(&ListParams {
                        limit: Some(MAX_PAGE_LIMIT),
                        cursor,
                    })
                    .await
            }
        },
        None,
    )
    .await?)
}

async fn list(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let nodes = all_nodes(&ctx.client()?).await?;
    if ctx.json {
        ctx.print_json(&nodes)?;
    } else if nodes.is_empty() {
        writeln!(
            ctx.host.err,
            "No machines yet. Create a join token with `p2pc join-token create` and run the command it prints on the machine."
        )?;
    } else {
        write!(ctx.host.out, "{}", node_table(&nodes, ctx.host.now).render())?;
    }
    Ok(0)
}

fn node_state(node: &Node) -> String {
    let state = match node.state {
        NodeState::Online => "online",
        NodeState::Offline => "offline",
    };
    if node.draining {
        format!("{state} (draining)")
    } else {
        state.to_string()
    }
}

fn node_table(nodes: &[Node], now: OffsetDateTime) -> Table {
    let mut table = Table::new([
        "NAME",
        "ID",
        "STATE",
        "APPROVAL",
        "PLATFORM",
        "CPU FREE/OFFERED",
        "RAM FREE/OFFERED",
        "GPU FREE/OFFERED",
        "LAST SEEN",
    ]);
    for n in nodes {
        let (free, offered) = (&n.free, &n.inventory.offered);
        table.row([
            n.name.clone(),
            n.id.to_string(),
            node_state(n),
            wire_name(&n.approval),
            wire_name(&n.inventory.platform),
            format!("{}/{}", fmt_cpu(free.cpu), fmt_cpu(offered.cpu)),
            format!("{}/{}", fmt_mib(free.memory_mb), fmt_mib(offered.memory_mb)),
            format!("{}/{}", free.gpu, offered.gpu),
            n.last_seen.map_or_else(|| "never".to_string(), |at| fmt_age(now, at)),
        ]);
    }
    table
}

/// A machine found by name or ID. `node` is set when the lookup listed the machines anyway.
struct Resolved {
    id: NodeId,
    node: Option<Node>,
}

/// Finds a machine by ID (no request needed) or by name, which lists the machines. The name match ignores case, as
/// the server's uniqueness rule does, and falls back to the hostname the agent reported. A name that matches more
/// than one machine is an error that lists them.
async fn resolve(client: &Client, text: &str) -> Result<Resolved, CliError> {
    if let Ok(id) = text.parse::<NodeId>() {
        return Ok(Resolved { id, node: None });
    }
    let nodes = all_nodes(client).await?;
    let by = |field: fn(&Node) -> &str| -> Vec<Node> {
        nodes
            .iter()
            .filter(|n| field(n).eq_ignore_ascii_case(text))
            .cloned()
            .collect()
    };
    let mut matches = by(|n| &n.name);
    if matches.is_empty() {
        matches = by(|n| &n.hostname);
    }
    match matches.len() {
        0 => Err(CliError::usage(format!(
            "no machine is named {text:?}; `p2pc machines` lists them"
        ))),
        1 => {
            let node = matches.remove(0);
            Ok(Resolved {
                id: node.id,
                node: Some(node),
            })
        }
        _ => {
            let mut message = format!("{text:?} matches more than one machine; use the ID of one of them:");
            for n in &matches {
                message.push_str(&format!("\n  {}  {} ({})", n.id, n.name, node_state(n)));
            }
            Err(CliError::Usage(message))
        }
    }
}

async fn show(ctx: &mut Ctx<'_, '_>, args: MachineArg) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let found = resolve(&client, &args.target).await?;
    let node = match found.node {
        Some(node) => node,
        None => client.get_node(&found.id).await?,
    };
    if ctx.json {
        ctx.print_json(&node)?;
    } else {
        write!(ctx.host.out, "{}", node_details(&node, ctx.host.now))?;
    }
    Ok(0)
}

fn node_details(n: &Node, now: OffsetDateTime) -> String {
    let inv = &n.inventory;
    let mut rows = vec![
        ("name", n.name.clone()),
        ("id", n.id.to_string()),
        ("hostname", n.hostname.clone()),
        ("state", node_state(n)),
        ("approval", wire_name(&n.approval)),
        ("platform", wire_name(&inv.platform)),
        ("os", format!("{} ({})", inv.os, inv.arch)),
        ("cpu", format!("{}, {} threads", inv.cpu.model, inv.cpu.cores)),
        ("ram", fmt_mib(inv.memory_mb)),
        (
            "offered",
            format!(
                "{} vCPU, {}, {} GPU",
                fmt_cpu(inv.offered.cpu),
                fmt_mib(inv.offered.memory_mb),
                inv.offered.gpu
            ),
        ),
        (
            "free",
            format!(
                "{} vCPU, {}, {} GPU",
                fmt_cpu(n.free.cpu),
                fmt_mib(n.free.memory_mb),
                n.free.gpu
            ),
        ),
    ];
    for gpu in &inv.gpus {
        let vram = gpu.vram_mb.map_or_else(|| "unknown memory".to_string(), fmt_mib);
        rows.push(("gpu", format!("{}, {vram}, driver {}", gpu.name, gpu.driver_version)));
    }
    for sandbox in &inv.sandbox {
        let ready = if sandbox.ready { "ready" } else { "not ready" };
        rows.push((
            "sandbox",
            format!("{} ({}), {ready}", sandbox.driver, wire_name(&sandbox.class)),
        ));
    }
    if !n.labels.is_empty() {
        let labels: Vec<String> = n.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        rows.push(("labels", labels.join(", ")));
    }
    if let Some(by) = &n.enrolled_by {
        rows.push(("enrolled by", by.to_string()));
    }
    if let Some(phrase) = &n.node_phrase {
        rows.push(("node phrase", printable(phrase)));
    }
    rows.push(("agent", inv.agent_version.clone()));
    rows.push((
        "last seen",
        or_dash(n.last_seen.map(|at| format!("{} ({})", fmt_time(at), fmt_age(now, at)))),
    ));
    rows.push(("joined", fmt_time(n.created_at)));
    render_kv(&rows)
}

async fn drain_or_resume(ctx: &mut Ctx<'_, '_>, args: MachineArg, drain: bool) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let found = resolve(&client, &args.target).await?;
    let node = if drain {
        client.drain_node(&found.id).await?
    } else {
        client.resume_node(&found.id).await?
    };
    if ctx.json {
        ctx.print_json(&node)?;
    } else {
        let verb = if drain { "draining" } else { "resumed" };
        writeln!(ctx.host.out, "{}: {verb} ({})", printable(&node.name), node.id)?;
    }
    Ok(0)
}

async fn remove(ctx: &mut Ctx<'_, '_>, args: MachineRm) -> Result<u8, CliError> {
    // Decided before any request: with no terminal there is nobody to ask.
    if !args.yes && !ctx.host.stdin_is_tty {
        return Err(CliError::usage(
            "refusing to remove a machine without confirmation: there is no terminal to ask, so pass --yes",
        ));
    }
    let client = ctx.client()?;
    let found = resolve(&client, &args.target).await?;
    let label = match &found.node {
        Some(n) => format!("{} ({})", printable(&n.name), n.id),
        None => found.id.to_string(),
    };
    if !args.yes {
        write!(
            ctx.host.err,
            "Remove machine {label}? Its agent will have to join again with a new token. [y/N] "
        )?;
        ctx.host.err.flush()?;
        let mut answer = String::new();
        ctx.host.stdin.read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            writeln!(ctx.host.err, "Not removed.")?;
            return Ok(crate::outcome::EXIT_INTERRUPTED);
        }
    }
    client.delete_node(&found.id).await?;
    if ctx.json {
        ctx.print_json(&serde_json::json!({"deleted": found.id}))?;
    } else {
        writeln!(ctx.host.out, "removed {label}")?;
    }
    Ok(0)
}

/// `p2pc nodes approve <node>` (H2 §5.5, §7.8): shows the node phrase, asks, and approves.
///
/// The phrase is six words derived from the machine's own key; the owner compares it with the words the joined machine
/// shows, so that the machine they approve is the one in front of them. Without a phrase there is nothing to compare,
/// so the command refuses (a hub that does not report it is older than this feature).
async fn approve(ctx: &mut Ctx<'_, '_>, args: MachineApprove) -> Result<u8, CliError> {
    // Decided before any request: with no terminal there is nobody to ask.
    if !args.yes && !ctx.host.stdin_is_tty {
        return Err(CliError::usage(
            "refusing to approve a machine without confirmation: there is no terminal to ask, so pass --yes",
        ));
    }
    let client = ctx.client()?;
    let found = resolve(&client, &args.target).await?;
    // Always the node as the hub has it now (a name lookup lists the machines, but the approval state and the phrase
    // are what matter here, and they must be fresh).
    let node = client.get_node(&found.id).await?;
    let label = format!("{} ({})", printable(&node.name), node.id);
    if node.approval.is_approved() {
        writeln!(ctx.host.err, "{label} is already approved.")?;
        if ctx.json {
            ctx.print_json(&serde_json::json!({"approved": node.id, "changed": false}))?;
        }
        return Ok(0);
    }
    let Some(phrase) = node.node_phrase.as_deref() else {
        return Err(CliError::usage(format!(
            "the hub did not report a node phrase for {label}, so there is nothing to compare with the machine's \
             own screen; update the hub before approving machines"
        )));
    };
    writeln!(ctx.host.err, "Machine {label} is waiting for approval.")?;
    writeln!(
        ctx.host.err,
        "Its node phrase is: {}\nApprove it only if the machine itself shows the same words.",
        printable(phrase)
    )?;
    if !args.yes {
        write!(ctx.host.err, "Approve {label}? It will start getting jobs. [y/N] ")?;
        ctx.host.err.flush()?;
        let mut answer = String::new();
        ctx.host.stdin.read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            writeln!(ctx.host.err, "Not approved.")?;
            return Ok(crate::outcome::EXIT_INTERRUPTED);
        }
    }
    client.approve_node(&node.id).await?;
    if ctx.json {
        ctx.print_json(&serde_json::json!({"approved": node.id, "changed": true}))?;
    } else {
        writeln!(ctx.host.out, "approved {label}")?;
    }
    Ok(0)
}
