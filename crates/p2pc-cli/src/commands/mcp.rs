// SPDX-License-Identifier: Apache-2.0

//! `p2pc mcp`: check the key, then serve MCP over stdio.

use std::path::PathBuf;

use crate::app::{CliError, Ctx};
use crate::cli::McpArgs;
use crate::config::Os;
use crate::mcp::{
    Allow, DEFAULT_UPLOAD_DIR_NAME, McpConfig, McpServer, UploadDir, check_key, init_stderr_logging, serve_stdio,
};

/// `p2pc mcp`.
///
/// The key is checked with `GET /v1/whoami` before anything is served: a key with the `admin` scope or without a
/// daily cap is refused (exit 125, message on stderr), unless `--allow-admin` or `--allow-uncapped` says otherwise,
/// and then a warning goes to stderr. The upload directory of `p2pc_blob_put` is then created (mode 0700) or checked,
/// and an unsafe one is refused the same way (SI-H2-21). After that, stdout carries only the MCP protocol.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: McpArgs) -> Result<u8, CliError> {
    let (client, key) = ctx.client_with_key()?;
    let limits = client.key_limits().await?;
    let allow = Allow {
        admin: args.allow_admin,
        uncapped: args.allow_uncapped,
    };
    let warnings = check_key(&limits, allow).map_err(CliError::Usage)?;
    for warning in &warnings {
        writeln!(ctx.host.err, "warning: {warning}")?;
    }
    let upload_dir = upload_dir(ctx, args.upload_dir)?;
    init_stderr_logging((ctx.host.env)("P2PC_LOG").as_deref());
    tracing::info!(key_id = %limits.key_id, "serving MCP over stdio");
    // A long-running session through a tunnel follows network changes (§10).
    let _network_watch = ctx.watch_networks().await;
    let server = McpServer::new(
        client,
        &key,
        McpConfig::new(args.results_dir).with_upload_dir(upload_dir),
    );
    serve_stdio(server).await.map_err(CliError::Usage)?;
    Ok(0)
}

/// The upload directory: `--upload-dir`, or `~/p2pc-uploads`, checked against the home and configuration directories.
fn upload_dir(ctx: &Ctx<'_, '_>, requested: Option<PathBuf>) -> Result<UploadDir, CliError> {
    let home = (ctx.host.env)(if Os::current() == Os::Windows {
        "USERPROFILE"
    } else {
        "HOME"
    })
    .filter(|h| !h.is_empty())
    .map(PathBuf::from);
    let dir = match (requested, &home) {
        (Some(dir), _) => dir,
        (None, Some(home)) => home.join(DEFAULT_UPLOAD_DIR_NAME),
        (None, None) => {
            return Err(CliError::usage(
                "cannot tell where the upload directory is: the home directory is unknown; give --upload-dir",
            ));
        }
    };
    let config_dir = ctx.store()?.dir().to_path_buf();
    UploadDir::prepare(&dir, home.as_deref(), &config_dir).map_err(CliError::Usage)
}
