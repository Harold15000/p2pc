// SPDX-License-Identifier: Apache-2.0

//! One module per command group. Every command returns its exit code, or the error that makes it 125.

pub mod audit;
pub mod auth;
pub mod blobs;
pub mod jobs;
pub mod keys;
pub mod logs;
pub mod machines;
pub mod mcp;
pub mod proxy;
pub mod results;
pub mod run;
pub mod templates;
pub mod tokens;
pub mod usage;
pub mod volumes;

use std::io::Write;

use p2pc_client::{Error, fetch_all};
use p2pc_proto::api::{MAX_PAGE_LIMIT, Page};

use crate::app::{CliError, Ctx};
use crate::cli::{CompletionArgs, Shell};

/// `p2pc completion <shell>`: the script goes to stdout.
pub fn completion(ctx: &mut Ctx<'_, '_>, args: CompletionArgs) -> Result<u8, CliError> {
    let shell = match args.shell {
        Shell::Bash => clap_complete::Shell::Bash,
        Shell::Zsh => clap_complete::Shell::Zsh,
        Shell::Fish => clap_complete::Shell::Fish,
        Shell::Powershell => clap_complete::Shell::PowerShell,
    };
    let mut command = crate::app::command();
    clap_complete::generate(shell, &mut command, "p2pc", ctx.host.out);
    Ok(0)
}

/// One page of `limit` items, or with `all` every page (100 at a time). When a single page leaves items out, stderr
/// says how to get them.
pub(crate) async fn collect<T, F, Fut>(
    all: bool,
    limit: u32,
    err: &mut dyn Write,
    mut fetch: F,
) -> Result<Vec<T>, CliError>
where
    F: FnMut(u32, Option<String>) -> Fut,
    Fut: Future<Output = Result<Page<T>, Error>>,
{
    if all {
        return Ok(fetch_all(|cursor| fetch(MAX_PAGE_LIMIT, cursor), None).await?);
    }
    let page = fetch(limit, None).await?;
    if page.next_cursor.is_some() {
        writeln!(err, "note: there are more results; use --all to fetch every page")?;
    }
    Ok(page.items)
}
