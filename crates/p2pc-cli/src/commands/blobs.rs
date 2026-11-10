// SPDX-License-Identifier: Apache-2.0

//! `blobs`: upload, list and remove blobs (H2 §7.5, §7.8), and the upload step that `p2pc run --input` shares.
//!
//! `p2pc blobs put` and `p2pc run --input` read the path the user typed, as any CLI command does. (The one place that
//! reads a local file on an AI agent's behalf, `p2pc_blob_put` of the MCP server, has its own directory rule: T2-54.)

use std::cell::Cell;
use std::io::Read;
use std::path::Path;

use p2pc_client::{Client, Error, ListParams, fetch_all};
use p2pc_proto::api::{BLOB_REF_PREFIX, BlobInfo, MAX_PAGE_LIMIT, Page, Sha256Digest};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::app::{CliError, Ctx};
use crate::cli::{BlobPut, BlobRm, BlobsArgs, BlobsCommand};
use crate::output::{Table, fmt_age, fmt_bytes, fmt_mib};

/// `p2pc blobs <put|ls|rm>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: BlobsArgs) -> Result<u8, CliError> {
    match args.command {
        BlobsCommand::Put(a) => put(ctx, a).await,
        BlobsCommand::Ls => list(ctx).await,
        BlobsCommand::Rm(a) => remove(ctx, a).await,
    }
}

/// A file measured and hashed, ready to be uploaded or named in a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Measured {
    /// SHA-256 of the file's bytes.
    pub digest: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
}

/// Reads the file once to hash it. It must be a regular file; the hash runs off the async threads, because a blob can
/// be 2 GiB.
pub(crate) async fn measure(path: &Path) -> Result<Measured, CliError> {
    let shown = path.display().to_string();
    let path = path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || -> Result<Measured, String> {
        let mut file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        // On the open descriptor, so what is measured is what is read.
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err("not a regular file".into());
        }
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut size: u64 = 0;
        loop {
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            hasher.update(buf.get(..n).unwrap_or_default());
            size = size.saturating_add(n as u64);
        }
        Ok(Measured {
            digest: Sha256Digest(hasher.finalize().into()),
            size,
        })
    })
    .await
    .map_err(|_| CliError::usage(format!("{shown}: reading the file was interrupted")))?;
    result.map_err(|e| CliError::usage(format!("{shown}: {e}")))
}

/// Makes sure the hub has the blob: a `HEAD` first, and an upload only when the hub answers that it does not have it.
/// Returns whether it uploaded.
///
/// An answer to a `HEAD` has no body, so a refusal there (`401`, `403`) carries no reason: the upload that follows
/// gets the hub's own answer, with its explanation.
pub(crate) async fn upload_if_missing(client: &Client, path: &Path, measured: Measured) -> Result<bool, CliError> {
    match client.head_blob(&measured.digest).await {
        Ok(Some(_)) => return Ok(false),
        Ok(None) => {}
        Err(Error::Unexpected(u)) if u.status.is_some_and(|s| (400..500).contains(&s)) => {}
        Err(e) => return Err(e.into()),
    }
    client.put_blob(path, &measured.digest, measured.size).await?;
    Ok(true)
}

/// `sha256:<hex>`, as a job's `inputs` entry writes it.
pub(crate) fn blob_ref(digest: &Sha256Digest) -> String {
    format!("{BLOB_REF_PREFIX}{digest}")
}

async fn put(ctx: &mut Ctx<'_, '_>, args: BlobPut) -> Result<u8, CliError> {
    // Measured before anything is sent: a missing file or a directory needs no server (or key) to be refused.
    let measured = measure(&args.file).await?;
    let client = ctx.client()?;
    let uploaded = upload_if_missing(&client, &args.file, measured).await?;
    let digest = blob_ref(&measured.digest);
    if uploaded {
        writeln!(
            ctx.host.err,
            "uploaded {} ({digest}). The hub keeps it for 24 hours after its last use.",
            fmt_bytes(measured.size)
        )?;
    } else {
        writeln!(ctx.host.err, "the hub already has {digest}: nothing to upload.")?;
    }
    if ctx.json {
        ctx.print_json(&serde_json::json!({"sha256": digest, "size": measured.size, "uploaded": uploaded}))?;
    } else {
        // Alone on stdout, so that `blob=$(p2pc blobs put file)` works.
        writeln!(ctx.host.out, "{digest}")?;
    }
    Ok(0)
}

async fn list(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let client = ctx.client()?;
    // Every page; the account's totals ride along with each one.
    let totals = Cell::new((0u64, 0u64));
    let blobs: Vec<BlobInfo> = fetch_all(
        |cursor| {
            let client = client.clone();
            let totals = &totals;
            async move {
                let page = client
                    .list_blobs(&ListParams {
                        limit: Some(MAX_PAGE_LIMIT),
                        cursor,
                    })
                    .await?;
                totals.set((page.total_bytes, page.quota_mb));
                Ok(Page {
                    items: page.items,
                    next_cursor: page.next_cursor,
                })
            }
        },
        None,
    )
    .await?;
    let (stored, quota_mb) = totals.get();
    if ctx.json {
        ctx.print_json(&blobs)?;
    } else {
        if blobs.is_empty() {
            writeln!(ctx.host.err, "No blobs.")?;
        } else {
            write!(ctx.host.out, "{}", blob_table(&blobs, ctx.host.now).render())?;
        }
        if quota_mb > 0 {
            writeln!(ctx.host.err, "{} stored of {}", fmt_bytes(stored), fmt_mib(quota_mb))?;
        }
    }
    Ok(0)
}

fn blob_table(blobs: &[BlobInfo], now: OffsetDateTime) -> Table {
    let mut table = Table::new(["DIGEST", "SIZE", "REFERENCED BY", "UPLOADED", "EXPIRES"]);
    for b in blobs {
        table.row([
            blob_ref(&b.sha256),
            fmt_bytes(b.size),
            b.referenced_by.to_string(),
            fmt_age(now, b.created_at),
            // `null` while a job that is not finished keeps it alive.
            b.expires_at
                .map_or_else(|| "in use".to_string(), |at| crate::output::fmt_time(at)),
        ]);
    }
    table
}

async fn remove(ctx: &mut Ctx<'_, '_>, args: BlobRm) -> Result<u8, CliError> {
    ctx.client()?.delete_blob(&args.digest).await?;
    let digest = blob_ref(&args.digest);
    if ctx.json {
        ctx.print_json(&serde_json::json!({"removed": digest}))?;
    } else {
        writeln!(ctx.host.out, "removed {digest}")?;
    }
    Ok(0)
}
