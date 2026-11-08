// SPDX-License-Identifier: Apache-2.0

//! `p2pc results`: download a job's output files.
//!
//! The server's list of files and every file's bytes are untrusted (spec §13, SI-9): each path is checked again before
//! it is joined to the destination directory, `p2pc-client` refuses a path that leaves it or a directory that is a
//! symbolic link, and each file is verified against the size and SHA-256 the job listed before it is put in place.

use std::path::{Path, PathBuf};

use p2pc_client::DownloadError;
use p2pc_proto::api::OutputFile;
use p2pc_proto::ids::JobId;
use p2pc_proto::validate::validate_output_path;
use serde_json::json;

use crate::app::{CliError, Ctx};
use crate::cli::ResultsArgs;
use crate::mcp::DEFAULT_RESULTS_DIR;
use crate::output::fmt_bytes;

/// The most files one run downloads. More than this is refused, never silently cut.
const MAX_FILES: usize = 10_000;

/// Where the files go when `--out` is not given: `./p2pc-results/<job_id>/`.
#[must_use]
pub fn default_dir(id: &JobId) -> PathBuf {
    Path::new(DEFAULT_RESULTS_DIR).join(id.to_string())
}

/// `p2pc results <job>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: ResultsArgs) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let id = args.id;
    let attempt = args.attempt;
    let dir = args.out.clone().unwrap_or_else(|| default_dir(&id));

    // One more than the most: if it comes back, there are more than we take, and we stop instead of cutting the list.
    let listed = match client.list_all_outputs(&id, attempt, MAX_FILES + 1).await {
        Ok(files) => files,
        Err(e) if e.status() == Some(410) => return Err(expired(&id)),
        Err(e) => return Err(e.into()),
    };
    if listed.len() > MAX_FILES {
        return Err(CliError::usage(format!(
            "job {id} has more than {MAX_FILES} output files, more than `p2pc results` downloads at once; nothing was \
             downloaded"
        )));
    }
    if listed.is_empty() {
        if ctx.json {
            ctx.print_json(&json!({"job_id": id, "directory": null, "files": [], "bytes": 0}))?;
        } else {
            writeln!(ctx.host.err, "Job {id} has no output files.")?;
        }
        return Ok(0);
    }

    let chosen = choose(listed, &args.files)?;
    // The server chose these names: look at every one before anything is written.
    for file in &chosen {
        validate_output_path(&file.path).map_err(|_| {
            CliError::usage("the server listed an output path that is not safe; nothing was downloaded")
        })?;
    }
    if !args.force {
        refuse_existing(&dir, &chosen)?;
    }

    let mut saved = Vec::with_capacity(chosen.len());
    let mut bytes = 0u64;
    for file in &chosen {
        if !ctx.json {
            writeln!(
                ctx.host.err,
                "{} ({})",
                crate::output::printable(&file.path),
                fmt_bytes(file.size)
            )?;
        }
        let result = if args.force {
            client.save_output(&id, attempt, file, &dir).await
        } else {
            client.save_new_output(&id, attempt, file, &dir).await
        };
        let path = result.map_err(|e| download_error(&id, &file.path, e))?;
        bytes = bytes.saturating_add(file.size);
        saved.push((file, path));
    }

    if ctx.json {
        let files: Vec<_> = saved
            .iter()
            .map(|(f, p)| json!({"path": f.path, "size": f.size, "sha256": f.sha256, "saved_to": p}))
            .collect();
        ctx.print_json(&json!({"job_id": id, "directory": dir, "files": files, "bytes": bytes}))?;
    } else {
        writeln!(
            ctx.host.out,
            "{} {}, {} saved to {} (sha256 verified)",
            saved.len(),
            if saved.len() == 1 { "file" } else { "files" },
            fmt_bytes(bytes),
            crate::output::printable(&dir.display().to_string()),
        )?;
    }
    Ok(0)
}

/// The files to download: all of them, or those named with `--file` (each must be one the job produced).
fn choose(listed: Vec<OutputFile>, wanted: &[String]) -> Result<Vec<OutputFile>, CliError> {
    if wanted.is_empty() {
        return Ok(listed);
    }
    let mut chosen = Vec::with_capacity(wanted.len());
    for path in wanted {
        let file = listed.iter().find(|f| &f.path == path).ok_or_else(|| {
            CliError::usage(format!(
                "the job has no output file {path:?}; run `p2pc results` without --file to download all {} of them",
                listed.len()
            ))
        })?;
        if !chosen.iter().any(|c: &OutputFile| c.path == file.path) {
            chosen.push(file.clone());
        }
    }
    Ok(chosen)
}

/// Fails, before anything is downloaded, when a file would land on one that exists (a link too, even a dangling one).
/// The download itself refuses again, atomically, in case one appears meanwhile.
fn refuse_existing(dir: &Path, files: &[OutputFile]) -> Result<(), CliError> {
    let existing: Vec<&str> = files
        .iter()
        .filter(|f| std::fs::symlink_metadata(dir.join(&f.path)).is_ok())
        .map(|f| f.path.as_str())
        .collect();
    if existing.is_empty() {
        return Ok(());
    }
    let shown: Vec<_> = existing.iter().take(5).map(|p| format!("{p:?}")).collect();
    let more = existing.len().saturating_sub(shown.len());
    Err(CliError::usage(format!(
        "{} already exist{} in {}: {}{}. Nothing was downloaded; use --force to replace them, or --out to choose another directory",
        if existing.len() == 1 {
            "1 file".to_string()
        } else {
            format!("{} files", existing.len())
        },
        if existing.len() == 1 { "s" } else { "" },
        dir.display(),
        shown.join(", "),
        if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        },
    )))
}

fn expired(id: &JobId) -> CliError {
    CliError::Expired(format!(
        "the output files of job {id} have expired: the server deletes them after its retention period (7 days by \
         default). Run the job again to produce them"
    ))
}

fn download_error(id: &JobId, path: &str, error: DownloadError) -> CliError {
    match error {
        DownloadError::Request(e) if e.status() == Some(410) => expired(id),
        DownloadError::Request(e) => e.into(),
        DownloadError::Exists { .. } => CliError::usage(format!(
            "{path:?} already exists. Use --force to replace it, or --out to choose another directory"
        )),
        other => CliError::usage(format!("{path:?}: {other}")),
    }
}
