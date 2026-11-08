// SPDX-License-Identifier: Apache-2.0

//! `p2pc logs`: a job's log, one page at a time or live.

use std::io::{self, Write};

use p2pc_client::Client;
use p2pc_proto::api::{Job, LogLine, LogStream};
use p2pc_proto::ids::JobId;

use crate::app::{CliError, Ctx};
use crate::cli::LogsArgs;
use crate::follow::{FollowError, Followed, LogSink, PollSchedule, Progress, StreamFollower, TokioSleeper};
use crate::outcome::EXIT_INTERRUPTED;
use crate::output::{escape_json_terminal, escape_terminal};

/// The bytes asked of the server per page when the log is read without `--follow`.
const PAGE_BYTES: usize = 1024 * 1024;

/// Writes the lines of a job's log: stdout lines to stdout and stderr lines to stderr (as the job wrote them). Failing
/// to write a stdout line is an error; the stderr lines are best effort, like our own notes.
///
/// Job output is untrusted. A stream that is a terminal gets it escaped ([`escape_terminal`]) unless the user asked for
/// `--raw`; a pipe or a file gets the bytes as stored. With `--json` every line is its NDJSON record.
pub(crate) struct LogWriter<'a> {
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
    escape_out: bool,
    escape_err: bool,
    json: bool,
}

impl<'a> LogWriter<'a> {
    pub(crate) fn new(
        out: &'a mut dyn Write,
        err: &'a mut dyn Write,
        out_is_tty: bool,
        err_is_tty: bool,
        raw: bool,
        json: bool,
    ) -> Self {
        Self {
            out,
            err,
            escape_out: out_is_tty && !raw,
            escape_err: err_is_tty && !raw,
            json,
        }
    }

    /// A message of ours (not the job's) on stderr, between the job's lines.
    pub(crate) fn note(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.err, "{text}")
    }
}

impl LogSink for LogWriter<'_> {
    fn line(&mut self, line: &LogLine) -> io::Result<()> {
        if self.json {
            let record = serde_json::to_string(line).map_err(io::Error::other)?;
            // JSON leaves DEL, C1 and the bidi controls as they are: on a terminal they are written as `\uXXXX`.
            let record = if self.escape_out {
                escape_json_terminal(&record)
            } else {
                record
            };
            return writeln!(self.out, "{record}");
        }
        let (target, escape): (&mut dyn Write, bool) = match line.stream {
            LogStream::Stdout => (&mut *self.out, self.escape_out),
            LogStream::Stderr => (&mut *self.err, self.escape_err),
        };
        let written = if escape {
            target.write_all(escape_terminal(&line.data).as_bytes())
        } else {
            target.write_all(line.data.as_bytes())
        };
        match line.stream {
            LogStream::Stdout => written,
            // The job's stderr is a courtesy, like our own notes: a closed stderr (`2>&-`, `2>/dev/full`) must not stop
            // the follow of a job that is still running, nor take the stdout away from whoever reads it.
            LogStream::Stderr => Ok(()),
        }
    }
}

/// What a live follow reports to: job lines through the [`LogWriter`], and the job's state changes on stderr when
/// `show_status` is set (`p2pc run` shows them, `p2pc logs --follow` stays quiet about them).
pub(crate) struct Live<'w, 'a> {
    pub(crate) writer: &'w mut LogWriter<'a>,
    pub(crate) show_status: bool,
}

impl Progress for Live<'_, '_> {
    fn on_status(&mut self, job: &Job) {
        if !self.show_status {
            return;
        }
        let mut line = format!("{}: {}", job.id, job.status);
        if job.attempt > 1 {
            line.push_str(&format!(" (attempt {})", job.attempt));
        }
        if let Some(node) = &job.node_id {
            line.push_str(&format!(" on {node}"));
        }
        // Progress is best effort: a closed stderr must not stop the job from being followed.
        let _ = self.writer.note(&line);
    }

    fn on_reconnecting(&mut self, error: &p2pc_client::Error) {
        let text = crate::output::printable(&error.to_string());
        let _ = self
            .writer
            .note(&format!("reconnecting… ({text}); the job keeps running"));
    }
}

impl LogSink for Live<'_, '_> {
    fn line(&mut self, line: &LogLine) -> io::Result<()> {
        self.writer.line(line)
    }
}

/// `p2pc logs <job>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: LogsArgs) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let json = ctx.json;
    let (out_tty, err_tty) = (ctx.host.stdout_is_tty, ctx.host.stderr_is_tty);
    if args.follow {
        let job = client.get_job(&args.id).await?;
        let interrupt = ctx.host.interrupt.take();
        let interrupt = async move {
            match interrupt {
                Some(signal) => signal.await,
                None => std::future::pending().await,
            }
        };
        let mut writer = LogWriter::new(&mut *ctx.host.out, &mut *ctx.host.err, out_tty, err_tty, args.raw, json);
        let mut follower = StreamFollower::new(PollSchedule::default(), TokioSleeper, args.since_seq, args.attempt);
        let followed = follower
            .follow(
                &client,
                job,
                &mut Live {
                    writer: &mut writer,
                    show_status: false,
                },
                interrupt,
            )
            .await;
        return match followed {
            // The log ended with the job. The command worked, whatever the job's outcome (`p2pc status` has it).
            Ok(Followed::Finished(_)) => Ok(0),
            // Ctrl-C only stops looking: the job is not touched.
            Ok(Followed::Interrupted(_)) => Ok(EXIT_INTERRUPTED),
            Err(FollowError::Client(e)) => Err(e.into()),
            Err(FollowError::Sink(e, _)) => Err(e.into()),
        };
    }

    let mut writer = LogWriter::new(&mut *ctx.host.out, &mut *ctx.host.err, out_tty, err_tty, args.raw, json);
    let printed = print_pages(&client, &args.id, args.since_seq, args.attempt, &mut writer).await?;
    if printed == 0 && !json {
        writer.note("No log output.")?;
    }
    Ok(0)
}

/// Prints the log from `since_seq` to its end, a page at a time. Returns how many lines it printed.
async fn print_pages(
    client: &Client,
    id: &JobId,
    since_seq: u64,
    attempt: Option<u32>,
    writer: &mut LogWriter<'_>,
) -> Result<u64, CliError> {
    let mut next = since_seq;
    let mut printed = 0u64;
    loop {
        let page = client.log_page(id, next, attempt, PAGE_BYTES).await?;
        for line in &page.lines {
            writer.line(line)?;
            next = line.seq.saturating_add(1);
            printed += 1;
        }
        if !page.more || page.lines.is_empty() {
            return Ok(printed);
        }
    }
}
