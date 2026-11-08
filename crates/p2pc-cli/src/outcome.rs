// SPDX-License-Identifier: Apache-2.0

//! The exit codes of `p2pc` and what a finished job means for them (spec §7 "Exit codes").
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | The job succeeded, or the command worked. |
//! | 1-255 | The job's own exit code, when it failed with one. |
//! | 75 | The job was lost. Retrying may work. |
//! | 124 | The job timed out. |
//! | 125 | p2pc could not run the job or the command: validation, authentication, the network, or a job that failed before it started. |
//! | 130 | Interrupted with Ctrl-C, or the job was cancelled. |
//!
//! A job's own exit code can collide with these codes. `--json` always gives the exact outcome.

use p2pc_proto::api::{Job, JobStatus};

/// The command worked, or the job succeeded.
pub const EXIT_OK: u8 = 0;
/// The job was lost: its node went away and no attempts remained. Retrying may work.
pub const EXIT_LOST: u8 = 75;
/// The job timed out.
pub const EXIT_TIMED_OUT: u8 = 124;
/// p2pc could not run the job or the command.
pub const EXIT_CANNOT_RUN: u8 = 125;
/// Interrupted with Ctrl-C, or the job was cancelled.
pub const EXIT_INTERRUPTED: u8 = 130;

/// The exit code of `p2pc run` for a job in its final state.
///
/// A job in a state that is not final has no outcome yet; it maps to [`EXIT_CANNOT_RUN`].
#[must_use]
pub fn exit_code(job: &Job) -> u8 {
    match job.status {
        JobStatus::Succeeded => EXIT_OK,
        JobStatus::Failed => match job.exit_code {
            // The job's own code. 0 cannot be a failure, and anything outside 1-255 cannot be an exit status.
            Some(code @ 1..=255) => u8::try_from(code).unwrap_or(EXIT_CANNOT_RUN),
            // No exit code, or an impossible one: the job never ran to the end (an image pull, the sandbox).
            _ => EXIT_CANNOT_RUN,
        },
        JobStatus::TimedOut => EXIT_TIMED_OUT,
        JobStatus::Lost => EXIT_LOST,
        JobStatus::Cancelled => EXIT_INTERRUPTED,
        JobStatus::Queued | JobStatus::Assigned | JobStatus::Running => EXIT_CANNOT_RUN,
    }
}

/// The `error` code of a job that wrote more than its disk limit.
pub const DISK_LIMIT_ERROR: &str = "disk_limit";

/// The one-line hint for a job that ended with `error="disk_limit"`: what happened and how to fix it. `None` for any
/// other job. `fix` names the way to ask for more (`--disk <MiB>` in the CLI).
#[must_use]
pub fn disk_limit_hint(job: &Job, fix: &str) -> Option<String> {
    (job.error.as_deref() == Some(DISK_LIMIT_ERROR)).then(|| {
        format!(
            "the job wrote more than its disk limit ({} MiB): run it again with {fix}",
            job.spec.resources.disk_mb
        )
    })
}

/// One line that says how the job ended, for stderr.
#[must_use]
pub fn describe(job: &Job) -> String {
    // `job.error` comes from the server: it is shown as text, never as terminal commands.
    let error = job.error.as_deref().map(crate::output::printable);
    if job.status == JobStatus::Failed
        && let Some(hint) = disk_limit_hint(job, "`--disk <MiB>`")
    {
        return format!("job failed: {hint}");
    }
    match job.status {
        JobStatus::Succeeded => "job succeeded".to_string(),
        JobStatus::Failed => match (job.exit_code, error.as_deref()) {
            (Some(code @ 1..=255), _) => format!("job failed with exit code {code}"),
            (_, Some(error)) => format!("job failed before it started: {error}"),
            (Some(code), None) => format!("job failed with exit code {code}"),
            (None, None) => "job failed before it started".to_string(),
        },
        JobStatus::TimedOut => format!("job timed out after {}s", job.spec.timeout_s),
        JobStatus::Lost => {
            "job was lost: its machine went away and no attempts were left; retrying may work".to_string()
        }
        JobStatus::Cancelled => "job was cancelled".to_string(),
        other => format!("job is {other}"),
    }
}

#[cfg(test)]
mod tests {
    use p2pc_client::testing::fixtures;
    use p2pc_proto::ids::JobId;

    use super::*;

    fn job(status: JobStatus, exit_code: Option<i32>) -> Job {
        fixtures::job(JobId::generate(), status, exit_code)
    }

    #[test]
    fn a_disk_limit_failure_says_how_to_fix_it() {
        let mut j = job(JobStatus::Failed, None);
        j.error = Some("disk_limit".into());
        j.spec.resources.disk_mb = 2048;
        assert_eq!(
            describe(&j),
            "job failed: the job wrote more than its disk limit (2048 MiB): run it again with `--disk <MiB>`"
        );
        // Another error gets no hint.
        j.error = Some("image_pull_failed".into());
        assert!(disk_limit_hint(&j, "x").is_none());
        assert!(!describe(&j).contains("--disk"));
    }

    #[test]
    fn succeeded_is_zero() {
        assert_eq!(exit_code(&job(JobStatus::Succeeded, Some(0))), 0);
        assert_eq!(exit_code(&job(JobStatus::Succeeded, None)), 0);
    }

    #[test]
    fn a_job_that_failed_with_an_exit_code_returns_that_code() {
        assert_eq!(exit_code(&job(JobStatus::Failed, Some(3))), 3);
        assert_eq!(exit_code(&job(JobStatus::Failed, Some(1))), 1);
        assert_eq!(exit_code(&job(JobStatus::Failed, Some(255))), 255);
    }

    #[test]
    fn a_job_that_failed_before_it_started_is_125() {
        // No exit code: for example an image pull that failed.
        let mut j = job(JobStatus::Failed, None);
        j.error = Some("image_pull_failed".into());
        assert_eq!(exit_code(&j), EXIT_CANNOT_RUN);
    }

    #[test]
    fn exit_codes_that_do_not_fit_are_125() {
        assert_eq!(exit_code(&job(JobStatus::Failed, Some(0))), EXIT_CANNOT_RUN);
        assert_eq!(exit_code(&job(JobStatus::Failed, Some(256))), EXIT_CANNOT_RUN);
        assert_eq!(exit_code(&job(JobStatus::Failed, Some(-9))), EXIT_CANNOT_RUN);
    }

    #[test]
    fn timed_out_is_124() {
        assert_eq!(exit_code(&job(JobStatus::TimedOut, None)), 124);
    }

    #[test]
    fn lost_is_75() {
        assert_eq!(exit_code(&job(JobStatus::Lost, None)), 75);
    }

    #[test]
    fn cancelled_is_130() {
        assert_eq!(exit_code(&job(JobStatus::Cancelled, None)), 130);
    }

    #[test]
    fn a_job_that_is_not_finished_has_no_outcome() {
        for s in [JobStatus::Queued, JobStatus::Assigned, JobStatus::Running] {
            assert_eq!(exit_code(&job(s, None)), EXIT_CANNOT_RUN);
        }
    }

    #[test]
    fn every_state_is_covered() {
        // Adding a state to the enum must force a decision here.
        for s in JobStatus::ALL {
            let code = exit_code(&job(s, if s == JobStatus::Failed { Some(7) } else { None }));
            assert_eq!(code == EXIT_OK, s == JobStatus::Succeeded, "{s}");
        }
    }

    #[test]
    fn a_hostile_error_string_cannot_inject_escape_sequences() {
        let mut j = job(JobStatus::Failed, None);
        j.error = Some("boom\u{1b}[2J".into());
        assert!(!describe(&j).contains('\u{1b}'));
    }

    #[test]
    fn descriptions_say_what_happened() {
        assert_eq!(describe(&job(JobStatus::Succeeded, Some(0))), "job succeeded");
        assert_eq!(
            describe(&job(JobStatus::Failed, Some(3))),
            "job failed with exit code 3"
        );
        let mut j = job(JobStatus::Failed, None);
        j.error = Some("image_pull_failed".into());
        assert_eq!(describe(&j), "job failed before it started: image_pull_failed");
        assert!(describe(&job(JobStatus::TimedOut, None)).contains("timed out"));
        assert!(describe(&job(JobStatus::Lost, None)).contains("lost"));
        assert!(describe(&job(JobStatus::Cancelled, None)).contains("cancelled"));
    }
}
