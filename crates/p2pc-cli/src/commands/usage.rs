// SPDX-License-Identifier: Apache-2.0

//! `p2pc usage`: what the project's jobs reserved and used (spec §11).

use p2pc_proto::api::{UsageGroupBy, UsageReport, UsageTotals};
use time::{Duration, OffsetDateTime};

use crate::app::{CliError, Ctx};
use crate::cli::{UsageArgs, UsageBy};
use crate::output::{Table, fmt_time};

/// A report with this many pages is a broken server, not a big account.
const MAX_PAGES: usize = 1000;

/// The range to ask for. Both ends are explicit, in UTC: today by default (`[00:00, tomorrow 00:00)`), and the day before
/// `--to` when only that is given. `--from` alone runs to the end of today.
fn range(
    now: OffsetDateTime,
    from: Option<OffsetDateTime>,
    to: Option<OffsetDateTime>,
) -> (OffsetDateTime, OffsetDateTime) {
    let today = now.to_offset(time::UtcOffset::UTC).date().midnight().assume_utc();
    match (from, to) {
        (Some(from), Some(to)) => (from, to),
        (Some(from), None) => (from, today + Duration::days(1)),
        (None, Some(to)) => (to - Duration::days(1), to),
        (None, None) => (today, today + Duration::days(1)),
    }
}

/// `p2pc usage`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: UsageArgs) -> Result<u8, CliError> {
    let client = ctx.client()?;
    let (from, to) = range(ctx.host.now, args.from, args.to);
    let group_by = match args.by {
        UsageBy::Job => UsageGroupBy::Job,
        UsageBy::Node => UsageGroupBy::Node,
        UsageBy::Key => UsageGroupBy::Key,
    };

    // Every page of groups: a table of the first page only would not add up to its own total.
    let mut report = client.usage(Some(from), Some(to), Some(group_by), None).await?;
    let mut cursor = report.next_cursor.take();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..MAX_PAGES {
        let Some(next) = cursor.take() else { break };
        if !seen.insert(next.clone()) {
            return Err(CliError::usage("the server returned the same page of usage twice"));
        }
        let mut page = client.usage(Some(from), Some(to), Some(group_by), Some(&next)).await?;
        report.items.append(&mut page.items);
        cursor = page.next_cursor.take();
    }
    if cursor.is_some() {
        return Err(CliError::usage("the usage report has too many pages"));
    }

    if ctx.json {
        ctx.print_json(&report)?;
    } else {
        write!(ctx.host.out, "{}", render(&report))?;
        if has_estimates(&report) {
            writeln!(
                ctx.host.err,
                "≈ includes the server's own estimates: for an attempt whose machine never reported its usage (it was \
                 lost, or unreachable when the job was cancelled), the server counts what it had reserved."
            )?;
        }
    }
    Ok(0)
}

fn has_estimates(report: &UsageReport) -> bool {
    report.total.estimated_attempts > 0 || report.items.iter().any(|g| g.estimated_attempts > 0)
}

/// The report as text: its range, then one row per group and a total.
fn render(report: &UsageReport) -> String {
    let by = match report.group_by {
        UsageGroupBy::Job => "JOB",
        UsageGroupBy::Node => "NODE",
        UsageGroupBy::Key => "KEY",
        UsageGroupBy::Device => "DEVICE",
        UsageGroupBy::Principal => "PRINCIPAL",
        UsageGroupBy::Kind => "KIND",
        UsageGroupBy::Template => "TEMPLATE",
    };
    let mut table = Table::new([
        by,
        "ATTEMPTS",
        "UNITS",
        "CPU RESERVED",
        "CPU USED",
        "GPU RESERVED",
        "ESTIMATED",
    ]);
    for group in &report.items {
        table.row(cells(group.key.as_deref().unwrap_or("-"), group));
    }
    table.row(cells("TOTAL", &report.total));
    format!(
        "{} to {} (UTC)\n{}",
        fmt_time(report.from),
        fmt_time(report.to),
        table.render()
    )
}

fn cells(key: &str, g: &UsageTotals) -> [String; 7] {
    // A number that includes a server estimate is marked "≈", and so is the count of estimated attempts.
    let mark = if g.estimated_attempts > 0 { "≈" } else { "" };
    [
        key.to_string(),
        g.attempts.to_string(),
        format!("{mark}{}", g.units),
        fmt_ms(g.reserved_cpu_ms),
        fmt_ms(g.used_cpu_ms),
        fmt_ms(g.reserved_gpu_ms),
        format!("{mark}{}", g.estimated_attempts),
    ]
}

/// CPU or GPU milliseconds as `0`, `850ms`, `12.3s`, `4m 05s`, `2h 10m`. It is vCPU-time or GPU-time, not wall-clock.
fn fmt_ms(ms: u64) -> String {
    match ms {
        0 => "0".to_string(),
        1..=999 => format!("{ms}ms"),
        1000..=59_999 => format!("{:.1}s", ms as f64 / 1000.0),
        _ => crate::output::fmt_duration_secs(ms / 1000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    #[test]
    fn the_default_range_is_today_in_utc() {
        // 2023-11-14T22:13:20Z, seen from a clock in +09:00 where it is already the 15th.
        let now = at(1_700_000_000).to_offset(time::UtcOffset::from_hms(9, 0, 0).unwrap());
        let (from, to) = range(now, None, None);
        assert_eq!((from, to), (at(1_699_920_000), at(1_700_006_400)));
        assert_eq!(from.offset(), time::UtcOffset::UTC);
    }

    #[test]
    fn one_end_given_the_other_follows() {
        let now = at(1_700_000_000);
        assert_eq!(
            range(now, Some(at(1_699_000_000)), None),
            (at(1_699_000_000), at(1_700_006_400))
        );
        assert_eq!(
            range(now, None, Some(at(1_699_000_000))),
            (at(1_698_913_600), at(1_699_000_000))
        );
        assert_eq!(range(now, Some(at(1)), Some(at(2))), (at(1), at(2)));
    }

    #[test]
    fn amounts_of_time_are_short() {
        assert_eq!(fmt_ms(0), "0");
        assert_eq!(fmt_ms(850), "850ms");
        assert_eq!(fmt_ms(12_345), "12.3s");
        assert_eq!(fmt_ms(245_000), "4m 5s");
        assert_eq!(fmt_ms(7_800_000), "2h 10m");
    }
}
