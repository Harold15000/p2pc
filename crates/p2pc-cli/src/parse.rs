// SPDX-License-Identifier: Apache-2.0

//! Parsing of the values users type: sizes, durations, `--env`, `--env-file`, `--file`, `--label` and `--cap`.
//!
//! Every error message is safe to print: it names the argument and the problem, never an environment value or a file
//! content (they may be secrets, SI-6).

use std::path::PathBuf;
use std::time::Duration;

use p2pc_proto::units::Units;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Parses a size into MiB, rounding up.
///
/// `512M`, `4G`, `4GiB`, `1.5G`, `2T`, `1024K`. The unit is optional: a bare number is MiB, like the API's
/// `memory_mb`. All units are binary (`G`, `GB` and `GiB` are all 1024 MiB), and case does not matter.
pub fn parse_size_mib(text: &str) -> Result<u64, String> {
    let split = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let mib_per_unit = match unit.to_ascii_lowercase().as_str() {
        "" | "m" | "mb" | "mib" => 1.0,
        "k" | "kb" | "kib" => 1.0 / 1024.0,
        "g" | "gb" | "gib" => 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0,
        _ => {
            return Err(format!(
                "{text:?} is not a size: use a number and K, M, G or T, for example 512M or 4GiB"
            ));
        }
    };
    let value: f64 = number
        .parse()
        .map_err(|_| format!("{text:?} is not a size: use a number and K, M, G or T, for example 512M or 4GiB"))?;
    let mib = (value * mib_per_unit).ceil();
    if !mib.is_finite() || mib < 1.0 {
        return Err(format!("{text:?} is not a positive size"));
    }
    if mib >= 18_446_744_073_709_551_615.0 {
        return Err(format!("{text:?} is too large"));
    }
    // `mib` is a whole number between 1 and u64::MAX here.
    Ok(mib as u64)
}

/// Parses a duration such as `90s`, `2h` or `1h30m` into whole seconds (at least 1).
pub fn parse_duration_secs(text: &str) -> Result<u32, String> {
    let d = parse_duration(text)?;
    if d.subsec_nanos() != 0 {
        return Err(format!("{text:?} is not a whole number of seconds"));
    }
    match u32::try_from(d.as_secs()) {
        Ok(secs) if secs >= 1 => Ok(secs),
        _ => Err(format!("{text:?} is out of range: use at least 1s")),
    }
}

/// Parses a duration such as `15m` or `30d` (humantime).
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    humantime::parse_duration(text)
        .map_err(|_| format!("{text:?} is not a duration: use for example 90s, 15m, 2h or 30d"))
}

/// Parses `--from` and `--to`: a date (`2026-11-06`, midnight UTC) or an RFC 3339 instant (`2026-11-06T10:00:00Z`, or
/// with an offset). The result is in UTC and has no fraction of a second (the API refuses one).
pub fn parse_when(text: &str) -> Result<OffsetDateTime, String> {
    let bad = || {
        format!(
            "{text:?} is not a date: use 2026-11-06 (midnight UTC) or an RFC 3339 time such as 2026-11-06T10:00:00Z"
        )
    };
    if let Ok(at) = OffsetDateTime::parse(text, &Rfc3339) {
        return Ok(p2pc_client::whole_seconds(at));
    }
    let format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").map_err(|_| bad())?;
    let date = time::Date::parse(text, &format).map_err(|_| bad())?;
    Ok(date.midnight().assume_utc())
}

/// One `--env` argument: `KEY=VAL`, or `KEY` to take the value from the local environment.
pub fn parse_env_arg(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<(String, String), String> {
    if let Some((name, value)) = text.split_once('=') {
        if name.is_empty() {
            return Err("--env needs a variable name before `=`".into());
        }
        return Ok((name.to_string(), value.to_string()));
    }
    if text.is_empty() {
        return Err("--env needs KEY=VALUE, or KEY to take the value from your environment".into());
    }
    match lookup(text) {
        Some(value) => Ok((text.to_string(), value)),
        None => Err(format!(
            "--env {text}: the variable {text} is not set in your environment; pass {text}=VALUE or set it"
        )),
    }
}

/// Parses the text of an `--env-file`: `KEY=VAL` lines, `#` comments, blank lines, an optional `export ` prefix and
/// optional single or double quotes around the value. Errors name the line number only.
pub fn parse_env_file(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut vars = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let bad = || format!("line {} is not KEY=VALUE", index + 1);
        let (name, value) = line.split_once('=').ok_or_else(bad)?;
        let name = name.trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(bad());
        }
        vars.push((name.to_string(), unquote(value.trim()).to_string()));
    }
    Ok(vars)
}

/// Removes one pair of matching quotes around a value. There are no escapes: what is inside is taken as is.
fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value.strip_prefix(quote).and_then(|v| v.strip_suffix(quote)) {
            return inner;
        }
    }
    value
}

/// A `--file LOCAL[:/inputs/PATH]` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileArg {
    /// The local file.
    pub local: PathBuf,
    /// The path inside the job, if given. Otherwise `/inputs/<file name>`.
    pub remote: Option<String>,
}

/// Parses `LOCAL` or `LOCAL:/inputs/PATH`. The split is at the last `:/inputs/`, so Windows paths such as
/// `C:\data\a.csv` and `C:/data/a.csv` are not cut at the drive letter.
pub fn parse_file_arg(text: &str) -> Result<FileArg, String> {
    let (local, remote) = match text.rfind(":/inputs/") {
        Some(i) => (&text[..i], Some(text[i + 1..].to_string())),
        None => (text, None),
    };
    if local.is_empty() {
        return Err("--file needs a local path, for example --file data.csv or --file data.csv:/inputs/in.csv".into());
    }
    Ok(FileArg {
        local: PathBuf::from(local),
        remote,
    })
}

/// Parses a `--input LOCAL[:/inputs/PATH]` argument: the same shape as `--file`.
pub fn parse_input_arg(text: &str) -> Result<FileArg, String> {
    parse_file_arg(text).map_err(|_| {
        "--input needs a local path, for example --input audio.wav or --input audio.wav:/inputs/audio".to_string()
    })
}

/// Parses a blob digest: `sha256:<64 lowercase hex>` as a job spec writes it, or the bare hex of the URL.
pub fn parse_digest(text: &str) -> Result<p2pc_proto::api::Sha256Digest, String> {
    let hex = text.strip_prefix(p2pc_proto::api::BLOB_REF_PREFIX).unwrap_or(text);
    hex.parse().map_err(|_| {
        format!("{text:?} is not a blob digest: use sha256:<64 lowercase hex characters>, as `p2pc blobs ls` shows it")
    })
}

/// Parses `key=value`.
pub fn parse_label(text: &str) -> Result<(String, String), String> {
    match text.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
        _ => Err(format!("{text:?} is not a label: use key=value")),
    }
}

/// Parses a count of compute units, such as `10` or `2.5`, into [`Units`] (at most three decimals).
pub fn parse_units(text: &str) -> Result<Units, String> {
    let bad =
        || format!("{text:?} is not an amount of units: use a number with at most three decimals, like 10 or 2.5");
    let (whole, frac) = match text.split_once('.') {
        Some((w, f)) => (w, f),
        None => (text, ""),
    };
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(frac) || frac.len() > 3 || (text.contains('.') && frac.is_empty())
    {
        return Err(bad());
    }
    let whole: u64 = whole.parse().map_err(|_| bad())?;
    let frac_milli: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<3}").parse().map_err(|_| bad())?
    };
    whole
        .checked_mul(1000)
        .and_then(|m| m.checked_add(frac_milli))
        .map(Units::from_milli)
        .ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_takes_a_date_or_an_rfc3339_time_and_gives_whole_seconds_in_utc() {
        let at = |secs: i64| OffsetDateTime::from_unix_timestamp(secs).unwrap();
        assert_eq!(parse_when("2023-11-14").unwrap(), at(1_699_920_000));
        assert_eq!(parse_when("2023-11-14T22:13:20Z").unwrap(), at(1_700_000_000));
        // An offset is converted; a fraction of a second is dropped.
        assert_eq!(parse_when("2023-11-15T03:43:20+05:30").unwrap(), at(1_700_000_000));
        let fractional = parse_when("2023-11-14T22:13:20.987654321Z").unwrap();
        assert_eq!((fractional, fractional.nanosecond()), (at(1_700_000_000), 0));
        assert_eq!(
            parse_when("2023-11-15T03:43:20+05:30").unwrap().offset(),
            time::UtcOffset::UTC
        );
        for bad in [
            "",
            "yesterday",
            "2023-13-01",
            "2023-11-14 22:13",
            "14/11/2023",
            "2023-11-14T22:13:20",
        ] {
            assert!(parse_when(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn digests_take_the_prefix_or_not_and_nothing_else() {
        let hex = "ab".repeat(32);
        let want = parse_digest(&hex).unwrap();
        assert_eq!(parse_digest(&format!("sha256:{hex}")).unwrap(), want);
        for bad in [
            "",
            "sha256:",
            "sha256:abc",
            &"AB".repeat(32),
            &format!("sha256:{}", "AB".repeat(32)),
            &format!("sha512:{hex}"),
            &format!(" {hex}"),
            &"g".repeat(64),
        ] {
            assert!(parse_digest(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn inputs_split_like_files_and_name_themselves_in_errors() {
        let a = parse_input_arg("C:/data/a.wav:/inputs/a").unwrap();
        assert_eq!(
            (a.local, a.remote),
            (PathBuf::from("C:/data/a.wav"), Some("/inputs/a".into()))
        );
        assert_eq!(parse_input_arg("a.wav").unwrap().remote, None);
        assert!(parse_input_arg(":/inputs/a").unwrap_err().starts_with("--input"));
    }

    fn size(s: &str) -> Result<u64, String> {
        parse_size_mib(s)
    }

    #[test]
    fn sizes_accept_the_documented_spellings() {
        assert_eq!(size("512M"), Ok(512));
        assert_eq!(size("4G"), Ok(4096));
        assert_eq!(size("4GiB"), Ok(4096));
        assert_eq!(size("4gib"), Ok(4096));
        assert_eq!(size("4GB"), Ok(4096));
        assert_eq!(size("2T"), Ok(2 * 1024 * 1024));
        assert_eq!(size("1.5G"), Ok(1536));
        assert_eq!(size("2048"), Ok(2048));
        assert_eq!(size("1024K"), Ok(1));
    }

    #[test]
    fn sizes_round_up_to_a_whole_mib() {
        assert_eq!(size("1500K"), Ok(2));
        assert_eq!(size("0.1M"), Ok(1));
    }

    #[test]
    fn bad_sizes_are_refused() {
        for bad in [
            "",
            "G",
            "0",
            "0G",
            "-1G",
            "abc",
            "4X",
            "4 G",
            "1e3G",
            "4GiBB",
            "99999999999999999999T",
            "B",
        ] {
            assert!(size(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn durations_are_whole_seconds() {
        assert_eq!(parse_duration_secs("90s"), Ok(90));
        assert_eq!(parse_duration_secs("2h"), Ok(7200));
        assert_eq!(parse_duration_secs("1h30m"), Ok(5400));
        assert_eq!(parse_duration_secs("1day"), Ok(86_400));
    }

    #[test]
    fn bad_durations_are_refused() {
        for bad in ["", "0s", "1500ms", "abc", "-5s", "5", "99999999999999d"] {
            assert!(parse_duration_secs(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn long_durations_parse() {
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("30d"), Ok(Duration::from_secs(30 * 86_400)));
        assert!(parse_duration("soon").is_err());
    }

    fn lookup(name: &str) -> Option<String> {
        (name == "HOME_TOKEN").then(|| "from-env".to_string())
    }

    #[test]
    fn env_args_take_a_value_or_the_local_environment() {
        assert_eq!(parse_env_arg("A=b", &lookup), Ok(("A".into(), "b".into())));
        assert_eq!(parse_env_arg("A=b=c", &lookup), Ok(("A".into(), "b=c".into())));
        assert_eq!(parse_env_arg("A=", &lookup), Ok(("A".into(), String::new())));
        assert_eq!(
            parse_env_arg("HOME_TOKEN", &lookup),
            Ok(("HOME_TOKEN".into(), "from-env".into()))
        );
    }

    #[test]
    fn an_unset_env_name_is_an_error_that_names_the_variable() {
        let err = parse_env_arg("MISSING", &lookup).unwrap_err();
        assert!(err.contains("MISSING") && err.contains("not set"), "{err}");
        assert!(parse_env_arg("", &lookup).is_err());
        assert!(parse_env_arg("=x", &lookup).is_err());
    }

    #[test]
    fn env_files_follow_dotenv_conventions() {
        let text = "# a comment\n\nA=1\nexport B=two words\nC=\"quoted # not a comment\"\nD='single'\nE=a=b\r\nF=\n";
        assert_eq!(
            parse_env_file(text).unwrap(),
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "quoted # not a comment".into()),
                ("D".into(), "single".into()),
                ("E".into(), "a=b".into()),
                ("F".into(), String::new()),
            ]
        );
    }

    #[test]
    fn env_file_errors_name_the_line_but_never_its_content() {
        let err = parse_env_file("A=1\nTHIS_LINE_HAS_A_SECRET\n").unwrap_err();
        assert!(err.contains("line 2"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");
    }

    #[test]
    fn file_args_split_at_the_inputs_path() {
        assert_eq!(
            parse_file_arg("data.csv").unwrap(),
            FileArg {
                local: "data.csv".into(),
                remote: None
            }
        );
        assert_eq!(
            parse_file_arg("./a/b.csv:/inputs/x/b.csv").unwrap(),
            FileArg {
                local: "./a/b.csv".into(),
                remote: Some("/inputs/x/b.csv".into())
            }
        );
        // Windows paths keep their drive letter.
        assert_eq!(
            parse_file_arg("C:/data/a.csv").unwrap(),
            FileArg {
                local: "C:/data/a.csv".into(),
                remote: None
            }
        );
        assert_eq!(
            parse_file_arg("C:/data/a.csv:/inputs/a.csv").unwrap().remote.as_deref(),
            Some("/inputs/a.csv")
        );
        assert!(parse_file_arg("").is_err());
        assert!(parse_file_arg(":/inputs/a").is_err());
    }

    #[test]
    fn labels_split_at_the_first_equals() {
        assert_eq!(parse_label("gpu=rtx"), Ok(("gpu".into(), "rtx".into())));
        assert_eq!(parse_label("a=b=c"), Ok(("a".into(), "b=c".into())));
        assert!(parse_label("novalue").is_err());
        assert!(parse_label("=x").is_err());
    }

    #[test]
    fn units_have_at_most_three_decimals() {
        assert_eq!(parse_units("10"), Ok(Units::from_units(10)));
        assert_eq!(parse_units("2.5"), Ok(Units::from_milli(2500)));
        assert_eq!(parse_units("0.001"), Ok(Units::from_milli(1)));
        for bad in ["", "-1", "1.2345", "abc", ".", "1."] {
            assert!(parse_units(bad).is_err(), "{bad:?}");
        }
    }
}
