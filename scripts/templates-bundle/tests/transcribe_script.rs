// SPDX-License-Identifier: Apache-2.0

//! The fixed script of the `transcribe` template (`templates/transcribe/transcribe.sh`), run with `sh` against fake
//! `ffmpeg`, `whisper-cli` and `curl` programs. This checks the script's own logic (it validates `LANGUAGE` and
//! `MODEL` again, passes each as one whole argument, downloads a model once and writes the three outputs). It does
//! not prove that the real whisper.cpp image has those programs: that needs a test node with a container runtime.

#![cfg(unix)]
// Helpers unwrap freely: a panic is the failure message of a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::shipped_dir;

struct Sandbox {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

fn script() -> PathBuf {
    shipped_dir().join("transcribe/transcribe.sh")
}

fn write_tool(bin: &Path, name: &str, body: &str) {
    let path = bin.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write tool");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// A fake container filesystem (`<root>/inputs`, `/outputs`, `/volumes`) and fake tools that log each call.
fn sandbox(with_audio: bool) -> Sandbox {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    let bin = dir.path().join("bin");
    let log = dir.path().join("calls.log");
    fs::create_dir_all(root.join("inputs")).expect("mkdir");
    fs::create_dir_all(&bin).expect("mkdir");
    fs::write(&log, "").expect("log");
    if with_audio {
        fs::write(root.join("inputs/audio"), b"not really audio").expect("audio");
    }
    // ffmpeg: log the arguments, one per line, then write something to the file named by the last argument.
    write_tool(
        &bin,
        "ffmpeg",
        &format!(
            "for a in \"$@\"; do last=\"$a\"; done\nprintf 'ffmpeg' >> '{log}'; for a in \"$@\"; do printf ' [%s]' \"$a\" >> '{log}'; done; echo >> '{log}'\nprintf wav > \"$last\"",
            log = log.display()
        ),
    );
    // whisper-cli: log the arguments and write the three outputs next to the `-of` prefix.
    write_tool(
        &bin,
        "whisper-cli",
        &format!(
            "prefix=''\nprev=''\nprintf 'whisper' >> '{log}'; for a in \"$@\"; do printf ' [%s]' \"$a\" >> '{log}'; [ \"$prev\" = '-of' ] && prefix=\"$a\"; prev=\"$a\"; done; echo >> '{log}'\nprintf 'hello\\n' > \"$prefix.txt\"\nprintf '1\\n00:00:00,000 --> 00:00:01,000\\nhello\\n' > \"$prefix.srt\"\nprintf 'WEBVTT\\n\\n00:00:00.000 --> 00:00:01.000\\nhello\\n' > \"$prefix.vtt\"",
            log = log.display()
        ),
    );
    // curl: log the arguments and write a fake model to the file named by `-o` or `--output`.
    write_tool(
        &bin,
        "curl",
        &format!(
            "prev=''\nprintf 'curl' >> '{log}'; for a in \"$@\"; do printf ' [%s]' \"$a\" >> '{log}'; {{ [ \"$prev\" = '-o' ] || [ \"$prev\" = '--output' ]; }} && target=\"$a\"; prev=\"$a\"; done; echo >> '{log}'\nprintf 'good model' > \"$target\"",
            log = log.display()
        ),
    );
    // sha256sum: the fake "good model" content stands for the real model of that size (the test cannot ship 466 MB),
    // so it gets the pinned hash of the model named by the file; any other content is hashed for real.
    for (model, hash) in PINNED_HASHES {
        fs::write(bin.join(format!("hash-{model}")), hash).expect("hash");
    }
    write_tool(
        &bin,
        "sha256sum",
        &format!(
            "printf 'sha256sum [%s]\\n' \"$1\" >> '{log}'\nname=\"${{1##*/}}\"; name=\"${{name%.part}}\"; m=\"${{name#ggml-}}\"; m=\"${{m%.bin}}\"\ncontent=\"$(cat \"$1\")\"\nif [ \"$content\" = 'good model' ] && [ -f '{bin}/hash-'\"$m\" ]; then printf '%s  %s\\n' \"$(cat '{bin}/hash-'\"$m\")\" \"$1\"; else exec /usr/bin/sha256sum \"$1\"; fi",
            log = log.display(),
            bin = bin.display()
        ),
    );
    Sandbox {
        _dir: dir,
        root,
        bin,
        log,
    }
}

/// The SHA-256 of each model file at the pinned Hugging Face revision (the LFS oid), as the architect recorded them.
const PINNED_HASHES: [(&str, &str); 3] = [
    (
        "base",
        "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe",
    ),
    (
        "small",
        "1be3a9b2063867b937e64e2ec7483364a79917e157fa98c5d94b5c1fffea987b",
    ),
    (
        "medium",
        "6c14d5adee5f86394037b4e4e8b59f1673b6cee10e3cf0b11bbdbee79c156208",
    ),
];

/// The Hugging Face commit the script downloads from.
const PINNED_REVISION: &str = "5359861c739e955e79d9a303bcbc70fb988958b1";

fn run(sb: &Sandbox, language: &str, model: &str) -> Output {
    Command::new("sh")
        .arg(script())
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", sb.bin.display()))
        .env("TRANSCRIBE_ROOT", &sb.root)
        .env("LANGUAGE", language)
        .env("MODEL", model)
        .output()
        .expect("sh runs")
}

fn calls(sb: &Sandbox, tool: &str) -> Vec<String> {
    fs::read_to_string(&sb.log)
        .expect("log")
        .lines()
        .filter(|l| l.split(' ').next() == Some(tool))
        .map(str::to_string)
        .collect()
}

#[test]
fn it_converts_downloads_the_model_once_and_writes_the_three_outputs() {
    let sb = sandbox(true);
    let out = run(&sb, "es", "small");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for f in ["transcript.txt", "transcript.srt", "transcript.vtt"] {
        assert!(sb.root.join("outputs").join(f).is_file(), "{f} is written to /outputs");
    }
    let whisper = calls(&sb, "whisper");
    assert_eq!(whisper.len(), 1);
    assert!(
        whisper[0].contains("[-l] [es]"),
        "the language is one whole argument: {}",
        whisper[0]
    );
    assert!(whisper[0].contains("ggml-small.bin"), "{}", whisper[0]);
    let curl = calls(&sb, "curl");
    assert_eq!(curl.len(), 1, "the model is downloaded when it is missing");
    assert!(curl[0].contains("https://huggingface.co/"), "{}", curl[0]);
    assert!(curl[0].contains("ggml-small.bin"), "{}", curl[0]);
    assert!(sb.root.join("volumes/models/ggml-small.bin").is_file());
    assert!(
        !sb.root.join("volumes/models/ggml-small.bin.part").exists(),
        "a finished download is renamed, never left half-written under the final name"
    );

    // A second run finds the model in the volume and does not download it again.
    let again = run(&sb, "es", "small");
    assert!(again.status.success());
    assert_eq!(calls(&sb, "curl").len(), 1, "the volume keeps the model");
    assert_eq!(calls(&sb, "whisper").len(), 2);
}

#[test]
fn the_model_download_is_bounded_against_a_stall_and_by_a_total_time() {
    // A download that hangs on a half-open connection must not run until the job's whole `timeout_s`, so curl gets a
    // floor for the speed over a window (`--speed-limit`/`--speed-time`) and a ceiling for the whole transfer
    // (`--max-time`) that leaves the conversion and the transcription their time.
    let sb = sandbox(true);
    assert!(run(&sb, "auto", "medium").status.success());
    let curl = calls(&sb, "curl");
    assert_eq!(curl.len(), 1);
    let value_of = |flag: &str| -> u64 {
        let marker = format!("[{flag}] [");
        let rest = curl[0]
            .split(&marker)
            .nth(1)
            .unwrap_or_else(|| panic!("no {flag} in: {}", curl[0]));
        rest.split(']')
            .next()
            .unwrap()
            .parse()
            .unwrap_or_else(|_| panic!("{flag} is not a number: {}", curl[0]))
    };
    let (floor, window, ceiling) = (
        value_of("--speed-limit"),
        value_of("--speed-time"),
        value_of("--max-time"),
    );
    assert_eq!(floor, 10240, "a stall is under 10 KiB/s");
    assert_eq!(window, 60, "for 60 s");
    let loaded = templates_bundle::source::load_dir(&shipped_dir()).expect("loads");
    let timeout_s = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe")
        .spec
        .timeout_s;
    assert!(
        ceiling == 1800 && ceiling < u64::from(timeout_s),
        "--max-time {ceiling} must be 1800 and under timeout_s {timeout_s}"
    );
}

#[test]
fn the_model_comes_from_the_pinned_revision_never_from_main() {
    let sb = sandbox(true);
    assert!(run(&sb, "auto", "small").status.success());
    let curl = calls(&sb, "curl");
    assert_eq!(curl.len(), 1);
    let url = format!("https://huggingface.co/ggerganov/whisper.cpp/resolve/{PINNED_REVISION}/ggml-small.bin");
    assert!(curl[0].contains(&format!("[{url}]")), "{}", curl[0]);
    assert!(!curl[0].contains("resolve/main"), "{}", curl[0]);
    let text = fs::read_to_string(script()).expect("script");
    assert!(
        !text.contains("resolve/main"),
        "the script must not name a moving branch"
    );
}

#[test]
fn every_listed_model_is_checked_against_its_own_pinned_hash() {
    // The fake "good model" content is accepted only when the script's table has the pinned hash for that model, so
    // this fails if a hash in the script is wrong or belongs to another model.
    for (model, _) in PINNED_HASHES {
        let sb = sandbox(true);
        let out = run(&sb, "auto", model);
        assert!(
            out.status.success(),
            "{model}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            calls(&sb, "sha256sum").len(),
            1,
            "{model}: the file is hashed before use"
        );
    }
    let text = fs::read_to_string(script()).expect("script");
    for (model, hash) in PINNED_HASHES {
        assert!(text.contains(hash), "the script has no hash for {model}");
    }
}

#[test]
fn a_correct_model_already_in_the_volume_is_used_without_a_download_and_is_still_hashed() {
    let sb = sandbox(true);
    let models = sb.root.join("volumes/models");
    fs::create_dir_all(&models).expect("mkdir");
    fs::write(models.join("ggml-small.bin"), b"good model").expect("model");
    let out = run(&sb, "auto", "small");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        calls(&sb, "curl").is_empty(),
        "no download for a model that is already there"
    );
    assert_eq!(calls(&sb, "whisper").len(), 1);
    assert_eq!(
        calls(&sb, "sha256sum").len(),
        1,
        "the check runs on every run, download or not"
    );
    // And again: still no download, still a check.
    assert!(run(&sb, "auto", "small").status.success());
    assert!(calls(&sb, "curl").is_empty());
    assert_eq!(calls(&sb, "sha256sum").len(), 2);
}

#[test]
fn a_corrupted_model_in_the_volume_is_deleted_and_the_run_fails() {
    for content in [&b"junk"[..], b"good mode", b"good model!", b"\0\0\0"] {
        let sb = sandbox(true);
        let models = sb.root.join("volumes/models");
        fs::create_dir_all(&models).expect("mkdir");
        fs::write(models.join("ggml-small.bin"), content).expect("model");
        let out = run(&sb, "auto", "small");
        assert!(!out.status.success(), "{content:?} was used");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("checksum"),
            "the error says why: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !models.join("ggml-small.bin").exists(),
            "{content:?} stays in the volume"
        );
        assert!(calls(&sb, "whisper").is_empty(), "no transcription with a bad model");
        assert!(
            calls(&sb, "curl").is_empty(),
            "the next run downloads it, this one stops"
        );
        assert!(
            sb.root
                .join("outputs")
                .read_dir()
                .map_or(true, |mut d| d.next().is_none()),
            "no transcript from a bad model"
        );
    }
}

#[test]
fn a_download_with_the_wrong_hash_is_deleted_and_the_run_fails() {
    // The hub's egress allowlist does not authenticate the file: only the hash does.
    let sb = sandbox(true);
    write_tool(
        &sb.bin,
        "curl",
        &format!(
            "printf 'curl' >> '{log}'; for a in \"$@\"; do printf ' [%s]' \"$a\" >> '{log}'; done; echo >> '{log}'\nprev=''; for a in \"$@\"; do [ \"$prev\" = '--output' ] && printf 'not the model' > \"$a\"; prev=\"$a\"; done",
            log = sb.log.display()
        ),
    );
    let out = run(&sb, "auto", "small");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("checksum"));
    let models = sb.root.join("volumes/models");
    assert!(!models.join("ggml-small.bin").exists());
    assert!(!models.join("ggml-small.bin.part").exists());
    assert!(calls(&sb, "whisper").is_empty());
}

#[test]
fn a_signal_still_removes_the_converted_audio() {
    // The converted audio is a full copy of the user's recording. An untrapped SIGTERM ends `sh` at once and skips the
    // EXIT trap, leaving the copy in the volume until the next run; trapping TERM, INT and HUP turns them into an
    // exit (143), so the EXIT trap runs. The fake whisper-cli signals the script's own shell and returns: the trap
    // runs when the foreground command is done, with no sleep and nothing to race.
    for signal in ["TERM", "INT", "HUP"] {
        let sb = sandbox(true);
        write_tool(&sb.bin, "whisper-cli", &format!("kill -{signal} $PPID"));
        let out = run(&sb, "auto", "small");
        assert_eq!(
            out.status.code(),
            Some(143),
            "{signal}: {:?} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let left: Vec<String> = fs::read_dir(sb.root.join("volumes/models"))
            .expect("models")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            left.iter().all(|n| !n.starts_with(".work.")),
            "{signal}: the scratch directory with the audio is gone: {left:?}"
        );
    }
}

#[test]
fn it_leaves_no_working_file_in_outputs() {
    let sb = sandbox(true);
    assert!(run(&sb, "auto", "base").status.success());
    let mut names: Vec<String> = fs::read_dir(sb.root.join("outputs"))
        .expect("outputs")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["transcript.srt", "transcript.txt", "transcript.vtt"]);
}

#[test]
fn it_removes_what_a_killed_run_left_in_the_models_volume() {
    // A job killed by its timeout or a node loss cannot run its `trap`, so the next run on the same volume must clear
    // the scratch directory and the half-written downloads it left, or the 5 GiB volume fills up with them.
    let sb = sandbox(true);
    let models = sb.root.join("volumes/models");
    fs::create_dir_all(models.join(".work.old")).expect("mkdir");
    fs::write(models.join(".work.old/audio.wav"), vec![b'x'; 4096]).expect("stale wav");
    fs::create_dir_all(models.join(".work.AbC123")).expect("mkdir");
    fs::write(models.join("ggml-base.bin.part"), b"half").expect("stale part");
    fs::write(models.join("ggml-medium.bin.part"), b"half").expect("stale part");
    // A finished model of another size is the volume's content and must stay.
    fs::write(models.join("ggml-medium.bin"), b"a finished model").expect("model");
    // Something that is not ours must stay too.
    fs::write(models.join("README"), b"keep").expect("other");

    let out = run(&sb, "auto", "small");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let mut left: Vec<String> = fs::read_dir(&models)
        .expect("models")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        ["README", "ggml-medium.bin", "ggml-small.bin"],
        "stale .work.* and *.part are gone, the finished models and unrelated files stay"
    );
}

#[test]
fn it_refuses_a_language_or_model_that_is_not_a_plain_listed_word() {
    for (language, model) in [
        ("en; touch pwned", "small"),
        ("$(touch pwned)", "small"),
        ("`touch pwned`", "small"),
        ("en\nB=c", "small"),
        ("../../etc", "small"),
        ("EN", "small"),
        ("english", "small"),
        ("", "small"),
        ("en", "large-v3"),
        ("en", "small; touch pwned"),
        ("en", "../models/x"),
        ("en", "--help"),
        ("en", ""),
    ] {
        let sb = sandbox(true);
        let out = run(&sb, language, model);
        assert_eq!(
            out.status.code(),
            Some(64),
            "{language:?}/{model:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(calls(&sb, "ffmpeg").is_empty() && calls(&sb, "curl").is_empty() && calls(&sb, "whisper").is_empty());
        assert!(!sb.root.join("pwned").exists());
        assert!(!Path::new("pwned").exists());
    }
}

#[test]
fn it_accepts_every_language_and_model_the_template_lists() {
    let loaded = templates_bundle::source::load_dir(&shipped_dir()).expect("loads");
    let t = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe");
    for p in &t.info.params {
        let p2pc_proto::api::ParamType::Enum { values } = &p.ty else {
            continue;
        };
        for v in values {
            let (language, model) = if p.name == "language" {
                (v.as_str(), "base")
            } else {
                ("auto", v.as_str())
            };
            let sb = sandbox(true);
            let out = run(&sb, language, model);
            assert!(
                out.status.success(),
                "{language}/{model}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn it_stops_when_there_is_no_input() {
    let sb = sandbox(false);
    let out = run(&sb, "auto", "small");
    assert_eq!(out.status.code(), Some(66), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(calls(&sb, "whisper").is_empty());
}

#[test]
fn it_fails_when_the_model_download_fails() {
    let sb = sandbox(true);
    write_tool(&sb.bin, "curl", "exit 22");
    let out = run(&sb, "auto", "small");
    assert!(!out.status.success());
    assert!(calls(&sb, "whisper").is_empty(), "no transcription without a model");
    assert!(
        !sb.root.join("volumes/models/ggml-small.bin").exists(),
        "no partial model under the final name"
    );
}

#[test]
fn the_script_does_not_use_eval_or_a_shell_string_built_from_input() {
    let text = fs::read_to_string(script()).expect("script");
    for word in ["eval ", "sh -c", "bash -c", "$(echo"] {
        assert!(!text.contains(word), "the script contains `{word}`");
    }
    assert!(
        text.lines()
            .take(3)
            .any(|l| l.contains("SPDX-License-Identifier: Apache-2.0")),
        "SPDX header"
    );
}
