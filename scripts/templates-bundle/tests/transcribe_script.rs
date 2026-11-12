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
            "prev=''\nprintf 'curl' >> '{log}'; for a in \"$@\"; do printf ' [%s]' \"$a\" >> '{log}'; {{ [ \"$prev\" = '-o' ] || [ \"$prev\" = '--output' ]; }} && target=\"$a\"; prev=\"$a\"; done; echo >> '{log}'\nprintf model > \"$target\"",
            log = log.display()
        ),
    );
    Sandbox {
        _dir: dir,
        root,
        bin,
        log,
    }
}

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
    assert!(
        floor >= 1,
        "a stalled transfer is one below a floor of at least 1 byte/s"
    );
    assert!((10..=300).contains(&window), "the stall window is {window} s");
    let loaded = templates_bundle::source::load_dir(&shipped_dir()).expect("loads");
    let timeout_s = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe")
        .spec
        .timeout_s;
    assert!(
        ceiling < u64::from(timeout_s) && ceiling >= 600,
        "--max-time {ceiling} must be under timeout_s {timeout_s} and long enough for the biggest model"
    );
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
