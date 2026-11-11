// SPDX-License-Identifier: Apache-2.0

//! The bundle compiler and signer (H2 §7.6 "Bundle", §14.1). No signing key exists in the repository: every test
//! makes a throwaway key pair at test time.

// Helpers and fixtures unwrap freely: a panic is the failure message of a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::io::Cursor;
use std::path::Path;

use common::{batch_toml, digest, service_toml, shipped_dir};
use minisign::KeyPair;
use p2pc_proto::api::JobSpec;
use templates_bundle::bundle::{Bundle, MAX_BUNDLE_BYTES, compile_dir};
use templates_bundle::check::{Mode, check_bundle};
use templates_bundle::sign::{VerifyError, sign_bundle, verify_bundle};

/// A directory with `bundle.toml` and the two fixtures (real-looking digests, so a release build accepts them).
fn fixture_dir(version: u64) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    write_fixture(dir.path(), version);
    dir
}

fn write_fixture(dir: &Path, version: u64) {
    fs::write(
        dir.join("bundle.toml"),
        format!("bundle_version = {version}\nmin_hub_version = \"0.1.0\"\n"),
    )
    .expect("write");
    fs::write(dir.join("fixture-chat.toml"), service_toml()).expect("write");
    fs::write(dir.join("fixture-batch.toml"), batch_toml()).expect("write");
}

fn keys() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("a throwaway key pair")
}

// ---- compiling ---------------------------------------------------------------------------------------------------

#[test]
fn compiling_twice_gives_the_same_bytes() {
    let a = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let b = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    assert_eq!(a.1, b.1, "the signed bytes must not depend on the run");
}

#[test]
fn the_json_is_canonical_compact_and_sorted() {
    let (_, bytes) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let text = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(
        text.starts_with("{\"bundle_version\":"),
        "keys are sorted: {}",
        &text[..40.min(text.len())]
    );
    assert!(!text.contains('\n') && !text.contains("  "), "compact");
    // Re-serializing the parsed value gives the same bytes: sorted keys at every level.
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(serde_json::to_vec(&value).expect("json"), bytes);
}

#[test]
fn the_bundle_round_trips_and_every_spec_parses_strictly() {
    let (bundle, bytes) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let back: Bundle = serde_json::from_slice(&bytes).expect("the hub parses what the compiler wrote");
    assert_eq!(back, bundle);
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    for t in value["templates"].as_array().expect("templates") {
        // `JobSpec` rejects unknown fields: this is the check the hub's launch will meet.
        let spec: JobSpec = serde_json::from_value(t["spec"].clone()).expect("the spec is a valid strict JobSpec");
        assert!(spec.image.contains("@sha256:"));
    }
    assert!(check_bundle(&back, Mode::Dev).is_empty());
}

#[test]
fn the_inline_script_of_transcribe_is_the_file_in_the_repository() {
    let (bundle, _) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let t = bundle
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe");
    let file = t
        .spec
        .files
        .iter()
        .find(|f| f.path == "/inputs/.template/transcribe.sh")
        .expect("the script is inline");
    let on_disk = fs::read(shipped_dir().join("transcribe/transcribe.sh")).expect("the script source");
    let inline = data_encoding::BASE64
        .decode(file.content_b64.as_bytes())
        .expect("base64");
    assert_eq!(inline, on_disk, "the bundle carries exactly the reviewed script");
}

#[test]
fn a_directory_without_bundle_toml_does_not_compile() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("fixture-chat.toml"), service_toml()).expect("write");
    assert!(compile_dir(dir.path(), Mode::Dev).is_err());
}

#[test]
fn an_empty_directory_does_not_compile() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("bundle.toml"),
        "bundle_version = 1\nmin_hub_version = \"0.1.0\"\n",
    )
    .expect("write");
    assert!(
        compile_dir(dir.path(), Mode::Dev).is_err(),
        "a bundle with no templates is refused"
    );
}

#[test]
fn a_release_build_refuses_a_placeholder_digest_and_a_dev_build_does_not() {
    let dir = fixture_dir(1);
    compile_dir(dir.path(), Mode::Release).expect("real digests pass a release build");
    let path = dir.path().join("fixture-chat.toml");
    let text = fs::read_to_string(&path)
        .expect("read")
        .replace(&digest(), &"0".repeat(64));
    fs::write(&path, text).expect("write");
    compile_dir(dir.path(), Mode::Dev).expect("a dev build accepts the placeholder");
    let err = compile_dir(dir.path(), Mode::Release).expect_err("a release build must not");
    assert!(err.to_string().contains("placeholder digest"), "{err}");
}

#[test]
fn a_template_that_breaks_a_rule_stops_the_compile_and_names_it() {
    let dir = fixture_dir(1);
    let path = dir.path().join("fixture-chat.toml");
    let text = fs::read_to_string(&path)
        .expect("read")
        .replace(&format!("@sha256:{}", digest()), ":latest");
    fs::write(&path, text).expect("write");
    let err = compile_dir(dir.path(), Mode::Dev).expect_err("refused");
    let shown = err.to_string();
    assert!(
        shown.contains("fixture-chat") && shown.contains("pinned by @sha256: digest"),
        "{shown}"
    );
}

#[test]
fn the_compiler_reads_inline_files_only_from_inside_the_templates_directory() {
    for from in ["../outside.sh", "/etc/passwd", "a/../../outside.sh", "sub/", ""] {
        let dir = fixture_dir(1);
        let path = dir.path().join("fixture-batch.toml");
        let text = fs::read_to_string(&path)
            .expect("read")
            .replace("content_b64 = \"ZWNobyBoaQ==\"", &format!("from = {from:?}"));
        fs::write(&path, text).expect("write");
        let r = compile_dir(dir.path(), Mode::Dev);
        assert!(r.is_err(), "from = {from:?} was accepted");
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_inline_file_is_refused() {
    let dir = fixture_dir(1);
    let outside = tempfile::tempdir().expect("tempdir");
    fs::write(outside.path().join("secret.sh"), "echo hi\n").expect("write");
    std::os::unix::fs::symlink(outside.path().join("secret.sh"), dir.path().join("link.sh")).expect("symlink");
    let path = dir.path().join("fixture-batch.toml");
    let text = fs::read_to_string(&path)
        .expect("read")
        .replace("content_b64 = \"ZWNobyBoaQ==\"", "from = \"link.sh\"");
    fs::write(&path, text).expect("write");
    assert!(compile_dir(dir.path(), Mode::Dev).is_err());
}

#[test]
fn an_inline_file_is_read_whole_and_bounded() {
    let dir = fixture_dir(1);
    fs::write(dir.path().join("run.sh"), "echo hi\n").expect("write");
    let path = dir.path().join("fixture-batch.toml");
    let text = fs::read_to_string(&path)
        .expect("read")
        .replace("content_b64 = \"ZWNobyBoaQ==\"", "from = \"run.sh\"");
    fs::write(&path, &text).expect("write");
    let (bundle, _) = compile_dir(dir.path(), Mode::Dev).expect("compiles");
    let t = bundle
        .templates
        .iter()
        .find(|t| t.info.id == "fixture-batch")
        .expect("batch");
    assert_eq!(t.spec.files[0].content_b64, data_encoding::BASE64.encode(b"echo hi\n"));

    fs::write(dir.path().join("run.sh"), vec![b'a'; 70 * 1024]).expect("write");
    assert!(
        compile_dir(dir.path(), Mode::Dev).is_err(),
        "an inline file over the bound is refused"
    );
}

// ---- signing -----------------------------------------------------------------------------------------------------

#[test]
fn a_signed_bundle_verifies_with_its_key_and_gives_back_the_bundle() {
    let kp = keys();
    let (bundle, bytes) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let sig = sign_bundle(&bytes, &kp.sk).expect("signs");
    let verified = verify_bundle(&bytes, &sig, &kp.pk).expect("verifies");
    assert_eq!(verified, bundle);
}

#[test]
fn one_changed_byte_breaks_the_signature() {
    let kp = keys();
    let (_, bytes) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let sig = sign_bundle(&bytes, &kp.sk).expect("signs");
    for i in [0, bytes.len() / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[i] ^= 0x01;
        let r = verify_bundle(&bad, &sig, &kp.pk);
        assert!(matches!(r, Err(VerifyError::BadSignature(_))), "byte {i}: {r:?}");
    }
    let mut longer = bytes.clone();
    longer.push(b' ');
    assert!(matches!(
        verify_bundle(&longer, &sig, &kp.pk),
        Err(VerifyError::BadSignature(_))
    ));
}

#[test]
fn another_key_does_not_verify() {
    let (signer, other) = (keys(), keys());
    let (_, bytes) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let sig = sign_bundle(&bytes, &signer.sk).expect("signs");
    assert!(matches!(
        verify_bundle(&bytes, &sig, &other.pk),
        Err(VerifyError::BadSignature(_))
    ));
}

#[test]
fn the_signature_of_one_bundle_does_not_verify_another() {
    let kp = keys();
    let dir = fixture_dir(1);
    let (_, one) = compile_dir(dir.path(), Mode::Release).expect("compiles");
    write_fixture(dir.path(), 2);
    let (_, two) = compile_dir(dir.path(), Mode::Release).expect("compiles");
    assert_ne!(one, two);
    let sig_one = sign_bundle(&one, &kp.sk).expect("signs");
    assert!(
        verify_bundle(&two, &sig_one, &kp.pk).is_err(),
        "a signature must not move to another bundle"
    );
}

#[test]
fn garbage_is_not_a_signature() {
    let kp = keys();
    let (_, bytes) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    for sig in [
        "",
        "not a signature",
        "untrusted comment: x\nAAAA\ntrusted comment: y\nAAAA\n",
    ] {
        assert!(verify_bundle(&bytes, sig, &kp.pk).is_err(), "{sig:?} verified");
    }
}

#[test]
fn the_trusted_comment_must_carry_the_bundles_own_version() {
    // A signature made by the release key over the right bytes, but claiming another version, is refused: the
    // version a hub compares against its high-water mark is the one the key signed.
    let kp = keys();
    let (_, bytes) = compile_dir(&shipped_dir(), Mode::Dev).expect("compiles");
    let forged = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        Cursor::new(&bytes),
        Some("p2pc-templates bundle_version=999"),
        None,
    )
    .expect("signs")
    .into_string();
    assert!(matches!(
        verify_bundle(&bytes, &forged, &kp.pk),
        Err(VerifyError::VersionMismatch { .. })
    ));
}

#[test]
fn signed_bytes_that_are_not_a_bundle_are_refused_after_the_signature_check() {
    let kp = keys();
    let junk = b"{\"bundle_version\":1}".to_vec();
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        Cursor::new(&junk),
        Some("p2pc-templates bundle_version=1"),
        None,
    )
    .expect("signs")
    .into_string();
    assert!(matches!(
        verify_bundle(&junk, &sig, &kp.pk),
        Err(VerifyError::NotABundle(_))
    ));
}

#[test]
fn an_oversized_bundle_is_refused_before_it_is_parsed() {
    let kp = keys();
    let big = vec![b' '; MAX_BUNDLE_BYTES + 1];
    let sig = minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        Cursor::new(&big),
        Some("p2pc-templates bundle_version=1"),
        None,
    )
    .expect("signs")
    .into_string();
    assert!(matches!(verify_bundle(&big, &sig, &kp.pk), Err(VerifyError::TooLarge)));
}

#[test]
fn signing_refuses_bytes_that_are_not_a_bundle() {
    let kp = keys();
    assert!(sign_bundle(b"not json", &kp.sk).is_err());
}

// ---- the command line, end to end ------------------------------------------------------------------------------------

#[test]
fn the_cli_compiles_signs_and_verifies() {
    use assert_cmd::Command;

    let work = tempfile::tempdir().expect("tempdir");
    let src = fixture_dir(3);
    let kp = keys();
    let sk_path = work.path().join("release.key");
    let pk_path = work.path().join("release.pub");
    fs::write(&sk_path, kp.sk.to_box(None).expect("sk box").into_string()).expect("write");
    fs::write(&pk_path, kp.pk.to_box().expect("pk box").into_string()).expect("write");
    let out = work.path().join("templates.json");
    let sig = work.path().join("templates.json.minisig");

    let run = |args: &[&str]| {
        Command::cargo_bin("templates-bundle")
            .expect("binary")
            .args(args)
            .assert()
    };
    let p = |p: &Path| p.to_str().expect("utf-8 path").to_string();

    run(&[
        "compile",
        "--templates-dir",
        &p(src.path()),
        "--out",
        &p(&out),
        "--release",
    ])
    .success();
    run(&[
        "sign",
        "--bundle",
        &p(&out),
        "--secret-key",
        &p(&sk_path),
        "--out",
        &p(&sig),
    ])
    .success();
    run(&[
        "verify",
        "--bundle",
        &p(&out),
        "--signature",
        &p(&sig),
        "--public-key",
        &p(&pk_path),
    ])
    .success();

    // A flipped byte fails the verification with a non-zero exit.
    let mut bytes = fs::read(&out).expect("read");
    bytes[5] ^= 0x01;
    fs::write(&out, bytes).expect("write");
    run(&[
        "verify",
        "--bundle",
        &p(&out),
        "--signature",
        &p(&sig),
        "--public-key",
        &p(&pk_path),
    ])
    .failure();
}

#[test]
fn the_cli_release_build_of_the_shipped_templates_fails_while_a_digest_is_a_placeholder() {
    use assert_cmd::Command;

    let loaded = templates_bundle::source::load_dir(&shipped_dir()).expect("loads");
    let has_placeholder = loaded.templates.iter().any(|t| t.spec.image.ends_with(&"0".repeat(64)));
    let work = tempfile::tempdir().expect("tempdir");
    let out = work.path().join("templates.json");
    let assert = Command::cargo_bin("templates-bundle")
        .expect("binary")
        .args([
            "compile",
            "--templates-dir",
            shipped_dir().to_str().expect("utf-8"),
            "--out",
            out.to_str().expect("utf-8"),
            "--release",
        ])
        .assert();
    if has_placeholder {
        assert.failure();
        assert!(!out.exists(), "nothing is written when the build is refused");
    } else {
        assert.success();
    }
}
