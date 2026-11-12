// SPDX-License-Identifier: Apache-2.0

//! What `sign_bundle` refuses (review finding 1): the release key signs only a bundle that passes the release rules
//! and whose bytes are exactly the canonical bytes of what they parse to. Whoever calls the library (the CLI, a
//! pipeline script, a test) cannot sign a Dev-mode bundle, a bundle with an unpinned image, or hand-edited JSON.

// Helpers and fixtures unwrap freely: a panic is the failure message of a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{batch_toml, digest, parse_ok, service_toml, shipped_dir};
use minisign::KeyPair;
use templates_bundle::bundle::{Bundle, compile_dir};
use templates_bundle::check::Mode;
use templates_bundle::sign::{SignError, sign_bundle, verify_bundle};

fn keys() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("a throwaway key pair")
}

fn canonical(templates: Vec<p2pc_proto::api::Template>) -> Vec<u8> {
    Bundle::new(1, "0.1.0", templates).to_canonical_json().expect("json")
}

fn good_templates() -> Vec<p2pc_proto::api::Template> {
    vec![parse_ok(&batch_toml()), parse_ok(&service_toml())]
}

#[test]
fn a_release_grade_canonical_bundle_signs_and_verifies() {
    let kp = keys();
    let bytes = canonical(good_templates());
    let sig = sign_bundle(&bytes, &kp.sk).expect("signs");
    verify_bundle(&bytes, &sig, &kp.pk).expect("verifies");
}

#[test]
fn the_shipped_bundle_compiled_for_release_signs_and_verifies() {
    // The shipped templates carry the digests taken from the registries, so the pipeline's own steps work on them:
    // compile in release mode, sign with a (throwaway) key, verify.
    let kp = keys();
    let (bundle, bytes) = compile_dir(&shipped_dir(), Mode::Release).expect("the shipped templates pass --release");
    let sig = sign_bundle(&bytes, &kp.sk).expect("signs");
    assert_eq!(verify_bundle(&bytes, &sig, &kp.pk).expect("verifies"), bundle);
}

#[test]
fn a_bundle_compiled_in_dev_mode_with_a_placeholder_digest_does_not_sign() {
    // A directory of fixtures where one image still has the placeholder: a Dev compile accepts it, the signer must not.
    let kp = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("bundle.toml"),
        "bundle_version = 1\nmin_hub_version = \"0.1.0\"\n",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("fixture-chat.toml"),
        service_toml().replace(&digest(), &"0".repeat(64)),
    )
    .expect("write");
    let (_, bytes) = compile_dir(dir.path(), Mode::Dev).expect("a dev compile accepts the placeholder");
    let err = sign_bundle(&bytes, &kp.sk).expect_err("must not sign");
    assert!(matches!(err, SignError::Rules(_)), "{err:?}");
    assert!(err.to_string().contains("placeholder digest"), "{err}");
}

#[test]
fn a_placeholder_built_by_hand_does_not_sign_either() {
    let kp = keys();
    let text = service_toml().replace(&digest(), &"0".repeat(64));
    let bytes = canonical(vec![parse_ok(&text)]);
    assert!(matches!(sign_bundle(&bytes, &kp.sk), Err(SignError::Rules(_))));
}

#[test]
fn a_bundle_with_an_unpinned_image_does_not_sign() {
    let kp = keys();
    let text = service_toml().replace(&format!("@sha256:{}", digest()), ":latest");
    let bytes = canonical(vec![parse_ok(&text)]);
    let err = sign_bundle(&bytes, &kp.sk).expect_err("must not sign");
    assert!(matches!(err, SignError::Rules(_)), "{err:?}");
    assert!(err.to_string().contains("pinned by @sha256: digest"), "{err}");
}

#[test]
fn a_bundle_that_breaks_any_other_rule_does_not_sign() {
    let kp = keys();
    // One broken rule per template, each in an otherwise valid bundle: a field target outside the JobSpec range,
    // and a route that pulls models.
    let range = service_toml().replace("min = 900", "min = 60");
    let route = format!(
        "{}\n[[allowed_routes]]\nport = 8080\nmethod = \"POST\"\npath = \"/api/pull\"\n",
        service_toml()
    );
    for text in [range, route] {
        let bytes = canonical(vec![parse_ok(&text)]);
        assert!(
            matches!(sign_bundle(&bytes, &kp.sk), Err(SignError::Rules(_))),
            "a rule-breaking bundle was signed"
        );
    }
}

#[test]
fn a_bundle_that_is_not_the_canonical_form_of_itself_does_not_sign() {
    let kp = keys();
    let bytes = canonical(good_templates());
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    // Pretty-printed: the same bundle, other bytes.
    let pretty = serde_json::to_vec_pretty(&value).expect("json");
    assert_ne!(pretty, bytes);
    assert!(matches!(sign_bundle(&pretty, &kp.sk), Err(SignError::NotCanonical)));

    // A trailing newline, and a leading space.
    let mut newline = bytes.clone();
    newline.push(b'\n');
    assert!(matches!(sign_bundle(&newline, &kp.sk), Err(SignError::NotCanonical)));
    let mut space = vec![b' '];
    space.extend_from_slice(&bytes);
    assert!(matches!(sign_bundle(&space, &kp.sk), Err(SignError::NotCanonical)));
}

#[test]
fn bytes_with_a_field_the_bundle_type_does_not_know_do_not_sign() {
    // A field that parsing would drop is a field the signature would cover and the hub would never see.
    let kp = keys();
    let bytes = canonical(good_templates());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    value["note"] = serde_json::Value::String("extra".to_string());
    let extra = serde_json::to_vec(&value).expect("json");
    let r = sign_bundle(&extra, &kp.sk);
    assert!(
        matches!(r, Err(SignError::NotCanonical | SignError::NotABundle(_))),
        "{r:?}"
    );
}

#[test]
fn the_bundle_level_rules_also_gate_signing() {
    let kp = keys();
    let zero_version = Bundle::new(0, "0.1.0", good_templates())
        .to_canonical_json()
        .expect("json");
    assert!(matches!(sign_bundle(&zero_version, &kp.sk), Err(SignError::Rules(_))));
    let bad_semver = Bundle::new(1, "soon", good_templates())
        .to_canonical_json()
        .expect("json");
    assert!(matches!(sign_bundle(&bad_semver, &kp.sk), Err(SignError::Rules(_))));
}
