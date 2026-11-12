// SPDX-License-Identifier: Apache-2.0

//! SI-H2-13, parameter side: parameters reach the job only through the targets of H2 §7.6, and the result is a valid
//! JobSpec. Out-of-type and out-of-bounds values are refused (`ParamError`, which the hub answers with
//! `422 invalid_params`), and a property test feeds shell metacharacters as values.

// Helpers and fixtures unwrap freely: a panic is the failure message of a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use common::{batch_toml, parse_ok, service_toml, shipped_dir};
use p2pc_proto::api::{BlobInput, JobSpec, ParamValue, Template, TemplateRef};
use p2pc_proto::validate::{H2Features, Limits, SpecContext};
use proptest::prelude::*;
use templates_bundle::params::{ParamError, build_spec};
use templates_bundle::source::load_dir;

fn shipped(id: &str) -> Template {
    let bundle = load_dir(&shipped_dir()).expect("templates/ loads");
    bundle
        .templates
        .into_iter()
        .find(|t| t.info.id == id)
        .unwrap_or_else(|| panic!("no template {id}"))
}

fn values(pairs: &[(&str, ParamValue)]) -> BTreeMap<String, ParamValue> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
}

fn text(s: &str) -> ParamValue {
    ParamValue::Text(s.to_string())
}

fn limits() -> Limits {
    Limits {
        h2: H2Features::ALL,
        ..Limits::default()
    }
}

fn assert_valid_launch(spec: &JobSpec) {
    if let Err(e) = spec.validate_in(&limits(), SpecContext::Launch) {
        panic!("the launched spec does not validate: {e}");
    }
}

fn blob(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

// ---- private-chat ------------------------------------------------------------------------------------------------

#[test]
fn chat_with_no_params_uses_the_defaults() {
    let t = shipped("private-chat");
    let spec = build_spec(&t, &BTreeMap::new(), true).expect("defaults build");
    assert_valid_launch(&spec);
    let model_default = match &t
        .info
        .params
        .iter()
        .find(|p| p.name == "model")
        .expect("model param")
        .default
    {
        Some(ParamValue::Text(m)) => m.clone(),
        other => panic!("model has a text default, got {other:?}"),
    };
    assert_eq!(
        spec.template,
        Some(TemplateRef {
            id: "private-chat".into(),
            version: t.info.version,
            pull: Some(model_default)
        })
    );
    assert_eq!(spec.timeout_s, 2_592_000, "the template's 30 days stay");
    assert_eq!(spec.service.as_ref().expect("service").idle_timeout_s, Some(3600));
    assert_eq!(spec.resources.gpu, 1);
}

#[test]
fn chat_runs_on_cpu_when_no_gpu_node_is_eligible() {
    let t = shipped("private-chat");
    let spec = build_spec(&t, &BTreeMap::new(), false).expect("builds");
    assert_eq!(
        spec.resources.gpu, 0,
        "requirements.gpu = preferred launches with gpu 0 without an eligible GPU"
    );
    assert_valid_launch(&spec);
}

#[test]
fn chat_model_goes_to_pull_and_only_there() {
    let t = shipped("private-chat");
    let base = build_spec(&t, &BTreeMap::new(), true).expect("builds");
    let listed = match &t.info.params.iter().find(|p| p.name == "model").expect("model").ty {
        p2pc_proto::api::ParamType::Enum { values } => values.clone(),
        other => panic!("model is an enum, got {other:?}"),
    };
    assert!(listed.len() >= 2, "a choice of models");
    for model in &listed {
        let spec = build_spec(&t, &values(&[("model", text(model))]), true).expect("a listed model builds");
        assert_eq!(
            spec.template.as_ref().and_then(|r| r.pull.as_deref()),
            Some(model.as_str())
        );
        let mut expected = base.clone();
        expected.template = spec.template.clone();
        assert_eq!(spec, expected, "only template.pull differs for {model}");
    }
}

#[test]
fn chat_idle_timeout_sets_the_service_field_within_its_bounds() {
    let t = shipped("private-chat");
    for (secs, ok) in [
        (899, false),
        (900, true),
        (86_400, true),
        (86_401, false),
        (0, false),
        (-1, false),
        (i64::MAX, false),
    ] {
        let r = build_spec(&t, &values(&[("idle_timeout_s", ParamValue::Int(secs))]), true);
        match (ok, r) {
            (true, Ok(spec)) => {
                assert_eq!(
                    spec.service.expect("service").idle_timeout_s,
                    Some(u32::try_from(secs).expect("fits"))
                );
            }
            (false, Err(ParamError::OutOfBounds { .. })) => {}
            (ok, r) => panic!("idle_timeout_s = {secs}: expected ok={ok}, got {r:?}"),
        }
    }
}

#[test]
fn chat_refuses_unknown_wrongly_typed_and_unlisted_values() {
    let t = shipped("private-chat");
    let cases: Vec<(&str, BTreeMap<String, ParamValue>)> = vec![
        ("an unknown parameter", values(&[("nope", text("x"))])),
        ("a bool for an enum", values(&[("model", ParamValue::Bool(true))])),
        ("an int for an enum", values(&[("model", ParamValue::Int(3))])),
        (
            "a model that is not listed",
            values(&[("model", text("not-a-listed-model:1b"))]),
        ),
        ("a text for an int", values(&[("idle_timeout_s", text("900"))])),
        (
            "a bool for an int",
            values(&[("idle_timeout_s", ParamValue::Bool(true))]),
        ),
    ];
    for (what, params) in cases {
        let r = build_spec(&t, &params, true);
        assert!(r.is_err(), "{what} was accepted: {r:?}");
    }
}

#[test]
fn the_error_names_the_parameter_and_never_echoes_the_value() {
    let t = shipped("private-chat");
    let payload = "x; rm -rf / $(id) `id`";
    let err = build_spec(&t, &values(&[("model", text(payload))]), true).expect_err("refused");
    let shown = err.to_string();
    assert!(shown.contains("model"), "{shown}");
    assert!(!shown.contains(payload), "{shown}");
    assert!(
        !format!("{err:?}").contains(payload),
        "Debug must not echo the value either"
    );
}

// ---- transcribe --------------------------------------------------------------------------------------------------

#[test]
fn transcribe_needs_its_audio_and_puts_it_at_the_fixed_path() {
    let t = shipped("transcribe");
    let missing = build_spec(&t, &BTreeMap::new(), true);
    assert!(matches!(missing, Err(ParamError::Missing { .. })), "{missing:?}");

    let spec = build_spec(&t, &values(&[("audio", text(&blob('a')))]), true).expect("builds");
    assert_valid_launch(&spec);
    assert_eq!(spec.inputs.len(), 1);
    let BlobInput { path, blob: b } = &spec.inputs[0];
    assert_eq!(path, "/inputs/audio");
    assert_eq!(b.to_string(), blob('a'));
    assert_eq!(spec.env.get("LANGUAGE").map(String::as_str), Some("auto"));
    assert_eq!(spec.env.get("MODEL").map(String::as_str), Some("small"));
    assert_eq!(
        spec.template.as_ref().map(|r| r.pull.clone()),
        Some(None),
        "no pull parameter: pull is null"
    );
}

#[test]
fn transcribe_language_and_model_are_whole_env_values() {
    let t = shipped("transcribe");
    let audio = text(&blob('b'));
    let spec = build_spec(
        &t,
        &values(&[
            ("audio", audio.clone()),
            ("language", text("es")),
            ("model", text("medium")),
        ]),
        true,
    )
    .expect("builds");
    assert_eq!(spec.env.get("LANGUAGE").map(String::as_str), Some("es"));
    assert_eq!(spec.env.get("MODEL").map(String::as_str), Some("medium"));
    let bad_model = build_spec(
        &t,
        &values(&[("audio", audio.clone()), ("model", text("large-v3"))]),
        true,
    );
    assert!(bad_model.is_err(), "a model outside base/small/medium is refused");
    let bad_language = build_spec(&t, &values(&[("audio", audio), ("language", text("en;id"))]), true);
    assert!(bad_language.is_err());
}

#[test]
fn a_blob_value_must_be_a_sha256_digest() {
    let t = shipped("transcribe");
    for bad in [
        "",
        "sha256:",
        "sha256:AAAA",
        &blob('a')[..70],
        "md5:aaaa",
        "../../etc/passwd",
        "sha256:zz",
        &format!("{} ", blob('a')),
    ] {
        let r = build_spec(&t, &values(&[("audio", text(bad))]), true);
        assert!(r.is_err(), "{bad:?} was accepted as a blob digest");
    }
    let upper = blob('A');
    assert!(
        build_spec(&t, &values(&[("audio", text(&upper))]), true).is_err(),
        "digests are lowercase hex"
    );
}

// ---- the other targets, on fixtures --------------------------------------------------------------------------------

#[test]
fn int_and_bool_values_render_as_plain_words_in_env_and_argv() {
    let text_with_extras = format!(
        "{}\n[[params]]\nname = \"flag\"\ntype = \"bool\"\ndefault = false\ntarget = \"argv:2\"\n",
        batch_toml()
    );
    let t = parse_ok(&text_with_extras);
    let spec = build_spec(
        &t,
        &values(&[
            ("audio", text(&blob('c'))),
            ("beam", ParamValue::Int(7)),
            ("flag", ParamValue::Bool(true)),
        ]),
        false,
    )
    .expect("builds");
    assert_eq!(spec.env.get("BEAM").map(String::as_str), Some("7"));
    assert_eq!(
        spec.command,
        ["/bin/sh", "/inputs/.template/run.sh", "true"],
        "the whole element is replaced"
    );
    let defaults = build_spec(&t, &values(&[("audio", text(&blob('c')))]), false).expect("builds");
    assert_eq!(defaults.env.get("BEAM").map(String::as_str), Some("5"));
    assert_eq!(defaults.command[2], "false");
}

#[test]
fn a_timeout_parameter_sets_timeout_s_and_the_service_default_stays_when_absent() {
    let t = parse_ok(&batch_toml());
    let spec = build_spec(
        &t,
        &values(&[("audio", text(&blob('d'))), ("limit", ParamValue::Int(600))]),
        false,
    )
    .expect("ok");
    assert_eq!(spec.timeout_s, 600);
    let spec = build_spec(&t, &values(&[("audio", text(&blob('d')))]), false).expect("ok");
    assert_eq!(spec.timeout_s, 3600);
    let service = parse_ok(&service_toml());
    let spec = build_spec(&service, &BTreeMap::new(), true).expect("ok");
    assert_eq!(spec.timeout_s, 86_400);
}

#[test]
fn a_parameter_is_never_interpolated_into_a_longer_string() {
    // The fixture's argv element 2 is "fixed"; a parameter replaces it whole. A value can never end up inside
    // another element, so a value with a space or a quote is one element (and an enum refuses it anyway).
    let text_with_target = format!(
        "{}\n[[params]]\nname = \"word\"\ntype = \"enum\"\nvalues = [\"a\", \"b\"]\ndefault = \"a\"\ntarget = \"argv:2\"\n",
        batch_toml().replace(
            "\"/inputs/.template/run.sh\", \"fixed\"",
            "\"/inputs/.template/run.sh\", \"fixed\", \"tail\""
        )
    );
    let t = parse_ok(&text_with_target);
    let spec = build_spec(&t, &values(&[("audio", text(&blob('e'))), ("word", text("b"))]), false).expect("ok");
    assert_eq!(spec.command, ["/bin/sh", "/inputs/.template/run.sh", "b", "tail"]);
}

// ---- property: shell metacharacters ----------------------------------------------------------------------------------

/// Strings built from the characters a shell, a path or a JSON body would treat specially.
fn hostile() -> impl Strategy<Value = String> {
    prop_oneof![
        "[;|&$`'\"\\\\ \\n\\t(){}<>*?!#~%=,:@^a-z0-9./-]{0,48}",
        Just("auto; id".to_string()),
        Just("$(touch pwned)".to_string()),
        Just("`id`".to_string()),
        Just("../../etc/passwd".to_string()),
        Just("a\nB=c".to_string()),
        Just("--help".to_string()),
        Just("".to_string()),
        any::<String>(),
    ]
}

fn any_value() -> impl Strategy<Value = ParamValue> {
    prop_oneof![
        hostile().prop_map(ParamValue::Text),
        any::<i64>().prop_map(ParamValue::Int),
        any::<bool>().prop_map(ParamValue::Bool)
    ]
}

/// Everything of the spec that no parameter may touch is the same as in `base`.
fn assert_only_targets_changed(base: &JobSpec, got: &JobSpec) {
    assert_eq!(got.image, base.image);
    assert_eq!(
        got.command, base.command,
        "no parameter targets the command of a shipped template"
    );
    assert_eq!(
        got.env.keys().collect::<Vec<_>>(),
        base.env.keys().collect::<Vec<_>>(),
        "the set of env names is fixed"
    );
    assert_eq!(got.files, base.files);
    assert_eq!(got.egress, base.egress, "egress is fixed by the template");
    assert_eq!(got.volumes, base.volumes);
    assert_eq!(got.resources, base.resources);
    assert_eq!(got.placement, base.placement);
    assert_eq!(got.outputs, base.outputs);
    assert_eq!(got.retry, base.retry);
    assert_eq!(got.kind, base.kind);
    assert_eq!(got.name, base.name);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn chat_accepts_only_listed_models_and_in_bounds_idle_values(model in any_value(), idle in any_value()) {
        let t = shipped("private-chat");
        let base = build_spec(&t, &BTreeMap::new(), true).expect("defaults");
        let params = values(&[("model", model.clone()), ("idle_timeout_s", idle.clone())]);
        match build_spec(&t, &params, true) {
            Err(_) => {}
            Ok(spec) => {
                assert_only_targets_changed(&base, &spec);
                assert_valid_launch(&spec);
                let listed = match &t.info.params.iter().find(|p| p.name == "model").expect("model").ty {
                    p2pc_proto::api::ParamType::Enum { values } => values.clone(),
                    other => panic!("model is an enum, got {other:?}"),
                };
                let pull = spec.template.as_ref().and_then(|r| r.pull.clone()).expect("a chat template records its model");
                prop_assert!(listed.contains(&pull), "{pull:?} is not a listed model");
                prop_assert!(matches!(model, ParamValue::Text(ref m) if *m == pull));
                let secs = spec.service.as_ref().expect("service").idle_timeout_s.expect("finite");
                prop_assert!((900..=86_400).contains(&secs));
                prop_assert!(matches!(idle, ParamValue::Int(i) if i64::from(secs) == i));
            }
        }
    }

    #[test]
    fn transcribe_accepts_only_listed_words_and_a_real_digest(
        audio in any_value(), language in any_value(), model in any_value(),
    ) {
        let t = shipped("transcribe");
        let base = build_spec(&t, &values(&[("audio", text(&blob('f')))]), true).expect("defaults");
        let params = values(&[("audio", audio.clone()), ("language", language), ("model", model)]);
        if let Ok(spec) = build_spec(&t, &params, true) {
            // `inputs` and the two env values are the only things that moved.
            let mut expected = base.clone();
            expected.inputs = spec.inputs.clone();
            expected.env = spec.env.clone();
            prop_assert_eq!(&spec, &expected);
            assert_only_targets_changed(&base, &spec);
            assert_valid_launch(&spec);
            prop_assert_eq!(spec.inputs.len(), 1);
            prop_assert_eq!(spec.inputs[0].path.as_str(), "/inputs/audio");
            let word = |v: &str| v.bytes().all(|b| b.is_ascii_alphanumeric());
            prop_assert!(word(&spec.env["LANGUAGE"]) && word(&spec.env["MODEL"]), "env values are plain words: {:?}", spec.env);
            let ParamValue::Text(digest) = audio else { return Err(TestCaseError::fail("a non-text blob was accepted")) };
            prop_assert!(digest.starts_with("sha256:") && digest.len() == 71);
            prop_assert!(digest[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
    }

    #[test]
    fn unknown_parameter_names_are_always_refused(name in hostile(), value in any_value()) {
        let t = shipped("private-chat");
        prop_assume!(name != "model" && name != "idle_timeout_s");
        prop_assert!(build_spec(&t, &values(&[(name.as_str(), value)]), true).is_err());
    }
}
