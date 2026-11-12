// SPDX-License-Identifier: Apache-2.0

//! SI-H2-13 and the "rules every template MUST meet" of H2 §7.6, over the shipped bundle and over fixtures.
//!
//! Each fixture starts from a valid template (`common`) and breaks one rule, so a failure names the rule.

// Helpers and fixtures unwrap freely: a panic is the failure message of a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{assert_accepted, assert_refused, batch_toml, digest, problems, service_toml, shipped_dir};
use templates_bundle::check::{Mode, check_bundle};
use templates_bundle::source::load_dir;

// ---- the shipped bundle -------------------------------------------------------------------------------------

#[test]
fn the_shipped_templates_pass_every_rule() {
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let found = check_bundle(&loaded, Mode::Dev);
    assert!(found.is_empty(), "the shipped bundle breaks rules: {found:#?}");
    let ids: Vec<&str> = loaded.templates.iter().map(|t| t.info.id.as_str()).collect();
    assert_eq!(
        ids,
        ["private-chat", "transcribe"],
        "the beta ships exactly these two, sorted by id"
    );
}

#[test]
fn the_shipped_templates_pass_the_release_rules_with_the_verified_digests() {
    // The digests were taken from the registries and the images were run on a test node (Ollama 0.40.16 and the
    // whisper.cpp CPU image, `main`). A release build refuses a placeholder, so the shipped bundle must pass it.
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let image_of = |id: &str| {
        loaded
            .templates
            .iter()
            .find(|t| t.info.id == id)
            .unwrap_or_else(|| panic!("no template {id}"))
            .spec
            .image
            .clone()
    };
    assert_eq!(
        image_of("private-chat"),
        "docker.io/ollama/ollama@sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592"
    );
    assert_eq!(
        image_of("transcribe"),
        "ghcr.io/ggml-org/whisper.cpp@sha256:5a7c4d82e5101a4fbbb047139c11638854a6452d1f4363fe3dff64bb758add32"
    );
    let release = check_bundle(&loaded, Mode::Release);
    assert!(
        release.is_empty(),
        "the shipped bundle fails the release rules: {release:#?}"
    );
}

#[test]
fn the_shipped_transcribe_template_runs_on_the_cpu_image() {
    // The `main-cuda` image needs CUDA 13.0 (the node's driver gives 12.9, so it fell back to the CPU) and does not
    // start at all without a GPU (`libcuda.so.1` missing). The CPU image works everywhere and transcribed 30 minutes
    // of audio with `small` in 286 s on 4 threads, so the template asks for no GPU.
    use p2pc_proto::api::GpuRequirement;
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let t = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe");
    assert_eq!(t.info.requirements.gpu, GpuRequirement::None);
    assert_eq!(t.info.requirements.min_vram_mb, None);
    assert_eq!(t.spec.resources.gpu, 0);
    assert_eq!(
        t.spec.timeout_s, 3600,
        "30 minutes of `small` take about 5 minutes; `medium` about 3 times that"
    );
    assert_eq!(
        t.info.download_mb, 1600,
        "1.15 GB image plus the 466 MB `small` model, in MiB, rounded up"
    );
}

#[test]
fn the_shipped_transcribe_description_states_the_supported_audio_length() {
    // Measured on 4 CPU threads: 30 minutes of audio took 286 s with `small` and 912 s with `medium`. With the job's
    // 3600 s limit that is about 6 hours of audio with `small` and about 1 h 55 min with `medium`.
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let t = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe");
    let limit = u64::from(t.spec.timeout_s);
    let half_hour = 30 * 60;
    assert!(
        limit * half_hour / 286 >= 6 * 3600,
        "`small` handles at least 6 h in {limit} s"
    );
    assert!(
        limit * half_hour / 912 >= (60 + 55) * 60,
        "`medium` handles at least 1 h 55 min in {limit} s"
    );
    let d = &t.info.description;
    assert!(d.contains("about 6 hours"), "{d}");
    assert!(d.contains("about 1 h 55 min"), "{d}");
    assert!(d.chars().count() <= 1000, "the description fits its limit");
}

#[test]
fn the_shipped_chat_template_defaults_to_a_model_that_does_not_think() {
    // `qwen3:4b` answers with its reasoning even with `"think": false`; the `-instruct` variant (Apache-2.0, 2.4 GB)
    // does not. `gemma3:1b` is gone from the list: its licence is not Apache-2.0 or MIT.
    use p2pc_proto::api::{ParamType, ParamValue};
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let chat = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "private-chat")
        .expect("private-chat");
    let model = chat.info.params.iter().find(|p| p.name == "model").expect("model");
    let ParamType::Enum { values } = &model.ty else {
        panic!("model is an enum")
    };
    assert_eq!(values, &["qwen3:4b-instruct", "qwen3:1.7b"]);
    assert_eq!(model.default, Some(ParamValue::Text("qwen3:4b-instruct".to_string())));
    // §7.6 fixes the floor at the reference PC's 6,144 MiB: the default used 5,020 MiB of VRAM after one chat, and a
    // card with less would be offered the template with almost no headroom. The hub and the UI use this as the
    // eligibility floor, so it is pinned here.
    assert_eq!(chat.info.requirements.min_vram_mb, Some(6144));
    let licenses = chat.info.licenses.join("\n");
    assert!(!licenses.to_lowercase().contains("gemma"), "{licenses}");
    assert_eq!(
        chat.info.download_mb, 7200,
        "5.10 GB image plus the 2.4 GB model, in MiB, rounded up"
    );
}

#[test]
fn the_shipped_chat_template_keeps_only_the_blobs_in_its_volume() {
    // Ollama 0.40.16 writes a relative symlink into `models/manifests-v2/...`, and a volume that holds a link is refused
    // at the next mount (§11.3). With the volume mounted at `<OLLAMA_MODELS>/blobs` only the blobs live in it (regular
    // files and one directory), and the manifests are written to `OLLAMA_MODELS`, in the container. The hub's pull
    // per attempt restores the manifest in about a second. The mount stays under `/volumes/` (§7.1).
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let chat = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "private-chat")
        .expect("private-chat");
    assert_eq!(chat.spec.volumes.len(), 1);
    let volume = &chat.spec.volumes[0];
    assert_eq!(volume.name, "tpl:private-chat/models");
    assert_eq!(volume.mount, "/volumes/models/blobs");
    assert_eq!(volume.max_mb, 20480);
    assert_eq!(
        chat.spec.env.get("OLLAMA_MODELS").map(String::as_str),
        Some("/volumes/models")
    );
    // A guard: some Ollama versions remove blobs no manifest names, and the volume holds blobs only.
    assert_eq!(chat.spec.env.get("OLLAMA_NOPRUNE").map(String::as_str), Some("1"));
    // The models directory is the mount's parent, and the mount is a valid volume mount.
    assert_eq!(volume.mount.rsplit_once('/'), Some(("/volumes/models", "blobs")));
    assert!(p2pc_proto::validate::validate_volume_mount(&volume.mount).is_ok());
}

#[test]
fn the_shipped_chat_template_reaches_every_host_a_model_pull_uses() {
    // Measured on a test node through a logging CONNECT proxy: a pull reached these three hosts and no other.
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let chat = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "private-chat")
        .expect("private-chat");
    let mut allow = chat.spec.egress.allow.clone();
    allow.sort();
    assert_eq!(
        allow,
        [
            "dd20bb891979d25aebc8bec07b2b3bbc.r2.cloudflarestorage.com",
            "ollama.com",
            "registry.ollama.ai"
        ]
    );
}

#[test]
fn the_shipped_transcribe_template_reaches_hugging_face_and_its_cdn() {
    // `huggingface.co` redirects the model file to `us.aws.cdn.hf.co`; an entry matches its subdomains, so `hf.co`
    // covers every CDN host.
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let t = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe");
    let mut allow = t.spec.egress.allow.clone();
    allow.sort();
    assert_eq!(allow, ["hf.co", "huggingface.co"]);
    assert!(p2pc_proto::validate::domain_allowed(
        &t.spec.egress.allow,
        "us.aws.cdn.hf.co"
    ));
}

#[test]
fn the_shipped_chat_template_allows_only_chat_and_tags_and_no_wildcard() {
    let loaded = load_dir(&shipped_dir()).expect("templates/ loads");
    let chat = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "private-chat")
        .expect("private-chat");
    let mut routes: Vec<(u32, &str, &str)> = chat
        .allowed_routes
        .iter()
        .map(|r| (r.port, r.method.as_str(), r.path.as_str()))
        .collect();
    routes.sort_unstable();
    assert_eq!(routes, [(11434, "GET", "/api/tags"), (11434, "POST", "/api/chat")]);
    let transcribe = loaded
        .templates
        .iter()
        .find(|t| t.info.id == "transcribe")
        .expect("transcribe");
    assert!(transcribe.allowed_routes.is_empty(), "a batch template has no routes");
}

// ---- fixtures: valid ----------------------------------------------------------------------------------------

#[test]
fn the_fixtures_are_valid() {
    assert_accepted(&service_toml());
    assert_accepted(&batch_toml());
}

// ---- fixtures: the image -------------------------------------------------------------------------------------

#[test]
fn an_image_without_a_digest_is_refused() {
    let text = service_toml().replace(&format!("@sha256:{}", digest()), ":latest");
    assert_refused(&text, "pinned by @sha256: digest");
}

#[test]
fn a_tag_next_to_the_digest_is_still_pinned() {
    let text = service_toml().replace("fixture@sha256", "fixture:1.2@sha256");
    assert_accepted(&text);
}

#[test]
fn a_placeholder_digest_passes_in_dev_and_fails_in_release() {
    let text = service_toml().replace(&digest(), &"0".repeat(64));
    assert_accepted(&text);
    let release = problems(&text, Mode::Release);
    assert!(release.iter().any(|p| p.contains("placeholder digest")), "{release:#?}");
}

#[test]
fn an_image_from_a_registry_outside_the_default_list_is_refused() {
    let text = service_toml().replace("docker.io/example/fixture", "registry.example.com/example/fixture");
    assert_refused(&text, "image");
}

// ---- fixtures: targets ---------------------------------------------------------------------------------------

#[test]
fn a_field_target_outside_the_closed_list_is_refused() {
    for field in [
        "resources.cpu",
        "resources.memory_mb",
        "image",
        "egress.allow",
        "retry.max_attempts",
        "service.ports",
    ] {
        let text = service_toml().replace("field:service.idle_timeout_s", &format!("field:{field}"));
        assert_refused(&text, "source:");
    }
}

#[test]
fn bounds_outside_the_jobspec_range_are_refused() {
    // idle_timeout_s is 300-604,800; timeout_s of a service is 60-2,592,000; of a batch job 1-86,400.
    let low = service_toml().replace("min = 900", "min = 60");
    assert_refused(&low, "outside the JobSpec range");
    let high = service_toml().replace("max = 86400", "max = 700000");
    assert_refused(&high, "outside the JobSpec range");
    let batch = batch_toml().replace("max = 7200", "max = 90000");
    assert_refused(&batch, "outside the JobSpec range");
    let batch_low = batch_toml().replace("min = 600", "min = 0");
    assert_refused(&batch_low, "outside the JobSpec range");
}

#[test]
fn bounds_at_the_edges_of_the_jobspec_range_are_accepted() {
    let text = service_toml()
        .replace("min = 900", "min = 300")
        .replace("max = 86400", "max = 604800");
    assert_accepted(&text);
}

#[test]
fn a_default_outside_its_bounds_is_refused() {
    let text = service_toml().replace("default = 3600\ntarget = \"field", "default = 100\ntarget = \"field");
    assert_refused(&text, "default");
}

#[test]
fn an_idle_timeout_target_on_a_batch_template_is_refused() {
    let text = batch_toml().replace("field:timeout_s", "field:service.idle_timeout_s");
    assert_refused(&text, "does not exist for a batch");
}

#[test]
fn a_field_target_on_a_non_int_parameter_is_refused() {
    let text = service_toml().replace("target = \"pull\"", "target = \"field:timeout_s\"");
    assert_refused(&text, "only for an int");
}

#[test]
fn a_pull_target_is_for_an_enum_of_a_chat_template_only() {
    let int_pull = service_toml().replace("target = \"field:service.idle_timeout_s\"", "target = \"pull\"");
    assert_refused(&int_pull, "enum");
    let not_chat = service_toml().replace("ui = \"chat\"", "ui = \"none\"");
    assert_refused(&not_chat, "ui = \"chat\"");
    let two = format!(
        "{}\n[[params]]\nname = \"model2\"\ntype = \"enum\"\nvalues = [\"a\"]\ndefault = \"a\"\ntarget = \"pull\"\n",
        service_toml()
    );
    assert_refused(&two, "more than one");
}

#[test]
fn an_input_target_is_for_a_blob_parameter_only() {
    let text = batch_toml().replace("target = \"env:LANGUAGE\"", "target = \"input:/inputs/lang\"");
    assert_refused(&text, "only for a blob");
}

#[test]
fn a_blob_parameter_has_no_default_and_only_an_input_target() {
    // The TOML loader refuses the key outright...
    let with_default = batch_toml().replace("type = \"blob\"\n", "type = \"blob\"\ndefault = \"sha256:aa\"\n");
    assert_refused(&with_default, "source:");
    // ...and the rule holds for a template that was not read from TOML.
    let mut t = common::parse_ok(&batch_toml());
    t.info.params[0].default = Some(p2pc_proto::api::ParamValue::Text("sha256:aa".to_string()));
    let found: Vec<String> = templates_bundle::check::check_template(&t, Mode::Dev)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        found.iter().any(|p| p.contains("a blob parameter has no default")),
        "{found:#?}"
    );
    let env_target = batch_toml().replace("target = \"input:/inputs/audio\"", "target = \"env:AUDIO\"");
    assert_refused(&env_target, "blob");
}

#[test]
fn an_input_path_outside_inputs_is_refused() {
    for path in ["/etc/passwd", "/inputs/../etc/passwd", "inputs/audio", "/inputs"] {
        let text = batch_toml().replace("input:/inputs/audio", &format!("input:{path}"));
        assert_refused(&text, "source:");
    }
}

#[test]
fn an_env_target_must_name_an_env_the_template_fixes() {
    let text = batch_toml().replace("target = \"env:BEAM\"", "target = \"env:NOT_IN_SPEC\"");
    assert_refused(&text, "NOT_IN_SPEC");
}

#[test]
fn an_env_target_with_a_reserved_or_loader_name_is_refused() {
    let reserved = batch_toml()
        .replace("env:BEAM", "env:P2PC_SECRET")
        .replace("BEAM = \"5\"", "P2PC_SECRET = \"5\"");
    assert_refused(&reserved, "source:");
    let loader = batch_toml()
        .replace("env:BEAM", "env:LD_PRELOAD")
        .replace("BEAM = \"5\"", "LD_PRELOAD = \"5\"");
    assert_refused(&loader, "LD_PRELOAD");
}

#[test]
fn an_argv_target_must_be_inside_the_command_and_not_the_program() {
    // The fixture's command has three elements: 0 is the program, 2 is the fixed word.
    let text = format!(
        "{}\n[[params]]\nname = \"extra\"\ntype = \"enum\"\nvalues = [\"a\", \"b\"]\ndefault = \"a\"\ntarget = \"argv:2\"\n",
        batch_toml()
    );
    assert_accepted(&text);
    let outside = text.replace("argv:2", "argv:3");
    assert_refused(&outside, "argv:3");
    let program = text.replace("argv:2", "argv:0");
    assert_refused(&program, "program");
}

#[test]
fn an_argv_target_may_not_be_the_script_of_a_shell_dash_c() {
    let text = batch_toml().replace(
        "command = [\"/bin/sh\", \"/inputs/.template/run.sh\", \"fixed\"]",
        "command = [\"/bin/sh\", \"-c\", \"echo fixed\"]",
    );
    let with_target = format!(
        "{text}\n[[params]]\nname = \"extra\"\ntype = \"enum\"\nvalues = [\"a\", \"b\"]\ndefault = \"a\"\ntarget = \"argv:2\"\n"
    );
    assert_refused(&with_target, "inline code");
}

/// The batch fixture with `command` replaced and one enum parameter that targets `argv:<index>`.
fn with_command_and_argv_target(command: &[&str], index: usize) -> String {
    let list = command.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>().join(", ");
    let text = batch_toml().replace(
        "command = [\"/bin/sh\", \"/inputs/.template/run.sh\", \"fixed\"]",
        &format!("command = [{list}]"),
    );
    format!(
        "{text}\n[[params]]\nname = \"extra\"\ntype = \"enum\"\nvalues = [\"a\", \"b\"]\ndefault = \"a\"\ntarget = \"argv:{index}\"\n"
    )
}

#[test]
fn an_argv_target_may_not_be_inline_code_of_any_common_interpreter() {
    // (command, the argv index a parameter would replace). Each index is the code (or a slot after the flag).
    let refused: &[(&[&str], usize)] = &[
        (&["/bin/sh", "-c", "echo x"], 2),
        (&["/bin/bash", "-ec", "echo x"], 2),
        (&["/bin/dash", "-c", "echo x", "name"], 3),
        // Wrappers: `env` (with options, assignments and options that take a value) and `busybox`.
        (&["/usr/bin/env", "sh", "-c", "echo x"], 3),
        (&["/usr/bin/env", "-i", "FOO=1", "bash", "-c", "echo x"], 5),
        (&["/usr/bin/env", "-u", "FOO", "sh", "-c", "echo x"], 5),
        (&["/usr/bin/env", "-iu", "FOO", "sh", "-c", "echo x"], 5),
        (&["/usr/bin/env", "--unset=FOO", "sh", "-c", "echo x"], 4),
        (&["/usr/bin/env", "--", "sh", "-c", "echo x"], 4),
        (&["/bin/busybox", "sh", "-c", "echo x"], 3),
        (&["/usr/bin/env", "busybox", "sh", "-c", "echo x"], 4),
        (&["/usr/bin/env", "FOO=1", "/bin/busybox", "ash", "-c", "echo x"], 5),
        // `env -S` splits one string into a command line: nothing after it can be told apart from code.
        (&["/usr/bin/env", "-S", "sh -c", "x"], 3),
        (&["/usr/bin/env", "--split-string=sh -c", "x"], 2),
        // Other interpreters' inline-code flags.
        (&["/usr/bin/python3", "-c", "print(1)"], 2),
        (&["/usr/bin/python3.12", "-c", "print(1)"], 2),
        (&["/usr/bin/python", "-Ic", "print(1)"], 2),
        (&["/usr/bin/env", "python3", "-c", "print(1)"], 3),
        (&["/usr/bin/node", "-e", "1"], 2),
        (&["/usr/bin/node", "-p", "1"], 2),
        (&["/usr/bin/node", "--eval", "1"], 2),
        (&["/usr/bin/node", "--print", "1"], 2),
        (&["/usr/bin/nodejs", "-e", "1"], 2),
        (&["/usr/bin/perl", "-e", "1"], 2),
        (&["/usr/bin/perl", "-E", "say 1"], 2),
        (&["/usr/bin/perl", "-w", "-e", "1"], 3),
        (&["/usr/bin/ruby", "-e", "1"], 2),
    ];
    for (command, index) in refused {
        let found = problems(&with_command_and_argv_target(command, *index), Mode::Dev);
        assert!(
            found.iter().any(|p| p.contains("inline code")),
            "{command:?} argv:{index} was not refused as inline code: {found:#?}"
        );
    }
}

#[test]
fn an_argv_target_that_is_a_script_argument_is_fine() {
    // The same interpreters running a script file: a parameter there is data for the script, not code.
    let accepted: &[(&[&str], usize)] = &[
        (&["/bin/sh", "/inputs/.template/run.sh", "fixed"], 2),
        (&["/usr/bin/python3", "/inputs/.template/run.py", "fixed"], 2),
        (&["/usr/bin/python3", "-u", "/inputs/.template/run.py", "fixed"], 3),
        (
            &["/usr/bin/env", "FOO=1", "python3", "/inputs/.template/run.py", "fixed"],
            4,
        ),
        (&["/usr/bin/node", "/inputs/.template/run.js", "fixed"], 2),
        (&["/usr/bin/perl", "/inputs/.template/run.pl", "fixed"], 2),
        (&["/usr/bin/ruby", "/inputs/.template/run.rb", "fixed"], 2),
        (&["/bin/busybox", "sh", "/inputs/.template/run.sh", "fixed"], 3),
        (&["/usr/bin/env", "-u", "FOO", "/bin/cat", "/inputs/audio", "fixed"], 5),
    ];
    for (command, index) in accepted {
        let found = problems(&with_command_and_argv_target(command, *index), Mode::Dev);
        assert!(
            !found.iter().any(|p| p.contains("inline code")),
            "{command:?} argv:{index} was refused: {found:#?}"
        );
    }
}

#[test]
fn enum_values_that_reach_env_or_argv_are_plain_words() {
    for bad in [
        "a;b", "$(id)", "a b", "`x`", "a|b", "a&b", "a\\nb", "a\"b", "a'b", "-rf", "a>b", "a\u{0}b",
    ] {
        let text = batch_toml().replace(
            "values = [\"auto\", \"en\", \"es\"]",
            &format!("values = [\"auto\", {bad:?}]"),
        );
        let found = problems(&text, Mode::Dev);
        assert!(!found.is_empty(), "{bad:?} was accepted as an env enum value");
    }
}

#[test]
fn an_enum_needs_values_a_listed_default_and_no_duplicates() {
    let no_values = batch_toml().replace("values = [\"auto\", \"en\", \"es\"]", "values = []");
    assert_refused(&no_values, "values");
    let unlisted = batch_toml().replace("default = \"auto\"", "default = \"fr\"");
    assert_refused(&unlisted, "default");
    let dup = batch_toml().replace(
        "values = [\"auto\", \"en\", \"es\"]",
        "values = [\"auto\", \"en\", \"en\"]",
    );
    assert_refused(&dup, "duplicate");
}

#[test]
fn a_pull_enum_value_is_a_model_name_and_nothing_else() {
    for bad in [
        "../x",
        "a b",
        "a;b",
        "http://evil.example/m",
        "a//b",
        "-x",
        "a/b/c",
        ".hidden",
    ] {
        let text = service_toml().replace(
            "values = [\"small:1b\", \"big:4b\"]",
            &format!("values = [\"small:1b\", {bad:?}]"),
        );
        let found = problems(&text, Mode::Dev);
        assert!(!found.is_empty(), "{bad:?} was accepted as a model name");
    }
}

#[test]
fn parameter_names_and_targets_are_unique() {
    let dup_name = batch_toml().replace("name = \"beam\"", "name = \"language\"");
    assert_refused(&dup_name, "duplicate parameter name");
    let dup_target = batch_toml().replace("target = \"env:BEAM\"", "target = \"env:LANGUAGE\"");
    assert_refused(&dup_target, "same target");
}

#[test]
fn a_bool_parameter_goes_to_env_or_argv_only() {
    let text = format!(
        "{}\n[[params]]\nname = \"flag\"\ntype = \"bool\"\ndefault = false\ntarget = \"env:FLAG\"\n",
        batch_toml().replace("BEAM = \"5\"", "BEAM = \"5\"\nFLAG = \"false\"")
    );
    assert_accepted(&text);
    let to_field = text.replace("env:FLAG", "field:timeout_s");
    assert_refused(&to_field, "bool");
}

// ---- fixtures: egress, volumes, timeout, resources ------------------------------------------------------------

#[test]
fn egress_is_a_fixed_list_that_must_be_valid() {
    let wildcard = service_toml().replace("registry.example.com", "*.example.com");
    assert_refused(&wildcard, "egress");
    let ip = service_toml().replace("registry.example.com", "192.0.2.1");
    assert_refused(&ip, "egress");
}

#[test]
fn volumes_use_the_templates_own_namespace() {
    let plain = service_toml().replace("tpl:fixture-chat/models", "models");
    assert_refused(&plain, "tpl:fixture-chat/");
    let other = service_toml().replace("tpl:fixture-chat/models", "tpl:other/models");
    assert_refused(&other, "tpl:fixture-chat/");
}

#[test]
fn a_service_must_set_a_finite_timeout_explicitly() {
    let missing = service_toml().replace("timeout_s = 86400\n", "");
    assert_refused(&missing, "timeout_s");
}

#[test]
fn the_gpu_in_the_spec_agrees_with_the_requirement() {
    let none_with_gpu = batch_toml().replace("gpu = 0\ndisk_mb", "gpu = 1\ndisk_mb");
    assert_refused(&none_with_gpu, "resources.gpu");
    let required_without = service_toml()
        .replace("gpu = \"preferred\"", "gpu = \"required\"")
        .replace("gpu = 1\ndisk_mb", "gpu = 0\ndisk_mb");
    assert_refused(&required_without, "resources.gpu");
}

#[test]
fn the_template_spec_carries_no_template_inputs_or_idempotency_key() {
    let text = batch_toml().replace(
        "[[spec.files]]",
        "[[spec.inputs]]\npath = \"/inputs/x\"\nblob = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\n[[spec.files]]",
    );
    assert_refused(&text, "spec.inputs");
    let key = batch_toml().replace(
        "timeout_s = 3600\n\n[spec.env]",
        "timeout_s = 3600\nidempotency_key = \"k\"\n\n[spec.env]",
    );
    assert_refused(&key, "idempotency_key");
}

#[test]
fn an_invalid_jobspec_is_refused_by_the_normal_validation() {
    let text = batch_toml().replace("cpu = 2", "cpu = 0.01");
    assert_refused(&text, "resources.cpu");
}

// ---- fixtures: kind, ui, singleton ----------------------------------------------------------------------------

#[test]
fn kind_and_ui_must_agree_with_the_spec() {
    let kind = service_toml().replace("kind = \"service\"\nui", "kind = \"batch\"\nui");
    assert_refused(&kind, "kind");
    let chat_batch = batch_toml().replace("ui = \"transcribe\"", "ui = \"chat\"");
    assert_refused(&chat_batch, "ui = \"chat\"");
    let transcribe_service = service_toml().replace("ui = \"chat\"", "ui = \"transcribe\"");
    assert_refused(&transcribe_service, "ui = \"transcribe\"");
    let singleton_batch = batch_toml().replace("ui = \"transcribe\"", "ui = \"transcribe\"\nsingleton = true");
    assert_refused(&singleton_batch, "singleton");
}

#[test]
fn unknown_keys_are_refused_rather_than_ignored() {
    let top = service_toml().replace("singleton = true", "singleton = true\nallowed_route = []");
    assert_refused(&top, "source:");
    let param = service_toml().replace("name = \"model\"", "name = \"model\"\nlable = \"x\"");
    assert_refused(&param, "source:");
    let route = service_toml().replace("path = \"/api/tags\"", "path = \"/api/tags\"\nmethods = [\"GET\"]");
    assert_refused(&route, "source:");
    let requirements = service_toml().replace("min_vram_mb = 1024", "min_vram_mb = 1024\nvram = 1");
    assert_refused(&requirements, "source:");
    let spec = service_toml().replace("timeout_s = 86400\n", "timeout_s = 86400\ntimeout = 1\n");
    assert_refused(&spec, "source:");
}

#[test]
fn a_template_id_must_be_a_valid_id() {
    for id in ["Bad", "has.dot", "has/slash", "", "9lives", "has space"] {
        let text = service_toml().replace("id = \"fixture-chat\"", &format!("id = {id:?}"));
        let found = problems(&text, Mode::Dev);
        assert!(!found.is_empty(), "id {id:?} was accepted");
    }
}

#[test]
fn licenses_and_download_estimate_are_required() {
    let no_licenses = service_toml().replace(
        "licenses = [\"Fixture server: MIT\", \"Fixture model: Apache-2.0\"]",
        "licenses = []",
    );
    assert_refused(&no_licenses, "licenses");
    let no_download = service_toml().replace("download_mb = 100", "download_mb = 0");
    assert_refused(&no_download, "download_mb");
}

// ---- fixtures: allowed_routes ----------------------------------------------------------------------------------

fn with_route(method: &str, path: &str, port: u32) -> String {
    format!(
        "{}\n[[allowed_routes]]\nport = {port}\nmethod = {method:?}\npath = {path:?}\n",
        service_toml()
    )
}

#[test]
fn a_good_extra_route_is_accepted() {
    assert_accepted(&with_route("GET", "/api/version", 8080));
}

#[test]
fn a_route_names_a_port_of_the_service() {
    assert_refused(&with_route("GET", "/api/version", 9999), "service.ports");
}

#[test]
fn a_route_is_one_get_or_post_with_an_exact_absolute_path() {
    for method in ["DELETE", "PUT", "PATCH", "CONNECT", "get", "GET, POST", "HEAD", ""] {
        let found = problems(&with_route(method, "/api/version", 8080), Mode::Dev);
        assert!(!found.is_empty(), "method {method:?} was accepted");
    }
    for path in [
        "api/version",
        "/api/version?x=1",
        "/api/version#f",
        "/api/%70ull",
        "/api/../etc",
        "/api/./x",
        "//api/version",
        "/api//version",
        "/api/version ",
        "/api/ver\u{0}sion",
        "",
    ] {
        let found = problems(&with_route("GET", path, 8080), Mode::Dev);
        assert!(!found.is_empty(), "path {path:?} was accepted");
    }
}

#[test]
fn a_route_may_never_reach_a_model_write() {
    for path in [
        "/api/pull",
        "/api/create",
        "/api/copy",
        "/api/push",
        "/api/delete",
        "/api/blobs/sha256-aa",
        "/api/blobs/*",
        "/api/PULL",
        "/api/*",
        "/*",
    ] {
        for method in ["GET", "POST"] {
            let found = problems(&with_route(method, path, 8080), Mode::Dev);
            assert!(!found.is_empty(), "{method} {path} was accepted");
        }
    }
}

#[test]
fn a_wildcard_is_refused_unless_the_template_is_on_the_reviewed_list() {
    // The reviewed list is empty in the beta (§7.4: "the beta templates do not"), so every wildcard is refused.
    assert_refused(&with_route("GET", "/files/*", 8080), "wildcard");
    assert_refused(&with_route("GET", "/files/a*", 8080), "wildcard");
    assert_refused(&with_route("GET", "/*/files", 8080), "wildcard");
}

#[test]
fn a_batch_template_has_no_routes_and_routes_are_unique() {
    let batch = format!(
        "{}\n[[allowed_routes]]\nport = 8080\nmethod = \"GET\"\npath = \"/x\"\n",
        batch_toml()
    );
    assert_refused(&batch, "no service");
    let dup = with_route("POST", "/api/chat", 8080);
    assert_refused(&dup, "duplicate route");
}

#[test]
fn a_service_without_routes_is_valid_and_closed() {
    let text = service_toml().replace(
        "[[allowed_routes]]\nport = 8080\nmethod = \"POST\"\npath = \"/api/chat\"\n\n[[allowed_routes]]\nport = 8080\nmethod = \"GET\"\npath = \"/api/tags\"\n",
        "",
    );
    assert!(!text.contains("allowed_routes"));
    assert_accepted(&text);
}

// ---- the whole bundle ------------------------------------------------------------------------------------------

#[test]
fn a_bundle_refuses_duplicate_ids_and_a_bad_version() {
    use templates_bundle::bundle::Bundle;
    let a = common::parse_ok(&service_toml());
    let b = common::parse_ok(&service_toml());
    let bundle = Bundle::new(1, "0.1.0", vec![a, b]);
    let found = check_bundle(&bundle, Mode::Dev);
    assert!(
        found.iter().any(|p| p.to_string().contains("duplicate template id")),
        "{found:#?}"
    );

    let bundle = Bundle::new(0, "0.1.0", vec![common::parse_ok(&service_toml())]);
    assert!(
        check_bundle(&bundle, Mode::Dev)
            .iter()
            .any(|p| p.to_string().contains("bundle_version"))
    );

    let bundle = Bundle::new(1, "not-semver", vec![common::parse_ok(&service_toml())]);
    assert!(
        check_bundle(&bundle, Mode::Dev)
            .iter()
            .any(|p| p.to_string().contains("min_hub_version"))
    );
}

#[test]
fn loading_a_directory_wants_the_file_name_to_be_the_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("bundle.toml"),
        "bundle_version = 1\nmin_hub_version = \"0.1.0\"\n",
    )
    .expect("write");
    std::fs::write(dir.path().join("other-name.toml"), service_toml()).expect("write");
    let err = load_dir(dir.path()).expect_err("a mismatched file name is refused");
    assert!(err.to_string().contains("fixture-chat"), "{err}");
}
