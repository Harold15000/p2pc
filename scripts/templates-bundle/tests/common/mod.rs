// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures: a valid service template and a valid batch template, as TOML text, plus helpers to bend them.
//!
//! The fixtures are small on purpose and use `example` names. A test that needs a broken template starts from one
//! of these and changes one thing, so a failure says exactly which rule fired.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use templates_bundle::check::{Mode, Problem, check_template};
use templates_bundle::source::parse_template;

/// A digest that is not the placeholder.
pub fn digest() -> String {
    "1".repeat(64)
}

/// The repository's `templates/` directory.
pub fn shipped_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates")
}

/// A valid service template (`ui = "chat"`), with one `pull` parameter and one `field:` parameter.
pub fn service_toml() -> String {
    format!(
        r#"
id = "fixture-chat"
version = 1
title = "Fixture chat"
description = "A fixture."
kind = "service"
ui = "chat"
singleton = true
licenses = ["Fixture server: MIT", "Fixture model: Apache-2.0"]
download_mb = 100

[requirements]
gpu = "preferred"
min_vram_mb = 1024

[[params]]
name = "model"
label = "Model"
type = "enum"
values = ["small:1b", "big:4b"]
default = "small:1b"
target = "pull"

[[params]]
name = "idle"
label = "Stop after idle seconds"
type = "int"
min = 900
max = 86400
default = 3600
target = "field:service.idle_timeout_s"

[spec]
kind = "service"
image = "docker.io/example/fixture@sha256:{digest}"
command = ["/bin/serve", "--listen", "127.0.0.1:8080"]
timeout_s = 86400

[spec.resources]
cpu = 2
memory_mb = 2048
gpu = 1
disk_mb = 1024

[spec.egress]
allow = ["registry.example.com"]

[spec.service]
idle_timeout_s = 3600
restart = "on_node_loss"

[[spec.service.ports]]
port = 8080
name = "api"

[spec.service.health]
http_get = "/health"
port = 8080

[[spec.volumes]]
name = "tpl:fixture-chat/models"
mount = "/volumes/models"
max_mb = 1024

[[allowed_routes]]
port = 8080
method = "POST"
path = "/api/chat"

[[allowed_routes]]
port = 8080
method = "GET"
path = "/api/tags"
"#,
        digest = digest()
    )
}

/// A valid batch template (`ui = "transcribe"`), with a blob, an enum and an int parameter.
pub fn batch_toml() -> String {
    format!(
        r#"
id = "fixture-batch"
version = 1
title = "Fixture batch"
description = "A fixture."
kind = "batch"
ui = "transcribe"
licenses = ["Fixture tool: MIT"]
download_mb = 50

[requirements]
gpu = "none"

[[params]]
name = "audio"
type = "blob"
target = "input:/inputs/audio"

[[params]]
name = "language"
type = "enum"
values = ["auto", "en", "es"]
default = "auto"
target = "env:LANGUAGE"

[[params]]
name = "beam"
type = "int"
min = 1
max = 8
default = 5
target = "env:BEAM"

[[params]]
name = "limit"
type = "int"
min = 600
max = 7200
default = 3600
target = "field:timeout_s"

[spec]
image = "ghcr.io/example/fixture@sha256:{digest}"
command = ["/bin/sh", "/inputs/.template/run.sh", "fixed"]
timeout_s = 3600

[spec.env]
LANGUAGE = "auto"
BEAM = "5"

[spec.resources]
cpu = 2
memory_mb = 2048
gpu = 0
disk_mb = 2048

[[spec.files]]
path = "/inputs/.template/run.sh"
content_b64 = "ZWNobyBoaQ=="

[[spec.volumes]]
name = "tpl:fixture-batch/models"
mount = "/volumes/models"
max_mb = 512
"#,
        digest = digest()
    )
}

/// Parses `text` as a template (no files to read) and returns it, panicking with the error if it does not parse.
pub fn parse_ok(text: &str) -> p2pc_proto::api::Template {
    parse_template(text, Path::new(".")).unwrap_or_else(|e| panic!("fixture should parse: {e}"))
}

/// The problems `text` has in `mode`: a parse error counts as one problem, so a test can say "this is refused"
/// without caring whether the source or the rules refused it.
pub fn problems(text: &str, mode: Mode) -> Vec<String> {
    match parse_template(text, Path::new(".")) {
        Err(e) => vec![format!("source: {e}")],
        Ok(t) => check_template(&t, mode).iter().map(Problem::to_string).collect(),
    }
}

/// Asserts that `text` is refused in `Mode::Dev` with a problem that mentions `needle`.
#[track_caller]
pub fn assert_refused(text: &str, needle: &str) {
    let found = problems(text, Mode::Dev);
    assert!(
        found.iter().any(|p| p.contains(needle)),
        "expected a problem mentioning {needle:?}, got {found:#?}"
    );
}

/// Asserts that `text` passes every rule in `Mode::Dev`.
#[track_caller]
pub fn assert_accepted(text: &str) {
    let found = problems(text, Mode::Dev);
    assert!(found.is_empty(), "expected no problems, got {found:#?}");
}
