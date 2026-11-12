// SPDX-License-Identifier: Apache-2.0

//! Reading `templates/` (spec §7.6): `bundle.toml`, one `<id>.toml` per template, and the files a template ships.
//!
//! The TOML maps onto [`p2pc_proto::api::Template`] directly, so the file says what the hub will serve. Three things
//! are done here, before the rules of [`crate::check`] run:
//!
//! - unknown keys are refused (the wire types ignore them, which would hide a typo such as `allowed_route`);
//! - `spec.timeout_s` must be written down (the wire default for a service is 30 days, and "a finite `timeout_s`" is a
//!   rule of the template, not a default it can fall back on);
//! - `[[spec.files]]` entries may say `from = "<file>"` instead of `content_b64`: the compiler reads that file from
//!   the templates directory and writes its base64, so the reviewed script is the one in the bundle.

use std::fs;
use std::path::{Component, Path};

use data_encoding::BASE64;
use p2pc_proto::api::Template;
use serde::Deserialize;

use crate::bundle::Bundle;

/// Largest inline file a template may ship, in bytes (the JobSpec allows 512 KiB of files in all).
pub const MAX_INLINE_FILE_BYTES: u64 = 64 * 1024;
/// Largest template source file, in bytes.
const MAX_TEMPLATE_FILE_BYTES: u64 = 256 * 1024;
/// The file with the bundle's own fields.
pub const BUNDLE_FILE: &str = "bundle.toml";

/// A template directory or file that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SourceError(String);

impl SourceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

const TOP_KEYS: &[&str] = &[
    "id",
    "version",
    "title",
    "description",
    "kind",
    "ui",
    "singleton",
    "requirements",
    "params",
    "spec",
    "licenses",
    "download_mb",
    "allowed_routes",
];
const REQUIREMENT_KEYS: &[&str] = &["gpu", "min_vram_mb"];
const ROUTE_KEYS: &[&str] = &["port", "method", "path"];
const ENUM_KEYS: &[&str] = &["name", "label", "type", "values", "default", "target"];
const INT_KEYS: &[&str] = &["name", "label", "type", "min", "max", "default", "target"];
const BOOL_KEYS: &[&str] = &["name", "label", "type", "default", "target"];
const BLOB_KEYS: &[&str] = &["name", "label", "type", "target"];

fn only_keys(table: &toml::Table, allowed: &[&str], what: &str) -> Result<(), SourceError> {
    match table.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(key) => Err(SourceError::new(format!(
            "unknown key `{}` in {what} (allowed: {})",
            key.escape_debug(),
            allowed.join(", ")
        ))),
        None => Ok(()),
    }
}

fn table_of<'a>(value: &'a toml::Value, what: &str) -> Result<&'a toml::Table, SourceError> {
    value
        .as_table()
        .ok_or_else(|| SourceError::new(format!("{what} must be a table")))
}

/// Parses one template. `base_dir` is where `from = "…"` files are read from.
pub fn parse_template(text: &str, base_dir: &Path) -> Result<Template, SourceError> {
    let mut table: toml::Table = text
        .parse()
        .map_err(|e| SourceError::new(format!("invalid TOML: {e}")))?;
    only_keys(&table, TOP_KEYS, "the template")?;
    if let Some(requirements) = table.get("requirements") {
        only_keys(
            table_of(requirements, "requirements")?,
            REQUIREMENT_KEYS,
            "requirements",
        )?;
    }
    for (i, param) in table
        .get("params")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let what = format!("params[{i}]");
        let param = table_of(param, &what)?;
        let allowed = match param.get("type").and_then(toml::Value::as_str) {
            Some("enum") => ENUM_KEYS,
            Some("int") => INT_KEYS,
            Some("bool") => BOOL_KEYS,
            Some("blob") => BLOB_KEYS,
            _ => {
                return Err(SourceError::new(format!(
                    "{what}: `type` must be enum, int, bool or blob"
                )));
            }
        };
        only_keys(param, allowed, &what)?;
    }
    for (i, route) in table
        .get("allowed_routes")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        only_keys(
            table_of(route, &format!("allowed_routes[{i}]"))?,
            ROUTE_KEYS,
            &format!("allowed_routes[{i}]"),
        )?;
    }

    let spec = table
        .get_mut("spec")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| SourceError::new("the template needs a [spec] table"))?;
    if !spec.contains_key("timeout_s") {
        return Err(SourceError::new(
            "spec.timeout_s must be written down: every template has a finite wall-clock limit of its own",
        ));
    }
    inline_files(spec, base_dir)?;

    Template::deserialize(toml::Value::Table(table)).map_err(|e| SourceError::new(format!("invalid template: {e}")))
}

/// Replaces each `[[spec.files]]` `from = "<file>"` with that file's `content_b64`.
fn inline_files(spec: &mut toml::Table, base_dir: &Path) -> Result<(), SourceError> {
    let Some(files) = spec.get_mut("files") else {
        return Ok(());
    };
    let files = files
        .as_array_mut()
        .ok_or_else(|| SourceError::new("spec.files must be an array of tables"))?;
    for (i, entry) in files.iter_mut().enumerate() {
        let entry = entry
            .as_table_mut()
            .ok_or_else(|| SourceError::new(format!("spec.files[{i}] must be a table")))?;
        let Some(from) = entry.remove("from") else { continue };
        if entry.contains_key("content_b64") {
            return Err(SourceError::new(format!(
                "spec.files[{i}] has both `from` and `content_b64`"
            )));
        }
        let from = from
            .as_str()
            .ok_or_else(|| SourceError::new(format!("spec.files[{i}].from must be a string")))?;
        let bytes =
            read_inline_file(base_dir, from).map_err(|e| SourceError::new(format!("spec.files[{i}].from: {e}")))?;
        entry.insert("content_b64".to_string(), toml::Value::String(BASE64.encode(&bytes)));
    }
    Ok(())
}

/// Reads a file that lives inside the templates directory: relative, no `..`, no symlink anywhere on the way, a
/// regular file of at most [`MAX_INLINE_FILE_BYTES`].
fn read_inline_file(base_dir: &Path, from: &str) -> Result<Vec<u8>, String> {
    let rel = Path::new(from);
    if from.is_empty() || rel.is_absolute() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err("must be a relative path inside the templates directory, with no `..`".to_string());
    }
    let mut current = base_dir.to_path_buf();
    for part in rel.components() {
        current.push(part);
        let meta = fs::symlink_metadata(&current).map_err(|e| format!("cannot read `{from}`: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!("`{from}` goes through a symlink"));
        }
    }
    let meta = fs::symlink_metadata(&current).map_err(|e| format!("cannot read `{from}`: {e}"))?;
    if !meta.is_file() {
        return Err(format!("`{from}` is not a regular file"));
    }
    if meta.len() > MAX_INLINE_FILE_BYTES {
        return Err(format!("`{from}` is over {MAX_INLINE_FILE_BYTES} bytes"));
    }
    fs::read(&current).map_err(|e| format!("cannot read `{from}`: {e}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    bundle_version: u64,
    min_hub_version: String,
}

/// Reads `dir/bundle.toml` and every `dir/<id>.toml`, sorted by id. Subdirectories (the files templates ship) and
/// other files are not templates and are ignored here; a template reaches them only through `from = "…"`.
pub fn load_dir(dir: &Path) -> Result<Bundle, SourceError> {
    let header_path = dir.join(BUNDLE_FILE);
    let header_text = read_regular(&header_path)?;
    let header: BundleFile =
        toml::from_str(&header_text).map_err(|e| SourceError::new(format!("{BUNDLE_FILE}: {e}")))?;

    let mut names: Vec<String> = Vec::new();
    let entries = fs::read_dir(dir).map_err(|e| SourceError::new(format!("cannot read {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| SourceError::new(format!("cannot read {}: {e}", dir.display())))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != BUNDLE_FILE && name.ends_with(".toml") {
            names.push(name);
        }
    }
    names.sort();

    let mut templates = Vec::with_capacity(names.len());
    for name in names {
        let text = read_regular(&dir.join(&name))?;
        let template = parse_template(&text, dir).map_err(|e| SourceError::new(format!("{name}: {e}")))?;
        let stem = name.strip_suffix(".toml").unwrap_or(&name);
        if template.info.id != stem {
            return Err(SourceError::new(format!(
                "{name}: the file must be named after the template id (`{}.toml`)",
                template.info.id.escape_debug()
            )));
        }
        templates.push(template);
    }
    templates.sort_by(|a, b| a.info.id.cmp(&b.info.id));
    Ok(Bundle::new(header.bundle_version, &header.min_hub_version, templates))
}

/// Reads a regular, non-symlink file of a bounded size as UTF-8.
fn read_regular(path: &Path) -> Result<String, SourceError> {
    let shown = path
        .file_name()
        .map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
    let meta = fs::symlink_metadata(path).map_err(|e| SourceError::new(format!("cannot read {shown}: {e}")))?;
    if !meta.is_file() {
        return Err(SourceError::new(format!("{shown} is not a regular file")));
    }
    if meta.len() > MAX_TEMPLATE_FILE_BYTES {
        return Err(SourceError::new(format!(
            "{shown} is over {MAX_TEMPLATE_FILE_BYTES} bytes"
        )));
    }
    fs::read_to_string(path).map_err(|e| SourceError::new(format!("cannot read {shown}: {e}")))
}
