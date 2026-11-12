// SPDX-License-Identifier: Apache-2.0

//! Checks, compiles and signs the template bundle (H2 spec §7.6, §14.1; SI-H2-13).
//!
//! A template is data: `templates/<id>.toml`, reviewed like code. This crate turns the directory into the signed
//! bundle the hub embeds and loads:
//!
//! - [`source`] reads `bundle.toml` and `templates/*.toml` into [`p2pc_proto::api::Template`]s (the wire type the hub
//!   serves), inlining the files a template ships (`from = "…"` becomes `content_b64`);
//! - [`check`] enforces "the rules every template MUST meet" (pinned image digest, parameter targets, `tpl:` volumes,
//!   `allowed_routes`, a finite `timeout_s`, the normal JobSpec validation) over every value a parameter can take;
//! - [`params`] builds the JobSpec of a launch from a template and its parameter values. The checks use it, and so
//!   do the tests that feed shell metacharacters as values. It is the reference for the hub's launch (T2-15);
//! - [`bundle`] compiles the directory into canonical `templates.json` bytes;
//! - [`sign`] signs those bytes with the release key and verifies them (minisign, spec §5.1).
//!
//! The release key is never in the repository: the CLI reads it from a file the release manager provides, and the
//! tests make a throwaway key at test time.

pub mod bundle;
pub mod check;
pub mod params;
pub mod sign;
pub mod source;
