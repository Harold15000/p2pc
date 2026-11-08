// SPDX-License-Identifier: Apache-2.0

//! The `p2pc` command-line client.
//!
//! The binary is a thin wrapper around [`app::run`]; everything lives here so that it can be tested in process.
//!
//! - [`cli`]: the clap definitions. There is no `--key` flag anywhere.
//! - [`app`]: [`app::Host`] (everything the process touches), the error type and the dispatcher.
//! - [`commands`]: one module per command group.
//! - [`config`]: profiles, `credentials.toml` and the flag > environment > file precedence.
//! - [`mcp`]: the MCP server behind `p2pc mcp`.
//! - [`follow`]: how `p2pc run` and `p2pc logs --follow` follow a job: by its state, or by streaming its live log.
//! - [`outcome`]: the exit-code table of spec §7.
//! - [`parse`] and [`output`]: user input and human output.

#![warn(missing_docs)]

pub mod app;
pub mod cli;
pub mod commands;
pub mod config;
pub mod follow;
pub mod mcp;
pub mod outcome;
pub mod output;
pub mod parse;
