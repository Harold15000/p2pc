// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc-server`: the P2PC control plane.
//!
//! This crate is the library behind the `p2pc-server` binary, so that the HTTP API can be tested in process.
//!
//! - [`config`]: `server.toml` and its validation;
//! - [`datadir`]: data dir resolution (spec §12);
//! - [`store`]: SQLite storage and the repository functions (§12, SI-7);
//! - [`identity`]: the server's iroh key (§5);
//! - [`gateway`]: the node gateway: the iroh endpoint, `p2pc/agent/1` and `p2pc/http/1` (§6, §10);
//! - [`auth`]: API key authentication and scopes (§5);
//! - [`error`] and [`extract`]: RFC 9457 problem responses (§7);
//! - [`app`]: the axum router and handlers; [`nodes_api`]: join tokens, nodes and `GET /v1/server`;
//! - [`jobs_api`]: the jobs endpoints (§7), with [`units`] (§11) and [`node_directory`];
//! - [`scheduler`]: placement, leases and fencing, liveness and the watchdog (§6, §8), and [`usage_api`] (§11);
//! - [`logs`] (with [`fsutil`]): stored job logs (§7, §12);
//! - [`openapi`]: the generated OpenAPI 3.1 document;
//! - [`init`] and [`serve`]: the two subcommands.

pub mod app;
pub mod artifacts_api;
pub mod audit_queue;
pub mod auth;
pub mod clock;
pub mod config;
mod conn;
pub mod datadir;
pub mod error;
pub mod extract;
pub mod fsutil;
pub mod gateway;
pub mod gc;
pub mod identity;
pub mod init;
pub mod jobs_api;
pub mod logging;
pub mod logs;
pub mod node_directory;
pub mod nodes_api;
pub mod openapi;
pub mod outputs;
pub mod recover;
pub mod scheduler;
pub mod serve;
pub mod spec_hash;
pub mod store;
pub mod units;
pub mod usage_api;
