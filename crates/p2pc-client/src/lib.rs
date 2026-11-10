// SPDX-License-Identifier: Apache-2.0

//! A typed async client for the P2PC REST API (spec §7).
//!
//! Every request and response uses the types of [`p2pc_proto`]; nothing is redefined here. The `p2pc` CLI uses this
//! crate, and so will `p2pc mcp` and, later, a Rust SDK.
//!
//! - [`Client`]: one method per endpoint. Build it with [`Client::builder`].
//! - [`Error`]: an [`ApiError`] (problem+json), a [`NetworkError`], an [`UnexpectedResponse`] or a [`LocalError`]
//!   (a request that could not be built here, never retried).
//! - `tunnel` (feature `tunnel`): the `p2pc/http/1` transport to a server address `p2pc_srv_…` (spec §10), and the
//!   relay behind `p2pc proxy`.
//! - [`fetch_all`]: walks cursor pages.
//! - [`RetryPolicy`]: connection errors and `502`/`503`/`504` are retried up to 3 times for every `GET` and for
//!   `create_job`, which always sends an idempotency key (the same one on every attempt). Other `POST`s and every
//!   `DELETE` are sent once.
//!
//! # Secrets (SI-6)
//!
//! The API key is a [`p2pc_proto::auth::ApiKey`]: its `Debug` and `Display` print `p2pc_sk_<id>_***`. It reaches the
//! wire only in a sensitive `Authorization` header, and no error, `Debug` output or log line of this crate contains it.
//!
//! # Licence
//!
//! Apache-2.0. This crate must never depend on `p2pc-server` (AGPL-3.0), not even in tests: use
//! [`testing::MockServer`] (feature `test-util`).

#![warn(missing_docs)]

mod client;
mod error;
mod logs;
mod retry;
#[cfg(feature = "test-util")]
pub mod testing;
mod transfer;
#[cfg(feature = "tunnel")]
pub mod tunnel;
mod upload;

pub use client::{
    Client, ClientBuilder, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, DOWNLOAD_TIMEOUT, FOLLOW_TIMEOUT,
    IDEMPOTENCY_HEADER, JobListParams, ListParams, MAX_RESPONSE_BYTES, PORT_UPGRADE_PROTOCOL, PortStream,
    TemplateLaunch, UPLOAD_FLOOR_BYTES_PER_S, UPLOAD_MAX_TIMEOUT, UPLOAD_MIN_TIMEOUT, fetch_all,
    generate_idempotency_key, whole_seconds,
};
pub use error::{ApiError, BuildError, Error, LocalError, NetworkError, NetworkKind, UnexpectedResponse};
pub use logs::{FollowOptions, LogFollow};
pub use retry::{RetryPolicy, is_retryable_status};
pub use transfer::{DownloadError, KeyLimits, LogPage, MAX_LOG_LINE_BYTES, save_verified_output};
