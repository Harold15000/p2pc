// SPDX-License-Identifier: AGPL-3.0-only

//! What the API asks about the nodes, before there is a node registry.
//!
//! `POST /v1/estimate` (spec §7) reports how many enrolled nodes could run a job. The registry arrives with T05 (the
//! node gateway) and T06 (the scheduler). Until then the API depends only on this trait, and the server runs with
//! [`EmptyNodeDirectory`], which knows no node: every estimate says `matching_nodes: 0`. T05/T06 replace it by
//! setting [`crate::app::AppState::nodes`] to an implementation backed by the registry; no handler changes.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use p2pc_proto::api::JobSpec;
use p2pc_proto::ids::AccountId;

/// A boxed future, so that [`NodeDirectory`] can be used as `dyn`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How the account's nodes match a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeMatch {
    /// Enrolled nodes of the account that could ever run the job: right pool, labels, hardware, sandbox driver and
    /// offered capacity large enough, whether or not they are busy or online at the moment.
    pub matching_nodes: u32,
    /// Of those, the nodes online and not draining that have room for the job right now.
    pub free_nodes: u32,
}

/// The node registry, as far as the API needs it.
pub trait NodeDirectory: Send + Sync + fmt::Debug + 'static {
    /// How the nodes of `account_id` match `spec` (already validated and normalized).
    fn match_job<'a>(&'a self, account_id: AccountId, spec: &'a JobSpec) -> BoxFuture<'a, NodeMatch>;
}

/// The directory of a server with no node registry yet: it knows no node, so `matching_nodes` is always 0.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyNodeDirectory;

impl NodeDirectory for EmptyNodeDirectory {
    fn match_job<'a>(&'a self, _account_id: AccountId, _spec: &'a JobSpec) -> BoxFuture<'a, NodeMatch> {
        Box::pin(async { NodeMatch::default() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_empty_directory_matches_nothing() {
        let spec: JobSpec = serde_json::from_value(serde_json::json!({
            "image": "docker.io/library/python:3.12-slim",
            "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 512},
        }))
        .unwrap();
        let m = EmptyNodeDirectory.match_job(AccountId::generate(), &spec).await;
        assert_eq!(
            m,
            NodeMatch {
                matching_nodes: 0,
                free_nodes: 0
            }
        );
    }
}
