// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc/pair/1` (H2 spec §5.2, §5.3, §10.5): one `Pair` with a one-time ticket per connection.
//!
//! Any NodeId can dial this ALPN, so everything here runs before authentication. It is bounded three ways.
//!
//! - **Served only while a pairing ticket is open** (§10.5, hard rule 4). [`refresh`] reads whether a ticket is
//!   unexpired and unrevoked and puts the ALPN in the endpoint's accepted list exactly then, so with no ticket open
//!   the TLS handshake fails before any message. It runs at start and at every gateway sweep. A consumed ticket
//!   stays open until its expiry, for the idempotent retry of §5.2. A connection that gets through the handshake
//!   in the moment between a ticket's expiry and the next sweep is closed here before a frame is read ([`is_open`],
//!   with the injected clock).
//! - **Limits that shed load** (§5.3), counted apart from every other ALPN: 32 connections and 8 pending `Pair`s at
//!   once, one `Pair` per connection within 10 s, a frame of at most 4 KiB. Beyond them a connection is closed with
//!   no detail. They bound the hub's work to 8 concurrent exchanges, each one hash and one transaction.
//! - **Failure counters that never lock the owner out** (§5.3). Failed pairings are counted per NodeId and per
//!   ticket-hash prefix. A NodeId over its own limit is refused when it connects (only its own failures count). A
//!   failing attempt in a prefix over its limit, or beyond the aggregate cap of the ALPN, is closed with no detail
//!   and is not logged one by one. No counter is read before the ticket is looked up: **a valid ticket that gets a
//!   slot pairs whatever the counters say**. Every failure is counted into one aggregated `auth_failed` audit row a
//!   minute (`subject_id` `pair`).
//!
//! The ticket's payload is not trusted (§5.2): the store looks the ticket up by the hash of its code, compares in
//! constant time and uses its own row's expiry, scopes and single-use flag ([`store::devices::pair`]). The ticket
//! and its code are never logged.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use iroh::endpoint::{Connection, SendStream, VarInt};
use p2pc_proto::api::{AuditKind, Principal};
use p2pc_proto::pair::{PAIR_MAX_FRAME_LEN, PairErrorCode, PairRequest, PairResponse, PairingTicket};
use p2pc_proto::protocol::{read_frame_bytes, write_frame};
use serde_json::json;
use time::OffsetDateTime;

use super::hub::CLOSE_BY_SERVER;
use super::{Inner, endpoint};
use crate::store::audit::NewEvent;
use crate::store::devices::{DeviceRow, PairOutcome};
use crate::store::{self, StoreError};

/// [`Inner::pair_open_until`] when no pairing ticket is open.
pub const CLOSED: i64 = i64::MIN;

/// Subject of the aggregated `auth_failed` audit rows of failed pairings (H2 §5.6).
pub const PAIR_FAILURE_SUBJECT: &str = "pair";

/// Closes with no detail.
fn close(conn: &Connection) {
    conn.close(VarInt::from_u32(CLOSE_BY_SERVER), b"");
}

/// Whether a pairing ticket is open at `now`, from the last [`refresh`]: no database read, so a connection costs
/// nothing before this check.
pub(super) fn is_open(inner: &Inner, now: OffsetDateTime) -> bool {
    store::ts(now) < inner.pair_open_until.load(Ordering::SeqCst)
}

/// The latest expiry (Unix seconds) among the pairing tickets that are open at `now`: unexpired and unrevoked,
/// consumed or not (H2 §10.5: a consumed ticket stays open until its expiry, for the idempotent retry of §5.2).
/// `None` when no ticket is open.
///
/// Protocol side, before there is a principal: it reads no ticket, only until when one is open.
async fn open_until(inner: &Inner, now: OffsetDateTime) -> Result<Option<i64>, StoreError> {
    let mut conn = inner.state.db.acquire().await?;
    let until: Option<i64> =
        sqlx::query_scalar("SELECT MAX(expires_at) FROM pairing_tickets WHERE revoked_at IS NULL AND expires_at > ?")
            .bind(store::ts(now))
            .fetch_one(&mut *conn)
            .await?;
    Ok(until)
}

/// Re-reads whether a pairing ticket is open and makes the endpoint accept `p2pc/pair/1` exactly then (H2 §10.5).
/// Returns whether one is open.
///
/// If the database cannot be read, the hub stops serving the ALPN until the next pass: without knowing that a
/// ticket is open, it does not accept pairing connections.
pub(super) async fn refresh(inner: &Inner) -> bool {
    // One at a time, and never interleaved with an endpoint replacement (`super::rebind` holds this lock too): the
    // accepted ALPNs of the endpoint in use always follow the last read.
    let _serial = inner.pair_refresh.lock().await;
    if inner.closing.load(Ordering::SeqCst) {
        return false;
    }
    let now = inner.state.clock.now();
    let until = match open_until(inner, now).await {
        Ok(until) => until,
        Err(e) => {
            tracing::warn!(error = %e, "cannot read whether a pairing ticket is open; not serving p2pc/pair/1");
            None
        }
    };
    let open = until.is_some();
    inner.pair_open_until.store(until.unwrap_or(CLOSED), Ordering::SeqCst);
    if inner.pair_alpn_accepted.swap(open, Ordering::SeqCst) != open {
        inner.endpoint().set_alpns(endpoint::accepted_alpns(open));
        if open {
            tracing::info!("a pairing ticket is open: accepting p2pc/pair/1");
        } else {
            tracing::info!("no pairing ticket is open: p2pc/pair/1 is no longer accepted");
        }
    }
    open
}

/// Handles one `p2pc/pair/1` connection: at most one `Pair`, one answer, then the connection is closed.
pub(super) async fn handle(inner: Arc<Inner>, conn: Connection) {
    let now = inner.state.clock.now();
    // §10.5: no ticket is open (it expired or was revoked after this connection's handshake began, or the accepted
    // ALPNs could not be changed in time). Closed at once, before a frame is read.
    if !is_open(&inner, now) {
        return close(&conn);
    }
    let iroh_id = conn.remote_id().to_string();
    // §5.3: a NodeId over its own failure limit is refused when it connects. Only its own failures count, and
    // nobody else holds its key.
    if !node_allowed(&inner, &iroh_id, now) {
        return close(&conn);
    }
    // §5.3: at most this many connections at once, counted apart from the other ALPNs.
    let Ok(_slot) = inner.pair_connections.clone().try_acquire_owned() else {
        return close(&conn);
    };
    // §5.3: one deadline for the stream, the frame and its decoding, counted from the handshake.
    let deadline = tokio::time::Instant::now() + inner.limits.pair_deadline;
    let read = async {
        let (send, mut recv) = conn.accept_bi().await.ok()?;
        // Size-limited before anything is decoded: a longer frame is refused on its length prefix.
        let body = read_frame_bytes(&mut recv, PAIR_MAX_FRAME_LEN).await.ok()??;
        let decoded = inner.decodes.decode::<PairRequest>(&body).await?;
        Some((send, decoded))
    };
    let Ok(Some((send, decoded))) = tokio::time::timeout_at(deadline, read).await else {
        return close(&conn);
    };
    let answer = match decoded {
        Ok(msg @ PairRequest::Pair { .. }) if msg.validate().is_err() => {
            // It breaks the protocol's own limits (SI-10 style): counted against the NodeId, never answered.
            failed(&inner, &iroh_id, None, now);
            None
        }
        Ok(PairRequest::Pair {
            ticket,
            label,
            platform,
        }) => pair(&inner, &iroh_id, &ticket, label, &platform).await,
        // H1 §6: an unknown `type` gets `unsupported_message`. It is counted like a failure, so a NodeId cannot
        // send them without limit.
        Ok(PairRequest::Unknown) => failed(&inner, &iroh_id, None, now).then(PairResponse::unsupported_message),
        // A frame whose ticket does not decode fails to decode as a whole: the one answer for every bad ticket.
        Err(_) => failed(&inner, &iroh_id, None, now).then_some(INVALID_TICKET),
    };
    match answer {
        Some(msg) => answer_and_close(&inner, &conn, send, &msg).await,
        None => close(&conn),
    }
}

const INVALID_TICKET: PairResponse = PairResponse::PairError {
    code: PairErrorCode::InvalidTicket,
};

/// Whether `iroh_id` is within its own failure limit at `now`. A refusal is logged only while the ALPN is within its
/// aggregate failure cap.
fn node_allowed(inner: &Inner, iroh_id: &str, now: OffsetDateTime) -> bool {
    let (key_ok, total_ok) = {
        let mut failures = inner.pair_failures();
        (failures.key_allows(iroh_id, now), failures.total_allows(now))
    };
    if !key_ok && total_ok {
        tracing::debug!("pairing refused: failure rate limit of this NodeId");
    }
    key_ok
}

/// Counts a failed pairing of `iroh_id` (and of the ticket-hash `prefix` it presented, if it presented a ticket)
/// and returns whether it may get a detailed answer: only while its prefix is within its limit and the ALPN is
/// within its aggregate failure cap (§5.3). Beyond either, the caller closes with no detail and nothing is logged
/// here; the failure is still counted into the one aggregated audit row of its minute.
fn failed(inner: &Inner, iroh_id: &str, prefix: Option<u16>, now: OffsetDateTime) -> bool {
    // Counted against the NodeId even beyond the aggregate cap, so its own limit keeps applying.
    let within_total = inner.pair_failures().record(iroh_id, now);
    let prefix_ok = prefix.is_none_or(|prefix| {
        let key = format!("{prefix:04x}");
        let mut failures = inner.pair_prefix_failures();
        let ok = failures.key_allows(&key, now);
        failures.record(&key, now);
        ok
    });
    if let Some(owner) = inner.state.owner_account {
        inner
            .state
            .auth_failures
            .record(owner, PAIR_FAILURE_SUBJECT.to_string(), now);
    }
    let detailed = within_total && prefix_ok;
    if detailed {
        tracing::debug!("pairing failed");
    }
    detailed
}

/// Runs a `Pair` (§5.3). `None` means "close with no detail".
///
/// The only counter read before the lookup is the NodeId's own (again, in case it filled up on other connections
/// since this one was accepted). The prefix counter and the aggregate cap are read **after** the lookup and only
/// for a failure, so a valid ticket pairs whatever they say.
async fn pair(
    inner: &Inner,
    iroh_id: &str,
    ticket: &PairingTicket,
    label: String,
    platform: &str,
) -> Option<PairResponse> {
    let now = inner.state.clock.now();
    if !node_allowed(inner, iroh_id, now) {
        return None;
    }
    // §5.3: at most this many `Pair`s being checked at once.
    let Ok(_pending) = inner.pending_pairs.clone().try_acquire_owned() else {
        return None;
    };
    match redeem(inner, iroh_id, ticket, label, platform).await {
        Ok(Some(device)) => Some(paired(inner, &device).await),
        Ok(None) => failed(inner, iroh_id, Some(ticket.hash_prefix()), now).then_some(INVALID_TICKET),
        Err(e) => {
            tracing::warn!(error = %e, "pairing failed on a storage error");
            None
        }
    }
}

/// The transaction of a `Pair`: the device this NodeId is paired as, new or the one this same ticket created for it
/// earlier (§5.2 "Retry is idempotent"). `Ok(None)` means `invalid_ticket` (nothing changed).
async fn redeem(
    inner: &Inner,
    iroh_id: &str,
    ticket: &PairingTicket,
    label: String,
    platform: &str,
) -> Result<Option<DeviceRow>, StoreError> {
    let digest = ticket.code_hash();
    let label = (!label.is_empty()).then_some(label);
    let mut tx = store::begin_immediate(&inner.state.db).await?;
    // One `now`, read once the write lock is held: the lock may have been waited for.
    let now = inner.state.clock.now();
    let outcome = store::devices::pair(
        &mut tx,
        &digest,
        &inner.state.dummy_digest,
        iroh_id,
        label,
        platform,
        now,
    )
    .await?;
    match outcome {
        PairOutcome::Paired(device) => {
            let detail = json!({
                "scopes": device.scopes,
                "project_id": device.project_id,
                "iroh_node_id": device.iroh_node_id,
                "platform": device.platform,
                "paired_by": device.paired_by,
            });
            let detail = match detail {
                serde_json::Value::Object(map) => map,
                _ => serde_json::Map::new(),
            };
            let event = NewEvent::new(
                AuditKind::DevicePaired,
                Some(Principal::Device(device.device_id)),
                Some(device.device_id.to_string()),
                detail,
            );
            store::audit::append(&mut tx, device.account_id, &event, now).await?;
            tx.commit().await?;
            tracing::info!(device_id = %device.device_id, "device paired");
            Ok(Some(*device))
        }
        // Nothing changed: the transaction is dropped.
        PairOutcome::Again(device) => Ok(Some(*device)),
        PairOutcome::Invalid => Ok(None),
    }
}

/// The `Paired` answer for `device`. The hub's name, version and API generation are what `GET /v1/server` says.
///
/// The device is paired already, so a name that cannot be read (a storage error) never costs it its answer: it gets
/// an empty name (what a hub nobody named sends) and reads the name later from `GET /v1/server`.
async fn paired(inner: &Inner, device: &DeviceRow) -> PairResponse {
    let info = match crate::nodes_api::server_info(&inner.state).await {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(error = %e, "cannot read the hub name for a Paired answer");
            let mut info = inner.state.server.info();
            info.api_version = p2pc_proto::api::API_VERSION_H2;
            info
        }
    };
    PairResponse::Paired {
        device_id: device.device_id.to_string(),
        hub_name: info.hub_name.unwrap_or_default(),
        account_id: device.account_id,
        scopes: device.scopes.clone(),
        server_version: info.version,
        api_version: info.api_version,
    }
}

/// Sends `msg`, waits (bounded by the final-message grace) for the peer to read it, then closes.
async fn answer_and_close(inner: &Inner, conn: &Connection, mut send: SendStream, msg: &PairResponse) {
    let sent = async {
        if write_frame(&mut send, msg).await.is_ok() && send.finish().is_ok() {
            let _ = send.stopped().await;
        }
    };
    let _ = tokio::time::timeout(inner.limits.final_message_grace, sent).await;
    close(conn);
}
