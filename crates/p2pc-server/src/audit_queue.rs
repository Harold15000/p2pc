// SPDX-License-Identifier: AGPL-3.0-only

//! Failed authentications are recorded off the request path (spec §5 "Audit").
//!
//! The auth middleware hands each failure to a bounded queue with `try_send` and answers its `401` at once: it never
//! waits for SQLite, whatever the database is doing. One writer task drains the queue, adds up the failures per
//! account, minute and subject, and writes each batch in one `BEGIN IMMEDIATE` transaction. When the queue is full,
//! the event is dropped and counted ([`AuthFailureQueue::dropped`]); the writer logs how many were dropped. A batch
//! that cannot be written is counted as dropped too.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use p2pc_proto::ids::AccountId;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};

use crate::store::{self, Db, StoreError};

/// Default capacity of the queue.
pub const DEFAULT_CAPACITY: usize = 1024;
/// Most messages the writer takes into one batch.
const MAX_BATCH: usize = 4096;

#[derive(Debug)]
enum Msg {
    Failure {
        account_id: AccountId,
        subject: String,
        at: OffsetDateTime,
    },
    /// Answered once every message queued before it has been written.
    Flush(oneshot::Sender<()>),
}

/// The sending side, held by the app state. Cheap to clone.
#[derive(Debug, Clone)]
pub struct AuthFailureQueue {
    tx: mpsc::Sender<Msg>,
    dropped: Arc<AtomicU64>,
}

impl AuthFailureQueue {
    /// Starts the writer task on the current runtime and returns the queue. The task ends when every clone of the
    /// queue is dropped.
    #[must_use]
    pub fn spawn(db: Db, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        tokio::spawn(writer(db, rx, dropped.clone()));
        Self { tx, dropped }
    }

    /// Queues one failed attempt without waiting. If the queue is full (or the writer is gone), the event is dropped
    /// and counted.
    pub fn record(&self, account_id: AccountId, subject: String, at: OffsetDateTime) {
        let msg = Msg::Failure {
            account_id,
            subject,
            at,
        };
        if self.tx.try_send(msg).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Failed attempts dropped so far because the queue was full or a batch could not be written.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Waits until every failure queued before this call has been written (or counted as dropped). For tests and
    /// shutdown; never called on the request path.
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.tx.send(Msg::Flush(ack)).await.is_ok() {
            let _ = done.await;
        }
    }
}

type Batch = BTreeMap<(AccountId, i64, String), (OffsetDateTime, u64)>;

fn take(msg: Msg, batch: &mut Batch, acks: &mut Vec<oneshot::Sender<()>>) {
    match msg {
        Msg::Failure {
            account_id,
            subject,
            at,
        } => {
            let entry = batch
                .entry((account_id, store::audit::minute_of(at), subject))
                .or_insert((at, 0));
            entry.1 += 1;
        }
        Msg::Flush(ack) => acks.push(ack),
    }
}

async fn writer(db: Db, mut rx: mpsc::Receiver<Msg>, dropped: Arc<AtomicU64>) {
    let mut reported = 0;
    while let Some(first) = rx.recv().await {
        let mut batch = Batch::new();
        let mut acks = Vec::new();
        take(first, &mut batch, &mut acks);
        while batch.len() + acks.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(msg) => take(msg, &mut batch, &mut acks),
                Err(_) => break,
            }
        }
        if !batch.is_empty()
            && let Err(e) = write(&db, &batch).await
        {
            let lost: u64 = batch.values().map(|(_, n)| n).sum();
            dropped.fetch_add(lost, Ordering::Relaxed);
            tracing::warn!(error = %e, lost, "cannot record failed authentications");
        }
        let now = dropped.load(Ordering::Relaxed);
        if now > reported {
            tracing::warn!(
                dropped = now - reported,
                "failed authentications dropped (audit queue full)"
            );
            reported = now;
        }
        for ack in acks {
            let _ = ack.send(());
        }
    }
}

async fn write(db: &Db, batch: &Batch) -> Result<(), StoreError> {
    let mut tx = store::begin_immediate(db).await?;
    for ((account_id, _, subject), (at, count)) in batch {
        store::audit::record_auth_failure(&mut tx, *account_id, subject, *at, *count).await?;
    }
    tx.commit().await?;
    Ok(())
}
