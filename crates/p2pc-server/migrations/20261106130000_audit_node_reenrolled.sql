-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Spec §5 "Re-enrolling the same machine" (amended 2026-11-06, T14b2 real run): a new audit kind, `node_reenrolled`.
-- SQLite cannot change a CHECK constraint in place, so `audit_events` is rebuilt with the same columns, rows,
-- indexes and append-only triggers; only the kind list grows. Forward-only.
--
-- The rows are copied with their `seq` (the list cursor) and `event_id` unchanged, so cursors and IDs handed out
-- before stay valid; AUTOINCREMENT goes on from the largest `seq` copied. Nothing references `audit_events`.

CREATE TABLE audit_events_new (
    -- Internal sequence: the order of events and the list cursor. Never shown as the event ID.
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Public event ID (`aud_<ULID>`, p2pc_proto::ids::AuditEventId).
    event_id     TEXT NOT NULL UNIQUE CHECK (event_id GLOB 'aud_*' AND length(event_id) = 30),
    -- For aggregated kinds (auth_failed), the start of the minute.
    at           INTEGER NOT NULL,
    account_id   TEXT NOT NULL REFERENCES accounts (account_id),
    actor_key_id TEXT,
    kind         TEXT NOT NULL CHECK (kind IN ('key_created', 'key_revoked', 'key_recovered', 'auth_failed',
                                               'join_token_created', 'join_token_consumed', 'join_token_revoked',
                                               'node_enrolled', 'node_reenrolled', 'node_deleted')),
    subject_id   TEXT,
    -- Non-secret details, a JSON object. For auth_failed it holds the aggregated `count`.
    detail       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail) AND json_type(detail) = 'object')
) STRICT;

INSERT INTO audit_events_new (seq, event_id, at, account_id, actor_key_id, kind, subject_id, detail)
SELECT seq, event_id, at, account_id, actor_key_id, kind, subject_id, detail FROM audit_events ORDER BY seq;

-- Dropping the table drops its indexes and triggers with it (no row-level DELETE runs, so the append-only trigger
-- does not fire); they are created again on the new table below, unchanged.
DROP TABLE audit_events;
ALTER TABLE audit_events_new RENAME TO audit_events;

CREATE INDEX audit_events_account_seq ON audit_events (account_id, seq);
CREATE INDEX audit_events_account_kind_seq ON audit_events (account_id, kind, seq);

-- One aggregated auth_failed row per account, minute and presented key ID (or 'unknown').
CREATE UNIQUE INDEX audit_events_auth_failed_bucket ON audit_events (account_id, at, subject_id)
    WHERE kind = 'auth_failed';

-- Append-only, enforced by the database too: rows are never deleted, and the only update ever allowed is raising
-- the integer `detail.count` of an aggregated auth_failed row (the writer adds a batch at once), nothing else.
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
WHEN NOT (OLD.kind = 'auth_failed'
          AND NEW.kind = OLD.kind
          AND NEW.seq = OLD.seq
          AND NEW.event_id = OLD.event_id
          AND NEW.at = OLD.at
          AND NEW.account_id = OLD.account_id
          AND NEW.actor_key_id IS OLD.actor_key_id
          AND NEW.subject_id IS OLD.subject_id
          AND json_type(NEW.detail, '$.count') = 'integer'
          AND json_extract(NEW.detail, '$.count') > json_extract(OLD.detail, '$.count')
          AND NEW.detail = json_set(OLD.detail, '$.count', json_extract(NEW.detail, '$.count')))
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
