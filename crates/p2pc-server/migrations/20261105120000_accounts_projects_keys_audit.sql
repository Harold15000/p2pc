-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T03: owner account, projects, API keys and the append-only audit log (spec §5, §12).
-- Timestamps are INTEGER Unix seconds (UTC). Migrations are forward-only.

CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY NOT NULL CHECK (account_id GLOB 'acc_*' AND length(account_id) = 30),
    -- v0.1 is single-owner: exactly one row has is_owner = 1 (the account created by `p2pc-server init`).
    is_owner   INTEGER NOT NULL DEFAULT 0 CHECK (is_owner IN (0, 1)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX accounts_single_owner ON accounts (is_owner) WHERE is_owner = 1;

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY NOT NULL CHECK (project_id GLOB 'prj_*' AND length(project_id) = 30),
    account_id TEXT NOT NULL REFERENCES accounts (account_id),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    created_at INTEGER NOT NULL,
    UNIQUE (account_id, name),
    -- Target of the composite foreign key below: a key's project must belong to the key's account.
    UNIQUE (project_id, account_id)
) STRICT;

CREATE TABLE api_keys (
    key_id         TEXT PRIMARY KEY NOT NULL
                   CHECK (length(key_id) = 12 AND NOT key_id GLOB '*[^a-z2-7]*'),
    account_id     TEXT NOT NULL REFERENCES accounts (account_id),
    project_id     TEXT NOT NULL,
    -- Versioned digest of the secret: 'sha256:' and 64 lowercase hex characters. Never the secret itself.
    secret_digest  TEXT NOT NULL
                   CHECK (length(secret_digest) = 71
                          AND substr(secret_digest, 1, 7) = 'sha256:'
                          AND NOT substr(secret_digest, 8) GLOB '*[^0-9a-f]*'),
    scopes         TEXT NOT NULL CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
    -- Milli-units per UTC day; NULL means no cap.
    daily_unit_cap INTEGER CHECK (daily_unit_cap IS NULL OR daily_unit_cap >= 0),
    -- JSON array of globs; NULL allows every image.
    allowed_images TEXT CHECK (allowed_images IS NULL
                               OR (json_valid(allowed_images) AND json_type(allowed_images) = 'array')),
    label          TEXT,
    expires_at     INTEGER,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER,
    revoked_at     INTEGER,
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

CREATE INDEX api_keys_account_created ON api_keys (account_id, created_at, key_id);


CREATE TABLE audit_events (
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
                                               'node_enrolled', 'node_deleted')),
    subject_id   TEXT,
    -- Non-secret details, a JSON object. For auth_failed it holds the aggregated `count`.
    detail       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail) AND json_type(detail) = 'object')
) STRICT;

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
