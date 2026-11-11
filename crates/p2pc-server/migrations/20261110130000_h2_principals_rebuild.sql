-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T2-10: how principals are stored (H2 spec §5.6), and the ledger's slice columns and key (§12). Forward-only.
--
-- H1 stores the principal of jobs, ledger rows and join tokens as a NOT NULL API key. A device principal has no API
-- key, so each of these tables gets a nullable key column and a nullable device column with a CHECK that exactly one
-- is set; `audit_events` gains `actor_device_id` (at most one actor). SQLite cannot relax NOT NULL, add a CHECK or
-- change a UNIQUE constraint in place, so `jobs`, `usage_records`, `join_tokens` and `audit_events` are rebuilt with
-- the procedure of `20261108120000_finished_lease_holds.sql`: rows saved in a temporary table, the table dropped and
-- created again under its own name, rows copied back. The tables that reference `jobs` and `join_tokens` keep
-- pointing at them, and the foreign keys are checked at COMMIT (`defer_foreign_keys`): dropping a table counts a
-- violation for every child row, and inserting the parent row again takes it back. The migration runs in one
-- transaction, so a failure leaves the H1 tables.
--
-- Dropping a table runs no row-level trigger, so the append-only triggers never fire during the rebuild; every index
-- and trigger of the old tables is created again below, before COMMIT, except the ones this migration replaces:
-- `jobs_idempotency` (now one partial unique index per principal column), the audit `kind` list (gains the H2
-- kinds), and the ledger's `UNIQUE (job_id, attempt)` and `lease_id UNIQUE` (now one row per slice).
--
-- H1 rows are copied with their device column NULL and their key unchanged. Each ledger row becomes one slice:
-- `slice_start = started_at`, `slice_end = ended_at`, `last_slice = 1`, `kind = 'batch'`, and `charge_day` the UTC day
-- of its job's `created_at`, so every H1 number (caps, `GET /v1/usage`) is the same after the migration (SI-H2-20).

PRAGMA defer_foreign_keys = ON;

-- 1. Save the rows.

CREATE TEMP TABLE jobs_saved AS
SELECT job_id, account_id, project_id, key_id, name, spec, files_meta, spec_view, spec_hash, status, attempt,
       max_attempts, idempotency_key, units_reserved, node_id, exit_code, outcome, error, reason, cancel_requested_at,
       created_at, updated_at, started_at, finished_at, epoch, offer_count, last_lost_node_id
FROM jobs;

CREATE TEMP TABLE usage_records_saved AS
SELECT id, job_id, attempt, lease_id, node_id, key_id, account_id, project_id, started_at, ended_at,
       reserved_cpu_ms, reserved_gpu_ms, used_cpu_ms, max_rss_mb, units, estimated
FROM usage_records;

CREATE TEMP TABLE join_tokens_saved AS
SELECT id, account_id, project_id, code_digest, label, created_by_key_id, created_at, expires_at, consumed_at,
       consumed_by_node_id, revoked_at
FROM join_tokens;

CREATE TEMP TABLE audit_events_saved AS
SELECT seq, event_id, at, account_id, actor_key_id, kind, subject_id, detail
FROM audit_events;

-- 2. Drop the old tables (children first). Their indexes and triggers go with them.

DROP TABLE usage_records;
DROP TABLE jobs;
DROP TABLE join_tokens;
DROP TABLE audit_events;

-- 3. jobs.

CREATE TABLE jobs (
    job_id              TEXT PRIMARY KEY NOT NULL CHECK (job_id GLOB 'job_*' AND length(job_id) = 30),
    account_id          TEXT NOT NULL REFERENCES accounts (account_id),
    project_id          TEXT NOT NULL,
    -- The principal that submitted the job (§5.6): an API key or a device, exactly one. Its `daily_unit_cap` is
    -- checked against this principal's spending (§12).
    key_id              TEXT REFERENCES api_keys (key_id),
    device_id           TEXT REFERENCES devices (device_id),
    -- `batch` (every H1 job) or `service` (§7.1), and the template a launch came from (§7.6), copied from the spec
    -- at creation so that the `kind` filter and the template view are plain indexed columns.
    kind                TEXT NOT NULL DEFAULT 'batch' CHECK (kind IN ('batch', 'service')),
    template_id         TEXT CHECK (template_id IS NULL OR length(template_id) BETWEEN 1 AND 64),
    name                TEXT,
    -- The validated and NORMALIZED JobSpec as JSON: the image in its normalized form, every default applied.
    -- SECRETS: `env` values and input file contents live here, and only here. Nothing may log this column, and API
    -- responses never read it: they use `spec_view` below (§7).
    spec                TEXT NOT NULL CHECK (json_valid(spec) AND json_type(spec) = 'object'),
    -- `[{path, size, sha256}]` of the input files, computed once at submission.
    files_meta          TEXT NOT NULL CHECK (json_valid(files_meta) AND json_type(files_meta) = 'array'),
    -- The REDACTED view of `spec` that API responses show (`JobSpecView`). Holds no secret.
    spec_view           TEXT NOT NULL CHECK (json_valid(spec_view) AND json_type(spec_view) = 'object'),
    -- 'sha256:' and the SHA-256 (lowercase hex) of the canonical JSON of `spec`. Never returned by the API.
    spec_hash           TEXT NOT NULL
                        CHECK (length(spec_hash) = 71
                               AND substr(spec_hash, 1, 7) = 'sha256:'
                               AND NOT substr(spec_hash, 8) GLOB '*[^0-9a-f]*'),
    -- Changed only through `job_state::transition`. Terminal states are immutable (trigger below).
    status              TEXT NOT NULL CHECK (status IN ('queued', 'assigned', 'running', 'succeeded', 'failed',
                                                        'timed_out', 'cancelled', 'lost')),
    attempt             INTEGER NOT NULL CHECK (attempt >= 1),
    max_attempts        INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 5),
    -- The client's idempotency key, scoped to the principal. Never returned by the API.
    idempotency_key     TEXT CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 255),
    -- Milli-units reserved at creation (0 for a service, whose reservation lives in `service_state`, §12).
    units_reserved      INTEGER NOT NULL CHECK (units_reserved >= 0),
    node_id             TEXT,
    exit_code           INTEGER,
    outcome             TEXT,
    error               TEXT,
    reason              TEXT,
    cancel_requested_at INTEGER,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    started_at          INTEGER,
    finished_at         INTEGER,
    epoch               INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    offer_count         INTEGER NOT NULL DEFAULT 0 CHECK (offer_count >= 0),
    last_lost_node_id   TEXT,
    CHECK ((key_id IS NULL) <> (device_id IS NULL)),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

INSERT INTO jobs (job_id, account_id, project_id, key_id, device_id, kind, template_id, name, spec, files_meta,
                  spec_view, spec_hash, status, attempt, max_attempts, idempotency_key, units_reserved, node_id,
                  exit_code, outcome, error, reason, cancel_requested_at, created_at, updated_at, started_at,
                  finished_at, epoch, offer_count, last_lost_node_id)
SELECT job_id, account_id, project_id, key_id, NULL, 'batch', NULL, name, spec, files_meta, spec_view, spec_hash,
       status, attempt, max_attempts, idempotency_key, units_reserved, node_id, exit_code, outcome, error, reason,
       cancel_requested_at, created_at, updated_at, started_at, finished_at, epoch, offer_count, last_lost_node_id
FROM jobs_saved;

-- Idempotency per principal (§5.6). SQLite treats NULLs as distinct in a unique index, so one index over a nullable
-- column would stop deduplicating; each partial index covers rows whose principal column is never NULL.
CREATE UNIQUE INDEX jobs_idempotency_key ON jobs (key_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND key_id IS NOT NULL;
CREATE UNIQUE INDEX jobs_idempotency_device ON jobs (device_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND device_id IS NOT NULL;
CREATE INDEX jobs_account_status_created ON jobs (account_id, status, created_at);
CREATE INDEX jobs_project_created ON jobs (project_id, created_at);
-- Cap lookups per principal.
CREATE INDEX jobs_key_created ON jobs (key_id, created_at);
CREATE INDEX jobs_device_created ON jobs (device_id, created_at);
-- The scheduler's FIFO queue, across accounts.
CREATE INDEX jobs_status_created ON jobs (status, created_at, job_id);
-- The GC's scan of terminal jobs past their retention.
CREATE INDEX jobs_finished_at ON jobs (finished_at) WHERE finished_at IS NOT NULL;

CREATE TRIGGER jobs_terminal_is_final BEFORE UPDATE OF status ON jobs
WHEN OLD.status IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost') AND NEW.status IS NOT OLD.status
BEGIN
    SELECT RAISE(ABORT, 'a terminal job status is immutable');
END;

-- 4. join_tokens.

CREATE TABLE join_tokens (
    id                   TEXT PRIMARY KEY NOT NULL CHECK (id GLOB 'jtk_*' AND length(id) = 30),
    account_id           TEXT NOT NULL REFERENCES accounts (account_id),
    project_id           TEXT NOT NULL,
    -- Versioned digest of the 16-byte code. Never the code itself.
    code_digest          TEXT NOT NULL UNIQUE
                         CHECK (length(code_digest) = 71
                                AND substr(code_digest, 1, 7) = 'sha256:'
                                AND NOT substr(code_digest, 8) GLOB '*[^0-9a-f]*'),
    label                TEXT CHECK (label IS NULL OR length(label) BETWEEN 1 AND 256),
    -- The principal that minted it (§5.6): exactly one.
    created_by_key_id    TEXT REFERENCES api_keys (key_id),
    created_by_device_id TEXT REFERENCES devices (device_id),
    -- Set only for the token of an approved join request: it enrolls this agent NodeId and no other (§5.4).
    bound_iroh_node_id   TEXT CHECK (bound_iroh_node_id IS NULL
                                     OR (length(bound_iroh_node_id) = 64
                                         AND NOT bound_iroh_node_id GLOB '*[^0-9a-f]*')),
    -- Set only by an `admin` principal's explicit option (§5.4): the node it enrolls starts `approved`.
    pre_approved         INTEGER NOT NULL DEFAULT 0 CHECK (pre_approved IN (0, 1)),
    created_at           INTEGER NOT NULL,
    -- The only expiry that counts (the token's own payload is not authenticated).
    expires_at           INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at          INTEGER,
    consumed_by_node_id  TEXT REFERENCES nodes (id),
    revoked_at           INTEGER,
    CHECK ((created_by_key_id IS NULL) <> (created_by_device_id IS NULL)),
    CHECK (consumed_at IS NULL OR revoked_at IS NULL),
    CHECK ((consumed_at IS NULL) = (consumed_by_node_id IS NULL)),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

INSERT INTO join_tokens (id, account_id, project_id, code_digest, label, created_by_key_id, created_by_device_id,
                         bound_iroh_node_id, pre_approved, created_at, expires_at, consumed_at, consumed_by_node_id,
                         revoked_at)
SELECT id, account_id, project_id, code_digest, label, created_by_key_id, NULL, NULL, 0, created_at, expires_at,
       consumed_at, consumed_by_node_id, revoked_at
FROM join_tokens_saved;

CREATE INDEX join_tokens_account_created ON join_tokens (account_id, created_at, id);

-- 5. usage_records: one row per finished slice (§12).

CREATE TABLE usage_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          TEXT NOT NULL REFERENCES jobs (job_id),
    attempt         INTEGER NOT NULL CHECK (attempt >= 1),
    -- Every slice of an attempt names its lease, so this is no longer UNIQUE.
    lease_id        TEXT NOT NULL REFERENCES leases (id),
    node_id         TEXT NOT NULL REFERENCES nodes (id),
    -- The job's principal (§5.6): exactly one.
    key_id          TEXT REFERENCES api_keys (key_id),
    device_id       TEXT REFERENCES devices (device_id),
    account_id      TEXT NOT NULL REFERENCES accounts (account_id),
    project_id      TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('batch', 'service')),
    template_id     TEXT CHECK (template_id IS NULL OR length(template_id) BETWEEN 1 AND 64),
    -- The attempt's start, kept on every slice; `ended_at` is the slice's end.
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER NOT NULL CHECK (ended_at >= started_at),
    slice_start     INTEGER NOT NULL,
    slice_end       INTEGER NOT NULL,
    -- 1 on the attempt's last row.
    last_slice      INTEGER NOT NULL CHECK (last_slice IN (0, 1)),
    -- 00:00 UTC of the day the row is charged to (§12).
    charge_day      INTEGER NOT NULL CHECK (charge_day % 86400 = 0),
    reserved_cpu_ms INTEGER NOT NULL CHECK (reserved_cpu_ms >= 0),
    reserved_gpu_ms INTEGER NOT NULL CHECK (reserved_gpu_ms >= 0),
    used_cpu_ms     INTEGER NOT NULL CHECK (used_cpu_ms >= 0),
    max_rss_mb      INTEGER NOT NULL CHECK (max_rss_mb >= 0),
    -- Milli-units.
    units           INTEGER NOT NULL CHECK (units >= 0),
    estimated       INTEGER NOT NULL DEFAULT 0 CHECK (estimated IN (0, 1)),
    CHECK ((key_id IS NULL) <> (device_id IS NULL)),
    CHECK (slice_start <= slice_end),
    CHECK (slice_start >= started_at),
    CHECK (ended_at = slice_end),
    UNIQUE (job_id, attempt, slice_start),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

INSERT INTO usage_records (id, job_id, attempt, lease_id, node_id, key_id, device_id, account_id, project_id, kind,
                           template_id, started_at, ended_at, slice_start, slice_end, last_slice, charge_day,
                           reserved_cpu_ms, reserved_gpu_ms, used_cpu_ms, max_rss_mb, units, estimated)
SELECT u.id, u.job_id, u.attempt, u.lease_id, u.node_id, u.key_id, NULL, u.account_id, u.project_id, 'batch', NULL,
       u.started_at, u.ended_at, u.started_at, u.ended_at, 1,
       j.created_at - (j.created_at % 86400 + 86400) % 86400,
       u.reserved_cpu_ms, u.reserved_gpu_ms, u.used_cpu_ms, u.max_rss_mb, u.units, u.estimated
FROM usage_records_saved u JOIN jobs_saved j ON j.job_id = u.job_id
ORDER BY u.id;

-- One last slice per attempt.
CREATE UNIQUE INDEX usage_records_last_slice ON usage_records (job_id, attempt) WHERE last_slice = 1;
CREATE INDEX usage_records_account_ended ON usage_records (account_id, ended_at);
CREATE INDEX usage_records_key_ended ON usage_records (key_id, ended_at);
CREATE INDEX usage_records_device_ended ON usage_records (device_id, ended_at) WHERE device_id IS NOT NULL;
-- The cap query reads the ledger by principal and charge day (§12).
CREATE INDEX usage_records_key_day ON usage_records (key_id, charge_day) WHERE key_id IS NOT NULL;
CREATE INDEX usage_records_device_day ON usage_records (device_id, charge_day) WHERE device_id IS NOT NULL;

-- A slice is written once and never updated or deleted.
CREATE TRIGGER usage_records_no_update BEFORE UPDATE ON usage_records
BEGIN
    SELECT RAISE(ABORT, 'usage_records is append-only');
END;

CREATE TRIGGER usage_records_no_delete BEFORE DELETE ON usage_records
BEGIN
    SELECT RAISE(ABORT, 'usage_records is append-only');
END;

-- 6. audit_events. The rows keep their `seq` (the list cursor) and event IDs; AUTOINCREMENT goes on from the
-- largest `seq` copied.

CREATE TABLE audit_events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT NOT NULL UNIQUE CHECK (event_id GLOB 'aud_*' AND length(event_id) = 30),
    -- For aggregated kinds (auth_failed), the start of the minute.
    at              INTEGER NOT NULL,
    account_id      TEXT NOT NULL REFERENCES accounts (account_id),
    actor_key_id    TEXT,
    -- The device that acted (§5.6). Aggregated failures have no actor.
    actor_device_id TEXT,
    kind            TEXT NOT NULL CHECK (kind IN ('key_created', 'key_revoked', 'key_recovered', 'auth_failed',
                                                  'join_token_created', 'join_token_consumed', 'join_token_revoked',
                                                  'node_enrolled', 'node_reenrolled', 'node_deleted',
                                                  'pairing_ticket_created', 'pairing_ticket_revoked', 'device_paired',
                                                  'device_revoked', 'device_added_offline', 'device_revoked_offline',
                                                  'join_request_created', 'join_request_revealed',
                                                  'join_request_reveal_failed', 'join_request_approved',
                                                  'join_request_rejected', 'join_request_delivered', 'node_approved',
                                                  'node_left', 'template_bundle_loaded')),
    subject_id      TEXT,
    -- Non-secret details, a JSON object. For auth_failed it holds the aggregated `count`.
    detail          TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail) AND json_type(detail) = 'object'),
    CHECK (actor_key_id IS NULL OR actor_device_id IS NULL)
) STRICT;

INSERT INTO audit_events (seq, event_id, at, account_id, actor_key_id, actor_device_id, kind, subject_id, detail)
SELECT seq, event_id, at, account_id, actor_key_id, NULL, kind, subject_id, detail FROM audit_events_saved ORDER BY seq;

CREATE INDEX audit_events_account_seq ON audit_events (account_id, seq);
CREATE INDEX audit_events_account_kind_seq ON audit_events (account_id, kind, seq);

-- One aggregated auth_failed row per account, minute and subject (a key ID, 'unknown', 'join', 'pair' or 'device').
CREATE UNIQUE INDEX audit_events_auth_failed_bucket ON audit_events (account_id, at, subject_id)
    WHERE kind = 'auth_failed';

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- The only update ever allowed is raising the integer `detail.count` of an aggregated auth_failed row.
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
WHEN NOT (OLD.kind = 'auth_failed'
          AND NEW.kind = OLD.kind
          AND NEW.seq = OLD.seq
          AND NEW.event_id = OLD.event_id
          AND NEW.at = OLD.at
          AND NEW.account_id = OLD.account_id
          AND NEW.actor_key_id IS OLD.actor_key_id
          AND NEW.actor_device_id IS OLD.actor_device_id
          AND NEW.subject_id IS OLD.subject_id
          AND json_type(NEW.detail, '$.count') = 'integer'
          AND json_extract(NEW.detail, '$.count') > json_extract(OLD.detail, '$.count')
          AND NEW.detail = json_set(OLD.detail, '$.count', json_extract(NEW.detail, '$.count')))
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- 7. Clean up.

DROP TABLE jobs_saved;
DROP TABLE usage_records_saved;
DROP TABLE join_tokens_saved;
DROP TABLE audit_events_saved;
