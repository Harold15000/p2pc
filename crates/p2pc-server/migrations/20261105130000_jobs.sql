-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T04: jobs and their append-only state history (spec §7, §8, §11).
-- Timestamps are INTEGER Unix seconds (UTC). Migrations are forward-only.

CREATE TABLE jobs (
    job_id              TEXT PRIMARY KEY NOT NULL CHECK (job_id GLOB 'job_*' AND length(job_id) = 30),
    account_id          TEXT NOT NULL REFERENCES accounts (account_id),
    project_id          TEXT NOT NULL,
    -- The key that submitted the job; its `daily_unit_cap` is checked against this key's reservations (§11).
    key_id              TEXT NOT NULL REFERENCES api_keys (key_id),
    name                TEXT,
    -- The validated and NORMALIZED JobSpec as JSON: the image in its normalized form, every default applied.
    -- SECRETS: `env` values and input file contents live here, and only here. Nothing may log this column, and API
    -- responses never read it: they use `spec_view` below (§7). Encrypting it at rest is a follow-up.
    spec                TEXT NOT NULL CHECK (json_valid(spec) AND json_type(spec) = 'object'),
    -- `[{path, size, sha256}]` of the input files, computed once at submission, so that responses never decode or
    -- hash file contents again (`JobSpecView::from_stored_with_meta`).
    files_meta          TEXT NOT NULL CHECK (json_valid(files_meta) AND json_type(files_meta) = 'array'),
    -- The REDACTED view of `spec` that API responses show (`JobSpecView`): env values are '<redacted>', `files` are
    -- `{path, size, sha256}` with no content, and there is no idempotency key. Computed once, in the same transaction
    -- that inserts the job. Every read that serves the API (list, get, cancel, the idempotent replay) selects THIS
    -- column and never `spec`, so a page of jobs never loads their file contents (up to 512 KiB each) from SQLite.
    -- Only lease building (T06) reads `spec`, one row at a time (`store::jobs::load_spec`). Holds no secret.
    spec_view           TEXT NOT NULL CHECK (json_valid(spec_view) AND json_type(spec_view) = 'object'),
    -- 'sha256:' and the SHA-256 (lowercase hex) of the canonical JSON of `spec`: how an idempotent replay tells the
    -- same request from a different one. Never returned by the API.
    spec_hash           TEXT NOT NULL
                        CHECK (length(spec_hash) = 71
                               AND substr(spec_hash, 1, 7) = 'sha256:'
                               AND NOT substr(spec_hash, 8) GLOB '*[^0-9a-f]*'),
    -- Changed only through `job_state::transition`. Terminal states are immutable (trigger below).
    status              TEXT NOT NULL CHECK (status IN ('queued', 'assigned', 'running', 'succeeded', 'failed',
                                                        'timed_out', 'cancelled', 'lost')),
    -- The current attempt: 1 at creation, plus one for each requeue after node loss (§7).
    attempt             INTEGER NOT NULL CHECK (attempt >= 1),
    max_attempts        INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 5),
    -- The client's idempotency key. Never returned by the API (it is also inside `spec`, which responses redact).
    idempotency_key     TEXT CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 255),
    -- Milli-units reserved at creation: estimate_units(resources, timeout_s, gpu_hour_units).
    units_reserved      INTEGER NOT NULL CHECK (units_reserved >= 0),
    -- Node of the current or last attempt. No foreign key yet: the nodes table arrives with T05.
    node_id             TEXT,
    exit_code           INTEGER,
    -- How the last attempt ended, as the agent reported it ('exited', 'timed_out', 'cancelled', 'error').
    outcome             TEXT,
    -- A short error code when the job failed without an exit code (for example 'disk_limit').
    error               TEXT,
    -- User-visible explanation of the current state (T06 sets it, for example after the offer cap, §8).
    reason              TEXT,
    -- A cancel was asked for while the job was assigned or running; T06 delivers it to the node.
    cancel_requested_at INTEGER,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    started_at          INTEGER,
    finished_at         INTEGER,
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

-- One job per (API key, idempotency key). Scoped to the KEY that submitted the job, not to the project (spec §7,
-- c47c0a5): another key reusing the same idempotency key gets its own job and learns nothing about this one,
-- so a `200` versus a `409` can never tell it whether a guessed `env` value was right. The unique index is also what
-- makes concurrent identical submissions safe.
CREATE UNIQUE INDEX jobs_idempotency ON jobs (key_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
-- The scheduler's queue and the account-wide listings.
CREATE INDEX jobs_account_status_created ON jobs (account_id, status, created_at);
-- The listing of a project, newest first.
CREATE INDEX jobs_project_created ON jobs (project_id, created_at);
-- "Reserved today" for a key's daily cap (`units::reserved_today`).
CREATE INDEX jobs_key_created ON jobs (key_id, created_at);

-- Terminal states are immutable, enforced by the database too: once a job is succeeded, failed, timed_out, cancelled
-- or lost, its status never changes again.
CREATE TRIGGER jobs_terminal_is_final BEFORE UPDATE OF status ON jobs
WHEN OLD.status IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost') AND NEW.status IS NOT OLD.status
BEGIN
    SELECT RAISE(ABORT, 'a terminal job status is immutable');
END;

-- Every status change of a job (§7), for the usage ledger (T15) and debugging. Append-only.
CREATE TABLE job_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT NOT NULL REFERENCES jobs (job_id),
    at          INTEGER NOT NULL,
    -- NULL for the creation event.
    from_status TEXT CHECK (from_status IS NULL OR from_status IN ('queued', 'assigned', 'running', 'succeeded',
                                                                   'failed', 'timed_out', 'cancelled', 'lost')),
    to_status   TEXT NOT NULL CHECK (to_status IN ('queued', 'assigned', 'running', 'succeeded', 'failed',
                                                   'timed_out', 'cancelled', 'lost')),
    -- A stable machine-readable code ('created', 'cancelled_by_user', …), never a secret.
    reason      TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256)
) STRICT;

CREATE INDEX job_events_job_seq ON job_events (job_id, seq);

CREATE TRIGGER job_events_no_delete BEFORE DELETE ON job_events
BEGIN
    SELECT RAISE(ABORT, 'job_events is append-only');
END;

CREATE TRIGGER job_events_no_update BEFORE UPDATE ON job_events
BEGIN
    SELECT RAISE(ABORT, 'job_events is append-only');
END;
