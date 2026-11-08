-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T10b: output uploads, their publication on `JobFinished`, and the GC of logs and artifacts (spec §6 "Uploads",
-- §7, §12). Timestamps are INTEGER Unix seconds (UTC). Migrations are forward-only.

-- One row per attempt that uploaded a file or was finalised. Files live under `<data>/artifacts/<job_id>/<attempt>/`:
-- `.staging/<path>` while staged, `files/<path>` once published.
CREATE TABLE output_attempts (
    job_id             TEXT NOT NULL REFERENCES jobs (job_id),
    attempt            INTEGER NOT NULL CHECK (attempt >= 1),
    -- The lease whose uploads opened the row; NULL when `JobFinished` finalised an attempt that uploaded nothing.
    lease_id           TEXT REFERENCES leases (id),
    -- The latest upload staged for the attempt (the staging GC counts its hour from here or the lease's end).
    last_upload_at     INTEGER,
    -- Set once, when `JobFinished` published the attempt's outputs. Uploads are refused from then on.
    finalized_at       INTEGER,
    -- The note finalising left for the job's `error` (`outputs_incomplete: N`), so a repeat returns the same.
    note               TEXT CHECK (note IS NULL OR length(note) BETWEEN 1 AND 256),
    -- When the `.staging` directory was removed: at finalisation, or by the GC an hour after the lease ended.
    staging_removed_at INTEGER,
    PRIMARY KEY (job_id, attempt)
) STRICT;

-- Files received, verified (size and sha256) and fsynced, not yet published.
CREATE TABLE output_staging (
    job_id    TEXT NOT NULL,
    attempt   INTEGER NOT NULL,
    path      TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    size      INTEGER NOT NULL CHECK (size >= 0),
    sha256    TEXT NOT NULL CHECK (length(sha256) = 64 AND NOT sha256 GLOB '*[^0-9a-f]*'),
    staged_at INTEGER NOT NULL,
    PRIMARY KEY (job_id, attempt, path),
    FOREIGN KEY (job_id, attempt) REFERENCES output_attempts (job_id, attempt)
) STRICT, WITHOUT ROWID;

-- Published outputs (`GET /v1/jobs/{id}/outputs`). Rows stay after the GC; `artifact_gc` says the bytes are gone.
CREATE TABLE job_outputs (
    job_id       TEXT NOT NULL REFERENCES jobs (job_id),
    attempt      INTEGER NOT NULL CHECK (attempt >= 1),
    path         TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    size         INTEGER NOT NULL CHECK (size >= 0),
    sha256       TEXT NOT NULL CHECK (length(sha256) = 64 AND NOT sha256 GLOB '*[^0-9a-f]*'),
    published_at INTEGER NOT NULL,
    PRIMARY KEY (job_id, attempt, path)
) STRICT, WITHOUT ROWID;

-- The GC's record, written before it deletes: the logs and artifacts of this terminal job are gone (§12). The job
-- and its rows stay; its outputs then show `expired: true` and their downloads answer `410 Gone`.
CREATE TABLE artifact_gc (
    job_id     TEXT PRIMARY KEY NOT NULL REFERENCES jobs (job_id),
    expired_at INTEGER NOT NULL
) STRICT;

-- The GC's scan of terminal jobs past their retention.
CREATE INDEX jobs_finished_at ON jobs (finished_at) WHERE finished_at IS NOT NULL;
-- The GC's scan of staging that never finalised.
CREATE INDEX output_attempts_open ON output_attempts (job_id, attempt)
    WHERE finalized_at IS NULL AND staging_removed_at IS NULL;
