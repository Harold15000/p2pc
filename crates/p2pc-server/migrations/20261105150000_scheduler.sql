-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T06: the scheduler, leases and fencing, attempts, offer cooldowns and the usage ledger (spec §6, §7, §8, §11).
-- Timestamps are INTEGER Unix seconds (UTC). Migrations are forward-only.

-- The last lease epoch issued for the job (0 before the first offer). Every offer gets `epoch + 1`, in the
-- transaction that creates the lease, so epochs increase strictly per job even when an offer is refused (an offer
-- is not an attempt, §8 "Offer cap"; `attempt` only moves on node loss).
ALTER TABLE jobs ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0);
-- Offers that were refused or not accepted within 10 s (§8 "Offer cap"). At 10 the job is no longer offered.
ALTER TABLE jobs ADD COLUMN offer_count INTEGER NOT NULL DEFAULT 0 CHECK (offer_count >= 0);
-- The node that just lost the job's lease: a retry prefers another node (§8 "Retries").
ALTER TABLE jobs ADD COLUMN last_lost_node_id TEXT;

-- The scheduler's FIFO queue, across accounts.
CREATE INDEX jobs_status_created ON jobs (status, created_at, job_id);

CREATE TABLE leases (
    id                TEXT PRIMARY KEY NOT NULL CHECK (id GLOB 'lse_*' AND length(id) = 30),
    job_id            TEXT NOT NULL REFERENCES jobs (job_id),
    node_id           TEXT NOT NULL REFERENCES nodes (id),
    -- The fencing token: strictly increasing per job (`jobs.epoch` at creation).
    epoch             INTEGER NOT NULL CHECK (epoch >= 1),
    -- The job's attempt this lease would run (`jobs.attempt` at creation).
    attempt           INTEGER NOT NULL CHECK (attempt >= 1),
    -- offered → accepted → running → finished; offered → revoked (refused, not accepted in time, job cancelled);
    -- accepted|running → revoked (cancelled on an unreachable node, watchdog) or lost (node loss).
    state             TEXT NOT NULL CHECK (state IN ('offered', 'accepted', 'running', 'finished', 'revoked', 'lost')),
    -- What the lease holds on its node: {"cpu": <vCPUs>, "memory_mb": <MiB>, "gpu_uuid": <offerable GPU UUID> | null}.
    reserved          TEXT NOT NULL CHECK (json_valid(reserved) AND json_type(reserved) = 'object'),
    gpu_uuid          TEXT GENERATED ALWAYS AS (json_extract(reserved, '$.gpu_uuid')) VIRTUAL,
    -- Milliseconds since the Unix epoch, unlike the other timestamps: the 10 s accept window (§6) is measured from
    -- here, and whole seconds would cut up to 1 s from it.
    offered_at_ms     INTEGER NOT NULL,
    accepted_at       INTEGER,
    started_at        INTEGER,
    ended_at          INTEGER,
    -- When the execution was confirmed dead: a JobFinished, a revoked offer, absence from a Hello, `lease_ttl_s`
    -- without contact, or the node's deletion. The reservation is held until this is set (§8 "Reservations are held
    -- until confirmed"), even when the lease or its job ended earlier.
    confirmed_dead_at INTEGER,
    -- Why the lease ended: a stable code, never a secret.
    end_reason        TEXT CHECK (end_reason IS NULL OR length(end_reason) BETWEEN 1 AND 256),
    -- The latest attempt to send a `Cancel` for a cancel request (sent again every 5 s until the node reports).
    cancel_sent_at    INTEGER,
    UNIQUE (job_id, epoch),
    -- A lease is active exactly while it has not ended, and an active lease always holds its reservation.
    CHECK ((state IN ('offered', 'accepted', 'running')) = (ended_at IS NULL)),
    CHECK (state NOT IN ('offered', 'accepted', 'running') OR confirmed_dead_at IS NULL),
    -- A finished lease reported its own end.
    CHECK (state <> 'finished' OR confirmed_dead_at IS NOT NULL)
) STRICT;

-- At most one active lease per job.
CREATE UNIQUE INDEX leases_one_active_per_job ON leases (job_id) WHERE state IN ('offered', 'accepted', 'running');
-- A GPU is held by at most one lease at a time, until that lease is confirmed dead.
CREATE UNIQUE INDEX leases_one_holder_per_gpu ON leases (node_id, gpu_uuid)
    WHERE gpu_uuid IS NOT NULL AND confirmed_dead_at IS NULL;
-- The reservations a node holds.
CREATE INDEX leases_node_held ON leases (node_id) WHERE confirmed_dead_at IS NULL;
-- Leases waiting for something: offers to time out, active leases to watch.
CREATE INDEX leases_state ON leases (state, offered_at_ms);

-- One row per attempt: an accepted lease (§7).
CREATE TABLE job_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT NOT NULL REFERENCES jobs (job_id),
    attempt     INTEGER NOT NULL CHECK (attempt >= 1),
    epoch       INTEGER NOT NULL CHECK (epoch >= 1),
    lease_id    TEXT NOT NULL UNIQUE REFERENCES leases (id),
    node_id     TEXT NOT NULL REFERENCES nodes (id),
    -- What the attempt came to; NULL while it is in progress.
    outcome     TEXT CHECK (outcome IS NULL OR outcome IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'lost')),
    reason_code TEXT CHECK (reason_code IS NULL OR length(reason_code) BETWEEN 1 AND 256),
    accepted_at INTEGER NOT NULL,
    started_at  INTEGER,
    ended_at    INTEGER,
    CHECK ((outcome IS NULL) = (ended_at IS NULL)),
    UNIQUE (job_id, epoch),
    UNIQUE (job_id, attempt)
) STRICT;

-- §8 "Offer cap": the same (job, node) pair is not offered again before `until`.
CREATE TABLE job_node_cooldowns (
    job_id  TEXT NOT NULL REFERENCES jobs (job_id),
    node_id TEXT NOT NULL REFERENCES nodes (id),
    until   INTEGER NOT NULL,
    PRIMARY KEY (job_id, node_id)
) STRICT, WITHOUT ROWID;

-- §11: the usage ledger, append-only, one row per finished attempt: one whose node reported JobFinished, or one that
-- ended with no report (the server ended it, or it was lost), estimated by the server (`estimated = 1`).
CREATE TABLE usage_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          TEXT NOT NULL REFERENCES jobs (job_id),
    attempt         INTEGER NOT NULL CHECK (attempt >= 1),
    lease_id        TEXT NOT NULL UNIQUE REFERENCES leases (id),
    node_id         TEXT NOT NULL REFERENCES nodes (id),
    key_id          TEXT NOT NULL REFERENCES api_keys (key_id),
    account_id      TEXT NOT NULL REFERENCES accounts (account_id),
    project_id      TEXT NOT NULL,
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER NOT NULL CHECK (ended_at >= started_at),
    reserved_cpu_ms INTEGER NOT NULL CHECK (reserved_cpu_ms >= 0),
    reserved_gpu_ms INTEGER NOT NULL CHECK (reserved_gpu_ms >= 0),
    used_cpu_ms     INTEGER NOT NULL CHECK (used_cpu_ms >= 0),
    max_rss_mb      INTEGER NOT NULL CHECK (max_rss_mb >= 0),
    -- Milli-units.
    units           INTEGER NOT NULL CHECK (units >= 0),
    -- 1 when the server estimated the row because the node never reported the end (watchdog, cancel on an unreachable
    -- node, node loss): the reservation from the start (or acceptance) to the end, nothing measured.
    estimated       INTEGER NOT NULL DEFAULT 0 CHECK (estimated IN (0, 1)),
    UNIQUE (job_id, attempt),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

CREATE INDEX usage_records_account_ended ON usage_records (account_id, ended_at);
CREATE INDEX usage_records_key_ended ON usage_records (key_id, ended_at);

CREATE TRIGGER usage_records_no_update BEFORE UPDATE ON usage_records
BEGIN
    SELECT RAISE(ABORT, 'usage_records is append-only');
END;

CREATE TRIGGER usage_records_no_delete BEFORE DELETE ON usage_records
BEGIN
    SELECT RAISE(ABORT, 'usage_records is append-only');
END;
