-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T06e (ACC-1 round 3). Forward-only.
--
-- A finished lease keeps its reservation until the node frees it: the node's first `Heartbeat` after `JobFinished`
-- that no longer lists the lease (spec §8 "Reservations are held until confirmed"). Until then `confirmed_dead_at`
-- stays NULL on a `finished` lease, which the first `leases` table forbade:
--
--     CHECK (state <> 'finished' OR confirmed_dead_at IS NOT NULL)
--
-- SQLite cannot drop a CHECK in place, so `leases` is rebuilt without that one constraint (the procedure of
-- https://www.sqlite.org/lang_altertable.html#otheralter). Every other column, constraint and index is the same, and
-- every row is copied as it is, so a lease that finished under the old rule keeps its `confirmed_dead_at`.
--
-- The tables that reference `leases` (`job_attempts`, `usage_records`, `output_attempts`) keep pointing at it, and are
-- not touched (`usage_records` is append-only). The rows are saved in a temporary table, `leases` is dropped and created
-- again under its own name, and the rows go back into it. The foreign keys are checked at COMMIT
-- (`defer_foreign_keys`): dropping the table counts a violation for every child row, and inserting a parent row
-- again takes it back, so at COMMIT none is left. The migration runs in one transaction, so a failure leaves the old
-- table.

PRAGMA defer_foreign_keys = ON;

CREATE TEMP TABLE leases_saved AS
SELECT id, job_id, node_id, epoch, attempt, state, reserved, offered_at_ms, accepted_at, started_at,
       ended_at, confirmed_dead_at, end_reason, cancel_sent_at
FROM leases;

-- The indexes of the old table go with it.
DROP TABLE leases;

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
    -- When the node's resources for the lease were confirmed free: the node's first `Heartbeat` that no longer lists
    -- a finished lease, a revoked offer, a `JobFinished` of a lease the server had ended, absence from a `Hello`,
    -- `lease_ttl_s` without contact, or the node's deletion. The reservation is held until this is set (§8
    -- "Reservations are held until confirmed"), even when the lease or its job ended earlier. A `finished` lease can
    -- have it NULL: the node reported the end and is still cleaning up.
    confirmed_dead_at INTEGER,
    -- Why the lease ended: a stable code, never a secret.
    end_reason        TEXT CHECK (end_reason IS NULL OR length(end_reason) BETWEEN 1 AND 256),
    -- The latest attempt to send a `Cancel` for a cancel request (sent again every 5 s until the node reports).
    cancel_sent_at    INTEGER,
    UNIQUE (job_id, epoch),
    -- A lease is active exactly while it has not ended, and an active lease always holds its reservation.
    CHECK ((state IN ('offered', 'accepted', 'running')) = (ended_at IS NULL)),
    CHECK (state NOT IN ('offered', 'accepted', 'running') OR confirmed_dead_at IS NULL)
) STRICT;

INSERT INTO leases (id, job_id, node_id, epoch, attempt, state, reserved, offered_at_ms, accepted_at, started_at,
                    ended_at, confirmed_dead_at, end_reason, cancel_sent_at)
SELECT id, job_id, node_id, epoch, attempt, state, reserved, offered_at_ms, accepted_at, started_at,
       ended_at, confirmed_dead_at, end_reason, cancel_sent_at
FROM leases_saved;

DROP TABLE leases_saved;

-- At most one active lease per job.
CREATE UNIQUE INDEX leases_one_active_per_job ON leases (job_id) WHERE state IN ('offered', 'accepted', 'running');
-- A GPU is held by at most one lease at a time, until that lease is confirmed dead.
CREATE UNIQUE INDEX leases_one_holder_per_gpu ON leases (node_id, gpu_uuid)
    WHERE gpu_uuid IS NOT NULL AND confirmed_dead_at IS NULL;
-- The reservations a node holds.
CREATE INDEX leases_node_held ON leases (node_id) WHERE confirmed_dead_at IS NULL;
-- Leases waiting for something: offers to time out, active leases to watch.
CREATE INDEX leases_state ON leases (state, offered_at_ms);
