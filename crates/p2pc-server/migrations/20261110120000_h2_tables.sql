-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T2-10: the new tables of H2 (H2 spec §13) and the two node columns of §5.5. Additive only; the tables whose
-- principal columns change (`jobs`, `usage_records`, `join_tokens`, `audit_events`) are rebuilt by the next
-- migration, which needs `devices` to exist first (§5.6). Timestamps are INTEGER Unix seconds (UTC). Forward-only.
--
-- No table here declares `ON DELETE CASCADE` towards `jobs` or `join_tokens`: the next migration drops and re-creates
-- both, and the implicit `DELETE` of a `DROP TABLE` would cascade into these rows.

-- A paired device: a principal like an API key, authenticated by its iroh NodeId on `p2pc/device/1` (§5.5). Its
-- project, scopes and limits come from the pairing ticket that created it (§5.2), or from `init --owner-device` and
-- `devices add` (§5.3). Revoked and expired rows are kept.
CREATE TABLE devices (
    device_id           TEXT PRIMARY KEY NOT NULL CHECK (device_id GLOB 'dev_*' AND length(device_id) = 30),
    account_id          TEXT NOT NULL REFERENCES accounts (account_id),
    project_id          TEXT NOT NULL,
    -- The device's iroh NodeId (lowercase hex of its Ed25519 public key): the credential, checked by iroh's TLS.
    iroh_node_id        TEXT NOT NULL
                        CHECK (length(iroh_node_id) = 64 AND NOT iroh_node_id GLOB '*[^0-9a-f]*'),
    label               TEXT CHECK (label IS NULL OR length(label) BETWEEN 1 AND 256),
    -- The free-text platform hint sent in `Pair` (at most 64 bytes); '' for devices registered offline.
    platform            TEXT NOT NULL DEFAULT '' CHECK (length(CAST(platform AS BLOB)) <= 64),
    scopes              TEXT NOT NULL CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
    -- Milli-units per UTC day; NULL means no cap.
    daily_unit_cap      INTEGER CHECK (daily_unit_cap IS NULL OR daily_unit_cap >= 0),
    -- JSON array of globs; NULL allows every image.
    allowed_images      TEXT CHECK (allowed_images IS NULL
                                    OR (json_valid(allowed_images) AND json_type(allowed_images) = 'array')),
    -- MiB of blobs the device may hold a claim on (§7.5); NULL: only the account's quota.
    blobs_quota_mb      INTEGER CHECK (blobs_quota_mb IS NULL OR blobs_quota_mb >= 0),
    -- NULL: the device never expires.
    expires_at          INTEGER,
    -- The principal that created its pairing ticket; both NULL for a device registered offline (§5.3).
    paired_by_key_id    TEXT REFERENCES api_keys (key_id),
    paired_by_device_id TEXT REFERENCES devices (device_id),
    created_at          INTEGER NOT NULL,
    -- Written at most once a minute (§5.5).
    last_seen_at        INTEGER,
    revoked_at          INTEGER,
    CHECK (paired_by_key_id IS NULL OR paired_by_device_id IS NULL),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

-- One unrevoked device per NodeId: the device check on `p2pc/device/1` is one indexed lookup (§6.3).
CREATE UNIQUE INDEX devices_unrevoked_iroh_node_id ON devices (iroh_node_id) WHERE revoked_at IS NULL;
CREATE INDEX devices_account_created ON devices (account_id, created_at, device_id);

-- A one-time pairing ticket (§5.2). Only SHA-256 of its 16-byte code is stored; the ticket is returned once.
CREATE TABLE pairing_tickets (
    id                   TEXT PRIMARY KEY NOT NULL CHECK (id GLOB 'ptk_*' AND length(id) = 30),
    account_id           TEXT NOT NULL REFERENCES accounts (account_id),
    project_id           TEXT NOT NULL,
    code_digest          TEXT NOT NULL UNIQUE
                         CHECK (length(code_digest) = 71
                                AND substr(code_digest, 1, 7) = 'sha256:'
                                AND NOT substr(code_digest, 8) GLOB '*[^0-9a-f]*'),
    -- What the device it pairs gets.
    label                TEXT CHECK (label IS NULL OR length(label) BETWEEN 1 AND 256),
    scopes               TEXT NOT NULL CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
    daily_unit_cap       INTEGER CHECK (daily_unit_cap IS NULL OR daily_unit_cap >= 0),
    allowed_images       TEXT CHECK (allowed_images IS NULL
                                     OR (json_valid(allowed_images) AND json_type(allowed_images) = 'array')),
    blobs_quota_mb       INTEGER CHECK (blobs_quota_mb IS NULL OR blobs_quota_mb >= 0),
    device_expires_at    INTEGER,
    -- The principal that created it: exactly one.
    created_by_key_id    TEXT REFERENCES api_keys (key_id),
    created_by_device_id TEXT REFERENCES devices (device_id),
    created_at           INTEGER NOT NULL,
    -- The only expiry that counts (the ticket's payload is not authenticated).
    expires_at           INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at          INTEGER,
    device_id            TEXT REFERENCES devices (device_id),
    revoked_at           INTEGER,
    CHECK ((created_by_key_id IS NULL) <> (created_by_device_id IS NULL)),
    CHECK (device_expires_at IS NULL OR device_expires_at > expires_at),
    CHECK (consumed_at IS NULL OR revoked_at IS NULL),
    CHECK ((consumed_at IS NULL) = (device_id IS NULL)),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

CREATE INDEX pairing_tickets_account_created ON pairing_tickets (account_id, created_at, id);

-- A join request (§5.4): an invite relayed by a phone, approved on the hub PC. It holds no secret: the listener
-- commitment and both nonces are public once revealed, and the join token it yields is stored only as a hash in
-- `join_tokens`.
CREATE TABLE join_requests (
    id                     TEXT PRIMARY KEY NOT NULL CHECK (id GLOB 'jrq_*' AND length(id) = 30),
    account_id             TEXT NOT NULL REFERENCES accounts (account_id),
    project_id             TEXT NOT NULL,
    -- The requesting principal (a `nodes:invite` device in practice): exactly one.
    requested_by_key_id    TEXT REFERENCES api_keys (key_id),
    requested_by_device_id TEXT REFERENCES devices (device_id),
    listener_node_id       TEXT NOT NULL
                           CHECK (length(listener_node_id) = 64 AND NOT listener_node_id GLOB '*[^0-9a-f]*'),
    iroh_node_id           TEXT NOT NULL
                           CHECK (length(iroh_node_id) = 64 AND NOT iroh_node_id GLOB '*[^0-9a-f]*'),
    invite_expires_at      INTEGER NOT NULL,
    listener_commitment    TEXT NOT NULL
                           CHECK (length(listener_commitment) = 64
                                  AND NOT listener_commitment GLOB '*[^0-9a-f]*'),
    -- Drawn by the hub after the row above is stored (§5.4 step 3).
    hub_nonce              TEXT NOT NULL CHECK (length(hub_nonce) = 64 AND NOT hub_nonce GLOB '*[^0-9a-f]*'),
    -- Set by the reveal that matched the commitment.
    listener_nonce         TEXT CHECK (listener_nonce IS NULL
                                       OR (length(listener_nonce) = 64 AND NOT listener_nonce GLOB '*[^0-9a-f]*')),
    state                  TEXT NOT NULL CHECK (state IN ('awaiting_reveal', 'pending', 'approved', 'rejected',
                                                          'expired', 'delivered')),
    created_at             INTEGER NOT NULL,
    -- `created_at` + 15 minutes. Approval and token minting are judged by `created_at`, never by `state` alone.
    expires_at             INTEGER NOT NULL CHECK (expires_at > created_at),
    revealed_at            INTEGER,
    approved_at            INTEGER,
    approved_by_key_id     TEXT REFERENCES api_keys (key_id),
    approved_by_device_id  TEXT REFERENCES devices (device_id),
    closed_at              INTEGER,
    delivered_at           INTEGER,
    join_token_id          TEXT REFERENCES join_tokens (id),
    CHECK ((requested_by_key_id IS NULL) <> (requested_by_device_id IS NULL)),
    CHECK (approved_by_key_id IS NULL OR approved_by_device_id IS NULL),
    CHECK ((approved_at IS NULL) = (approved_by_key_id IS NULL AND approved_by_device_id IS NULL)),
    -- No phrase before the reveal; every state past it has the revealed nonce.
    CHECK (state <> 'awaiting_reveal' OR listener_nonce IS NULL),
    CHECK (state NOT IN ('pending', 'approved', 'delivered') OR listener_nonce IS NOT NULL),
    CHECK (state NOT IN ('approved', 'delivered') OR approved_at IS NOT NULL),
    CHECK (state <> 'delivered' OR join_token_id IS NOT NULL),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

CREATE INDEX join_requests_account_created ON join_requests (account_id, created_at, id);
CREATE INDEX join_requests_device_created ON join_requests (requested_by_device_id, created_at)
    WHERE requested_by_device_id IS NOT NULL;
CREATE INDEX join_requests_key_created ON join_requests (requested_by_key_id, created_at)
    WHERE requested_by_key_id IS NOT NULL;

-- Blobs (§7.5): content-addressed per account. The file lives at `<data>/blobs/<account_id>/sha256/<aa>/<bb>/<hex>`.
CREATE TABLE blobs (
    account_id      TEXT NOT NULL REFERENCES accounts (account_id),
    sha256          TEXT NOT NULL CHECK (length(sha256) = 64 AND NOT sha256 GLOB '*[^0-9a-f]*'),
    size            INTEGER NOT NULL CHECK (size >= 0),
    created_at      INTEGER NOT NULL,
    -- The GC's tombstone (step 1): from then on the blob is absent to every reader.
    deleting_at     INTEGER,
    -- When the GC last tried to delete it (H1's retry-queue order).
    last_attempt_at INTEGER,
    PRIMARY KEY (account_id, sha256)
) STRICT, WITHOUT ROWID;

CREATE INDEX blobs_gc ON blobs (last_attempt_at, created_at);

-- One principal's claim on a blob (§5.6): exactly one principal column is set.
CREATE TABLE blob_uploaders (
    account_id            TEXT NOT NULL,
    sha256                TEXT NOT NULL,
    uploaded_by_key_id    TEXT REFERENCES api_keys (key_id),
    uploaded_by_device_id TEXT REFERENCES devices (device_id),
    created_at            INTEGER NOT NULL,
    CHECK ((uploaded_by_key_id IS NULL) <> (uploaded_by_device_id IS NULL)),
    FOREIGN KEY (account_id, sha256) REFERENCES blobs (account_id, sha256) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX blob_uploaders_key ON blob_uploaders (account_id, sha256, uploaded_by_key_id)
    WHERE uploaded_by_key_id IS NOT NULL;
CREATE UNIQUE INDEX blob_uploaders_device ON blob_uploaders (account_id, sha256, uploaded_by_device_id)
    WHERE uploaded_by_device_id IS NOT NULL;
CREATE INDEX blob_uploaders_device_quota ON blob_uploaders (uploaded_by_device_id)
    WHERE uploaded_by_device_id IS NOT NULL;

-- A job's blob inputs (§7.1 `inputs`), inserted in the job-creation transaction. Rows stay after the job ends: a
-- terminal job's references only extend the blob's lifetime (§7.5 "Lifetime"). No foreign key to `blobs`, whose rows
-- the GC deletes once they are expired.
CREATE TABLE blob_refs (
    job_id     TEXT NOT NULL REFERENCES jobs (job_id),
    path       TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 4096),
    account_id TEXT NOT NULL REFERENCES accounts (account_id),
    sha256     TEXT NOT NULL CHECK (length(sha256) = 64 AND NOT sha256 GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (job_id, path)
) STRICT, WITHOUT ROWID;

CREATE INDEX blob_refs_blob ON blob_refs (account_id, sha256);

-- The latest `VolumeReport` of each node (§6.1), for `GET /v1/volumes` and placement (§11.3).
CREATE TABLE volume_reports (
    node_id            TEXT NOT NULL REFERENCES nodes (id),
    name               TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    size_mb            INTEGER NOT NULL CHECK (size_mb >= 0),
    last_used_at       INTEGER,
    in_use_by_lease_id TEXT REFERENCES leases (id),
    reported_at        INTEGER NOT NULL,
    PRIMARY KEY (node_id, name)
) STRICT, WITHOUT ROWID;

-- The hub's state of a service job (§7.2, §7.6, §12). One row per service job.
CREATE TABLE service_state (
    job_id              TEXT PRIMARY KEY NOT NULL REFERENCES jobs (job_id),
    -- Health of the current attempt, from the agent's `ServiceHealth`.
    health              TEXT CHECK (health IS NULL OR health IN ('starting', 'healthy', 'unhealthy')),
    health_since        INTEGER,
    -- When the current attempt last became healthy: 10 minutes of health reset the count below.
    healthy_since       INTEGER,
    -- Written at most every 10 s (§7.4 "Idle accounting").
    last_activity_at    INTEGER,
    -- Consecutive attempts that never became healthy (§7.2).
    unhealthy_attempts  INTEGER NOT NULL DEFAULT 0 CHECK (unhealthy_attempts >= 0),
    -- JSON array of the Unix seconds of the node-loss restarts of the last 24 h (at most 5, §7.2).
    node_loss_restarts  TEXT NOT NULL DEFAULT '[]'
                        CHECK (json_valid(node_loss_restarts) AND json_type(node_loss_restarts) = 'array'),
    -- The hub's model pull of the current attempt (§7.6 `service.setup`); NULL for a job without one.
    setup_state         TEXT CHECK (setup_state IS NULL OR setup_state IN ('pulling', 'done', 'failed')),
    setup_completed_mb  INTEGER NOT NULL DEFAULT 0 CHECK (setup_completed_mb >= 0),
    setup_total_mb      INTEGER CHECK (setup_total_mb IS NULL OR setup_total_mb >= 0),
    setup_tries         INTEGER NOT NULL DEFAULT 0 CHECK (setup_tries BETWEEN 0 AND 2),
    setup_reason        TEXT CHECK (setup_reason IS NULL
                                    OR setup_reason IN ('error_line', 'bad_line', 'eof', 'stream_broken', 'deadline')),
    setup_try_started_at INTEGER,
    -- The day's cap reservation (§12): 00:00 UTC of the day and the milli-units reserved for it.
    cap_day             INTEGER CHECK (cap_day IS NULL OR cap_day % 86400 = 0),
    cap_reserved_units  INTEGER CHECK (cap_reserved_units IS NULL OR cap_reserved_units >= 0),
    updated_at          INTEGER NOT NULL,
    CHECK ((cap_day IS NULL) = (cap_reserved_units IS NULL)),
    CHECK (setup_state <> 'failed' OR setup_reason IS NOT NULL)
) STRICT;

CREATE INDEX service_state_cap_day ON service_state (cap_day) WHERE cap_day IS NOT NULL;

-- Service traffic per UTC day (§12): recorded, not billed, never logged.
CREATE TABLE service_traffic (
    job_id      TEXT NOT NULL REFERENCES jobs (job_id),
    day         INTEGER NOT NULL CHECK (day % 86400 = 0),
    bytes_in    INTEGER NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out   INTEGER NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    connections INTEGER NOT NULL DEFAULT 0 CHECK (connections >= 0),
    PRIMARY KEY (job_id, day)
) STRICT, WITHOUT ROWID;

-- The template bundle's high-water mark (§7.6): one row, the highest `bundle_version` ever loaded and its SHA-256.
CREATE TABLE template_bundle_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    bundle_version INTEGER NOT NULL CHECK (bundle_version >= 0),
    sha256         TEXT NOT NULL CHECK (length(sha256) = 64 AND NOT sha256 GLOB '*[^0-9a-f]*'),
    loaded_at      INTEGER NOT NULL
) STRICT;

-- Node approval (§5.5): every H1 node is `approved`. `enrolled_by_*` is the principal that minted the node's join
-- token (both NULL for H1 nodes), set once at enrollment.
ALTER TABLE nodes ADD COLUMN approval TEXT NOT NULL DEFAULT 'approved'
    CHECK (approval IN ('approved', 'pending_approval'));
ALTER TABLE nodes ADD COLUMN enrolled_by_key_id TEXT REFERENCES api_keys (key_id);
ALTER TABLE nodes ADD COLUMN enrolled_by_device_id TEXT REFERENCES devices (device_id)
    CHECK (enrolled_by_device_id IS NULL OR enrolled_by_key_id IS NULL);
