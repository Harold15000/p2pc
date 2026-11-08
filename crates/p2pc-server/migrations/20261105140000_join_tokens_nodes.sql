-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T05: join tokens, the node registry and the disconnection log (spec §5, §6, §8 "Disconnection log").
-- Timestamps are INTEGER Unix seconds (UTC). Migrations are forward-only.

CREATE TABLE join_tokens (
    id                  TEXT PRIMARY KEY NOT NULL CHECK (id GLOB 'jtk_*' AND length(id) = 30),
    account_id          TEXT NOT NULL REFERENCES accounts (account_id),
    project_id          TEXT NOT NULL,
    -- Versioned digest of the 16-byte code: 'sha256:' and 64 lowercase hex characters. Never the code itself.
    code_digest         TEXT NOT NULL UNIQUE
                        CHECK (length(code_digest) = 71
                               AND substr(code_digest, 1, 7) = 'sha256:'
                               AND NOT substr(code_digest, 8) GLOB '*[^0-9a-f]*'),
    label               TEXT CHECK (label IS NULL OR length(label) BETWEEN 1 AND 256),
    created_by_key_id   TEXT NOT NULL REFERENCES api_keys (key_id),
    created_at          INTEGER NOT NULL,
    -- The only expiry that counts (the token's own payload is not authenticated, §5).
    expires_at          INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at         INTEGER,
    consumed_by_node_id TEXT REFERENCES nodes (id),
    revoked_at          INTEGER,
    -- Consumed and revoked are exclusive, and a consumed token names its node.
    CHECK (consumed_at IS NULL OR revoked_at IS NULL),
    CHECK ((consumed_at IS NULL) = (consumed_by_node_id IS NULL)),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

CREATE INDEX join_tokens_account_created ON join_tokens (account_id, created_at, id);

CREATE TABLE nodes (
    id                    TEXT PRIMARY KEY NOT NULL CHECK (id GLOB 'node_*' AND length(id) = 31),
    account_id            TEXT NOT NULL REFERENCES accounts (account_id),
    project_id            TEXT NOT NULL,
    -- The agent's iroh NodeId (lowercase hex of its Ed25519 public key), authenticated by iroh's TLS.
    iroh_node_id          TEXT NOT NULL
                          CHECK (length(iroh_node_id) = 64 AND NOT iroh_node_id GLOB '*[^0-9a-f]*'),
    -- Derived by the server from the hostname; unique per account, case-insensitively (§5 "Names").
    name                  TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 63),
    hostname              TEXT NOT NULL,
    inventory             TEXT NOT NULL CHECK (json_valid(inventory) AND json_type(inventory) = 'object'),
    agent_version         TEXT NOT NULL,
    features              TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(features) AND json_type(features) = 'array'),
    -- `draining` here means connected and draining; the owner's drain request itself is the `draining` flag,
    -- which survives disconnects.
    state                 TEXT NOT NULL CHECK (state IN ('online', 'offline', 'draining')),
    draining              INTEGER NOT NULL DEFAULT 0 CHECK (draining IN (0, 1)),
    last_seen_at          INTEGER,
    enrolled_via_token_id TEXT NOT NULL REFERENCES join_tokens (id),
    created_at            INTEGER NOT NULL,
    -- Soft delete: the row stays for the audit trail and the job history.
    deleted_at            INTEGER,
    CHECK (state <> 'draining' OR draining = 1),
    FOREIGN KEY (project_id, account_id) REFERENCES projects (project_id, account_id)
) STRICT;

-- One live node per iroh NodeId; a deleted node's key may enrol again with a new token.
CREATE UNIQUE INDEX nodes_live_iroh_node_id ON nodes (iroh_node_id) WHERE deleted_at IS NULL;
-- Names are unique per account among live nodes, compared case-insensitively.
CREATE UNIQUE INDEX nodes_live_name ON nodes (account_id, name COLLATE NOCASE) WHERE deleted_at IS NULL;
CREATE INDEX nodes_account_created ON nodes (account_id, created_at, id);

CREATE TABLE node_disconnections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT NOT NULL REFERENCES nodes (id),
    last_contact_at INTEGER NOT NULL,
    resolved_at     INTEGER,
    -- `requeued` is written by T06's scheduler when it requeues the node's leases.
    outcome         TEXT CHECK (outcome IS NULL OR outcome IN ('recovered', 'offline', 'requeued')),
    CHECK ((resolved_at IS NULL) = (outcome IS NULL))
) STRICT;

-- At most one open disconnection per node.
CREATE UNIQUE INDEX node_disconnections_open ON node_disconnections (node_id) WHERE resolved_at IS NULL;
