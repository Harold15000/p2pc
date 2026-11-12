-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T2-18: the hub's own settings (H2 spec §7.3, §13). One row at most, created by the first `PATCH /v1/server`; no
-- row means nothing was set, and `GET /v1/server` then leaves `hub_name` out. Additive only; forward-only.
-- Timestamps are INTEGER Unix seconds (UTC).

CREATE TABLE hub_settings (
    -- Always 1: the hub has one set of settings.
    id         INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    -- The hub's display name (`PATCH /v1/server`), 1-64 characters; shown by the apps and sent in `Paired` (§5.3).
    hub_name   TEXT CHECK (hub_name IS NULL OR length(hub_name) BETWEEN 1 AND 64),
    updated_at INTEGER NOT NULL
) STRICT;
