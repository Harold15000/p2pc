-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Review P3 (T10b): the GC records that a job's logs and artifacts expire (`artifact_gc`, before it deletes them, so
-- the API shows them expired at once), and now also when they are actually gone. `removed_at` is set only after the
-- files are deleted; a row where it is still NULL is retried by the next pass. Forward-only.
--
-- Rows written before this column get NULL: the next pass deletes their directories again, which is harmless (a
-- missing directory is not an error) and then records them removed.

ALTER TABLE artifact_gc ADD COLUMN removed_at INTEGER;

-- The GC's scan of what is still to be deleted.
CREATE INDEX artifact_gc_pending ON artifact_gc (expired_at, job_id) WHERE removed_at IS NULL;

-- The staging scan now also covers finalised attempts (their `.staging` is removed at finalisation, and
-- `staging_removed_at` is set only when that worked), so the partial index no longer filters on `finalized_at`.
DROP INDEX output_attempts_open;
CREATE INDEX output_attempts_staging ON output_attempts (job_id, attempt) WHERE staging_removed_at IS NULL;
