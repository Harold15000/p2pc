-- SPDX-License-Identifier: AGPL-3.0-only
--
-- T10d (hardening after T10b). Forward-only.
--
-- 1. `finalizing_at`: finalisation no longer holds SQLite's write lock while it moves files. Its first short
--    transaction sets this column (uploads are refused from then on, like after `finalized_at`) and reads the staged
--    files; the files are moved with no lock held; a second short transaction records the publication and sets
--    `finalized_at`. A crash in between (or a failed fsync of the directories, which the scheduler does not retry)
--    leaves `finalizing_at` set and `finalized_at` NULL. Nothing finalises such an attempt again unless `JobFinished`
--    is delivered again; otherwise the GC's staging sweep finishes it, an hour after its lease ended: it publishes the
--    files that were already moved to `files/` and discards the rest.
-- 2. `last_attempt_at`: when the GC last tried to delete what a row stands for, successfully or not. The GC takes the
--    rows it never tried first and the ones it tried longest ago next, so a few undeletable directories go to the
--    back of the queue instead of using every pass's limit.

ALTER TABLE output_attempts ADD COLUMN finalizing_at INTEGER;
ALTER TABLE output_attempts ADD COLUMN last_attempt_at INTEGER;
ALTER TABLE artifact_gc ADD COLUMN last_attempt_at INTEGER;

-- The GC's scan of what is still to be deleted, in its new order.
DROP INDEX artifact_gc_pending;
CREATE INDEX artifact_gc_pending ON artifact_gc (last_attempt_at, expired_at, job_id) WHERE removed_at IS NULL;

-- The staging scan, in the same order (never tried first, then the longest ago), so the queue needs no sort.
DROP INDEX output_attempts_staging;
CREATE INDEX output_attempts_staging ON output_attempts (last_attempt_at, job_id, attempt) WHERE staging_removed_at IS NULL;
