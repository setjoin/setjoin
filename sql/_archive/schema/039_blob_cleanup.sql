-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 039_blob_cleanup.sql — Deferred blob cleanup queue.
-- When a blob's ref_count drops to 0, it is queued here with a 5-minute
-- delay before deletion. This prevents premature deletion if a transaction
-- rolls back after the decrement, and enables deduplication across
-- concurrent deletes.
CREATE TABLE IF NOT EXISTS blob_cleanup_queue (
  blob_sha256   TEXT        PRIMARY KEY REFERENCES blobs(sha256) ON DELETE CASCADE,
  scheduled_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  delay_minutes INT         NOT NULL DEFAULT 5
);
