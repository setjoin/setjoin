-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V063: Storage migration tracking for cross-driver blob migration.
CREATE TABLE IF NOT EXISTS storage_migrations (
  id            BIGSERIAL PRIMARY KEY,
  source_driver TEXT NOT NULL,
  target_driver TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'dual_write'
                CHECK (status IN ('dual_write','backfill','cutover','completed','failed','cancelled')),
  total_blobs   BIGINT,
  migrated      BIGINT DEFAULT 0,
  last_key      TEXT,
  error_message TEXT,
  started_at    TIMESTAMPTZ DEFAULT now(),
  completed_at  TIMESTAMPTZ
);
