-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Disaster Recovery scan tracking for blob storage reconciliation.
-- Used when PostgreSQL is restored from backup but MinIO objects survive;
-- the scanner walks MinIO, compares with the blobs table, and can re-import orphans.

CREATE TABLE storage_dr_scans (
  id              BIGSERIAL   PRIMARY KEY,
  status          TEXT        NOT NULL DEFAULT 'running'
                      CHECK (status IN ('running','completed','failed')),
  total_scanned   BIGINT      NOT NULL DEFAULT 0,
  orphaned_count  BIGINT      NOT NULL DEFAULT 0,
  missing_count   BIGINT      NOT NULL DEFAULT 0,
  reimported_count BIGINT     NOT NULL DEFAULT 0,
  details         JSONB       DEFAULT '[]',
  started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at    TIMESTAMPTZ
);

CREATE INDEX storage_dr_scans_status_idx ON storage_dr_scans(status);
CREATE INDEX storage_dr_scans_started_idx ON storage_dr_scans(started_at DESC);
