-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 047: Backup runs table for scheduled backup jobs (Phase 37 storage HA).
CREATE TABLE IF NOT EXISTS backup_runs (
    id              BIGSERIAL PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','completed','failed')),
    retention_policy JSONB,
    config_size     BIGINT,
    blob_count      INT,
    blob_total_size BIGINT,
    blobs_copied    INT,
    blobs_skipped   INT,
    error_log       JSONB NOT NULL DEFAULT '[]',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Trigger to NOTIFY the backup worker on new backup jobs.
CREATE OR REPLACE FUNCTION trg_backup_runs_notify()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('backup_run', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_backup_runs_insert ON backup_runs;
CREATE TRIGGER trg_backup_runs_insert
AFTER INSERT ON backup_runs
FOR EACH ROW EXECUTE FUNCTION trg_backup_runs_notify();
