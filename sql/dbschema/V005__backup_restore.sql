-- ════════════════════════════════════════════════════════════════════════
-- V005__backup_restore.sql — forward migration (Backup/Restore DR, P0).
--
-- Restores the backup/restore data model that the ARCH-007 baseline collapse
-- dropped: `backup_runs` (+ its NOTIFY trigger) and `restore_jobs`. The
-- pre-collapse definitions lived in the now-archived
-- mailserver/sql/_archive/schema/047_backup_runs.sql; they were never carried
-- into V001__baseline.sql, so the backup worker (internal/backup/engine.go) has
-- been writing to a non-existent table and the feature has been dormant. This
-- migration re-creates the tables the worker + the restore engine require, so
-- the DR build (docs/superpowers/plans/archive/2026-06-21-backup-restore-dr.md) can wire
-- a live trigger source, manifest emission, retention, replica, and restore on
-- top of a real schema.
--
-- These are org-wide OPERATOR tables (no per-user data, no user_id) — like
-- schema_migrations / system_config they carry NO row-level security; access is
-- gated at the gateway by the backup.read / backup.write admin permissions. The
-- native-RLS program (V003/V004) FORCEs RLS only on the per-user partitioned
-- tables (messages / message_tags); ops tables are out of that scope by design.
-- ════════════════════════════════════════════════════════════════════════

-- ── backup_runs: one row per backup execution (manual or scheduled). ──────────
-- A row INSERT fires trg_backup_runs_notify → pg_notify('backup_run', id) → the
-- backup.Engine.Worker picks it up. Columns match internal/backup/engine.go's
-- UPDATEs (status/started_at/completed_at/blob_count/blobs_copied/blobs_skipped/
-- error_log) plus the manifest/retention bookkeeping the DR build writes.
CREATE TABLE IF NOT EXISTS public.backup_runs (
    id               BIGSERIAL PRIMARY KEY,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    retention_policy JSONB,
    config_size      BIGINT,
    blob_count       INTEGER,
    blob_total_size  BIGINT,
    blobs_copied     INTEGER,
    blobs_skipped    INTEGER,
    error_log        JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at       TIMESTAMP WITH TIME ZONE,
    completed_at     TIMESTAMP WITH TIME ZONE,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_backup_runs_status ON public.backup_runs (status);
CREATE INDEX IF NOT EXISTS idx_backup_runs_created_at ON public.backup_runs (created_at DESC);

-- Trigger: NOTIFY the dormant backup worker the instant a job row appears. This
-- is the edge the collapse severed — re-adding it (plus a live INSERT path in
-- P1) is what ends the dormancy.
CREATE OR REPLACE FUNCTION public.trg_backup_runs_notify()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('backup_run', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_backup_runs_insert ON public.backup_runs;
CREATE TRIGGER trg_backup_runs_insert
AFTER INSERT ON public.backup_runs
FOR EACH ROW EXECUTE FUNCTION public.trg_backup_runs_notify();

-- ── restore_jobs: one row per restore execution (first-boot wizard or mailctl). ─
-- The single-flight guard (a pending/running row + a pg_advisory_lock) prevents
-- two concurrent restores from colliding. backup_timestamp records which backup
-- manifest the restore targets.
CREATE TABLE IF NOT EXISTS public.restore_jobs (
    id               BIGSERIAL PRIMARY KEY,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    restore_type     TEXT NOT NULL
                     CHECK (restore_type IN ('full', 'config', 'blobs')),
    backup_timestamp TEXT,
    error_log        JSONB NOT NULL DEFAULT '[]'::jsonb,
    started_at       TIMESTAMP WITH TIME ZONE,
    completed_at     TIMESTAMP WITH TIME ZONE,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_restore_jobs_status ON public.restore_jobs (status);
CREATE INDEX IF NOT EXISTS idx_restore_jobs_created_at ON public.restore_jobs (created_at DESC);

-- Advance MAX(version) so the loader's apply step + main.go startup guard +
-- admin SchemaVersionStatus see this migration as applied (matches the V001 seed
-- columns version, applied_at). dbschema.ExpectedVersion() auto-derives 5 from
-- this filename.
INSERT INTO public.schema_migrations (version, applied_at) VALUES (5, now())
    ON CONFLICT (version) DO NOTHING;
