-- ════════════════════════════════════════════════════════════════════════
-- V006__backup_manifest_timestamp.sql — forward migration (Backup/Restore DR, P3).
--
-- GFS retention (backup.Engine.ApplyRetention) prunes old backup runs by deleting
-- their per-run index objects from the backup store: backup-manifest-<ts>.json,
-- manifests/incr-<ts>.json, config-<ts>.json. Those keys are suffixed with the
-- manifest timestamp the worker generates at write time (Format 20060102T150405Z),
-- which the backup_runs row did NOT record — so retention had no way to know which
-- objects belong to a run. This adds the column the worker now writes on success
-- and ApplyRetention reads to build the delete keys.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.backup_runs ADD COLUMN IF NOT EXISTS manifest_timestamp TEXT;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (6, now())
    ON CONFLICT (version) DO NOTHING;
