-- V118__worker_ownership_applicator.sql — Drive architecture-hardening Task 2.
-- Plan: docs/superpowers/plans/archive/2026-07-11-drive-architecture-hardening.md

-- ===== Section 1: apply_worker_ownership applicator (C4) =====
-- Collapses the repeated DEFINER-under-FORCE-RLS worker-ownership footer
-- (OWNER TO setjoin_worker + REVOKE EXECUTE FROM PUBLIC + GRANT EXECUTE to
-- setjoin_app/setjoin_owner/setjoin_worker) that every such reducer pastes
-- inline today (e.g. drive_file_unlock.sql) into one call. Lives in the
-- schema layer, not reducers/, so it exists before any reducer file that
-- calls it loads (schema loads before reducers).
-- ponytail: generic name — repo-wide reusable; only Drive is wired in Task 3.
CREATE OR REPLACE FUNCTION apply_worker_ownership(p_func regprocedure) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
    EXECUTE format('ALTER FUNCTION %s OWNER TO setjoin_worker', p_func::text);
  END IF;
  EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', p_func::text);
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_app', p_func::text); END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_owner', p_func::text); END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_worker', p_func::text); END IF;
END $$;

-- ===== Section 2: WORM-pending generated column (C3) =====
-- Replaces the byte-copied "retain_until IS NOT NULL AND (worm_applied_until
-- IS NULL OR worm_applied_until < retain_until)" predicate (6 sites:
-- drive_member_grant.sql, drive_export_request.sql, drive_export_consume.sql,
-- drive_worm_pending.sql, worker.go, worm_live_test.go) with one STORED
-- generated column every reader filters/reads instead of re-deriving. Pure
-- function of drive_chunks' own columns (no now()/volatile), so STORED is
-- valid. Swaps the V116 partial index to the column — same name, same key
-- column (scope_key; drive_chunks has NO space_id — it is content-addressed,
-- keyed on scope_key/sha256), only the predicate changes.
ALTER TABLE public.drive_chunks
  ADD COLUMN worm_pending boolean
  GENERATED ALWAYS AS (retain_until IS NOT NULL
    AND (worm_applied_until IS NULL OR worm_applied_until < retain_until)) STORED;
DROP INDEX IF EXISTS drive_chunks_worm_pending_idx;
CREATE INDEX drive_chunks_worm_pending_idx ON public.drive_chunks (scope_key) WHERE worm_pending;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (118, now())
ON CONFLICT (version) DO NOTHING;
