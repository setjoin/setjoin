-- prune_session_runtime.sql — setjoin_worker cron prune of expired CAE state.
-- Cross-user maintenance; session_revocations and session_activity are FORCE RLS'd
-- with only FOR-SELECT (+ V057 INSERT) policies, so a DELETE under the default
-- (NOBYPASSRLS) worker pool is default-deny → 0 rows, no error. SECURITY DEFINER so
-- the prune succeeds when DB_WORKER_DSN is not yet split and the caller is the
-- regular pool — mirrors prune_changes_journal. Registered as the
-- 'prune-session-runtime' daily cron task in mailserver/internal/cron/tasks.go.
-- Returns total rows pruned across both tables.
-- ponytail: 7-day session_activity TTL matches a typical max access-token TTL;
--           upgrade path = make it a system_config key when it needs to vary.
CREATE OR REPLACE FUNCTION prune_session_runtime() RETURNS INT AS $$
DECLARE v_n INT := 0; v_d INT;
BEGIN
  DELETE FROM session_revocations WHERE expires_at IS NOT NULL AND expires_at < now();
  GET DIAGNOSTICS v_d = ROW_COUNT; v_n := v_n + v_d;
  DELETE FROM session_activity WHERE last_activity < now() - interval '7 days';
  GET DIAGNOSTICS v_d = ROW_COUNT; v_n := v_n + v_d;
  RETURN v_n;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;
