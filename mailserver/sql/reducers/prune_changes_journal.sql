-- prune_changes_journal.sql: retention prune for the JMAP change journal.
-- Cross-tenant (run by the setjoin_worker BYPASSRLS cron — the admin/cron
-- exception to R1). SECURITY DEFINER so the DELETE succeeds when DB_WORKER_DSN
-- is not yet split and the caller is the regular pool (FORCE RLS on
-- jmap_changes_journal would otherwise reject cross-tenant deletes). Mirrors the
-- ca_signin_log_prune / login_events_prune pattern for the default deployment.
--
-- F7 retention invariant: retention is ALWAYS >= MAX(configured offline window)
-- AND >= the RFC 8620 §5.3 30-day SHOULD floor (p_max_window_days is clamped UP
-- via GREATEST, never DOWN). A misconfigured too-small window retains MORE, never
-- strands windowed clients into perpetual cannotCalculateChanges.
--
-- Two arms:
--   1. Time-based DELETE: rows older than GREATEST(p_max_window_days, 30) days.
--   2. High-water cap: per-mailbox row-count cap (covers All-window / NULL-days
--      accounts that escape the time arm; keeps the journal bounded).
--
-- Returns total deleted rows.
CREATE OR REPLACE FUNCTION prune_changes_journal(
  p_max_window_days INT DEFAULT 30,
  p_high_water      INT DEFAULT 50000
) RETURNS BIGINT AS $$
DECLARE
  v_invoker_role   TEXT := COALESCE(NULLIF(current_setting('role', TRUE), 'none'), session_user);
  v_deleted        BIGINT := 0;
  v_n              BIGINT;
  -- Wave 2.6 (#553): uniform GREATEST(requested, configured_offline_window_days, 30) floor.
  v_retention_days INT    := public.effective_journal_retention_days(p_max_window_days);
  v_high_water     INT    := GREATEST(COALESCE(p_high_water, 50000), 0);
  v_cutoff         TIMESTAMPTZ := now() - make_interval(days => v_retention_days);
BEGIN
  PERFORM public.work_queue_require_worker();
  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_roles
     WHERE rolname = v_invoker_role
       AND (rolbypassrls OR rolsuper)
  ) THEN
    RAISE EXCEPTION 'prune_changes_journal: worker privilege (BYPASSRLS or superuser) required'
      USING ERRCODE = 'BZ003',
            HINT = '{"type":"worker_privilege_required"}';
  END IF;

  -- Arm 1: contiguous prefix-only age prune per (mailbox_id, datatype) so
  -- concurrent transactions with skewed timestamps never punch a hole after a
  -- retained sequence.
  WITH bounds AS (
    SELECT mailbox_id, datatype,
           MIN(state_seq) FILTER (WHERE created_at >= v_cutoff) AS keep_from_seq
      FROM jmap_changes_journal
     GROUP BY mailbox_id, datatype
  ),
  del AS (
    DELETE FROM jmap_changes_journal j
     USING bounds b
     WHERE j.mailbox_id = b.mailbox_id
       AND j.datatype   = b.datatype
       AND (b.keep_from_seq IS NULL OR j.state_seq < b.keep_from_seq)
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM del;
  v_deleted := v_deleted + v_n;

  -- Arm 2: high-water cap per mailbox (covers All-window accounts with
  -- offline_window_days IS NULL — they have no finite time horizon so the time
  -- arm never prunes them; the cap keeps the journal bounded).
  -- ponytail: dense_rank over state_seq DESC lets multiple rows at one seq
  -- (F2 batch) count as one rank — correct behaviour for the journal PK shape.
  WITH ranked AS (
    SELECT mailbox_id, datatype, state_seq,
           dense_rank() OVER (PARTITION BY mailbox_id, datatype ORDER BY state_seq DESC) AS rnk
      FROM jmap_changes_journal
  ),
  del2 AS (
    DELETE FROM jmap_changes_journal j
     USING ranked r
     WHERE j.mailbox_id = r.mailbox_id
       AND j.datatype   = r.datatype
       AND j.state_seq  = r.state_seq
       AND r.rnk > v_high_water
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM del2;
  v_deleted := v_deleted + v_n;

  RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

DO $$
DECLARE
  v_granted_create BOOLEAN := FALSE;
BEGIN
  REVOKE ALL ON FUNCTION public.prune_changes_journal(integer, integer) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    REVOKE ALL ON FUNCTION public.prune_changes_journal(integer, integer) FROM setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      GRANT CREATE ON SCHEMA public TO setjoin_worker;
      v_granted_create := TRUE;
    END IF;
    ALTER FUNCTION public.prune_changes_journal(integer, integer) OWNER TO setjoin_worker;
    GRANT EXECUTE ON FUNCTION public.prune_changes_journal(integer, integer) TO setjoin_worker;
    IF v_granted_create THEN
      REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
    END IF;
  END IF;
END $$;
