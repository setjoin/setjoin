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
  v_deleted        BIGINT := 0;
  v_n              BIGINT;
  -- ponytail: clamp UP to RFC 8620 floor; a too-small arg retains more, never less.
  v_retention_days INT    := GREATEST(p_max_window_days, 30);
BEGIN
  -- Arm 1: time-based prune at the clamped retention window.
  -- idx_changes_journal_prune (mailbox_id, created_at) covers this delete path.
  WITH del AS (
    DELETE FROM jmap_changes_journal
     WHERE created_at < now() - make_interval(days => v_retention_days)
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
       AND r.rnk > p_high_water
    RETURNING 1
  )
  SELECT count(*) INTO v_n FROM del2;
  v_deleted := v_deleted + v_n;

  RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;
