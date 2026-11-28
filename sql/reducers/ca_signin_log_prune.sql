-- ca_signin_log_prune.sql (CA-0b): retention prune for the append-only telemetry
-- table. Sets a txn-local GUC (ca.signin_log_prune='on') that the append-only
-- trigger checks — this is the ONLY authorised DELETE path, regardless of the
-- caller's role. SECURITY DEFINER so it has DELETE privilege even when called
-- from the main pool (default deployment, DB_WORKER_DSN not yet split).
-- Called by the prune-ca-signin-log cron task. Returns rows deleted. (Spec L6/§8 #6.)
-- med-shard3-010: destructive-parameter guard (CWE-20) — zero, negative or
-- NULL day counts are REFUSED (BZ040, generic invalidArguments slug) BEFORE
-- the GUC is armed, so a bad system_config value (the cron task SQL reads
-- ca_signin_log_retain_days unclamped) can never open a deletion window over
-- the whole table. The sanctioned transaction-local GUC path and the armed
-- append-only trigger are unchanged.
CREATE OR REPLACE FUNCTION ca_signin_log_prune(p_retain_days int) RETURNS bigint AS $$
DECLARE
  v_deleted bigint;
BEGIN
  IF p_retain_days IS NULL OR p_retain_days <= 0 THEN
    RAISE EXCEPTION 'ca_signin_log_prune: p_retain_days must be a positive day count (got %)',
      COALESCE(p_retain_days, -1)
      USING ERRCODE = 'BZ040',
      HINT = '{"type":"invalidArguments","param":"p_retain_days"}'::TEXT;
  END IF;

  -- Arm the txn-local flag the append-only trigger requires.
  PERFORM set_config('ca.signin_log_prune', 'on', true);
  DELETE FROM ca_signin_log
   WHERE occurred_at < now() - make_interval(days => p_retain_days);
  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;
