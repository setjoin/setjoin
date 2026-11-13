-- Reducer: prune_old_lockouts — the ONE cleanup path for auth_lockouts,
-- scheduled in the Go cron registry (mailserver/internal/cron: task
-- "prune-auth-lockouts", @every 5m). The historical pg_cron schedule never
-- landed a Go-registry replacement, so even expired rows were never removed
-- in deployed systems; this function + the registration bound the table.
--
-- Coverage (D-AUTHSERVER-SQL-REDUCERS-002):
--   1. Recovery — pre-existing excessive lock durations (far-future
--      locked_until left by the pre-cap escalation overflow) are normalized
--      to the saturating maximum (900s * 2^5 = 8h, the lockout_escalate cap)
--      WITHOUT touching failed_count/escalation_level: failure accounting is
--      preserved, the attacker is not silently un-locked.
--   2. Expired locks — rows whose lock has passed AND reached the failure
--      threshold are fully prunable (the original documented behaviour).
--   3. Stale sub-threshold counters — failure counters below the threshold
--      are kept for a retention window that is LONG relative to the maximum
--      escalation window (24h retention vs 8h max lock) and only then
--      removed. An ACTIVE attacker's recent sub-threshold failure history is
--      never erased by the schedule: every new failure refreshes updated_at,
--      so prune cycles cannot reset a building escalation history (the old
--      failed_count >= 5 predicate deleted nothing below the threshold —
--      unbounded growth — while a naive locked_until < now() predicate would
--      have deleted this history every cycle and defeated escalation).
--
-- Signature note: the legacy zero-arg signature is dropped first so
-- prune_old_lockouts() (the form the Go cron registration calls) resolves to
-- the parameterized default-arg version, never an ambiguous overload pair.
--
-- SECURITY DEFINER + worker-only ACLs (PLAN-20260913 D2 / REDUCERS-004, the
-- V259 deny-all FORCE flip): auth_lockouts is deny-all FORCE RLS for every
-- runtime role, so this cleanup path is one of the table's trusted seams.
-- SECURITY DEFINER owned by setjoin_worker (BYPASSRLS) keeps the mailserver
-- cron registry's `SELECT prune_old_lockouts()` working unchanged on the
-- worker pool (mailserver/internal/cron tasks.go "prune-auth-lockouts").
-- The ACL footer follows security_event_enqueue.sql:72-78 — deliberately NOT
-- apply_worker_ownership(), whose contract grants setjoin_app EXECUTE
-- (V118:19-20); the exact signature belongs in provision-roles.sql's
-- worker-only carve-out block (re-established after the broad
-- GRANT EXECUTE ON ALL FUNCTIONS, provision-roles.sql:168).
DROP FUNCTION IF EXISTS prune_old_lockouts();
CREATE OR REPLACE FUNCTION prune_old_lockouts(
    p_threshold       INT DEFAULT 5,
    p_retention_hours INT DEFAULT 24
) RETURNS INT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_max_window INTERVAL := INTERVAL '8 hours';  -- lockout_escalate cap: 900s * 2^5
    v_deleted    INT;
BEGIN
    -- Recovery pass: clamp far-future legacy locks to the saturating maximum.
    -- Legitimate windows never exceed 8h ahead at write time, so only
    -- overflow-era rows match; normalization keeps them locked (finite) and
    -- keeps every counter.
    UPDATE auth_lockouts
    SET locked_until = now() + v_max_window
    WHERE locked_until > now() + v_max_window;

    DELETE FROM auth_lockouts
    WHERE locked_until < now()
      AND (
          -- expired lock that reached the threshold: fully recoverable.
          -- failed_count is the stored POST-increment count, and
          -- lockout_escalate arms locked_until on the very attempt the count
          -- reaches p_threshold, so this arm only matches rows whose lock has
          -- since EXPIRED — never the fresh history of an attacker whose
          -- count just crossed the threshold.
          failed_count >= p_threshold
          -- sub-threshold counter: only when stale beyond the retention
          -- window (fresh attacker history survives every cycle)
          OR updated_at < now() - (p_retention_hours * INTERVAL '1 hour')
      );

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

-- ── Worker-only function ACLs (security_event_enqueue.sql:72-78 form) ──────
ALTER FUNCTION prune_old_lockouts(INT, INT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION prune_old_lockouts(INT, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION prune_old_lockouts(INT, INT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION prune_old_lockouts(INT, INT) TO setjoin_worker;
