-- Reducer: lockout_escalate — atomic lockout escalation with exponential backoff.
-- Increments failed_count, extends locked_until with doubling duration per escalation.
-- Returns the new escalation level (0-indexed).
-- Threshold semantics are POST-increment: the CASE expressions below see the
-- PRE-increment failed_count, so the predicate adds the increment back
-- (failed_count + 1 >= p_threshold) and escalation fires on the attempt whose
-- count REACHES p_threshold — never one attempt late. A row that just crossed
-- the threshold is therefore already locked, and prune_old_lockouts (which
-- reads the same stored post-increment counts) can never treat its fresh
-- history as an expired threshold lock.
-- The escalation level is CAPPED (v_max_level): repeated unauthenticated
-- failures must not grow per-identity lockouts without bound (900s * 2^level
-- reaches days at level 8 and overflows the POWER into absurd intervals at
-- extreme levels). At the cap the level stops growing and every further
-- escalation re-arms the maximum window (900s * 2^5 = 8h).
--
-- Audit + notify (D-AUTHSERVER-SQL-REDUCERS-003): every call that ARMS or
-- RE-ARMS a lock (the threshold-crossing branch — post-update locked_until is
-- in the future) also INSERTs an audit_log row in this same statement stream,
-- so data + state bump + audit + pg_notify commit atomically with the
-- caller's transaction. The pg_notify half rides the live audit_log INSERT
-- trigger trg_audit_log_notify ('audit:anon' channel — lockout keys are
-- pre-auth ip/username keys, not user ids). Sub-threshold failures and the
-- first-failure INSERT branch are NOT escalated events and write no audit
-- row. Note: like every audit_log writer, this INSERT requires the current-
-- month partition to exist (startup partition maintenance owns that; there is
-- no default catch-all partition).
--
-- SECURITY DEFINER + worker-only ACLs (PLAN-20260913 D2 / REDUCERS-004, the
-- V259 deny-all FORCE flip): auth_lockouts is deny-all FORCE RLS for every
-- runtime role, so this mutator is one of the table's trusted seams. The
-- definer is setjoin_worker (BYPASSRLS), so the escalation lands identically
-- regardless of the caller's pool credential. The ACL footer below follows
-- security_event_enqueue.sql:72-78 (OWNER TO setjoin_worker + REVOKE from
-- PUBLIC/setjoin_app + GRANT to setjoin_worker) — deliberately NOT
-- apply_worker_ownership(), whose contract grants setjoin_app EXECUTE
-- (V118:19-20). The exact signature belongs in provision-roles.sql's
-- worker-only carve-out block so every provisioning run re-establishes the
-- denial after the broad GRANT EXECUTE ON ALL FUNCTIONS
-- (provision-roles.sql:168) — the same registration duty V253 carries.
-- Signature is UNCHANGED (shared/threat calls `SELECT lockout_escalate($1)`).
CREATE OR REPLACE FUNCTION lockout_escalate(
    p_lockout_key  TEXT,
    p_threshold    INT DEFAULT 5
) RETURNS INT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_base_seconds INT := 900;  -- 15 minutes
    v_max_level    INT := 5;    -- cap: 900s * 2^5 = 8h maximum lockout window
    v_new_level    INT;
    v_failed_count INT;
    v_locked_until TIMESTAMPTZ;
BEGIN
    UPDATE auth_lockouts
    SET
        failed_count     = failed_count + 1,
        escalation_level = CASE
            -- Post-increment: `failed_count` here is the pre-increment value;
            -- the increment in this same UPDATE is what crosses the threshold.
            WHEN failed_count + 1 >= p_threshold AND escalation_level < v_max_level
            THEN escalation_level + 1
            ELSE escalation_level
        END,
        locked_until = CASE
            WHEN failed_count + 1 >= p_threshold  -- post-increment, matches above
            THEN now() + (v_base_seconds * POWER(2, LEAST(escalation_level + 1, v_max_level))) * INTERVAL '1 second'
            ELSE locked_until
        END,
        updated_at    = now()
    WHERE lockout_key = p_lockout_key
    RETURNING escalation_level, failed_count, locked_until
      INTO v_new_level, v_failed_count, v_locked_until;

    -- Row did not exist: insert first failing attempt without lockout
    IF v_new_level IS NULL THEN
        INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until, escalation_level)
        VALUES (p_lockout_key, 1, now(), 0)
        ON CONFLICT (lockout_key) DO NOTHING;
        RETURN 0;
    END IF;

    -- Escalation audit row: written only when this call armed/re-armed a lock
    -- (post-update locked_until in the future). The row lands in the SAME
    -- transaction as the state bump; trg_audit_log_notify fires the
    -- 'audit:anon' pg_notify on INSERT (user_id is NULL — pre-auth key).
    IF v_locked_until > now() THEN
        INSERT INTO audit_log (user_id, event_type, metadata)
        VALUES (
            NULL,
            'lockout_escalate',
            jsonb_build_object(
                'lockout_key',      p_lockout_key,
                'failed_count',     v_failed_count,
                'escalation_level', v_new_level,
                'locked_until',     v_locked_until
            )
        );
    END IF;

    RETURN v_new_level;
END;
$$;

-- ── Worker-only function ACLs (security_event_enqueue.sql:72-78 form) ──────
ALTER FUNCTION lockout_escalate(TEXT, INT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION lockout_escalate(TEXT, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lockout_escalate(TEXT, INT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION lockout_escalate(TEXT, INT) TO setjoin_worker;
