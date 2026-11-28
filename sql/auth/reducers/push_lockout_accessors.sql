-- push_lockout_accessors.sql — the push-MFA recovery-lockout accessors for
-- auth_lockouts under the V259 deny-all FORCE flip (PLAN-20260913 D2 /
-- REDUCERS-004, Astra AGREE: ALL accessor paths INCLUDING push-MFA lockout).
--
-- The forgot-password push-branch lockout (authserver/internal/authn/
-- push_lockout.go) keeps per-account lock state in the SHARED auth_lockouts
-- table under the push_user:{user_id} key. Its three statements were the
-- last DIRECT table writes on any pre-auth path; under deny-all FORCE they
-- move behind these worker-owned SECURITY DEFINER functions, called in the
-- SAME transaction positions as the statements they replace (the
-- INSERT..ON CONFLICT row lock the serialization contract rests on is taken
-- by push_lockout_acquire inside the caller's transaction and held to
-- commit — SECURITY DEFINER changes the privilege context, never the
-- transaction/lock scope):
--
--   push_lockout_acquire(BIGINT) — lockPushAccountRow: atomically acquire +
--       read the account row (INSERT count-0 "never locked" sentinel row /
--       conflict-bump takes the row lock on BOTH paths) and RETURN the
--       failed_count, locked_until, updated_at triple the Go scan expects.
--   push_lockout_record(BIGINT, INT, TIMESTAMPTZ) —
--       recordPushVerificationOutcome: failure → prior+1 count with the
--       tripped lock horizon; success/reset → count 0 + the unlocked
--       sentinel. NULL p_locked_until means "re-arm the unlocked sentinel
--       (now())" so the sentinel convention lives on ONE side (SQL).
--   push_lockout_count_locked(BIGINT) — countLockedAttempt: count-only
--       bump for an attempt refused by an active lock; locked_until is
--       deliberately NOT recomputed (the lock expires on schedule — an
--       attacker cannot extend it by hammering).
--
-- KEY-PARITY (load-bearing): the row key is 'push_user:' || p_user_id,
-- byte-identical to the Go pushLockoutKey convention. The accessor OWNS the
-- convention on the SQL side so a caller cannot address arbitrary ip:/user:/
-- ip_user: lockout rows through it (R1 by construction: the account id is
-- the only addressable dimension).
--
-- WORKER-ONLY FUNCTION ACLS — the security_event_enqueue.sql:72-78 footer
-- form (NOT apply_worker_ownership(), which grants setjoin_app EXECUTE by
-- contract, V118:19-20). Every exact signature belongs in
-- provision-roles.sql's worker-only carve-out block so every provisioning
-- run re-establishes the denial after the broad GRANT EXECUTE ON ALL
-- FUNCTIONS (provision-roles.sql:168).

-- ── push_lockout_acquire: the transaction-opening row lock + state read ───
CREATE OR REPLACE FUNCTION push_lockout_acquire(p_user_id BIGINT)
RETURNS TABLE (
    failed_count INT,
    locked_until TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until)
    VALUES ('push_user:' || p_user_id, 0, now())
    ON CONFLICT (lockout_key) DO UPDATE
        SET lockout_key = EXCLUDED.lockout_key
    RETURNING auth_lockouts.failed_count,
              auth_lockouts.locked_until,
              auth_lockouts.updated_at
$$;

-- ── push_lockout_record: the post-verification counter write ──────────────
CREATE OR REPLACE FUNCTION push_lockout_record(
    p_user_id      BIGINT,
    p_failed_count INT,
    p_locked_until TIMESTAMPTZ DEFAULT NULL
)
RETURNS VOID
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE auth_lockouts
       SET failed_count = p_failed_count,
           locked_until = COALESCE(p_locked_until, now()),
           updated_at = now()
     WHERE lockout_key = 'push_user:' || p_user_id
$$;

-- ── push_lockout_count_locked: the count-only locked-attempt bump ─────────
CREATE OR REPLACE FUNCTION push_lockout_count_locked(p_user_id BIGINT)
RETURNS VOID
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE auth_lockouts
       SET failed_count = failed_count + 1,
           updated_at = now()
     WHERE lockout_key = 'push_user:' || p_user_id
$$;

-- ── Worker-only function ACLs (security_event_enqueue.sql:72-78 form) ──────
ALTER FUNCTION push_lockout_acquire(BIGINT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION push_lockout_acquire(BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION push_lockout_acquire(BIGINT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION push_lockout_acquire(BIGINT) TO setjoin_worker;

ALTER FUNCTION push_lockout_record(BIGINT, INT, TIMESTAMPTZ) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION push_lockout_record(BIGINT, INT, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION push_lockout_record(BIGINT, INT, TIMESTAMPTZ) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION push_lockout_record(BIGINT, INT, TIMESTAMPTZ) TO setjoin_worker;

ALTER FUNCTION push_lockout_count_locked(BIGINT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION push_lockout_count_locked(BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION push_lockout_count_locked(BIGINT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION push_lockout_count_locked(BIGINT) TO setjoin_worker;
