-- recovery_budget_accessors.sql — the forgot-password per-account recovery
-- budget accessors for auth_lockouts (ER5 s07 named residual: forgot-password
-- per-account recovery budget decoupled from the per-IP login lockout).
--
-- The forgot-password begin/verify endpoints (authserver/internal/handlers/
-- forgot_password.go) previously bounded grinding ONLY per source IP
-- (enumIPGuard, in-process) and per-factor (the TOTP/push 5-failure locks). A
-- DISTRIBUTED attacker — many IPs, one account — could grind recovery
-- attempts (begin challenge minting, verify traffic that no factor lockout
-- sees, e.g. empty-code requests) without any per-account bound. The budget
-- closes that: a fixed-window per-account attempt counter keyed
-- recovery_user:{user_id} in the SHARED auth_lockouts table — the same
-- deny-all FORCE'd guard-table genre the push-MFA recovery lockout uses
-- (V259 posture; zero permissive policies, so like that seam these
-- worker-owned SECURITY DEFINER functions are the budget's ONLY surface).
--
--   recovery_budget_acquire(BIGINT) — atomically acquire + read the account's
--       budget row. The INSERT..ON CONFLICT DO UPDATE takes the row lock on
--       BOTH paths (fresh insert / conflict bump), so every recovery attempt
--       for the account serializes on this statement and reads the freshest
--       committed state while the caller's transaction holds the lock to
--       commit — the same serialization contract as push_lockout_acquire.
--       The fresh insert uses window_until = now() as the "no window open"
--       sentinel, matching the push accessor's unlocked-sentinel convention.
--   recovery_budget_record(BIGINT, INT, TIMESTAMPTZ) — the post-decision
--       counter write: attempt consumption (count+1 under the unchanged or
--       freshly anchored window), refusal accounting (count-only bump under
--       the UNCHANGED window — the caller passes the prior window_until so a
--       refusal never extends it), window restore (count 1 + a new horizon
--       after expiry), and reset (count 0 + NULL → the now() sentinel).
--       NULL p_window_until means "re-arm the no-window sentinel (now())" so
--       the sentinel convention lives on ONE side (SQL), exactly as in
--       push_lockout_record.
--
-- KEY-PARITY (load-bearing): the row key is 'recovery_user:' || p_user_id,
-- byte-identical to the Go recoveryBudgetKey convention. The accessor OWNS
-- the convention on the SQL side so a caller cannot address arbitrary ip:/
-- user:/ip_user:/push_user: lockout rows through it (R1 by construction: the
-- account id — server-resolved from the email lookup, never request-owned —
-- is the only addressable dimension).
--
-- WINDOW POLICY NOTE: the threshold/window constants (30 attempts / 15
-- minutes) and the fixed-window decision live Go-side in
-- forgot_password.go (consumeRecoveryBudget), mirroring how the TOTP/push
-- lockout policy lives Go-side over its accessors; the accessors stay
-- dumb primitives so the window arithmetic is unit-testable without a
-- database. The SQL side owns the row-lock atomicity, the key convention,
-- and the sentinel.
--
-- WORKER-ONLY FUNCTION ACLS — the security_event_enqueue.sql:72-78 footer
-- form (NOT apply_worker_ownership(), which grants setjoin_app EXECUTE by
-- contract, V118:19-20). Every exact signature belongs in
-- provision-roles.sql's worker-only carve-out block so every provisioning
-- run re-establishes the denial after the broad GRANT EXECUTE ON ALL
-- FUNCTIONS (provision-roles.sql:168).

-- ── recovery_budget_acquire: the transaction-opening row lock + state read ─
CREATE OR REPLACE FUNCTION recovery_budget_acquire(p_user_id BIGINT)
RETURNS TABLE (
    attempt_count INT,
    window_until  TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until)
    VALUES ('recovery_user:' || p_user_id, 0, now())
    ON CONFLICT (lockout_key) DO UPDATE
        SET lockout_key = EXCLUDED.lockout_key
    RETURNING auth_lockouts.failed_count,
              auth_lockouts.locked_until,
              auth_lockouts.updated_at
$$;

-- ── recovery_budget_record: the post-decision counter write ────────────────
CREATE OR REPLACE FUNCTION recovery_budget_record(
    p_user_id      BIGINT,
    p_attempt_count INT,
    p_window_until TIMESTAMPTZ DEFAULT NULL
)
RETURNS VOID
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE auth_lockouts
       SET failed_count = p_attempt_count,
           locked_until = COALESCE(p_window_until, now()),
           updated_at = now()
     WHERE lockout_key = 'recovery_user:' || p_user_id
$$;

-- ── Worker-only function ACLs (security_event_enqueue.sql:72-78 form) ──────
ALTER FUNCTION recovery_budget_acquire(BIGINT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION recovery_budget_acquire(BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION recovery_budget_acquire(BIGINT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION recovery_budget_acquire(BIGINT) TO setjoin_worker;

ALTER FUNCTION recovery_budget_record(BIGINT, INT, TIMESTAMPTZ) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION recovery_budget_record(BIGINT, INT, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION recovery_budget_record(BIGINT, INT, TIMESTAMPTZ) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION recovery_budget_record(BIGINT, INT, TIMESTAMPTZ) TO setjoin_worker;
