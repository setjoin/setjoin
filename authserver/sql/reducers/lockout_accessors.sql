-- lockout_accessors.sql — the threat-pipeline + admin-console accessors for
-- auth_lockouts under the V259 deny-all FORCE flip (PLAN-20260913 D2 /
-- REDUCERS-004, Astra AGREE).
--
-- auth_lockouts is ENABLE+FORCE RLS with ZERO policies (deny-all to every
-- runtime role, including the owner — V217/V246/V249/V254 posture D): the
-- rows are pre-auth attack-accounting keyed by attacker-supplied material,
-- so there is no per-user predicate that is honest. Every accessor path is
-- therefore a worker-owned SECURITY DEFINER function. This file carries the
-- five paths shared/threat and the admin threat console drive today:
--
--   lockout_check(TEXT[])            — the login-path IsLocked probe
--                                      (shared/threat store.go IsLocked: the
--                                      EXISTS probe + the longest-remaining
--                                      follow-up, folded into ONE definer
--                                      call; same result shape)
--   lockout_clear(TEXT[])            — the auth-success reset
--                                      (shared/threat store.go Clear)
--   lockout_arm(TEXT, INT)           — the spray-detector IP lock upsert
--                                      (shared/threat store.go LockIP, the
--                                      exact ON CONFLICT statement shape)
--   lockout_list(TEXT, INT, INT,     — the admin threat-console "lockouts"
--                TEXT, TEXT)          view (mailserver/internal/admin
--                                      admin_threat.go: same column set —
--                                      lockout_key, failed_count, locked_
--                                      until, escalation_level, updated_at —
--                                      the ILIKE q-filter, the allow-listed
--                                      p_sort/p_dir order applied BEFORE the
--                                      page bounds (locked_until DESC when
--                                      absent or not allow-listed; a
--                                      GetDeviceEvents-style read accessor).
--                                      Astra impl-r2 P2: the previous
--                                      fixed locked_until DESC silently
--                                      dropped the view's ?sort/dir API
--                                      contract — sorting lives inside the
--                                      accessor again, validated by the
--                                      CASE allow-list below, never dynamic
--                                      SQL.
--   lockout_count(TEXT)              — the admin view's FULL filtered count
--                                      (same ILIKE q-filter, no page bounds).
--                                      Astra impl-r2 P2: counting a
--                                      lockout_list page capped the reported
--                                      total at 500, hiding every lockout
--                                      beyond the first page of the ceiling —
--                                      pagination needs the honest total.
--
-- lockout_escalate + prune_old_lockouts (the other two accessor paths) are
-- converted in place in their own files; the push-MFA seam lives in
-- push_lockout_accessors.sql.
--
-- WORKER-ONLY FUNCTION ACLS — the security_event_enqueue.sql:72-78 footer
-- form (NOT apply_worker_ownership(), which grants setjoin_app EXECUTE by
-- contract, V118:19-20). Every exact signature belongs in
-- provision-roles.sql's worker-only carve-out block so every provisioning run
-- re-establishes the denial after the broad GRANT EXECUTE ON ALL FUNCTIONS
-- (provision-roles.sql:168). SET search_path=pg_catalog,public is required
-- for a definer-privilege function (webhook_delivery_complete.sql:11
-- precedent — the SECURITY DEFINER escalation foot-gun belt).

-- ── lockout_check: the IsLocked probe (one round trip, result shape matched
-- to the Go scan order: locked, remaining seconds of the LONGEST lock) ────
CREATE OR REPLACE FUNCTION lockout_check(p_keys TEXT[])
RETURNS TABLE (locked BOOLEAN, remaining_seconds DOUBLE PRECISION)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT
        EXISTS(
            SELECT 1 FROM auth_lockouts
            WHERE lockout_key = ANY(p_keys)
              AND locked_until > now()
        ),
        COALESCE((
            SELECT EXTRACT(EPOCH FROM (locked_until - now()))
            FROM auth_lockouts
            WHERE lockout_key = ANY(p_keys)
              AND locked_until > now()
            ORDER BY locked_until DESC
            LIMIT 1
        ), 0)
$$;

-- ── lockout_clear: the auth-success reset; returns the deleted row count ──
CREATE OR REPLACE FUNCTION lockout_clear(p_keys TEXT[])
RETURNS INT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_deleted INT;
BEGIN
    DELETE FROM auth_lockouts WHERE lockout_key = ANY(p_keys);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

-- ── lockout_arm: the spray-detector IP lock (verbatim LockIP upsert shape;
-- a non-positive p_minutes arms an already-expired lock — harmless no-lock,
-- matching the current caller contract) ────────────────────────────────────
CREATE OR REPLACE FUNCTION lockout_arm(p_lockout_key TEXT, p_minutes INT)
RETURNS VOID
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    INSERT INTO auth_lockouts (lockout_key, locked_until, escalation_level)
    VALUES (p_lockout_key, now() + make_interval(mins => p_minutes), 1)
    ON CONFLICT (lockout_key) DO UPDATE
      SET locked_until = now() + make_interval(mins => p_minutes),
          updated_at = now()
$$;

-- ── lockout_list: the admin threat-console lockouts read (bounded page:
-- limit clamped to 500, default 100; offset floored at 0; allow-listed
-- p_sort/p_dir order applied BEFORE the page bounds — unknown sorts fall back
-- to the locked_until DESC default; no dynamic SQL) ─────────────────────────
-- Signature note: p_sort/p_dir were added after the V259 conversion (Astra
-- impl-r2 P2). The old lockout_list(TEXT, INT, INT) overload is dropped so an
-- already-loaded cluster cannot keep the unsorted accessor alive beside this
-- one (calendar_itip.sql:259 precedent for the DROP-on-signature-change).
DROP FUNCTION IF EXISTS lockout_list(TEXT, INT, INT);
CREATE OR REPLACE FUNCTION lockout_list(
    p_q      TEXT DEFAULT NULL,
    p_limit  INT DEFAULT NULL,
    p_offset INT DEFAULT NULL,
    p_sort   TEXT DEFAULT NULL,
    p_dir    TEXT DEFAULT NULL
)
RETURNS TABLE (
    lockout_key      TEXT,
    failed_count     INT,
    locked_until     TIMESTAMPTZ,
    escalation_level INT,
    updated_at       TIMESTAMPTZ
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT l.lockout_key, l.failed_count, l.locked_until,
           l.escalation_level, l.updated_at
      FROM auth_lockouts l
     WHERE (p_q IS NULL OR p_q = '' OR l.lockout_key ILIKE '%' || p_q || '%')
     -- Allow-listed sort: each CASE pair matches ONE (column, direction)
     -- combination; every non-matching pair folds to a constant NULL and
     -- cannot disturb the ordering. IS [NOT] DISTINCT FROM keeps a NULL
     -- p_dir on the ascending branch. A NULL or non-allow-listed p_sort
     -- leaves every pair constant, so the trailing locked_until DESC is the
     -- contract default (and the stable tiebreaker otherwise).
     ORDER BY
        CASE WHEN p_sort = 'locked_until' AND p_dir IS DISTINCT FROM 'desc'
             THEN l.locked_until END,
        CASE WHEN p_sort = 'locked_until' AND p_dir IS NOT DISTINCT FROM 'desc'
             THEN l.locked_until END DESC,
        CASE WHEN p_sort = 'failed_count' AND p_dir IS DISTINCT FROM 'desc'
             THEN l.failed_count END,
        CASE WHEN p_sort = 'failed_count' AND p_dir IS NOT DISTINCT FROM 'desc'
             THEN l.failed_count END DESC,
        CASE WHEN p_sort = 'updated_at'   AND p_dir IS DISTINCT FROM 'desc'
             THEN l.updated_at END,
        CASE WHEN p_sort = 'updated_at'   AND p_dir IS NOT DISTINCT FROM 'desc'
             THEN l.updated_at END DESC,
        l.locked_until DESC
     LIMIT COALESCE(LEAST(p_limit, 500), 100)
     OFFSET GREATEST(COALESCE(p_offset, 0), 0)
$$;

-- ── lockout_count: the admin view's FULL filtered count (same ILIKE
-- q-filter as lockout_list, NO page bounds — the total behind pagination must
-- be the honest match count, not a lockout_list page capped at 500) ─────────
CREATE OR REPLACE FUNCTION lockout_count(p_q TEXT)
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT COUNT(*)
      FROM auth_lockouts l
     WHERE (p_q IS NULL OR p_q = '' OR l.lockout_key ILIKE '%' || p_q || '%')
$$;

-- ── Worker-only function ACLs (security_event_enqueue.sql:72-78 form) ──────
ALTER FUNCTION lockout_check(TEXT[]) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION lockout_check(TEXT[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION lockout_check(TEXT[]) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION lockout_check(TEXT[]) TO setjoin_worker;

ALTER FUNCTION lockout_clear(TEXT[]) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION lockout_clear(TEXT[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION lockout_clear(TEXT[]) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION lockout_clear(TEXT[]) TO setjoin_worker;

ALTER FUNCTION lockout_arm(TEXT, INT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION lockout_arm(TEXT, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lockout_arm(TEXT, INT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION lockout_arm(TEXT, INT) TO setjoin_worker;

ALTER FUNCTION lockout_list(TEXT, INT, INT, TEXT, TEXT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION lockout_list(TEXT, INT, INT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lockout_list(TEXT, INT, INT, TEXT, TEXT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION lockout_list(TEXT, INT, INT, TEXT, TEXT) TO setjoin_worker;

ALTER FUNCTION lockout_count(TEXT) OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION lockout_count(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lockout_count(TEXT) FROM setjoin_app;
GRANT EXECUTE ON FUNCTION lockout_count(TEXT) TO setjoin_worker;
