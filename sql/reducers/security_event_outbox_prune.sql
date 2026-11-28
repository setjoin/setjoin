-- security_event_outbox_prune.sql: retention sweep for security_event_outbox
-- (V253, L2-C4). The never-delete posture in V253 flagged the reap decision to
-- the owner; that decision landed (W-P1.5 "C4 residue: outbox retention
-- migration row", PLAN-20260913-consolidated-implementation.md, 2026-09-13).
-- Deletes only DELIVERED rows (status='done', delivered_at set) whose delivery
-- left the retention window. Pending rows are never touched — an aged pending
-- row is still owed its delivery promise (the drain worker owns that
-- lifecycle). Failed rows are retained deliberately: status='failed' is the
-- durable alert signal (mailserver/internal/secevents/worker.go) and a failed
-- row has no delivery timestamp to age against.
--
-- The window comes from the optional system_config key
-- security_event_outbox_retain_days (default 90 — audit-adjacent posture, the
-- dmarc_reports/health_history precedent) and is resolved through
-- cron_retention_days so zero/negative/non-integer stored values are REFUSED
-- (BZ040) instead of turning the sweep into a mass delete. Returns the number
-- of rows deleted.
--
-- Caller posture (C4-RETENTION r2, Astra HOLD fix): worker-only ACLs on a
-- definer sweep — the established pattern for the only mutators of a
-- FORCE-RLS-deny-all substrate. SECURITY DEFINER owned by setjoin_worker
-- (BYPASSRLS) keeps the secevents delivery worker's
-- `SELECT security_event_outbox_prune()` (mailserver/internal/secevents/
-- worker.go pruneSQL) working unchanged on the BYPASSRLS pool, and the ACL
-- footer denies the app credential EXECUTE outright — data protection no
-- longer rides on FORCE-RLS row-blindness alone (r2 FINDING 2). The footer
-- follows security_event_enqueue.sql:72-78 — deliberately NOT
-- apply_worker_ownership(), whose contract grants setjoin_app EXECUTE
-- (V118:19-20); the exact signature belongs in provision-roles.sql's
-- worker-only carve-out block (re-established after the broad
-- GRANT EXECUTE ON ALL FUNCTIONS, provision-roles.sql:168).
--
-- SET search_path=pg_catalog,public is required for a definer-privilege
-- function (webhook_delivery_complete.sql:11 precedent — the SECURITY DEFINER
-- escalation foot-gun belt).
CREATE OR REPLACE FUNCTION security_event_outbox_prune() RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_days    int;
    v_deleted bigint;
BEGIN
    v_days := cron_retention_days('security_event_outbox_retain_days', 90);
    DELETE FROM security_event_outbox
     WHERE status = 'done'
       AND delivered_at < now() - make_interval(days => v_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

COMMENT ON FUNCTION security_event_outbox_prune() IS
  'Security-event outbox retention sweep (V261, W-P1.5 owner-approved reap): '
  'deletes only DELIVERED (status=''done'') rows past system_config '
  'security_event_outbox_retain_days (default 90, BZ040 refusal of '
  'zero/negative/non-integer). Pending rows are never pruned (delivery '
  'promise); failed rows are retained (durable alert signal). SECURITY '
  'DEFINER owned by setjoin_worker; the app credential is denied EXECUTE '
  '(worker-only carve-out in provision-roles.sql). Invoked by the secevents '
  'worker tick.';

-- ── Worker-only function ACLs (security_event_enqueue.sql:72-78 form) ──────
-- NOT apply_worker_ownership(): that applicator grants setjoin_app EXECUTE by
-- contract (V118:19-20) — the grant this substrate must not have.
ALTER FUNCTION security_event_outbox_prune() OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION security_event_outbox_prune() FROM PUBLIC;
REVOKE ALL ON FUNCTION security_event_outbox_prune() FROM setjoin_app;
GRANT EXECUTE ON FUNCTION security_event_outbox_prune() TO setjoin_worker;
