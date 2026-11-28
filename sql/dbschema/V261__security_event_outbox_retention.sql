-- V261: security_event_outbox retention — the owner-approved reap decision for
-- the V253 outbox (plan row W-P1.5 "C4 residue: outbox retention migration row",
-- PLAN-20260913-consolidated-implementation.md, owner answers 2026-09-13).
--
-- V253 shipped the durable security-event outbox with rows NEVER deleted:
-- "security events are audit-adjacent, retention defaults to retain (a reap
-- decision belongs to the owner)". That decision is this migration. It installs
-- the retention sweep security_event_outbox_prune(), which deletes only
-- DELIVERED rows (status='done', delivered_at set) past the retention window:
--
--   * pending rows are never touched — an aged pending row is still owed its
--     delivery promise (the drain worker owns that lifecycle);
--   * failed rows are retained deliberately — status='failed' is the durable
--     alert signal (mailserver/internal/secevents/worker.go) and a failed row
--     has no delivery timestamp to age against.
--
-- The window reads the optional system_config key
-- security_event_outbox_retain_days (seeded here at the 90-day audit-adjacent
-- default — the dmarc_reports/health_history precedent) through the shared
-- cron_retention_days resolver, so zero/negative/non-integer stored values are
-- REFUSED (BZ040) instead of turning the sweep into a mass delete
-- (destructive-parameter clamping, CWE-20). The secevents delivery worker
-- (mailserver/internal/secevents, BYPASSRLS pool) invokes the sweep on its
-- tick, rate-limited in Go (retentionSweepInterval) — a daily-class sweep on a
-- 3s delivery ticker.
--
-- Reducer-source discipline (V241 precedent): the LIVE source stays
-- reducers/security_event_outbox_prune.sql (post-ARCH-007 the fixed-point
-- reducer reload re-applies it on top, so any later logic fix is a reducer
-- edit, never a new migration — this file keeps only the original CREATE,
-- byte-identical to the reducer at install time).
--
-- Caller posture (C4-RETENTION r2, Astra HOLD fix): worker-only ACLs on a
-- definer sweep — the established pattern for the only mutators of a
-- FORCE-RLS-deny-all substrate. SECURITY DEFINER owned by setjoin_worker
-- (BYPASSRLS) keeps the secevents worker's `SELECT
-- security_event_outbox_prune()` working unchanged on the BYPASSRLS pool, and
-- the footer below (the security_event_enqueue V253 form) revokes EXECUTE from
-- PUBLIC and setjoin_app and grants it to setjoin_worker — the app credential
-- is denied the sweep outright, so data protection no longer rides on
-- FORCE-RLS row-blindness alone. The exact signature is registered in
-- provision-roles.sql's worker-only carve-out block so every provisioning run
-- re-establishes the denial AFTER the broad GRANT EXECUTE ON ALL FUNCTIONS
-- (provision-roles.sql:168).

-- From reducers/security_event_outbox_prune.sql (byte-identical body;
-- schema-qualified name):
CREATE OR REPLACE FUNCTION public.security_event_outbox_prune() RETURNS bigint
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

COMMENT ON FUNCTION public.security_event_outbox_prune() IS
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
-- contract (V118:19-20) — the grant this substrate must not have. The
-- fixed-point reducer reload re-applies the identical footer on top (the
-- reducer file is the live source).
ALTER FUNCTION public.security_event_outbox_prune() OWNER TO setjoin_worker;
REVOKE ALL ON FUNCTION public.security_event_outbox_prune() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_event_outbox_prune() FROM setjoin_app;
GRANT EXECUTE ON FUNCTION public.security_event_outbox_prune() TO setjoin_worker;

-- Retention config seed (V048 form): the operator-visible day count. Absent or
-- blank resolves to the same built-in 90 via cron_retention_days; the seed
-- makes the knob discoverable without reading the reducer.
INSERT INTO public.system_config (key, value)
VALUES ('security_event_outbox_retain_days', '90')
ON CONFLICT (key) DO NOTHING;

-- Table-comment refresh: the V253 COMMENT promised "never deleted here
-- (retention decision flagged to the owner)". The decision landed; the live
-- catalog must not contradict the behavior.
COMMENT ON TABLE public.security_event_outbox IS
  'Durable security-event outbox (V253, L2-C4): one row per security event; '
  'the row IS the event (LISTEN/NOTIFY is a latency optimization only). '
  'At-least-once delivery; consumers dedupe on the immutable id. Rows only '
  'move pending→done|failed. Retention (V261, owner-approved W-P1.5): '
  'delivered rows are pruned past system_config '
  'security_event_outbox_retain_days (default 90) by '
  'security_event_outbox_prune() on the worker tick; pending rows are never '
  'pruned and failed rows are retained as the durable alert signal. '
  'Worker-only: FORCE RLS deny-all; enqueue and retention via worker-owned '
  'SECURITY DEFINER reducers (security_event_enqueue, '
  'security_event_outbox_prune — app EXECUTE denied via the provision-roles '
  'carve-out), delivery on the BYPASSRLS worker pool.';

INSERT INTO public.schema_migrations (version, applied_at) VALUES (261, now())
    ON CONFLICT (version) DO NOTHING;
