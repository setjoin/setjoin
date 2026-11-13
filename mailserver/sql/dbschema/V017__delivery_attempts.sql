-- ════════════════════════════════════════════════════════════════════════
-- V017__delivery_attempts.sql — forward migration (Phase 2a outbound tracking).
--
-- Adds per-recipient outbound delivery logging. delivery_attempts is an
-- append-only side log written best-effort by OutboundWorker; outbound_queue
-- remains the source of truth. Surrogate-keyed (message_pk = messages.id).
--
-- outbound_queue.message_pk (bigint, nullable): set by send.sql when the Sent
-- messages row is created; links delivery_attempts to the sent message without
-- requiring the non-unique RFC message_id.
--
-- RLS: inert per-mailbox policy mirroring messages_tenant_isolation (V003).
-- ENABLE+FORCE here matches the production-flip pattern of V004 so the table
-- is defence-in-depth-ready immediately. delivery_attempts is UNPARTITIONED —
-- no partition/startup wiring required.
--
-- Retention: log_retention_delivery_attempts_days (default 30) added to
-- system_config; prune_log_tables() extended to prune this table in parallel
-- with message_trace.
--
-- Plan: docs/superpowers/plans/archive/2026-06-22-delivery-path-inspector-phase2a-outbound.md
-- ════════════════════════════════════════════════════════════════════════

-- ── 1. outbound_queue + outbound_queue_hot: surrogate link column ─────────────
-- BOTH tables must stay column-identical: drain_outbound_hot() uses a positional
-- SELECT * INSERT.  Adding message_pk to outbound_queue only would make them
-- 16 vs 15 columns and break every interactive send.
ALTER TABLE public.outbound_queue     ADD COLUMN IF NOT EXISTS message_pk bigint;
ALTER TABLE public.outbound_queue_hot ADD COLUMN IF NOT EXISTS message_pk bigint;
COMMENT ON COLUMN public.outbound_queue.message_pk IS
  'Surrogate id of the Sent messages row (set by send.sql); links delivery_attempts without the non-unique RFC message_id.';
COMMENT ON COLUMN public.outbound_queue_hot.message_pk IS
  'Mirror of outbound_queue.message_pk — kept column-identical for positional SELECT * drain.';

-- ── 2. delivery_attempts table ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.delivery_attempts (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  message_pk      bigint      NOT NULL,        -- Sent messages.id (surrogate); NOT the RFC message_id
  received_at     timestamptz NOT NULL,         -- messages partition key (resolves the (id, received_at) PK)
  mailbox_id      bigint      NOT NULL,         -- sender mailbox (RLS + ownership)
  recipient_email text        NOT NULL,
  mx_host         text,
  attempt_number  int         NOT NULL,
  attempted_at    timestamptz NOT NULL DEFAULT now(),
  smtp_code       int,
  smtp_text       text,
  outcome         text        NOT NULL
                  CONSTRAINT delivery_attempts_outcome_chk
                  CHECK (outcome IN ('accepted','deferred','rejected','error')),  -- closed enum; the read path (Task 4) groups on these exact values
  tls             boolean     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS delivery_attempts_owner_idx
  ON public.delivery_attempts (mailbox_id, message_pk);

CREATE INDEX IF NOT EXISTS delivery_attempts_prune_idx
  ON public.delivery_attempts (attempted_at);

-- ── 3. RLS: per-mailbox policy (mirrors messages_tenant_isolation, V003) ─────
-- ENABLE + FORCE here (unlike V003 which stayed inert) as defence-in-depth.
-- The read path enforces ownership by the JOIN (the ResolveOwnedMessage pattern),
-- NOT by this policy, so the FORCE is belt-and-suspenders, not the primary guard.
--
-- WRITE-PATH DEPENDENCY (native-RLS rollout): OutboundWorker.logDeliveryAttempt
-- writes via the worker pool and sets NO app.current_mailbox_id GUC. TODAY that
-- pool aliases DB_DSN (a pre-flip role that bypasses RLS) so writes land. But once
-- DB_DSN flips to setjoin_app (NOBYPASSRLS) at native-RLS W6, a FORCE'd table with
-- no GUC set fails WITH CHECK → every insert is rejected (error is discarded:
-- delivery stays safe, but delivery_attempts silently stops logging). The outbound
-- worker MUST be on DB_WORKER_DSN (setjoin_worker, BYPASSRLS) before that flip.
-- See 2026-06-18-native-rls-backstop.md. (Do NOT assume BYPASSRLS is in effect today.)
--
-- InitPlan GUC form — NULLIF(…,'')::bigint is FAIL-CLOSED: an unset/empty GUC
-- → NULL → no row qualifies.
ALTER TABLE public.delivery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.delivery_attempts FORCE  ROW LEVEL SECURITY;

CREATE POLICY delivery_attempts_tenant_isolation ON public.delivery_attempts
  FOR ALL
  TO public
  USING      (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  WITH CHECK (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint));

-- setjoin_app: SELECT (read path) + INSERT (OutboundWorker via app role).
-- No UPDATE/DELETE — the table is append-only; pruning is done by the superuser
-- via prune_log_tables() scheduled job.
GRANT SELECT, INSERT ON public.delivery_attempts TO setjoin_app;

-- ── 4. Retention config ──────────────────────────────────────────────────────
-- Exact column list and format mirrors V001 log_retention_* inserts (line ~12386).
INSERT INTO public.system_config VALUES ('log_retention_delivery_attempts_days', '30', false, 'Number of days to retain delivery_attempts rows. NULL or 0 = keep forever.', now(), NULL)
  ON CONFLICT (key) DO NOTHING;

-- ── 5. Extend prune_log_tables() to prune delivery_attempts ─────────────────
-- Replaces the V001 baseline definition with an identical body plus a parallel
-- block for delivery_attempts (keyed on attempted_at, matching the prune index).
CREATE OR REPLACE FUNCTION public.prune_log_tables()
  RETURNS TABLE(pruned_table text, rows_deleted integer)
  LANGUAGE plpgsql
AS $$
DECLARE
  v_trace_days             INT;
  v_audit_days             INT;
  v_auth_event_days        INT;
  v_webhook_days           INT;
  v_delivery_attempts_days INT;
  v_deleted                INT;
BEGIN
  -- Read retention settings from system_config
  SELECT (value #>> '{}')::INT INTO v_trace_days
  FROM system_config WHERE key = 'log_retention_message_trace_days';

  SELECT (value #>> '{}')::INT INTO v_audit_days
  FROM system_config WHERE key = 'log_retention_mailbox_audit_days';

  SELECT (value #>> '{}')::INT INTO v_auth_event_days
  FROM system_config WHERE key = 'log_retention_auth_event_days';

  SELECT (value #>> '{}')::INT INTO v_webhook_days
  FROM system_config WHERE key = 'log_retention_webhook_delivery_days';

  SELECT (value #>> '{}')::INT INTO v_delivery_attempts_days
  FROM system_config WHERE key = 'log_retention_delivery_attempts_days';

  -- Prune message_trace if configured (> 0)
  IF v_trace_days IS NOT NULL AND v_trace_days > 0 THEN
    DELETE FROM message_trace WHERE occurred_at < now() - make_interval(days => v_trace_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    pruned_table := 'message_trace';
    rows_deleted := v_deleted;
    RETURN NEXT;
  END IF;

  -- mailbox_audit_log is WORM-protected (trg_audit_append_only): rows are never deleted.
  -- The log_retention_mailbox_audit_days config key is retained for future reference only.

  -- Prune auth_event_log if configured (> 0)
  IF v_auth_event_days IS NOT NULL AND v_auth_event_days > 0 THEN
    DELETE FROM auth_event_log WHERE occurred_at < now() - make_interval(days => v_auth_event_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    pruned_table := 'auth_event_log';
    rows_deleted := v_deleted;
    RETURN NEXT;
  END IF;

  -- Prune webhook_deliveries if configured (> 0)
  IF v_webhook_days IS NOT NULL AND v_webhook_days > 0 THEN
    DELETE FROM webhook_deliveries WHERE created_at < now() - make_interval(days => v_webhook_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    pruned_table := 'webhook_deliveries';
    rows_deleted := v_deleted;
    RETURN NEXT;
  END IF;

  -- Prune delivery_attempts if configured (> 0)
  IF v_delivery_attempts_days IS NOT NULL AND v_delivery_attempts_days > 0 THEN
    DELETE FROM delivery_attempts WHERE attempted_at < now() - make_interval(days => v_delivery_attempts_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    pruned_table := 'delivery_attempts';
    rows_deleted := v_deleted;
    RETURN NEXT;
  END IF;

  RETURN;
END;
$$;

-- ── 6. schema_migrations self-insert ────────────────────────────────────────
-- Columns match the V001 seed (version, applied_at).
INSERT INTO public.schema_migrations (version, applied_at) VALUES (17, now())
    ON CONFLICT (version) DO NOTHING;
