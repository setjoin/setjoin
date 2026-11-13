-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Migration: Retention policy admin UI + log retention pruning

-- 1. Seed system_config keys for log retention defaults.
INSERT INTO system_config (key, value, description, updated_at)
VALUES
  ('log_retention_message_trace_days', '30',
   'Number of days to retain message_trace rows. NULL or 0 = keep forever.', now()),
  ('log_retention_mailbox_audit_days', '90',
   'Number of days to retain mailbox_audit_log rows. NULL or 0 = keep forever.', now()),
  ('log_retention_auth_event_days', '90',
   'Number of days to retain auth_event_log rows. NULL or 0 = keep forever.', now()),
  ('log_retention_webhook_delivery_days', '30',
   'Number of days to retain webhook_deliveries rows. NULL or 0 = keep forever.', now())
ON CONFLICT (key) DO NOTHING;

-- 2. Seed a default global email retention policy (30 days delete).
-- This ensures tag_retention() has something to apply out of the box.
INSERT INTO retention_policies (name, description, retain_days, action, is_default, domain_id)
VALUES
  ('Default Global Policy', 'Applies to all domains unless overridden', 30, 'delete', TRUE, NULL)
ON CONFLICT DO NOTHING;

-- 3. Function to prune log tables based on system_config settings.
CREATE OR REPLACE FUNCTION prune_log_tables() RETURNS TABLE(pruned_table TEXT, rows_deleted INT) AS $$
DECLARE
  v_trace_days INT;
  v_audit_days INT;
  v_auth_event_days INT;
  v_webhook_days INT;
  v_deleted INT;
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

  RETURN;
END;
$$ LANGUAGE plpgsql;

-- 4. pg_cron job: prune logs daily at 03:30 (after health_history prune at 03:00).
-- [pg_cron→Go cron worker] SELECT cron.schedule('prune-log-tables', '30 3 * * *', $$ SELECT * FROM prune_log_tables(); $$);
