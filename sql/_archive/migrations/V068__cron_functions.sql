-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V068: Create missing cron functions that were previously inline pg_cron jobs.
-- These were moved to the Go cron worker but the SQL functions were never created.

-- Drain deferred outbound queue items that are ready for retry.
CREATE OR REPLACE FUNCTION drain_outbound_queue(p_retry_only BOOLEAN DEFAULT false) RETURNS VOID AS $$
BEGIN
    UPDATE outbound_queue
    SET status = 'pending', next_attempt_at = NULL
    WHERE status = 'deferred'
      AND next_attempt_at <= now()
      AND attempt_count < 20;
END;
$$ LANGUAGE plpgsql;

-- Prune stale WebSocket subscriptions.
CREATE OR REPLACE FUNCTION prune_ws_subscriptions() RETURNS VOID AS $$
BEGIN
    DELETE FROM ws_subscriptions WHERE last_ping_at < now() - interval '5 minutes';
END;
$$ LANGUAGE plpgsql;

-- Reset daily sending quotas at midnight.
CREATE OR REPLACE FUNCTION reset_sending_quotas() RETURNS VOID AS $$
BEGIN
    UPDATE mailboxes
    SET sending_sent_today = 0, sending_quota_reset_at = CURRENT_DATE
    WHERE sending_quota_reset_at < CURRENT_DATE;
END;
$$ LANGUAGE plpgsql;

INSERT INTO schema_migrations (version) VALUES (68) ON CONFLICT (version) DO NOTHING;
