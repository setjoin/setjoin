-- Frozen Go's admin outbound-queue retry and bounce (admin.QueueHandler.ForceRetry and
-- Bounce) as reducers. Each is Go's single UPDATE; the AFTER UPDATE trigger that enqueues
-- the DSN scheduled action (bounce) and the status guard (a delivered or bounced item
-- cannot change status: BZ012, which surfaces as Go's 500) run inside the same statement.
-- The queue is global (no tenant column): authority is the caller's queue.write grant,
-- checked by the gateway before the call. Returns false when no row matched.
CREATE OR REPLACE FUNCTION rust_mailsec_queue_retry(p_id bigint)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 UPDATE outbound_queue SET status = 'pending', next_attempt_at = now()
  WHERE id = p_id AND status IN ('deferred','pending');
 RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION rust_mailsec_queue_bounce(p_id bigint)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 UPDATE outbound_queue SET status = 'bounced', delivered_at = now() WHERE id = p_id;
 RETURN FOUND;
END;
$$;
