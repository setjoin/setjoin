-- journal_retry.sql: U7 operator action. Re-pends a dead-lettered journal_queue
-- row so the next drain/retry pass re-attempts delivery. Idempotent: the
-- WHERE status='dead' guard makes a double-click or a concurrent drain safe
-- (a non-dead row affects 0 rows, returned to the caller as a no-op). Mirrors
-- the outbound ForceRetry pattern (admin_queue.go ForceRetry). Mail is held,
-- never deleted, so this only ever recovers a row. Admin-gated (queue.write) at
-- the Go route layer; cross-mailbox by design (no p_mailbox_id).
CREATE OR REPLACE FUNCTION repend_dead_journal_row(p_id BIGINT)
RETURNS INT AS $$
DECLARE
  v_affected INT;
BEGIN
  UPDATE journal_queue
     SET status = 'deferred',
         next_attempt_at = now()
   WHERE id = p_id
     AND status = 'dead';
  GET DIAGNOSTICS v_affected = ROW_COUNT;
  RETURN v_affected;
END;
$$ LANGUAGE plpgsql;
