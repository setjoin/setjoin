-- approval_expire_due: sweeps all pending approval_requests past expires_at,
-- marks them 'expired', writes an audit row, and runs per-consumer on-expire effects:
--   mail.external_send    → NDR to the sender via mail_external_ndr (same as deny path)
--   mail.group_moderation → DELETE held_inbound_messages row (same as deny path)
--   rbac.jit_activation   → status='expired' + audit only; no side effect
-- FOR UPDATE SKIP LOCKED: concurrent workers (rolling deploy) don't double-process.
-- Called by approvaljobs.Worker on workerPool (BYPASSRLS) — cross-tenant sweep.
-- Returns count of rows expired.
CREATE OR REPLACE FUNCTION approval_expire_due() RETURNS int AS $$
DECLARE
  v_req   record;
  v_count int := 0;
BEGIN
  FOR v_req IN
    SELECT * FROM approval_requests
     WHERE status = 'pending' AND expires_at < now()
     FOR UPDATE SKIP LOCKED
  LOOP
    UPDATE approval_requests SET status = 'expired' WHERE id = v_req.id;

    -- NULL actor: system sweep, not a user action; admin_audit_log.user_id is nullable.
    PERFORM audit_write(
      NULL, 'approval_expired', 'approval_request', v_req.id,
      NULL, jsonb_build_object('consumer_type', v_req.consumer_type),
      NULL, 'approval window expired', 'core'
    );

    CASE v_req.consumer_type
      WHEN 'mail.external_send' THEN
        -- NDR the sender; reuses the same helper as the deny path.
        PERFORM mail_external_ndr(v_req.id, 'Approval window expired.');
      WHEN 'mail.group_moderation' THEN
        -- Drop the held message; same as the deny path in group_moderation_approval_decide.
        DELETE FROM held_inbound_messages WHERE approval_request_id = v_req.id;
      ELSE
        NULL; -- rbac.jit_activation: no side effect needed
    END CASE;

    v_count := v_count + 1;
  END LOOP;

  RETURN v_count;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
