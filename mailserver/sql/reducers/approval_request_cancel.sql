-- approval_request_cancel: requester withdraws a pending request. Consumer-agnostic
-- (never reads payload/consumer_type — D1, same posture as approval_decide). Atomic
-- pending-guard mirrors approval_decide's FOR UPDATE idempotency shape. Closes the
-- spec §10.1 "Cancel while pending" gap for ALL FIVE consumers (engine-level, not
-- per-consumer) — see retired-docs:superpowers/plans/archive/2026-07-08-hr-approval-templates.md.
-- BZ125: not found / not the requester / not pending — deliberately indistinguishable
-- (no ownership oracle, mirrors BZ108's approval_decide posture).
CREATE OR REPLACE FUNCTION approval_request_cancel(
  p_request_id bigint,
  p_actor      bigint
) RETURNS text AS $$
DECLARE
  v_id bigint;
BEGIN
  UPDATE approval_requests
     SET status = 'cancelled', decided_at = now(), decided_by_user_id = p_actor
   WHERE id = p_request_id AND status = 'pending' AND requester_user_id = p_actor
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    RAISE EXCEPTION 'approval request not found or not pending' USING ERRCODE = 'BZ125';
  END IF;

  PERFORM audit_write(
    p_actor, 'approval_cancelled', 'approval_request', v_id,
    NULL, NULL, NULL, NULL, 'core'
  );

  PERFORM app_notify('approval_decided',
    json_build_object('request_id', v_id, 'status', 'cancelled')::text);

  RETURN 'cancelled';
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
