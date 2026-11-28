-- approval_decide: consumer-agnostic approve/deny. Records the decision, enforces SoD and
-- approver-authorization, writes the audit row, fires app_notify. NEVER reads consumer_type
-- or payload — per-consumer wrappers call this then apply.
-- Errors: BZ106 (SoD), BZ107 (not the approver), BZ108 (not found / not pending).
CREATE OR REPLACE FUNCTION approval_decide(
  p_request_id    bigint,
  p_actor_user_id bigint,
  p_decision      text,
  p_comment       text
) RETURNS text AS $$
DECLARE
  v_req        record;
  v_new_status text;
BEGIN
  -- Lock the row; treat missing or non-pending uniformly as BZ108 (idempotency).
  SELECT id, requester_user_id, approver_kind, approver_ref
    INTO v_req
    FROM approval_requests
   WHERE id = p_request_id AND status = 'pending'
     FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'approval request not found or not pending' USING ERRCODE = 'BZ108';
  END IF;

  -- SoD: requester cannot decide their own request.
  IF p_actor_user_id = v_req.requester_user_id THEN
    RAISE EXCEPTION 'requester cannot decide their own request' USING ERRCODE = 'BZ106';
  END IF;

  -- Authorization: actor must be the assigned approver (user) or a member of the approver
  -- role group with a non-expired, JIT-ACTIVE assignment. Deciding an approval is
  -- actor-side authority enforcement, so admin_assignment_active applies (rbac.jit read
  -- inside it): a dormant eligible grant must self-activate before it can decide.
  -- Matches the V073 approval_requests RLS policy, which carries the same gate inline.
  IF NOT (
    (v_req.approver_kind = 'user' AND v_req.approver_ref = p_actor_user_id)
    OR
    (v_req.approver_kind = 'role_group' AND EXISTS(
      SELECT 1 FROM admin_role_assignments
       WHERE user_id      = p_actor_user_id
         AND role_group_id = v_req.approver_ref
         AND (expires_at IS NULL OR expires_at > now())
         AND admin_assignment_active(eligible, activated_until)
    ))
  ) THEN
    RAISE EXCEPTION 'actor is not authorized to decide this request' USING ERRCODE = 'BZ107';
  END IF;

  v_new_status := CASE p_decision WHEN 'approve' THEN 'approved' WHEN 'deny' THEN 'denied' END;
  IF v_new_status IS NULL THEN
    RAISE EXCEPTION 'decision must be ''approve'' or ''deny''' USING ERRCODE = 'BZ108';
  END IF;

  UPDATE approval_requests
     SET status             = v_new_status,
         decided_by_user_id = p_actor_user_id,
         decided_at         = now(),
         decision_comment   = p_comment
   WHERE id = p_request_id;

  PERFORM audit_write(
    p_actor_user_id,
    'approval_' || v_new_status,
    'approval_request',
    p_request_id,
    NULL,
    NULL,
    NULL,
    p_comment,
    'core'
  );

  -- ponytail: best-effort notify; no jmap_approval_state bump (approvals are poll-based, §9).
  PERFORM app_notify('approval_decided',
    json_build_object('request_id', p_request_id, 'status', v_new_status)::text);

  RETURN v_new_status;
END;
$$ LANGUAGE plpgsql VOLATILE;
