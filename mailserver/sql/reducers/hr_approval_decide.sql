-- hr_approval_decide: HR consumer decide wrapper (hr.leave + hr.expense — same
-- apply). Shape mirrors rbac_approval_decide, minus the window-open (v1 apply
-- is record-keeping only — see plan Open Decisions).
-- ponytail: v1 apply is record-keeping (status 'applied' + audit); an
-- HRIS/balance write plugs in here later without touching the engine.
CREATE OR REPLACE FUNCTION hr_approval_decide(
  p_request_id bigint,
  p_actor      bigint,
  p_decision   text,
  p_comment    text
) RETURNS text AS $$
DECLARE
  v_status text;
BEGIN
  v_status := approval_decide(p_request_id, p_actor, p_decision, p_comment);

  IF v_status = 'approved' THEN
    UPDATE approval_requests SET status = 'applied' WHERE id = p_request_id;

    PERFORM audit_write(
      p_actor, 'approval_applied', 'approval_request', p_request_id,
      NULL,
      (SELECT jsonb_build_object('consumer_type', consumer_type, 'requester', requester_user_id)
         FROM approval_requests WHERE id = p_request_id),
      NULL, p_comment, 'core'
    );

    RETURN 'applied';
  END IF;

  RETURN v_status;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
