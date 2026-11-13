-- rbac_approval_decide: RBAC JIT approval consumer wrapper.
-- Delegates to approval_decide (SoD + authorization + audit), then on 'approved'
-- opens the activation window using the request's stored payload and marks the
-- request 'applied'. SECURITY INVOKER (no privilege elevation beyond the caller).
-- Returns the final lifecycle status ('applied'|'denied').
CREATE OR REPLACE FUNCTION rbac_approval_decide(
  p_request_id bigint,
  p_actor      bigint,
  p_decision   text,
  p_comment    text
) RETURNS text AS $$
DECLARE
  v_status text;
  v_req    record;
  v_window timestamptz;
BEGIN
  v_status := approval_decide(p_request_id, p_actor, p_decision, p_comment);

  IF v_status = 'approved' THEN
    -- read the stored activation params (only the consumer wrapper may read payload)
    SELECT requester_user_id, payload INTO v_req
      FROM approval_requests WHERE id = p_request_id;

    -- open the time-boxed window using the same clamp/cap logic as self-service;
    -- returns NULL when the eligible assignment was revoked/expired since the request was created.
    v_window := admin_role_window_open(
      v_req.requester_user_id,
      (v_req.payload->>'role_group_id')::bigint,
      (v_req.payload->>'duration_minutes')::int
    );

    -- BZ110: guard against a false approval_applied audit when no window was actually opened.
    -- The RAISE rolls back the whole transaction; the request stays 'pending' and the expiry
    -- sweep will clean it up. No approval_applied audit is written.
    IF v_window IS NULL THEN
      RAISE EXCEPTION 'assignment no longer eligible at apply' USING ERRCODE = 'BZ110';
    END IF;

    UPDATE approval_requests SET status = 'applied' WHERE id = p_request_id;

    PERFORM audit_write(
      p_actor,
      'approval_applied',
      'approval_request',
      p_request_id,
      NULL,
      jsonb_build_object(
        'role_group_id', v_req.payload->>'role_group_id',
        'requester',     v_req.requester_user_id
      ),
      NULL,
      p_comment,
      'core'
    );

    RETURN 'applied';
  END IF;

  RETURN v_status;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
