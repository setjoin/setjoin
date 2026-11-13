-- group_moderation_approval_decide: inbound group-moderation consumer wrapper (T8).
-- Delegates to approval_decide (SoD + approver-authorization + audit + notify), then:
--   approved → REPLAY the held delivery via deliver(<the 32 stored args>). deliver()
--              expands the group to members exactly as a live inbound would, reusing the
--              PERSISTED verdict verbatim (NO S/MIME / DMARC / spam re-verify — the
--              verdict columns are read straight out of deliver_params). The held row is
--              dropped; status becomes 'applied'.
--   denied   → drop the held row (the post never reaches the members).
-- SECURITY INVOKER (no privilege elevation). Returns the final lifecycle status
-- ('applied' | 'denied'). Errors propagate from approval_decide (BZ106 SoD /
-- BZ107 not-the-approver / BZ108 not-found-or-not-pending).
CREATE OR REPLACE FUNCTION group_moderation_approval_decide(
  p_request_id bigint,
  p_actor      bigint,
  p_decision   text,
  p_comment    text
) RETURNS text AS $$
DECLARE
  v_status text;
  v_p      jsonb;
BEGIN
  v_status := approval_decide(p_request_id, p_actor, p_decision, p_comment);

  IF v_status = 'approved' THEN
    -- Only the consumer wrapper reads the held row; it holds every deliver() arg verbatim.
    SELECT deliver_params INTO v_p
      FROM held_inbound_messages WHERE approval_request_id = p_request_id;

    IF v_p IS NOT NULL THEN
      -- Replay the original delivery. The group expands to members here, exactly as the
      -- live inbound path would have, reusing the stored verdict (spf/dkim/dmarc/spam/smime).
      -- deliver_json unpacks the stored jsonb by the same parameter names the live Go
      -- path uses, so the key->position mapping lives in exactly one place.
      PERFORM deliver_json(v_p);
    END IF;

    DELETE FROM held_inbound_messages WHERE approval_request_id = p_request_id;
    UPDATE approval_requests SET status = 'applied' WHERE id = p_request_id;

    PERFORM audit_write(
      p_actor, 'approval_applied', 'approval_request', p_request_id,
      NULL, jsonb_build_object('consumer_type', 'mail.group_moderation'),
      NULL, p_comment, 'core'
    );

    RETURN 'applied';
  END IF;

  IF v_status = 'denied' THEN
    -- The post is rejected: drop the held row so the message never reaches members.
    -- ponytail: NDR-to-sender on deny skipped; the held envelope is retained nowhere
    --           after the drop. Add a bounce here if product wants the sender notified.
    DELETE FROM held_inbound_messages WHERE approval_request_id = p_request_id;
  END IF;

  RETURN v_status;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
