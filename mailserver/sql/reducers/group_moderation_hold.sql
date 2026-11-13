-- group_moderation_hold: park an inbound moderated-group post (T8). Atomically
-- creates the approval request (approver = the group moderator's mailbox owner) and
-- the held_inbound_messages row that carries the VERBATIM deliver() args (verdict
-- included) so the delivery can be replayed on approve with NO S/MIME / DMARC / spam
-- re-verify. The external sender has NO internal requester → requester_user_id NULL
-- (V047); the sender address lives in the subject + payload instead.
-- Returns the new approval_request id. SECURITY INVOKER.
CREATE OR REPLACE FUNCTION group_moderation_hold(
  p_group_id       bigint,
  p_sender         text,
  p_raw_ref        text,
  p_envelope       jsonb,
  p_deliver_params jsonb
) RETURNS bigint AS $$
DECLARE
  v_mod_mailbox bigint;
  v_approver    bigint;
  v_ttl         int;
  v_domain_id   bigint;
  v_request_id  bigint;
BEGIN
  SELECT moderator_mailbox_id INTO v_mod_mailbox
    FROM distribution_groups WHERE id = p_group_id;

  -- No requester (the sender is external) to derive domain_id from — pass the
  -- target group's own mailbox domain explicitly (V093).
  SELECT mb.domain_id INTO v_domain_id
    FROM distribution_groups dg JOIN mailboxes mb ON mb.id = dg.mailbox_id
   WHERE dg.id = p_group_id;

  -- Approver = the moderator mailbox's owner; fall back to the configured default.
  SELECT user_id INTO v_approver FROM mailboxes WHERE id = v_mod_mailbox;
  IF v_approver IS NULL THEN
    SELECT NULLIF((value #>> '{}')::bigint, 0) INTO v_approver
      FROM system_config WHERE key = 'approval.default_approver_user_id';
  END IF;
  IF v_approver IS NULL THEN
    RAISE EXCEPTION 'group % has no moderator and no default approver', p_group_id
      USING ERRCODE = 'BZ111';
  END IF;

  SELECT COALESCE((value #>> '{}')::int, 2880) INTO v_ttl
    FROM system_config WHERE key = 'approval.request_ttl_minutes';
  v_ttl := COALESCE(v_ttl, 2880);

  v_request_id := approval_request_create(
    'mail.group_moderation',
    NULL,                                          -- external sender: no internal requester (V072)
    'Moderate post from ' || p_sender || ' to group',
    jsonb_build_object('group_id', p_group_id, 'sender', p_sender),
    NULL,                                          -- no policy (moderator is caller-supplied)
    'user',
    v_approver,
    v_ttl,
    v_domain_id
  );

  INSERT INTO held_inbound_messages(approval_request_id, group_id, raw_ref, envelope, deliver_params)
    VALUES (v_request_id, p_group_id, p_raw_ref, p_envelope, p_deliver_params);

  RETURN v_request_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
