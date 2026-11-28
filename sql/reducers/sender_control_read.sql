-- Unified, message-bound projection over Focus, VIP and sender-list authority.

CREATE OR REPLACE FUNCTION sender_control_read(
  p_user_id bigint,p_mailbox_id bigint,p_message_id bigint,p_received_at timestamptz
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_sender text; v_generation bigint;
BEGIN
  SELECT lower(m.from_addr) INTO v_sender FROM messages m
   WHERE m.id=p_message_id AND m.received_at=p_received_at AND m.mailbox_id=p_mailbox_id
     AND EXISTS(SELECT 1 FROM account_scope(p_mailbox_id) s WHERE s.user_id=p_user_id);
  IF v_sender IS NULL THEN RAISE EXCEPTION 'message not found' USING ERRCODE='BZ006'; END IF;
  SELECT generation INTO v_generation FROM sender_control_state WHERE user_id=p_user_id;
  RETURN jsonb_build_object(
    'sender',v_sender,'senderDigest',encode(digest(v_sender,'sha256'),'hex'),
    'generation',v_generation::text,
    'alwaysFocus',COALESCE((SELECT focused FROM focus_sender_overrides WHERE user_id=p_user_id AND sender=v_sender),false),
    'neverFocus',COALESCE((SELECT NOT focused FROM focus_sender_overrides WHERE user_id=p_user_id AND sender=v_sender),false),
    'vip',EXISTS(SELECT 1 FROM vip_senders WHERE user_id=p_user_id AND sender_email=v_sender),
    'safe',EXISTS(SELECT 1 FROM user_sender_list WHERE user_id=p_user_id AND sender=v_sender AND list_type='safe'),
    'blocked',EXISTS(SELECT 1 FROM user_sender_list WHERE user_id=p_user_id AND sender=v_sender AND list_type='blocked'));
END $$;

ALTER FUNCTION sender_control_read(bigint,bigint,bigint,timestamptz) OWNER TO setjoin_worker;
