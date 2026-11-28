-- One transaction for message-bound sender controls, reports and exact undo.

CREATE OR REPLACE FUNCTION sender_control_action(
  p_user_id bigint,p_mailbox_id bigint,p_message_id bigint,p_received_at timestamptz,
  p_operation_id uuid,p_action text,p_expected_generation bigint,p_request_digest text,
  p_target_operation_id uuid DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_sender text; v_state sender_control_state%ROWTYPE; v_existing sender_control_operations%ROWTYPE;
  v_target sender_control_operations%ROWTYPE; v_before jsonb; v_result jsonb; v_focused boolean;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.sender_control_center'),false) THEN
    RAISE EXCEPTION 'sender control center is disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_expected_generation<1 OR p_request_digest!~'^[0-9a-f]{64}$'
     OR p_action NOT IN ('always_focus','never_focus','vip','not_vip','safe','block','never_block','report_phishing','report_spam','undo') THEN
    RAISE EXCEPTION 'invalid sender control action' USING ERRCODE='BZ301';
  END IF;
  SELECT lower(m.from_addr) INTO v_sender FROM messages m
   WHERE m.id=p_message_id AND m.received_at=p_received_at AND m.mailbox_id=p_mailbox_id
     AND EXISTS(SELECT 1 FROM account_scope(p_mailbox_id) s WHERE s.user_id=p_user_id)
   FOR UPDATE;
  IF v_sender IS NULL THEN RAISE EXCEPTION 'message not found' USING ERRCODE='BZ006'; END IF;
  SELECT * INTO v_existing FROM sender_control_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.user_id=p_user_id AND v_existing.sender_address=v_sender AND v_existing.action=p_action
       AND v_existing.request_digest=p_request_digest AND v_existing.target_operation_id IS NOT DISTINCT FROM p_target_operation_id THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'sender control idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_state FROM sender_control_state WHERE user_id=p_user_id FOR UPDATE;
  IF NOT FOUND THEN INSERT INTO sender_control_state(user_id) VALUES(p_user_id) RETURNING * INTO v_state; END IF;
  IF v_state.generation<>p_expected_generation THEN RAISE EXCEPTION 'sender control generation is stale' USING ERRCODE='BZ304'; END IF;
  SELECT NOT EXISTS(SELECT 1 FROM message_tags mt JOIN tags t ON t.id=mt.tag_id
    WHERE mt.message_id=p_message_id AND mt.received_at=p_received_at AND t.mailbox_id=p_mailbox_id AND t.name='Other') INTO v_focused;
  v_before:=jsonb_build_object(
    'focusOverride',(SELECT focused FROM focus_sender_overrides WHERE user_id=p_user_id AND sender=v_sender),
    'messageFocused',v_focused,
    'vip',EXISTS(SELECT 1 FROM vip_senders WHERE user_id=p_user_id AND sender_email=v_sender),
    'safe',EXISTS(SELECT 1 FROM user_sender_list WHERE user_id=p_user_id AND sender=v_sender AND list_type='safe'),
    'blocked',EXISTS(SELECT 1 FROM user_sender_list WHERE user_id=p_user_id AND sender=v_sender AND list_type='blocked'));

  IF p_action='always_focus' THEN
    PERFORM set_message_focus(p_message_id,p_received_at,true,p_mailbox_id);
  ELSIF p_action='never_focus' THEN
    PERFORM set_message_focus(p_message_id,p_received_at,false,p_mailbox_id);
  ELSIF p_action='vip' THEN
    INSERT INTO vip_senders(user_id,sender_email) VALUES(p_user_id,v_sender) ON CONFLICT DO NOTHING;
  ELSIF p_action='not_vip' THEN
    DELETE FROM vip_senders WHERE user_id=p_user_id AND sender_email=v_sender;
  ELSIF p_action IN ('safe','never_block') THEN
    DELETE FROM user_sender_list WHERE user_id=p_user_id AND sender=v_sender AND list_type='blocked';
    INSERT INTO user_sender_list(user_id,sender,list_type) VALUES(p_user_id,v_sender,'safe') ON CONFLICT DO NOTHING;
  ELSIF p_action='block' THEN
    DELETE FROM user_sender_list WHERE user_id=p_user_id AND sender=v_sender AND list_type='safe';
    INSERT INTO user_sender_list(user_id,sender,list_type) VALUES(p_user_id,v_sender,'blocked') ON CONFLICT DO NOTHING;
  ELSIF p_action IN ('report_spam','report_phishing') THEN
    NULL;
  ELSE
    IF p_target_operation_id IS NULL THEN RAISE EXCEPTION 'undo target is required' USING ERRCODE='BZ301'; END IF;
    SELECT * INTO v_target FROM sender_control_operations WHERE operation_id=p_target_operation_id AND user_id=p_user_id FOR UPDATE;
    IF NOT FOUND OR v_target.sender_address<>v_sender OR v_target.generation<>v_state.generation
       OR v_target.action='undo' THEN RAISE EXCEPTION 'sender control undo is stale' USING ERRCODE='BZ304'; END IF;
    IF v_target.action IN ('always_focus','never_focus') THEN
      PERFORM set_message_focus(p_message_id,p_received_at,COALESCE((v_target.before_state->>'messageFocused')::boolean,true),p_mailbox_id);
      IF v_target.before_state->'focusOverride'='null'::jsonb THEN
        DELETE FROM focus_sender_overrides WHERE user_id=p_user_id AND sender=v_sender;
      ELSE
        INSERT INTO focus_sender_overrides(user_id,sender,focused) VALUES(p_user_id,v_sender,(v_target.before_state->>'focusOverride')::boolean)
        ON CONFLICT(user_id,sender) DO UPDATE SET focused=excluded.focused,updated_at=statement_timestamp();
      END IF;
    ELSIF v_target.action IN ('vip','not_vip') THEN
      IF (v_target.before_state->>'vip')::boolean THEN INSERT INTO vip_senders(user_id,sender_email) VALUES(p_user_id,v_sender) ON CONFLICT DO NOTHING;
      ELSE DELETE FROM vip_senders WHERE user_id=p_user_id AND sender_email=v_sender; END IF;
    ELSIF v_target.action IN ('safe','block','never_block') THEN
      DELETE FROM user_sender_list WHERE user_id=p_user_id AND sender=v_sender;
      IF (v_target.before_state->>'safe')::boolean THEN INSERT INTO user_sender_list(user_id,sender,list_type) VALUES(p_user_id,v_sender,'safe'); END IF;
      IF (v_target.before_state->>'blocked')::boolean THEN INSERT INTO user_sender_list(user_id,sender,list_type) VALUES(p_user_id,v_sender,'blocked'); END IF;
    ELSIF v_target.action IN ('report_spam','report_phishing') THEN
      UPDATE sender_feedback_outbox SET state='cancelled',completed_at=statement_timestamp()
       WHERE operation_id=v_target.operation_id AND state='pending';
      IF NOT FOUND THEN RAISE EXCEPTION 'sender report already dispatched' USING ERRCODE='BZ304'; END IF;
    END IF;
  END IF;

  UPDATE sender_control_state SET generation=generation+1,updated_at=statement_timestamp()
   WHERE user_id=p_user_id RETURNING * INTO v_state;
  v_result:=sender_control_read(p_user_id,p_mailbox_id,p_message_id,p_received_at)
    ||jsonb_build_object('operationId',p_operation_id,'action',p_action,'replayed',false);
  INSERT INTO sender_control_operations(operation_id,user_id,generation,sender_address,sender_digest,action,
    request_digest,target_operation_id,before_state,result) VALUES(p_operation_id,p_user_id,v_state.generation,v_sender,
    encode(digest(v_sender,'sha256'),'hex'),p_action,p_request_digest,p_target_operation_id,v_before,v_result);
  IF p_action IN ('report_spam','report_phishing') THEN
    INSERT INTO sender_feedback_outbox(operation_id,user_id,mailbox_id,message_id,received_at,feedback_kind)
    VALUES(p_operation_id,p_user_id,p_mailbox_id,p_message_id,p_received_at,substring(p_action from 8));
  END IF;
  PERFORM audit_write(p_user_id,'sender_control_'||p_action,'message',p_message_id,v_before,v_result,NULL,NULL,'core');
  PERFORM app_notify('sender_control',json_build_object('user_id',p_user_id,'generation',v_state.generation)::text);
  RETURN v_result;
END $$;

ALTER FUNCTION sender_control_action(bigint,bigint,bigint,timestamptz,uuid,text,bigint,text,uuid) OWNER TO setjoin_worker;
