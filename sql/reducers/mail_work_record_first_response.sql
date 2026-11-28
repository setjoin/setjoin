CREATE OR REPLACE FUNCTION mail_work_record_first_response(
  p_mailbox_id bigint,p_actor_user_id bigint,p_thread_id text,p_sent_message_id bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_work mail_thread_work%ROWTYPE; v_event_id uuid:=gen_random_uuid();
  v_before jsonb; v_after jsonb; v_seconds bigint; v_state bigint; v_display text;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RETURN jsonb_build_object('recorded',false,'why','disabled');
  END IF;
  IF p_thread_id IS NULL OR octet_length(p_thread_id) NOT BETWEEN 1 AND 256 OR p_sent_message_id IS NULL THEN
    RAISE EXCEPTION 'invalid first-response evidence' USING ERRCODE='BZ301';
  END IF;
  IF p_actor_user_id IS NOT NULL AND NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared-mail response permission required' USING ERRCODE='BZ005';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM messages WHERE mailbox_id=p_mailbox_id AND id=p_sent_message_id
      AND thread_id=p_thread_id AND NOT is_draft AND NOT is_deleted) THEN
    RAISE EXCEPTION 'sent response evidence not found' USING ERRCODE='BZ007';
  END IF;
  SELECT * INTO v_work FROM mail_thread_work WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('recorded',false,'why','work_absent'); END IF;
  IF v_work.first_response_at IS NOT NULL THEN
    RETURN jsonb_build_object('recorded',false,'why','already_recorded','eventId',v_work.last_event_id);
  END IF;
  v_before:=to_jsonb(v_work)-ARRAY['mailbox_id'];
  v_seconds:=mail_work_business_seconds(v_work.first_activity_at,statement_timestamp(),v_work.sla_policy_snapshot);
  v_work.first_response_at:=statement_timestamp(); v_work.last_activity_at:=statement_timestamp();
  v_work.generation:=v_work.generation+1; v_work.last_event_id:=v_event_id;
  UPDATE mail_thread_work SET first_response_at=v_work.first_response_at,last_activity_at=v_work.last_activity_at,
    generation=v_work.generation,last_event_id=v_event_id WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id;
  v_after:=(to_jsonb(v_work)-ARRAY['mailbox_id'])||jsonb_build_object('first_response_seconds',v_seconds);
  SELECT COALESCE(NULLIF(display_name,''),'System') INTO v_display FROM users WHERE id=p_actor_user_id;
  INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,
    actor_display_snapshot,before_state,after_state,reason)
  VALUES(v_event_id,p_mailbox_id,p_thread_id,v_work.generation,'first_response',p_actor_user_id,
    COALESCE(v_display,'System'),v_before,v_after,'First eligible shared-mail response submitted');
  INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload)
  VALUES(v_event_id,'metric',v_event_id||':metric',jsonb_build_object('version',1,
    'mailboxId',p_mailbox_id::text,'threadId',p_thread_id,'eventId',v_event_id,
    'eventType','first_response','generation',v_work.generation::text,'recipientUserIds','[]'::jsonb));
  v_state:=notify_mailwork_state(p_mailbox_id,'work',p_thread_id,'updated');
  RETURN jsonb_build_object('recorded',true,'eventId',v_event_id,'state',v_state::text,
    'generation',v_work.generation::text,'businessSeconds',v_seconds);
END $$;

ALTER FUNCTION mail_work_record_first_response(bigint,bigint,text,bigint) OWNER TO setjoin_worker;
