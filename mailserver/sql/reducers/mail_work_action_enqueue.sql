CREATE OR REPLACE FUNCTION mail_work_action_enqueue(
  p_mailbox_id bigint,p_actor_user_id bigint,p_thread_id text,p_operation_id uuid,
  p_expected_generation bigint,p_action_kind text,p_target_id bigint,p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_work mail_thread_work%ROWTYPE; v_existing mail_work_operations%ROWTYPE;
  v_event uuid:=gen_random_uuid(); v_outbox bigint; v_state bigint; v_result jsonb; v_display text;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false)
     OR NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_integrations'),false) THEN
    RAISE EXCEPTION 'shared mail integrations are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_expected_generation<1 OR p_action_kind NOT IN ('task','chat','drive')
     OR p_thread_id IS NULL OR octet_length(p_thread_id) NOT BETWEEN 1 AND 256
     OR p_request_digest!~'^[0-9a-f]{64}$'
     OR (p_action_kind='task' AND p_target_id IS NOT NULL)
     OR (p_action_kind IN ('chat','drive') AND COALESCE(p_target_id,0)<=0) THEN
    RAISE EXCEPTION 'invalid shared mail action' USING ERRCODE='BZ301';
  END IF;
  PERFORM 1 FROM mailboxes WHERE id=p_mailbox_id FOR UPDATE;
  PERFORM 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id ORDER BY user_id,permission FOR UPDATE;
  IF NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared mail action permission required' USING ERRCODE='BZ005';
  END IF;
  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='outbox_action' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'shared mail action idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_work FROM mail_thread_work
    WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id FOR UPDATE;
  IF NOT FOUND OR v_work.generation<>p_expected_generation THEN
    RAISE EXCEPTION 'mail-work generation is stale' USING ERRCODE='BZ304';
  END IF;
  IF p_action_kind='task' AND NOT EXISTS(SELECT 1 FROM mailboxes
      WHERE user_id=p_actor_user_id AND is_primary AND enabled) THEN
    RAISE EXCEPTION 'task target mailbox is unavailable' USING ERRCODE='BZ005';
  ELSIF p_action_kind='chat' AND chat_member_role(p_target_id,p_actor_user_id) IS NULL THEN
    RAISE EXCEPTION 'chat target is unavailable' USING ERRCODE='BZ005';
  ELSIF p_action_kind='drive' AND NOT drive_runtime_has_node_capability(
      p_actor_user_id,p_target_id,'read_metadata') THEN
    RAISE EXCEPTION 'Drive target is unavailable' USING ERRCODE='BZ005';
  END IF;
  SELECT COALESCE(NULLIF(display_name,''),'Unknown user') INTO v_display FROM users WHERE id=p_actor_user_id;
  UPDATE mail_thread_work SET generation=generation+1,last_activity_at=statement_timestamp(),last_event_id=v_event
    WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id RETURNING * INTO v_work;
  INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,
    actor_display_snapshot,before_state,after_state,reason)
  VALUES(v_event,p_mailbox_id,p_thread_id,v_work.generation,'action_requested',p_actor_user_id,v_display,
    '{}'::jsonb,jsonb_build_object('actionKind',p_action_kind,'targetId',p_target_id),'Approved internal action requested');
  INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload)
  VALUES(v_event,p_action_kind,v_event||':'||p_action_kind,jsonb_build_object('version',1,
    'mailboxId',p_mailbox_id::text,'threadId',p_thread_id,'actorUserId',p_actor_user_id::text,
    'actionKind',p_action_kind,'targetId',p_target_id)) RETURNING id INTO v_outbox;
  v_state:=notify_mailwork_state(p_mailbox_id,'work',p_thread_id,'updated');
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'threadId',p_thread_id,
    'eventId',v_event,'outboxId',v_outbox::text,'actionKind',p_action_kind,
    'targetId',CASE WHEN p_target_id IS NULL THEN NULL ELSE p_target_id::text END,
    'generation',v_work.generation::text,'state',v_state::text,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
  VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'outbox_action',p_request_digest,v_result);
  RETURN v_result;
END $$;
ALTER FUNCTION mail_work_action_enqueue(bigint,bigint,text,uuid,bigint,text,bigint,text) OWNER TO setjoin_worker;
