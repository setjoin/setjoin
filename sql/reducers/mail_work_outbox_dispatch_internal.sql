CREATE OR REPLACE FUNCTION mail_work_outbox_dispatch_internal(p_outbox_id bigint)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_out mail_work_outbox%ROWTYPE; v_event mail_thread_work_events%ROWTYPE;
  v_actor bigint; v_target bigint; v_result_id bigint; v_actor_mailbox bigint;
  v_subject text; v_task jsonb; v_sent jsonb; v_receipt jsonb; v_complete_event uuid:=gen_random_uuid();
  v_work mail_thread_work%ROWTYPE;
BEGIN
  SELECT * INTO v_out FROM mail_work_outbox WHERE id=p_outbox_id AND state='claimed' FOR UPDATE;
  IF NOT FOUND OR v_out.consumer_kind NOT IN ('task','chat','drive') THEN
    RAISE EXCEPTION 'mail-work internal action claim is unavailable' USING ERRCODE='BZ304';
  END IF;
  SELECT receipt INTO v_receipt FROM mail_work_consumer_effects WHERE outbox_id=p_outbox_id;
  IF FOUND THEN RETURN v_receipt||'{"replayed":true}'::jsonb; END IF;
  SELECT * INTO v_event FROM mail_thread_work_events WHERE id=v_out.event_id FOR SHARE;
  v_actor:=NULLIF(v_out.payload->>'actorUserId','')::bigint;
  v_target:=NULLIF(v_out.payload->>'targetId','')::bigint;
  IF v_event.id IS NULL OR v_actor IS NULL OR NOT mail_work_can_collaborate(v_event.mailbox_id,v_actor) THEN
    RAISE EXCEPTION 'mail-work internal action authority is unavailable' USING ERRCODE='BZ005';
  END IF;
  SELECT * INTO v_work FROM mail_thread_work
    WHERE mailbox_id=v_event.mailbox_id AND thread_id=v_event.thread_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'mail-work thread is unavailable' USING ERRCODE='BZ006'; END IF;

  IF v_out.consumer_kind='task' THEN
    SELECT id INTO v_actor_mailbox FROM mailboxes
      WHERE user_id=v_actor AND is_primary AND enabled ORDER BY id LIMIT 1;
    SELECT COALESCE(NULLIF(subject,''),'Shared mailbox conversation') INTO v_subject
      FROM messages WHERE mailbox_id=v_event.mailbox_id AND thread_id=v_event.thread_id
        AND NOT is_deleted ORDER BY received_at DESC,id DESC LIMIT 1;
    IF v_actor_mailbox IS NULL OR v_subject IS NULL THEN
      RAISE EXCEPTION 'task source is unavailable' USING ERRCODE='BZ005';
    END IF;
    v_task:=jmap_task_set_create(v_actor_mailbox,jsonb_build_object('mailwork',jsonb_build_object(
      'title',v_subject,'description','Setjoin shared mailbox '||v_event.mailbox_id||' thread '||v_event.thread_id,
      'categories',jsonb_build_array('shared-mail'))));
    v_result_id:=NULLIF(v_task#>>'{created,mailwork,id}','')::bigint;
    IF v_result_id IS NULL THEN RAISE EXCEPTION 'task creation failed' USING ERRCODE='BZ304'; END IF;
  ELSIF v_out.consumer_kind='chat' THEN
    v_sent:=chat_message_send(v_actor,v_target,
      'Shared mailbox work: /inbox?accountId='||v_event.mailbox_id||'&threadId='||v_event.thread_id);
    v_result_id:=NULLIF(v_sent->>'messageId','')::bigint;
    IF v_result_id IS NULL THEN RAISE EXCEPTION 'chat post failed' USING ERRCODE='BZ304'; END IF;
  ELSE
    IF NOT drive_runtime_has_node_capability(v_actor,v_target,'read_metadata')
       OR NOT EXISTS(SELECT 1 FROM drive_nodes WHERE id=v_target AND deleted_at IS NULL) THEN
      RAISE EXCEPTION 'Drive target is unavailable' USING ERRCODE='BZ005';
    END IF;
    v_result_id:=v_target;
  END IF;

  INSERT INTO mail_work_action_links(mailbox_id,thread_id,action_kind,target_id,result_id,event_id,created_by)
  VALUES(v_event.mailbox_id,v_event.thread_id,v_out.consumer_kind,v_target,v_result_id,v_event.id,v_actor);
  UPDATE mail_thread_work SET generation=generation+1,last_activity_at=statement_timestamp(),last_event_id=v_complete_event
    WHERE mailbox_id=v_event.mailbox_id AND thread_id=v_event.thread_id RETURNING * INTO v_work;
  INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,
    actor_display_snapshot,before_state,after_state,reason)
  VALUES(v_complete_event,v_event.mailbox_id,v_event.thread_id,v_work.generation,'action_completed',v_actor,
    v_event.actor_display_snapshot,'{}'::jsonb,
    jsonb_build_object('actionKind',v_out.consumer_kind,'targetId',v_target,'resultId',v_result_id),
    'Approved internal action completed');
  PERFORM notify_mailwork_state(v_event.mailbox_id,'work',v_event.thread_id,'updated');
  v_receipt:=jsonb_build_object('outboxId',p_outbox_id::text,'eventId',v_event.id,
    'completionEventId',v_complete_event,'actionKind',v_out.consumer_kind,
    'targetId',CASE WHEN v_target IS NULL THEN NULL ELSE v_target::text END,
    'resultId',v_result_id::text,'outcome','completed','replayed',false);
  INSERT INTO mail_work_consumer_effects(outbox_id,receipt) VALUES(p_outbox_id,v_receipt);
  RETURN v_receipt;
END $$;
ALTER FUNCTION mail_work_outbox_dispatch_internal(bigint) OWNER TO setjoin_worker;
