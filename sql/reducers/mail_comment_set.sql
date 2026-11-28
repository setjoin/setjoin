-- Append-only private comment/edit with optional atomic full-access handoff.
CREATE OR REPLACE FUNCTION mail_comment_set(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_thread_id text,
  p_operation_id uuid,
  p_expected_generation bigint,
  p_body text,
  p_mention_user_ids bigint[],
  p_replaces_comment_id uuid,
  p_handoff_user_id bigint,
  p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_mailbox mailboxes%ROWTYPE; v_existing mail_work_operations%ROWTYPE;
  v_work mail_thread_work%ROWTYPE; v_original mail_thread_comments%ROWTYPE;
  v_comment_id uuid:=gen_random_uuid(); v_event_id uuid:=gen_random_uuid();
  v_before jsonb; v_after jsonb; v_result jsonb; v_state bigint;
  v_is_full boolean; v_mention bigint; v_capability text; v_display text;
  v_new_work boolean:=false; v_policy jsonb; v_first_activity timestamptz;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false)
     OR NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_comments'),false) THEN
    RAISE EXCEPTION 'shared mail comments are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_expected_generation<0 OR p_request_digest!~'^[0-9a-f]{64}$'
     OR p_thread_id IS NULL OR octet_length(p_thread_id) NOT BETWEEN 1 AND 256
     OR p_body IS NULL OR octet_length(p_body) NOT BETWEEN 1 AND 8192 OR p_body~E'[\\x00]' THEN
    RAISE EXCEPTION 'invalid private comment' USING ERRCODE='BZ301';
  END IF;
  IF COALESCE(cardinality(p_mention_user_ids),0)>50 THEN
    RAISE EXCEPTION 'too many comment mentions' USING ERRCODE='BZ301';
  END IF;

  SELECT * INTO v_mailbox FROM mailboxes WHERE id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_mailbox.user_id IS NOT NULL THEN
    RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006';
  END IF;
  PERFORM 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id ORDER BY user_id,permission FOR UPDATE;
  IF NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'comment permission required' USING ERRCODE='BZ005';
  END IF;
  v_is_full:=EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id
    AND user_id=p_actor_user_id AND permission='full_access');
  IF NOT EXISTS(SELECT 1 FROM messages WHERE mailbox_id=p_mailbox_id
      AND thread_id=p_thread_id AND NOT is_deleted) THEN
    RAISE EXCEPTION 'mail thread not found' USING ERRCODE='BZ007';
  END IF;

  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind IN ('comment_set','comment_edit')
       AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'mail-comment idempotency conflict' USING ERRCODE='BZ303';
  END IF;

  SELECT * INTO v_work FROM mail_thread_work WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id FOR UPDATE;
  IF NOT FOUND THEN
    IF p_expected_generation<>0 THEN RAISE EXCEPTION 'mail-work generation is stale' USING ERRCODE='BZ304'; END IF;
    v_policy:=mail_work_sla_policy_snapshot(p_mailbox_id);
    SELECT COALESCE(min(m.received_at),statement_timestamp()) INTO v_first_activity
      FROM messages m WHERE m.mailbox_id=p_mailbox_id AND m.thread_id=p_thread_id
        AND m.is_external AND NOT m.is_draft AND NOT m.is_deleted
        AND NOT EXISTS(SELECT 1 FROM migration_source_objects o
          WHERE o.target_kind='message' AND o.target_id=m.id AND o.projection_state='applied');
    INSERT INTO mail_thread_work(mailbox_id,thread_id,first_activity_at,sla_minutes,sla_policy_snapshot,due_at)
      VALUES(p_mailbox_id,p_thread_id,v_first_activity,(v_policy->>'slaMinutes')::integer,v_policy,
        mail_work_business_due_at(v_first_activity,(v_policy->>'slaMinutes')::integer,v_policy)) RETURNING * INTO v_work;
    v_new_work:=true;
  ELSIF v_work.generation<>p_expected_generation THEN
    RAISE EXCEPTION 'mail-work generation is stale' USING ERRCODE='BZ304';
  END IF;
  v_before:=to_jsonb(v_work)-ARRAY['mailbox_id'];

  IF p_replaces_comment_id IS NOT NULL THEN
    SELECT * INTO v_original FROM mail_thread_comments
      WHERE id=p_replaces_comment_id AND mailbox_id=p_mailbox_id AND thread_id=p_thread_id FOR UPDATE;
    IF NOT FOUND OR (v_original.author_user_id<>p_actor_user_id AND NOT v_is_full)
       OR v_original.tombstoned_at IS NOT NULL THEN
      RAISE EXCEPTION 'comment cannot be edited' USING ERRCODE='BZ005';
    END IF;
    UPDATE mail_thread_comments SET tombstoned_at=statement_timestamp(),tombstoned_by=p_actor_user_id
      WHERE id=p_replaces_comment_id;
  END IF;
  IF p_handoff_user_id IS NOT NULL THEN
    IF NOT v_is_full OR NOT mail_work_can_collaborate(p_mailbox_id,p_handoff_user_id) THEN
      RAISE EXCEPTION 'full access and eligible handoff target are required' USING ERRCODE='BZ005';
    END IF;
    v_work.status:='owned'; v_work.assignee_user_id:=p_handoff_user_id; v_work.completed_at:=NULL;
  END IF;

  SELECT COALESCE(NULLIF(display_name,''),'Unknown user') INTO v_display FROM users WHERE id=p_actor_user_id;
  INSERT INTO mail_thread_comments(id,mailbox_id,thread_id,author_user_id,author_display_snapshot,
    body,replaces_comment_id,operation_id)
  VALUES(v_comment_id,p_mailbox_id,p_thread_id,p_actor_user_id,v_display,p_body,p_replaces_comment_id,p_operation_id);
  FOREACH v_mention IN ARRAY COALESCE(p_mention_user_ids,ARRAY[]::bigint[]) LOOP
    IF NOT mail_work_can_read(p_mailbox_id,v_mention) THEN
      RAISE EXCEPTION 'mentioned user cannot view this mailbox' USING ERRCODE='BZ005';
    END IF;
    v_capability:=CASE WHEN mail_work_can_collaborate(p_mailbox_id,v_mention) THEN 'comment' ELSE 'view_only' END;
    INSERT INTO mail_thread_comment_mentions(comment_id,user_id,capability)
      VALUES(v_comment_id,v_mention,v_capability) ON CONFLICT DO NOTHING;
  END LOOP;

  v_work.generation:=CASE WHEN v_new_work THEN 1 ELSE v_work.generation+1 END;
  v_work.last_activity_at:=statement_timestamp();
  v_work.last_event_id:=v_event_id;
  UPDATE mail_thread_work SET status=v_work.status,assignee_user_id=v_work.assignee_user_id,
    completed_at=v_work.completed_at,generation=v_work.generation,
    last_activity_at=v_work.last_activity_at,last_event_id=v_event_id
   WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id;
  v_after:=to_jsonb(v_work)-ARRAY['mailbox_id'];
  INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,
    actor_user_id,actor_display_snapshot,before_state,after_state,reason)
  VALUES(v_event_id,p_mailbox_id,p_thread_id,v_work.generation,
    CASE WHEN p_handoff_user_id IS NULL THEN 'commented' ELSE 'handed_off' END,
    p_actor_user_id,v_display,v_before,v_after,
    CASE WHEN p_handoff_user_id IS NULL THEN 'Private comment added' ELSE 'Private comment and handoff' END);
  v_state:=notify_mailwork_state(p_mailbox_id,'comment',v_comment_id::text,'created');
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'threadId',p_thread_id,
    'commentId',v_comment_id,'eventId',v_event_id,'state',v_state::text,
    'generation',v_work.generation::text,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
  VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,
    CASE WHEN p_replaces_comment_id IS NULL THEN 'comment_set' ELSE 'comment_edit' END,
    p_request_digest,v_result);
  INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload)
  SELECT v_event_id,k,v_event_id||':'||k,jsonb_build_object(
    'version',1,'mailboxId',p_mailbox_id::text,'threadId',p_thread_id,
    'eventId',v_event_id,'eventType',CASE WHEN p_handoff_user_id IS NULL THEN 'commented' ELSE 'handed_off' END,
    'recipientUserIds',to_jsonb(ARRAY(SELECT DISTINCT x::text FROM unnest(
      COALESCE(p_mention_user_ids,ARRAY[]::bigint[])||CASE WHEN p_handoff_user_id IS NULL THEN ARRAY[]::bigint[] ELSE ARRAY[p_handoff_user_id] END
    ) x ORDER BY x)))
  FROM unnest(ARRAY['push','digest']) k;
  RETURN v_result;
END $$;

ALTER FUNCTION mail_comment_set(bigint,bigint,text,uuid,bigint,text,bigint[],uuid,bigint,text) OWNER TO setjoin_worker;
