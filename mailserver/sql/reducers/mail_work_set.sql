-- Mailbox/thread-scoped shared-work authority. Folder/tag mutations never
-- participate, so one thread retains one work row across every view.
CREATE OR REPLACE FUNCTION mail_work_set(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_thread_id text,
  p_operation_id uuid,
  p_action text,
  p_expected_generation bigint,
  p_assignee_user_id bigint,
  p_status text,
  p_due_at timestamptz,
  p_reason text,
  p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_mailbox mailboxes%ROWTYPE; v_existing mail_work_operations%ROWTYPE;
  v_work mail_thread_work%ROWTYPE; v_before jsonb; v_after jsonb; v_result jsonb;
  v_is_full boolean; v_event_type text; v_event_id uuid:=gen_random_uuid();
  v_state bigint; v_target_ok boolean; v_policy jsonb; v_first_activity timestamptz;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RAISE EXCEPTION 'shared mail work is disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_action NOT IN ('claim','assign','status','due','handoff')
     OR p_expected_generation<0 OR p_request_digest!~'^[0-9a-f]{64}$'
     OR p_thread_id IS NULL OR octet_length(p_thread_id) NOT BETWEEN 1 AND 256
     OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid mail-work mutation' USING ERRCODE='BZ301';
  END IF;

  SELECT * INTO v_mailbox FROM mailboxes WHERE id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_mailbox.user_id IS NOT NULL THEN
    RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006';
  END IF;
  PERFORM 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id ORDER BY user_id,permission FOR UPDATE;
  IF NOT mail_work_can_collaborate(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared-mail collaboration permission required' USING ERRCODE='BZ005';
  END IF;
  v_is_full:=EXISTS(
    SELECT 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id
      AND user_id=p_actor_user_id AND permission='full_access');
  IF NOT EXISTS(SELECT 1 FROM messages WHERE mailbox_id=p_mailbox_id
      AND thread_id=p_thread_id AND NOT is_deleted) THEN
    RAISE EXCEPTION 'mail thread not found' USING ERRCODE='BZ007';
  END IF;

  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='work_set' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'mail-work idempotency conflict' USING ERRCODE='BZ303';
  END IF;

  SELECT * INTO v_work FROM mail_thread_work
   WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id FOR UPDATE;
  IF NOT FOUND THEN
    IF p_expected_generation<>0 THEN RAISE EXCEPTION 'mail-work generation is stale' USING ERRCODE='BZ304'; END IF;
    v_before:='null'::jsonb;
    v_policy:=mail_work_sla_policy_snapshot(p_mailbox_id);
    SELECT COALESCE(min(m.received_at),statement_timestamp()) INTO v_first_activity
      FROM messages m WHERE m.mailbox_id=p_mailbox_id AND m.thread_id=p_thread_id
        AND m.is_external AND NOT m.is_draft AND NOT m.is_deleted
        AND NOT EXISTS(SELECT 1 FROM migration_source_objects o
          WHERE o.target_kind='message' AND o.target_id=m.id AND o.projection_state='applied');
    INSERT INTO mail_thread_work(mailbox_id,thread_id,first_activity_at,sla_minutes,sla_policy_snapshot,due_at)
      VALUES(p_mailbox_id,p_thread_id,v_first_activity,(v_policy->>'slaMinutes')::integer,v_policy,
        mail_work_business_due_at(v_first_activity,(v_policy->>'slaMinutes')::integer,v_policy))
      RETURNING * INTO v_work;
  ELSE
    IF v_work.generation<>p_expected_generation THEN RAISE EXCEPTION 'mail-work generation is stale' USING ERRCODE='BZ304'; END IF;
    v_before:=to_jsonb(v_work)-ARRAY['mailbox_id'];
  END IF;

  IF p_action='claim' THEN
    IF v_work.status<>'unassigned' OR v_work.assignee_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'mail thread is already claimed' USING ERRCODE='BZ304';
    END IF;
    v_work.status:='owned'; v_work.assignee_user_id:=p_actor_user_id; v_event_type:='claimed';
  ELSIF p_action IN ('assign','handoff') THEN
    IF p_assignee_user_id IS NULL THEN RAISE EXCEPTION 'assignee is required' USING ERRCODE='BZ301'; END IF;
    IF p_assignee_user_id<>p_actor_user_id AND NOT v_is_full THEN
      RAISE EXCEPTION 'full access is required to assign another delegate' USING ERRCODE='BZ005';
    END IF;
    SELECT mail_work_can_collaborate(p_mailbox_id,p_assignee_user_id) INTO v_target_ok;
    IF NOT v_target_ok THEN RAISE EXCEPTION 'assignee is not collaboration-capable' USING ERRCODE='BZ005'; END IF;
    v_event_type:=CASE WHEN p_action='handoff' THEN 'handed_off'
      WHEN v_work.assignee_user_id IS NULL THEN 'assigned' ELSE 'reassigned' END;
    v_work.status:='owned'; v_work.assignee_user_id:=p_assignee_user_id; v_work.completed_at:=NULL;
  ELSIF p_action='status' THEN
    IF p_status NOT IN ('unassigned','owned','waiting','done') THEN
      RAISE EXCEPTION 'invalid mail-work status' USING ERRCODE='BZ301';
    END IF;
    IF v_work.assignee_user_id IS DISTINCT FROM p_actor_user_id AND NOT v_is_full THEN
      RAISE EXCEPTION 'only the assignee or full-access delegate may change status' USING ERRCODE='BZ005';
    END IF;
    IF p_status='unassigned' THEN v_work.assignee_user_id:=NULL; v_work.completed_at:=NULL;
    ELSIF p_status='done' THEN
      IF v_work.assignee_user_id IS NULL THEN v_work.assignee_user_id:=p_actor_user_id; END IF;
      v_work.completed_at:=statement_timestamp();
    ELSE
      IF v_work.assignee_user_id IS NULL THEN v_work.assignee_user_id:=p_actor_user_id; END IF;
      v_work.completed_at:=NULL;
    END IF;
    v_event_type:=CASE WHEN p_status='done' THEN 'completed'
      WHEN v_work.status='done' THEN 'reopened' ELSE 'status_changed' END;
    v_work.status:=p_status;
  ELSE
    IF v_work.assignee_user_id IS DISTINCT FROM p_actor_user_id AND NOT v_is_full THEN
      RAISE EXCEPTION 'only the assignee or full-access delegate may change due time' USING ERRCODE='BZ005';
    END IF;
    v_work.due_at:=p_due_at; v_event_type:='due_changed';
  END IF;

  v_work.generation:=CASE WHEN v_before='null'::jsonb THEN 1 ELSE v_work.generation+1 END;
  v_work.last_activity_at:=statement_timestamp(); v_work.last_event_id:=v_event_id;
  UPDATE mail_thread_work SET status=v_work.status,assignee_user_id=v_work.assignee_user_id,
    due_at=v_work.due_at,generation=v_work.generation,last_activity_at=v_work.last_activity_at,
    completed_at=v_work.completed_at,last_event_id=v_event_id
   WHERE mailbox_id=p_mailbox_id AND thread_id=p_thread_id;
  v_after:=to_jsonb(v_work)-ARRAY['mailbox_id'];

  INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,
    actor_user_id,actor_display_snapshot,before_state,after_state,reason)
  VALUES(v_event_id,p_mailbox_id,p_thread_id,v_work.generation,v_event_type,p_actor_user_id,
    COALESCE((SELECT NULLIF(display_name,'') FROM users WHERE id=p_actor_user_id),'Unknown user'),
    v_before,v_after,p_reason);
  v_state:=notify_mailwork_state(p_mailbox_id,'work',p_thread_id,
    CASE WHEN v_before='null'::jsonb THEN 'created' ELSE 'updated' END);
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'id',p_thread_id,
    'operationId',p_operation_id,'eventId',v_event_id,'state',v_state::text,
    'generation',v_work.generation::text,'status',v_work.status,
    'assigneeUserId',CASE WHEN v_work.assignee_user_id IS NULL THEN NULL ELSE v_work.assignee_user_id::text END,
    'dueAt',v_work.due_at,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
  VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'work_set',p_request_digest,v_result);
  INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload)
  SELECT v_event_id,k,v_event_id||':'||k,
    jsonb_build_object('version',1,'mailboxId',p_mailbox_id::text,'threadId',p_thread_id,
      'eventId',v_event_id,'eventType',v_event_type,'generation',v_work.generation::text,
      'recipientUserIds',CASE WHEN v_work.assignee_user_id IS NULL THEN '[]'::jsonb
        ELSE jsonb_build_array(v_work.assignee_user_id::text) END)
  FROM unnest(ARRAY['push','digest','metric']||CASE WHEN v_event_type IN
    ('claimed','assigned','reassigned','handed_off','completed') AND COALESCE(
      (SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_integrations'),false)
    THEN ARRAY['webhook'] ELSE ARRAY[]::text[] END) k;
  PERFORM audit_write(p_actor_user_id,'mail_work_'||v_event_type,'mailbox',p_mailbox_id,
    v_before,v_after,NULL::inet,p_reason,'core');
  RETURN v_result;
END $$;

ALTER FUNCTION mail_work_set(bigint,bigint,text,uuid,text,bigint,bigint,text,timestamptz,text,text) OWNER TO setjoin_worker;
