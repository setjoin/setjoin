-- Bounded server-time SLA scanner. Work rows are authoritative; Go only ticks.
CREATE OR REPLACE FUNCTION mail_work_sla_scan(p_limit integer DEFAULT 100)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_work mail_thread_work%ROWTYPE; v_event uuid; v_count integer:=0;
BEGIN
  IF p_limit NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'invalid mail-work SLA scan limit' USING ERRCODE='BZ301';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RETURN jsonb_build_object('scanned',0,'disabled',true);
  END IF;
  FOR v_work IN
    SELECT * FROM mail_thread_work
     WHERE due_at<=statement_timestamp() AND sla_breached_at IS NULL AND status<>'done'
     ORDER BY due_at,mailbox_id,thread_id FOR UPDATE SKIP LOCKED LIMIT p_limit
  LOOP
    v_event:=gen_random_uuid();
    UPDATE mail_thread_work SET sla_breached_at=statement_timestamp(),generation=generation+1,
      last_event_id=v_event,last_activity_at=statement_timestamp()
     WHERE mailbox_id=v_work.mailbox_id AND thread_id=v_work.thread_id;
    INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,
      actor_display_snapshot,before_state,after_state,reason)
    VALUES(v_event,v_work.mailbox_id,v_work.thread_id,v_work.generation+1,'sla_breached',
      'System',to_jsonb(v_work)-ARRAY['mailbox_id'],
      (SELECT to_jsonb(w)-ARRAY['mailbox_id'] FROM mail_thread_work w
        WHERE w.mailbox_id=v_work.mailbox_id AND w.thread_id=v_work.thread_id),
      'Server-time due threshold reached');
    INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload)
    SELECT v_event,k,v_event||':'||k,jsonb_build_object('version',1,
      'mailboxId',v_work.mailbox_id::text,'threadId',v_work.thread_id,'eventId',v_event,
      'eventType','sla_breached','generation',(v_work.generation+1)::text,
      'recipientUserIds',CASE WHEN v_work.assignee_user_id IS NULL THEN '[]'::jsonb
        ELSE jsonb_build_array(v_work.assignee_user_id::text) END)
    FROM unnest(ARRAY['push','digest','metric']||CASE WHEN COALESCE(
      (SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_integrations'),false)
      THEN ARRAY['webhook'] ELSE ARRAY[]::text[] END) k;
    PERFORM notify_mailwork_state(v_work.mailbox_id,'work',v_work.thread_id,'updated');
    v_count:=v_count+1;
  END LOOP;
  RETURN jsonb_build_object('scanned',v_count,'disabled',false);
END $$;

ALTER FUNCTION mail_work_sla_scan(integer) OWNER TO setjoin_worker;
