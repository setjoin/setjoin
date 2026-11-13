CREATE OR REPLACE FUNCTION mail_work_outbox_dispatch_local(p_outbox_id bigint)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_out mail_work_outbox%ROWTYPE; v_event mail_thread_work_events%ROWTYPE;
  v_category text; v_user bigint; v_delivery text; v_tz text; v_hour integer;
  v_push boolean; v_dnd_start time; v_dnd_end time; v_dnd_days smallint;
  v_local timestamp; v_in_dnd boolean:=false; v_window timestamptz; v_deliver_after timestamptz; v_count integer;
  v_delivered integer:=0; v_queued integer:=0; v_suppressed integer:=0;
  v_recipients bigint[]; v_receipt jsonb;
  v_metric_day date;
BEGIN
  SELECT * INTO v_out FROM mail_work_outbox WHERE id=p_outbox_id AND state='claimed' FOR UPDATE;
  IF NOT FOUND OR v_out.consumer_kind NOT IN ('push','digest','metric') THEN
    RAISE EXCEPTION 'mail-work outbox claim is unavailable' USING ERRCODE='BZ304';
  END IF;
  SELECT receipt INTO v_receipt FROM mail_work_consumer_effects WHERE outbox_id=p_outbox_id;
  IF FOUND THEN RETURN v_receipt||'{"replayed":true}'::jsonb; END IF;
  SELECT * INTO v_event FROM mail_thread_work_events WHERE id=v_out.event_id;
  IF NOT FOUND THEN
    v_receipt:=jsonb_build_object('outboxId',p_outbox_id::text,'outcome','suppressed','why','event_missing','replayed',false);
    INSERT INTO mail_work_consumer_effects(outbox_id,receipt) VALUES(p_outbox_id,v_receipt);
    RETURN v_receipt;
  END IF;

  IF v_out.consumer_kind='metric' THEN
    SELECT (v_event.occurred_at AT TIME ZONE COALESCE(w.sla_policy_snapshot->>'timezone','UTC'))::date
      INTO v_metric_day FROM mail_thread_work w
      WHERE w.mailbox_id=v_event.mailbox_id AND w.thread_id=v_event.thread_id;
    v_metric_day:=COALESCE(v_metric_day,(v_event.occurred_at AT TIME ZONE 'UTC')::date);
    INSERT INTO mail_work_metric_conversations(mailbox_id,metric_day,policy_version,thread_id)
    VALUES(v_event.mailbox_id,v_metric_day,1,v_event.thread_id)
    ON CONFLICT DO NOTHING;
    IF v_event.actor_user_id IS NOT NULL THEN
      INSERT INTO mail_work_metric_actors(mailbox_id,metric_day,policy_version,actor_user_id)
      VALUES(v_event.mailbox_id,v_metric_day,1,v_event.actor_user_id)
      ON CONFLICT DO NOTHING;
    END IF;
    INSERT INTO mail_work_metric_daily(mailbox_id,metric_day,policy_version,conversation_count,
      first_response_count,first_response_seconds,completed_count,breached_count,actor_cohort_count)
    VALUES(v_event.mailbox_id,v_metric_day,1,
      (SELECT count(*) FROM mail_work_metric_conversations c WHERE c.mailbox_id=v_event.mailbox_id
        AND c.metric_day=v_metric_day AND c.policy_version=1),
      CASE WHEN v_event.event_type='first_response' THEN 1 ELSE 0 END,
      CASE WHEN v_event.event_type='first_response' THEN GREATEST(0,COALESCE((v_event.after_state->>'first_response_seconds')::bigint,0)) ELSE 0 END,
      CASE WHEN v_event.event_type='completed' THEN 1 ELSE 0 END,
      CASE WHEN v_event.event_type='sla_breached' THEN 1 ELSE 0 END,
      (SELECT count(*) FROM mail_work_metric_actors a WHERE a.mailbox_id=v_event.mailbox_id
        AND a.metric_day=v_metric_day AND a.policy_version=1))
    ON CONFLICT(mailbox_id,metric_day,policy_version) DO UPDATE SET
      conversation_count=EXCLUDED.conversation_count,
      first_response_count=mail_work_metric_daily.first_response_count+EXCLUDED.first_response_count,
      first_response_seconds=mail_work_metric_daily.first_response_seconds+EXCLUDED.first_response_seconds,
      completed_count=mail_work_metric_daily.completed_count+EXCLUDED.completed_count,
      breached_count=mail_work_metric_daily.breached_count+EXCLUDED.breached_count,
      actor_cohort_count=EXCLUDED.actor_cohort_count,
      rebuilt_at=statement_timestamp();
    v_receipt:=jsonb_build_object('outboxId',p_outbox_id::text,'outcome','projected','eventId',v_event.id,'replayed',false);
    INSERT INTO mail_work_consumer_effects(outbox_id,receipt) VALUES(p_outbox_id,v_receipt);
    RETURN v_receipt;
  END IF;

  v_category:=CASE v_event.event_type
    WHEN 'mentioned' THEN 'mention' WHEN 'commented' THEN 'comment'
    WHEN 'handed_off' THEN 'handoff' WHEN 'due_changed' THEN 'due'
    WHEN 'sla_breached' THEN 'breach' ELSE 'assignment' END;
  SELECT COALESCE(array_agg(DISTINCT value::bigint),ARRAY[]::bigint[]) INTO v_recipients
  FROM jsonb_array_elements_text(COALESCE(v_out.payload->'recipientUserIds','[]'::jsonb)) r(value)
  WHERE value~'^[1-9][0-9]{0,18}$';
  IF cardinality(v_recipients)=0 AND COALESCE(v_event.after_state->>'assignee_user_id','')~'^[1-9][0-9]{0,18}$' THEN
    v_recipients:=ARRAY[(v_event.after_state->>'assignee_user_id')::bigint];
  END IF;

  FOREACH v_user IN ARRAY v_recipients LOOP
    v_in_dnd:=false;
    v_count:=NULL;
    IF v_user IS NOT DISTINCT FROM v_event.actor_user_id OR NOT mail_work_can_read(v_event.mailbox_id,v_user) THEN
      v_suppressed:=v_suppressed+1; CONTINUE;
    END IF;
    SELECT p.delivery,p.timezone,p.digest_hour INTO v_delivery,v_tz,v_hour
      FROM mail_work_notification_preferences p WHERE p.mailbox_id=v_event.mailbox_id
        AND p.user_id=v_user AND p.category=v_category;
    IF NOT FOUND THEN
      v_delivery:=CASE WHEN v_category IN ('due','breach','priority','mailbox_rule') THEN 'digest' ELSE 'immediate' END;
      v_tz:='UTC'; v_hour:=9;
      INSERT INTO mail_work_notification_preferences(mailbox_id,user_id,category,delivery,timezone,digest_hour)
      VALUES(v_event.mailbox_id,v_user,v_category,v_delivery,v_tz,v_hour)
      ON CONFLICT(mailbox_id,user_id,category) DO NOTHING;
    END IF;
    v_local:=statement_timestamp() AT TIME ZONE v_tz;
    IF (v_out.consumer_kind='push' AND v_delivery<>'immediate') OR
       (v_out.consumer_kind='digest' AND v_delivery<>'digest') THEN
      INSERT INTO mail_work_notification_deliveries(outbox_id,user_id,event_id,category,channel,outcome,why)
      VALUES(v_out.id,v_user,v_event.id,v_category,CASE WHEN v_out.consumer_kind='push' THEN 'realtime' ELSE 'digest' END,
        'suppressed','preference_'||v_delivery) ON CONFLICT DO NOTHING;
      v_suppressed:=v_suppressed+1; CONTINUE;
    END IF;
    IF v_out.consumer_kind='digest' THEN
      v_deliver_after:=((v_local::date+make_interval(hours=>v_hour)) AT TIME ZONE v_tz);
      IF v_deliver_after<=statement_timestamp() THEN
        v_deliver_after:=(((v_local::date+1)+make_interval(hours=>v_hour)) AT TIME ZONE v_tz);
      END IF;
      INSERT INTO mail_work_digest_ledger(mailbox_id,user_id,category,window_start,cursor_event_id,dedupe_key,deliver_after)
      VALUES(v_event.mailbox_id,v_user,v_category,date_trunc('day',statement_timestamp() AT TIME ZONE v_tz) AT TIME ZONE v_tz,
        v_event.id,'mailwork-digest:'||v_event.mailbox_id||':'||v_user||':'||v_category||':'||
        (v_deliver_after AT TIME ZONE v_tz)::date, v_deliver_after)
      ON CONFLICT(mailbox_id,user_id,category,window_start) DO UPDATE SET
        cursor_event_id=EXCLUDED.cursor_event_id,deliver_after=LEAST(mail_work_digest_ledger.deliver_after,EXCLUDED.deliver_after);
      INSERT INTO mail_work_notification_deliveries(outbox_id,user_id,event_id,category,channel,outcome,why)
      VALUES(v_out.id,v_user,v_event.id,v_category,'digest','queued','digest_preference') ON CONFLICT DO NOTHING;
      v_queued:=v_queued+1; CONTINUE;
    END IF;
    SELECT COALESCE(p.push_enabled,true),p.dnd_start,p.dnd_end,COALESCE(p.dnd_days,127)
      INTO v_push,v_dnd_start,v_dnd_end,v_dnd_days FROM user_notification_prefs p
      WHERE p.user_id=v_user ORDER BY (p.device_fingerprint IS NULL) DESC,p.id LIMIT 1;
    IF NOT FOUND THEN v_push:=true; v_dnd_days:=127; END IF;
    IF v_dnd_start IS NOT NULL AND v_dnd_end IS NOT NULL
       AND ((v_dnd_days>>extract(dow FROM v_local)::integer)&1)=1 THEN
      v_in_dnd:=CASE WHEN v_dnd_start<=v_dnd_end THEN v_local::time>=v_dnd_start AND v_local::time<v_dnd_end
        ELSE v_local::time>=v_dnd_start OR v_local::time<v_dnd_end END;
    END IF;
    IF NOT v_push OR v_in_dnd THEN
      INSERT INTO mail_work_notification_deliveries(outbox_id,user_id,event_id,category,channel,outcome,why)
      VALUES(v_out.id,v_user,v_event.id,v_category,'realtime','suppressed',CASE WHEN NOT v_push THEN 'push_disabled' ELSE 'dnd' END)
      ON CONFLICT DO NOTHING; v_suppressed:=v_suppressed+1; CONTINUE;
    END IF;
    v_window:=date_trunc('hour',statement_timestamp())+
      make_interval(mins=>(extract(minute FROM statement_timestamp())::integer/10)*10);
    v_count:=NULL;
    INSERT INTO mail_work_notification_rate_windows(user_id,window_start,delivered_count)
      VALUES(v_user,v_window,1) ON CONFLICT(user_id,window_start) DO UPDATE
      SET delivered_count=mail_work_notification_rate_windows.delivered_count+1
      WHERE mail_work_notification_rate_windows.delivered_count<6
      RETURNING delivered_count INTO v_count;
    IF v_count IS NULL THEN
      v_deliver_after:=((v_local::date+make_interval(hours=>v_hour)) AT TIME ZONE v_tz);
      IF v_deliver_after<=statement_timestamp() THEN
        v_deliver_after:=(((v_local::date+1)+make_interval(hours=>v_hour)) AT TIME ZONE v_tz);
      END IF;
      INSERT INTO mail_work_digest_ledger(mailbox_id,user_id,category,window_start,cursor_event_id,dedupe_key,deliver_after)
      VALUES(v_event.mailbox_id,v_user,v_category,date_trunc('day',statement_timestamp() AT TIME ZONE v_tz) AT TIME ZONE v_tz,
        v_event.id,'mailwork-digest:'||v_event.mailbox_id||':'||v_user||':'||v_category||':'||
        (v_deliver_after AT TIME ZONE v_tz)::date, v_deliver_after)
      ON CONFLICT(mailbox_id,user_id,category,window_start) DO UPDATE SET
        cursor_event_id=EXCLUDED.cursor_event_id,deliver_after=LEAST(mail_work_digest_ledger.deliver_after,EXCLUDED.deliver_after);
      INSERT INTO mail_work_notification_deliveries(outbox_id,user_id,event_id,category,channel,outcome,why)
      VALUES(v_out.id,v_user,v_event.id,v_category,'digest','queued','rate_cap_digest') ON CONFLICT DO NOTHING;
      v_queued:=v_queued+1; CONTINUE;
    END IF;
    PERFORM app_notify('mailwork:'||v_user,jsonb_build_object('type','mailWorkNotification',
      'mailboxId',v_event.mailbox_id::text,'threadId',v_event.thread_id,'eventId',v_event.id,
      'category',v_category,'why','shared_mail_'||v_category)::text);
    INSERT INTO mail_work_notification_deliveries(outbox_id,user_id,event_id,category,channel,outcome,why)
      VALUES(v_out.id,v_user,v_event.id,v_category,'realtime','delivered','shared_mail_'||v_category) ON CONFLICT DO NOTHING;
    v_delivered:=v_delivered+1;
  END LOOP;
  v_receipt:=jsonb_build_object('outboxId',p_outbox_id::text,'eventId',v_event.id,
    'delivered',v_delivered,'queued',v_queued,'suppressed',v_suppressed,'replayed',false);
  INSERT INTO mail_work_consumer_effects(outbox_id,receipt) VALUES(p_outbox_id,v_receipt);
  RETURN v_receipt;
END $$;

ALTER FUNCTION mail_work_outbox_dispatch_local(bigint) OWNER TO setjoin_worker;
