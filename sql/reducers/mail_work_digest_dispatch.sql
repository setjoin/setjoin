CREATE OR REPLACE FUNCTION mail_work_digest_dispatch(p_limit integer DEFAULT 100)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_batch record; v_counts jsonb; v_reasons jsonb;
  v_dispatched integer:=0; v_suppressed integer:=0;
BEGIN
  IF p_limit NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'invalid mail-work digest limit' USING ERRCODE='BZ301';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_notifications'),false) THEN
    RETURN jsonb_build_object('disabled',true,'dispatched',0,'suppressed',0);
  END IF;
  FOR v_batch IN
    WITH due AS (
      SELECT l.mailbox_id,l.user_id,l.deliver_after FROM mail_work_digest_ledger l
      WHERE l.delivered_at IS NULL AND l.deliver_after<=statement_timestamp()
      ORDER BY l.deliver_after,l.mailbox_id,l.user_id LIMIT p_limit FOR UPDATE SKIP LOCKED
    )
    SELECT mailbox_id,user_id,min(deliver_after) AS deliver_after FROM due
    GROUP BY mailbox_id,user_id ORDER BY min(deliver_after),mailbox_id,user_id
  LOOP
    IF NOT pg_try_advisory_xact_lock(hashtextextended(v_batch.mailbox_id::text||':'||v_batch.user_id::text,0)) THEN
      CONTINUE;
    END IF;
    IF NOT mail_work_can_read(v_batch.mailbox_id,v_batch.user_id) THEN
      UPDATE mail_work_digest_ledger SET delivered_at=statement_timestamp()
       WHERE mailbox_id=v_batch.mailbox_id AND user_id=v_batch.user_id
         AND delivered_at IS NULL AND deliver_after<=statement_timestamp();
      v_suppressed:=v_suppressed+1; CONTINUE;
    END IF;
    SELECT jsonb_build_object(
      'unassigned',count(*) FILTER(WHERE w.status='unassigned'),
      'mine',count(*) FILTER(WHERE w.assignee_user_id=v_batch.user_id AND w.status<>'done'),
      'dueSoon',count(*) FILTER(WHERE w.status<>'done' AND w.sla_breached_at IS NULL
        AND w.due_at>statement_timestamp() AND w.due_at<=statement_timestamp()+interval '24 hours'),
      'breached',count(*) FILTER(WHERE w.status<>'done' AND w.sla_breached_at IS NOT NULL),
      'priorityUnread',(SELECT count(*) FROM messages m WHERE m.mailbox_id=v_batch.mailbox_id
        AND m.priority=1 AND NOT m.is_read AND NOT m.is_deleted)
    ) INTO v_counts FROM mail_thread_work w WHERE w.mailbox_id=v_batch.mailbox_id;
    SELECT COALESCE(jsonb_object_agg(category,n),'{}'::jsonb) INTO v_reasons FROM (
      SELECT category,count(*) AS n FROM mail_work_digest_ledger
       WHERE mailbox_id=v_batch.mailbox_id AND user_id=v_batch.user_id
         AND delivered_at IS NULL AND deliver_after<=statement_timestamp() GROUP BY category
    ) reason_counts;
    PERFORM app_notify('mailwork:'||v_batch.user_id,jsonb_build_object(
      'type','mailWorkDailyReset','mailboxId',v_batch.mailbox_id::text,
      'why','scheduled_digest','counts',v_counts,'reasons',v_reasons)::text);
    UPDATE mail_work_digest_ledger SET delivered_at=statement_timestamp()
     WHERE mailbox_id=v_batch.mailbox_id AND user_id=v_batch.user_id
       AND delivered_at IS NULL AND deliver_after<=statement_timestamp();
    v_dispatched:=v_dispatched+1;
  END LOOP;
  RETURN jsonb_build_object('dispatched',v_dispatched,'suppressed',v_suppressed);
END $$;

ALTER FUNCTION mail_work_digest_dispatch(integer) OWNER TO setjoin_worker;
