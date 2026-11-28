CREATE OR REPLACE FUNCTION mail_work_notification_preferences_set(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_operation_id uuid,
  p_category text,
  p_delivery text,
  p_timezone text,
  p_digest_hour integer,
  p_expected_generation bigint,
  p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing mail_work_operations%ROWTYPE; v_pref mail_work_notification_preferences%ROWTYPE;
  v_result jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_notifications'),false) THEN
    RAISE EXCEPTION 'shared mail notifications are disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_category NOT IN ('assignment','mention','due','breach','comment','handoff','priority','mailbox_rule')
     OR p_delivery NOT IN ('immediate','digest','off') OR p_expected_generation<0
     OR p_timezone IS NULL OR octet_length(p_timezone) NOT BETWEEN 1 AND 64
     OR p_digest_hour NOT BETWEEN 0 AND 23 OR p_request_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid notification preference' USING ERRCODE='BZ301';
  END IF;
  IF NOT mail_work_can_read(p_mailbox_id,p_actor_user_id) THEN
    RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006';
  END IF;
  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='outbox_action' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'notification preference idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_pref FROM mail_work_notification_preferences
    WHERE mailbox_id=p_mailbox_id AND user_id=p_actor_user_id AND category=p_category FOR UPDATE;
  IF NOT FOUND THEN
    IF p_expected_generation<>0 THEN RAISE EXCEPTION 'notification preference generation is stale' USING ERRCODE='BZ304'; END IF;
    INSERT INTO mail_work_notification_preferences(mailbox_id,user_id,category,delivery,timezone,digest_hour)
      VALUES(p_mailbox_id,p_actor_user_id,p_category,p_delivery,p_timezone,p_digest_hour) RETURNING * INTO v_pref;
  ELSE
    IF v_pref.generation<>p_expected_generation THEN RAISE EXCEPTION 'notification preference generation is stale' USING ERRCODE='BZ304'; END IF;
    UPDATE mail_work_notification_preferences SET delivery=p_delivery,timezone=p_timezone,
      digest_hour=p_digest_hour,generation=generation+1
      WHERE mailbox_id=p_mailbox_id AND user_id=p_actor_user_id AND category=p_category RETURNING * INTO v_pref;
  END IF;
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'category',v_pref.category,
    'delivery',v_pref.delivery,'timezone',v_pref.timezone,'digestHour',v_pref.digest_hour,
    'generation',v_pref.generation::text,'operationId',p_operation_id,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
    VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'outbox_action',p_request_digest,v_result);
  RETURN v_result;
END $$;

ALTER FUNCTION mail_work_notification_preferences_set(bigint,bigint,uuid,text,text,text,integer,bigint,text) OWNER TO setjoin_worker;
