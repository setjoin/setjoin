CREATE OR REPLACE FUNCTION mail_work_sla_policy_set(
  p_mailbox_id bigint,
  p_actor_user_id bigint,
  p_operation_id uuid,
  p_expected_generation bigint,
  p_timezone text,
  p_weekday_mask integer,
  p_workday_start time,
  p_workday_end time,
  p_holidays date[],
  p_sla_minutes integer,
  p_request_digest text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_existing mail_work_operations%ROWTYPE; v_current mail_work_sla_policies%ROWTYPE;
  v_result jsonb; v_before jsonb; v_policy jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.shared_mail_work'),false) THEN
    RAISE EXCEPTION 'shared mail work is disabled' USING ERRCODE='BZ300';
  END IF;
  IF p_operation_id IS NULL OR p_expected_generation<0 OR p_timezone IS NULL
     OR octet_length(p_timezone) NOT BETWEEN 1 AND 64 OR p_weekday_mask NOT BETWEEN 1 AND 127
     OR p_workday_start IS NULL OR p_workday_end IS NULL OR p_workday_start>=p_workday_end
     OR p_holidays IS NULL OR cardinality(p_holidays)>366 OR p_sla_minutes NOT BETWEEN 1 AND 525600
     OR p_request_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid mail-work SLA policy' USING ERRCODE='BZ301';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=p_timezone) THEN
    RAISE EXCEPTION 'invalid mail-work SLA timezone' USING ERRCODE='BZ301';
  END IF;
  IF cardinality(p_holidays)<>cardinality(ARRAY(SELECT DISTINCT h FROM unnest(p_holidays) h)) THEN
    RAISE EXCEPTION 'duplicate mail-work SLA holiday' USING ERRCODE='BZ301';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM mailbox_delegates WHERE mailbox_id=p_mailbox_id
    AND user_id=p_actor_user_id AND permission='full_access') THEN
    RAISE EXCEPTION 'full access is required to change the SLA policy' USING ERRCODE='BZ005';
  END IF;

  SELECT * INTO v_existing FROM mail_work_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.actor_user_id=p_actor_user_id
       AND v_existing.operation_kind='sla_policy_set' AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'SLA policy idempotency conflict' USING ERRCODE='BZ303';
  END IF;

  PERFORM 1 FROM mailboxes WHERE id=p_mailbox_id AND user_id IS NULL FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'shared mailbox not found' USING ERRCODE='BZ006'; END IF;
  SELECT * INTO v_current FROM mail_work_sla_policies WHERE mailbox_id=p_mailbox_id FOR UPDATE;
  IF FOUND THEN
    IF v_current.generation<>p_expected_generation THEN
      RAISE EXCEPTION 'SLA policy generation is stale' USING ERRCODE='BZ304';
    END IF;
    v_before:=mail_work_sla_policy_snapshot(p_mailbox_id);
    UPDATE mail_work_sla_policies SET timezone=p_timezone,weekday_mask=p_weekday_mask,
      workday_start=p_workday_start,workday_end=p_workday_end,holidays=p_holidays,
      sla_minutes=p_sla_minutes,generation=generation+1,updated_at=statement_timestamp(),updated_by=p_actor_user_id
      WHERE mailbox_id=p_mailbox_id;
  ELSE
    IF p_expected_generation<>0 THEN
      RAISE EXCEPTION 'SLA policy generation is stale' USING ERRCODE='BZ304';
    END IF;
    v_before:=mail_work_sla_policy_snapshot(p_mailbox_id);
    INSERT INTO mail_work_sla_policies(mailbox_id,timezone,weekday_mask,workday_start,workday_end,
      holidays,sla_minutes,updated_by) VALUES(p_mailbox_id,p_timezone,p_weekday_mask,p_workday_start,
      p_workday_end,p_holidays,p_sla_minutes,p_actor_user_id);
  END IF;
  v_policy:=mail_work_sla_policy_snapshot(p_mailbox_id);
  v_result:=jsonb_build_object('accountId',p_mailbox_id::text,'canManage',true,'policy',v_policy,
    'operationId',p_operation_id,'replayed',false);
  INSERT INTO mail_work_operations(operation_id,mailbox_id,actor_user_id,operation_kind,request_digest,result)
    VALUES(p_operation_id,p_mailbox_id,p_actor_user_id,'sla_policy_set',p_request_digest,v_result);
  PERFORM notify_mailwork_state(p_mailbox_id,'policy','sla','updated');
  PERFORM audit_write(p_actor_user_id,'mail_work_sla_policy_set','mailbox',p_mailbox_id,
    v_before,v_policy,NULL::inet,'Future work adopts the new policy generation; existing snapshots are unchanged','core');
  RETURN v_result;
END $$;

ALTER FUNCTION mail_work_sla_policy_set(bigint,bigint,uuid,bigint,text,integer,time,time,date[],integer,text) OWNER TO setjoin_worker;
