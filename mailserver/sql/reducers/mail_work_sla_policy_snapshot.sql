CREATE OR REPLACE FUNCTION mail_work_sla_policy_snapshot(p_mailbox_id bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_policy mail_work_sla_policies%ROWTYPE;
BEGIN
  SELECT * INTO v_policy FROM mail_work_sla_policies WHERE mailbox_id=p_mailbox_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('version',1,'timezone','UTC','weekdayMask',62,
      'workdayStart','09:00:00','workdayEnd','17:00:00','holidays','[]'::jsonb,
      'slaMinutes',480,'source','organization_default');
  END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=v_policy.timezone) THEN
    RAISE EXCEPTION 'mail-work SLA timezone is invalid' USING ERRCODE='BZ301';
  END IF;
  RETURN jsonb_build_object('version',1,'timezone',v_policy.timezone,
    'weekdayMask',v_policy.weekday_mask,'workdayStart',v_policy.workday_start,
    'workdayEnd',v_policy.workday_end,'holidays',to_jsonb(v_policy.holidays),
    'slaMinutes',v_policy.sla_minutes,'generation',v_policy.generation::text,
    'source','mailbox');
END $$;

ALTER FUNCTION mail_work_sla_policy_snapshot(bigint) OWNER TO setjoin_worker;
