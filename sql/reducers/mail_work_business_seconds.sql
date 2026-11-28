CREATE OR REPLACE FUNCTION mail_work_business_seconds(
  p_from timestamptz,p_to timestamptz,p_policy jsonb
) RETURNS bigint LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_tz text:=COALESCE(p_policy->>'timezone','UTC');
  v_mask integer:=COALESCE((p_policy->>'weekdayMask')::integer,62);
  v_start time:=COALESCE((p_policy->>'workdayStart')::time,'09:00'::time);
  v_end time:=COALESCE((p_policy->>'workdayEnd')::time,'17:00'::time);
  v_holidays date[]:=COALESCE(ARRAY(SELECT jsonb_array_elements_text(COALESCE(p_policy->'holidays','[]'::jsonb))::date),ARRAY[]::date[]);
  v_day date; v_open timestamptz; v_close timestamptz; v_total numeric:=0;
BEGIN
  IF p_from IS NULL OR p_to IS NULL OR p_to<=p_from THEN RETURN 0; END IF;
  IF p_to-p_from>interval '10 years' OR v_mask NOT BETWEEN 1 AND 127 OR v_start>=v_end
     OR NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=v_tz) THEN
    RAISE EXCEPTION 'invalid mail-work business-time input' USING ERRCODE='BZ301';
  END IF;
  FOR v_day IN SELECT d::date FROM generate_series((p_from AT TIME ZONE v_tz)::date,
      (p_to AT TIME ZONE v_tz)::date,interval '1 day') d LOOP
    IF ((v_mask>>extract(dow FROM v_day)::integer)&1)=0 OR v_day=ANY(v_holidays) THEN CONTINUE; END IF;
    v_open:=(v_day+v_start) AT TIME ZONE v_tz;
    v_close:=(v_day+v_end) AT TIME ZONE v_tz;
    IF LEAST(p_to,v_close)>GREATEST(p_from,v_open) THEN
      v_total:=v_total+extract(epoch FROM (LEAST(p_to,v_close)-GREATEST(p_from,v_open)));
    END IF;
  END LOOP;
  RETURN floor(v_total)::bigint;
END $$;

ALTER FUNCTION mail_work_business_seconds(timestamptz,timestamptz,jsonb) OWNER TO setjoin_worker;
