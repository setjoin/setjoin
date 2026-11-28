CREATE OR REPLACE FUNCTION mail_work_business_due_at(
  p_from timestamptz,p_minutes integer,p_policy jsonb
) RETURNS timestamptz LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_tz text:=COALESCE(p_policy->>'timezone','UTC');
  v_mask integer:=COALESCE((p_policy->>'weekdayMask')::integer,62);
  v_start time:=COALESCE((p_policy->>'workdayStart')::time,'09:00'::time);
  v_end time:=COALESCE((p_policy->>'workdayEnd')::time,'17:00'::time);
  v_holidays date[]:=COALESCE(ARRAY(SELECT jsonb_array_elements_text(COALESCE(p_policy->'holidays','[]'::jsonb))::date),ARRAY[]::date[]);
  v_day date:=(p_from AT TIME ZONE v_tz)::date; v_cursor timestamptz:=p_from;
  v_open timestamptz; v_close timestamptz; v_available bigint; v_remaining bigint:=p_minutes::bigint*60;
  v_iterations integer:=0;
BEGIN
  IF p_from IS NULL OR p_minutes NOT BETWEEN 1 AND 525600 OR v_mask NOT BETWEEN 1 AND 127
     OR v_start>=v_end OR NOT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=v_tz) THEN
    RAISE EXCEPTION 'invalid mail-work SLA policy' USING ERRCODE='BZ301';
  END IF;
  WHILE v_remaining>0 LOOP
    v_iterations:=v_iterations+1;
    IF v_iterations>3700 THEN RAISE EXCEPTION 'mail-work SLA calendar made no bounded progress' USING ERRCODE='BZ301'; END IF;
    IF ((v_mask>>extract(dow FROM v_day)::integer)&1)=1 AND NOT v_day=ANY(v_holidays) THEN
      v_open:=(v_day+v_start) AT TIME ZONE v_tz;
      v_close:=(v_day+v_end) AT TIME ZONE v_tz;
      v_cursor:=GREATEST(v_cursor,v_open);
      IF v_cursor<v_close THEN
        v_available:=floor(extract(epoch FROM (v_close-v_cursor)))::bigint;
        IF v_remaining<=v_available THEN RETURN v_cursor+make_interval(secs=>v_remaining); END IF;
        v_remaining:=v_remaining-v_available;
      END IF;
    END IF;
    v_day:=v_day+1; v_cursor:=(v_day+v_start) AT TIME ZONE v_tz;
  END LOOP;
  RETURN v_cursor;
END $$;

ALTER FUNCTION mail_work_business_due_at(timestamptz,integer,jsonb) OWNER TO setjoin_worker;
