CREATE OR REPLACE FUNCTION office_preference_set(
  p_user_id bigint,p_device_id text,p_file_family text,p_provider_id text,p_mode text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF p_device_id IS NULL OR length(p_device_id) NOT BETWEEN 1 AND 200
     OR p_file_family NOT IN ('word','sheet','presentation')
     OR p_mode NOT IN ('edit_online','open_local','preview','download') THEN
    RAISE EXCEPTION 'invalid Office preference' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"invalid Office preference"}';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.office_provider_policies
                  WHERE provider_id=p_provider_id AND enabled AND NOT draining) THEN
    RAISE EXCEPTION 'Office provider unavailable' USING ERRCODE='BZ327',
      HINT='{"type":"conflict","detail":"Office provider unavailable"}';
  END IF;
  INSERT INTO public.office_user_preferences(user_id,device_id,file_family,provider_id,mode,last_success_at)
  VALUES(p_user_id,p_device_id,p_file_family,p_provider_id,p_mode,now())
  ON CONFLICT(user_id,device_id,file_family) DO UPDATE
    SET provider_id=EXCLUDED.provider_id,mode=EXCLUDED.mode,last_success_at=EXCLUDED.last_success_at;
  RETURN jsonb_build_object('saved',true);
END;
$$;
SELECT apply_worker_ownership('office_preference_set(bigint,text,text,text,text)'::regprocedure);
