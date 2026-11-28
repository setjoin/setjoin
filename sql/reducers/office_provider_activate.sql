CREATE OR REPLACE FUNCTION office_provider_activate(
  p_user_id bigint,
  p_provider_id text,
  p_expected_generation bigint,
  p_qualification_id uuid,
  p_scope jsonb,
  p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_provider office_provider_policies%ROWTYPE;
  v_receipt office_provider_qualifications%ROWTYPE;
  v_generation bigint;
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id,'office.manage') THEN
    RAISE EXCEPTION 'Office management forbidden' USING ERRCODE='BZ323';
  END IF;
  IF COALESCE(p_expected_generation,0)<=0 OR p_qualification_id IS NULL
     OR p_scope IS NULL OR jsonb_typeof(p_scope)<>'object'
     OR octet_length(p_scope::text)>16384 OR NULLIF(btrim(p_reason),'') IS NULL THEN
    RAISE EXCEPTION 'invalid Office activation request' USING ERRCODE='BZ322';
  END IF;
  SELECT * INTO v_provider FROM public.office_provider_policies
   WHERE provider_id=p_provider_id AND removed_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Office provider unavailable' USING ERRCODE='BZ327';
  END IF;
  SELECT * INTO v_receipt FROM public.office_provider_qualifications
   WHERE id=p_qualification_id FOR UPDATE;
  IF v_provider.generation<>p_expected_generation OR NOT FOUND
     OR v_receipt.provider_id<>p_provider_id
     OR v_receipt.provider_generation<>v_provider.generation
     OR v_receipt.config_sha256<>v_provider.config_sha256
     OR v_receipt.status<>'passed' OR v_receipt.expires_at<=statement_timestamp()
     OR v_provider.active_qualification_id IS DISTINCT FROM p_qualification_id THEN
    RAISE EXCEPTION 'Office activation evidence is stale or mismatched' USING ERRCODE='BZ324',
      HINT='{"type":"stateMismatch","detail":"qualify the current provider configuration again"}';
  END IF;
  UPDATE public.office_provider_policies
     SET enabled=true,draining=false,route_state='active_for_scope',
         default_modes=p_scope,generation=generation+1,
         updated_by=p_user_id,updated_at=statement_timestamp()
   WHERE provider_id=p_provider_id AND generation=p_expected_generation
  RETURNING generation INTO v_generation;
  IF v_generation IS NULL THEN
    RAISE EXCEPTION 'Office provider activation raced another mutation' USING ERRCODE='BZ324';
  END IF;
  INSERT INTO public.office_provider_health_observations(
    provider_id,provider_generation,state,capacity_state,facts,expires_at
  ) VALUES(p_provider_id,v_generation,'healthy','available',
    jsonb_build_object('source','activation','qualificationId',p_qualification_id::text),
    statement_timestamp()+interval '5 minutes');
  PERFORM public.audit_write(p_user_id,'office.provider.activated','office_provider',NULL,
    jsonb_build_object('routeState',v_provider.route_state,'generation',v_provider.generation),
    jsonb_build_object('routeState','active_for_scope','generation',v_generation,
      'qualificationId',p_qualification_id::text,'scope',p_scope),NULL,p_reason,'core');
  PERFORM public.app_notify('office_provider_changed',json_build_object(
    'provider_id',p_provider_id,'generation',v_generation,'route_state','active_for_scope')::text);
  RETURN jsonb_build_object('providerId',p_provider_id,'generation',v_generation,
    'routeState','active_for_scope','qualificationId',p_qualification_id::text,
    'scope',p_scope);
END;
$$;
SELECT apply_worker_ownership('office_provider_activate(bigint,text,bigint,uuid,jsonb,text)'::regprocedure);
