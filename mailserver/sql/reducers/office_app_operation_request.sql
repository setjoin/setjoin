CREATE OR REPLACE FUNCTION office_app_operation_request(
  p_user_id bigint,
  p_kind text,
  p_provider_id text,
  p_expected_provider_generation bigint,
  p_idempotency_key uuid,
  p_request jsonb,
  p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_provider office_provider_policies%ROWTYPE;
  v_request jsonb;
  v_digest text;
  v_existing office_app_operations%ROWTYPE;
  v_id uuid;
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id,'apps.manage') THEN
    RAISE EXCEPTION 'application management forbidden' USING ERRCODE='BZ323',
      HINT='{"type":"forbidden","detail":"apps.manage is required"}';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM public.feature_toggles
                    WHERE key='feature.office_managed_delivery'),false) THEN
    RAISE EXCEPTION 'managed Office delivery is disabled' USING ERRCODE='BZ327';
  END IF;
  IF p_kind<>'install'
     OR p_idempotency_key IS NULL OR p_request IS NULL
     OR jsonb_typeof(p_request)<>'object' OR octet_length(p_request::text)>65536
     OR NULLIF(btrim(p_reason),'') IS NULL
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(p_request) k
                 WHERE k NOT IN ('profile','ingress','catalogRevision','rollbackRevision'))
     OR COALESCE(p_request->>'profile','') NOT IN (
          'managed-wildcard','managed-customer-cert','managed-customer-proxy')
     OR jsonb_typeof(COALESCE(p_request->'ingress','null'::jsonb))<>'object' THEN
    RAISE EXCEPTION 'invalid managed Office operation' USING ERRCODE='BZ322';
  END IF;
  SELECT * INTO v_provider FROM public.office_provider_policies
   WHERE provider_id=p_provider_id AND removed_at IS NULL FOR UPDATE;
  IF NOT FOUND OR v_provider.generation<>p_expected_provider_generation
     OR v_provider.route_state NOT IN ('connected_inactive','fenced') THEN
    RAISE EXCEPTION 'managed Office provider state changed' USING ERRCODE='BZ324',
      HINT='{"type":"stateMismatch","detail":"configure an inactive provider and retry preflight"}';
  END IF;
  IF EXISTS (SELECT 1 FROM public.office_app_revisions
              WHERE app_id='collabora-code' AND state NOT IN ('removed','failed')) THEN
    RAISE EXCEPTION 'managed Office application is already installed' USING ERRCODE='BZ327',
      HINT='{"type":"providerUnavailable","detail":"inspect the installed revision; reinstall is not an available action"}';
  END IF;
  v_request:=p_request || jsonb_build_object(
    'providerId',p_provider_id,'providerGeneration',p_expected_provider_generation,
    'providerConfigSha256',v_provider.config_sha256,
    'wopiPublicBaseUrl',v_provider.config->>'wopiPublicBaseUrl',
    'transportMode',CASE WHEN v_provider.config->>'wopiPublicBaseUrl' ~ '^https://'
                         THEN 'https' ELSE 'test_direct_http' END);
  v_digest:=encode(digest(jsonb_build_object(
    'kind',p_kind,'appId','collabora-code','request',v_request)::text,'sha256'),'hex');
  SELECT * INTO v_existing FROM public.office_app_operations
   WHERE app_id='collabora-code' AND idempotency_key=p_idempotency_key;
  IF FOUND THEN
    IF v_existing.request_digest<>v_digest THEN
      RAISE EXCEPTION 'managed Office idempotency replay changed input' USING ERRCODE='BZ326';
    END IF;
    RETURN jsonb_build_object('operationId',v_existing.id::text,'state',v_existing.state,
      'stateGeneration',v_existing.state_generation,'phase',v_existing.phase,'replayed',true);
  END IF;
  BEGIN
    INSERT INTO public.office_app_operations(
      app_id,kind,state,requested_by,reason,idempotency_key,request_digest,request
    ) VALUES('collabora-code',p_kind,'requested',p_user_id,p_reason,
      p_idempotency_key,v_digest,v_request) RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'another managed Office operation is active' USING ERRCODE='BZ327',
      HINT='{"type":"providerUnavailable","detail":"inspect the active operation before retrying"}';
  END;
  PERFORM public.audit_write(p_user_id,'office.app.operation.requested','office_app',NULL,NULL,
    jsonb_build_object('operationId',v_id::text,'kind',p_kind,'providerId',p_provider_id,
      'requestDigest',v_digest),NULL,p_reason,'core');
  PERFORM public.app_notify('office_app_operation_changed',json_build_object(
    'operation_id',v_id,'state','requested','generation',1)::text);
  RETURN jsonb_build_object('operationId',v_id::text,'state','requested',
    'stateGeneration',1,'phase','requested','replayed',false);
END;
$$;
SELECT apply_worker_ownership('office_app_operation_request(bigint,text,text,bigint,uuid,jsonb,text)'::regprocedure);
