CREATE OR REPLACE FUNCTION office_provider_configure(
  p_user_id bigint,
  p_provider_id text,
  p_expected_generation bigint,
  p_profile text,
  p_entitlement_state text,
  p_build_id text,
  p_config jsonb,
  p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_current office_provider_policies%ROWTYPE;
  v_generation bigint;
  v_hash text;
	v_test_transport boolean:=public.office_test_transport_enabled();
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id,'office.manage') THEN
    RAISE EXCEPTION 'Office management forbidden' USING ERRCODE='BZ323',
      HINT='{"type":"forbidden","detail":"Office management permission required"}';
  END IF;
  IF p_provider_id !~ '^[a-z][a-z0-9._-]{1,63}$'
     OR COALESCE(p_expected_generation,-1)<0
     OR p_profile NOT IN ('existing-provider','managed-wildcard','managed-customer-cert','managed-customer-proxy')
     OR p_entitlement_state NOT IN ('unknown','evaluation','valid','expiring','expired','build_mismatch','not_permitted')
     OR p_config IS NULL OR jsonb_typeof(p_config)<>'object'
     OR octet_length(p_config::text)>65536
	 OR NOT (
	   (COALESCE(p_config->>'proofDiscoveryUrl','') ~ '^https://'
	    AND COALESCE(p_config->>'wopiPublicBaseUrl','') ~ '^https://'
	    AND COALESCE(p_config->>'editorUrl','') ~ '^https://'
	    AND COALESCE(p_config->>'proofMode','')<>'test_disabled')
	   OR
	   (v_test_transport
	    AND COALESCE(p_config->>'proofDiscoveryUrl','') ~ '^http://127[.]0[.]0[.]1:[0-9]{2,5}/hosting/discovery$'
	    AND COALESCE(p_config->>'editorUrl','') ~ '^http://127[.]0[.]0[.]1:[0-9]{2,5}/browser/[A-Za-z0-9._-]+/cool[.]html[?]?$'
	    AND COALESCE(p_config->>'wopiPublicBaseUrl','') ~ '^http://(host[.]docker[.]internal|127[.]0[.]0[.]1):[0-9]{2,5}$'
	    AND p_config->>'proofMode'='test_disabled')
	 )
     OR NULLIF(btrim(p_reason),'') IS NULL THEN
    RAISE EXCEPTION 'invalid Office provider configuration' USING ERRCODE='BZ322',
	  HINT='{"type":"invalidArguments","detail":"profile, secure endpoints, generation and audit reason are required"}';
  END IF;
  SELECT * INTO v_current FROM public.office_provider_policies
   WHERE provider_id=p_provider_id FOR UPDATE;
  IF FOUND THEN
    IF v_current.generation<>p_expected_generation THEN
      RAISE EXCEPTION 'Office provider generation changed' USING ERRCODE='BZ324',
        HINT='{"type":"stateMismatch","detail":"reload provider state and retry"}';
    END IF;
    IF v_current.route_state IN ('active_for_scope','draining') THEN
      RAISE EXCEPTION 'active Office provider must be drained before reconfiguration' USING ERRCODE='BZ327',
        HINT='{"type":"providerUnavailable","detail":"disable new launches and drain before changing endpoints"}';
    END IF;
  ELSIF p_expected_generation<>0 THEN
    RAISE EXCEPTION 'Office provider generation changed' USING ERRCODE='BZ324',
      HINT='{"type":"stateMismatch","detail":"provider no longer exists"}';
  END IF;
  v_hash:=encode(digest(p_config::text,'sha256'),'hex');
  INSERT INTO public.office_provider_policies(
    provider_id,enabled,draining,generation,route_state,config_sha256,
    entitlement_state,build_id,config,updated_by,active_qualification_id
  ) VALUES(
    p_provider_id,false,false,1,'connected_inactive',v_hash,
    p_entitlement_state,NULLIF(btrim(p_build_id),''),p_config,p_user_id,NULL
  )
  ON CONFLICT(provider_id) DO UPDATE SET
    enabled=false,draining=false,generation=office_provider_policies.generation+1,
    route_state='connected_inactive',config_sha256=v_hash,
    entitlement_state=EXCLUDED.entitlement_state,build_id=EXCLUDED.build_id,
    config=EXCLUDED.config,updated_by=p_user_id,updated_at=statement_timestamp(),
    removed_at=NULL,active_qualification_id=NULL
  RETURNING generation INTO v_generation;
  PERFORM public.audit_write(p_user_id,'office.provider.configured','office_provider',NULL,
    CASE WHEN v_current.provider_id IS NULL THEN NULL ELSE to_jsonb(v_current)-'config' END,
    jsonb_build_object('providerId',p_provider_id,'generation',v_generation,
      'profile',p_profile,'configSha256',v_hash,'routeState','connected_inactive'),
    NULL,p_reason,'core');
  PERFORM public.app_notify('office_provider_changed',json_build_object(
    'provider_id',p_provider_id,'generation',v_generation,'route_state','connected_inactive')::text);
  RETURN jsonb_build_object('providerId',p_provider_id,'generation',v_generation,
    'routeState','connected_inactive','configSha256',v_hash,'qualified',false);
END;
$$;
SELECT apply_worker_ownership('office_provider_configure(bigint,text,bigint,text,text,text,jsonb,text)'::regprocedure);
