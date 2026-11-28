CREATE OR REPLACE FUNCTION office_provider_qualify(
  p_user_id bigint,
  p_provider_id text,
  p_expected_generation bigint,
  p_profile text,
  p_config_sha256 text,
  p_checks jsonb,
  p_discovery_fingerprint text,
  p_build_digest text,
  p_route_revision bigint,
  p_synthetic_receipt_id bigint,
  p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_provider office_provider_policies%ROWTYPE;
  v_id uuid;
  v_app_revision_id uuid;
  v_expires_at timestamptz := statement_timestamp()+interval '1 hour';
BEGIN
  IF NOT public.drive_has_admin_perm(p_user_id,'office.manage') THEN
    RAISE EXCEPTION 'Office management forbidden' USING ERRCODE='BZ323';
  END IF;
  IF COALESCE(p_expected_generation,0)<=0
     OR p_profile NOT IN ('existing-provider','managed-wildcard','managed-customer-cert','managed-customer-proxy')
     OR p_config_sha256 !~ '^[0-9a-f]{64}$'
     OR p_checks IS NULL OR jsonb_typeof(p_checks)<>'object'
     OR octet_length(p_checks::text)>262144
     OR p_discovery_fingerprint !~ '^[0-9a-f]{64}$'
     OR (p_build_digest IS NOT NULL AND p_build_digest !~ '^sha256:[0-9a-f]{64}$')
     OR COALESCE(p_route_revision,0)<=0 OR COALESCE(p_synthetic_receipt_id,0)<=0
     OR NULLIF(btrim(p_reason),'') IS NULL THEN
    RAISE EXCEPTION 'invalid Office qualification evidence' USING ERRCODE='BZ322';
  END IF;
  IF NOT (p_checks @> '{"discovery":"pass","proof":"pass","editor":"pass","wopiSave":"pass"}'::jsonb) THEN
    RAISE EXCEPTION 'Office qualification checks are incomplete' USING ERRCODE='BZ327',
      HINT='{"type":"providerUnavailable","detail":"discovery, proof, editor and synthetic WOPI save must all pass"}';
  END IF;
  SELECT * INTO v_provider FROM public.office_provider_policies
   WHERE provider_id=p_provider_id AND removed_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Office provider unavailable' USING ERRCODE='BZ327';
  END IF;
  IF v_provider.generation<>p_expected_generation
     OR v_provider.config_sha256<>p_config_sha256 THEN
    RAISE EXCEPTION 'Office provider qualification is stale' USING ERRCODE='BZ324',
      HINT='{"type":"stateMismatch","detail":"configuration changed; run qualification again"}';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.office_save_receipts r
                  WHERE r.id=p_synthetic_receipt_id
                    AND r.provider_id=p_provider_id
                    AND r.response_class IN ('accepted','branched')) THEN
    RAISE EXCEPTION 'synthetic WOPI save receipt is unavailable' USING ERRCODE='BZ327',
      HINT='{"type":"providerUnavailable","detail":"complete the synthetic WOPI save before qualification"}';
  END IF;
  IF p_profile<>'existing-provider' THEN
    SELECT r.id INTO v_app_revision_id
      FROM public.office_app_revisions r
     WHERE r.provider_id=p_provider_id AND r.image_digest=p_build_digest
       AND r.state='installed_inactive'
     ORDER BY r.revision DESC LIMIT 1 FOR UPDATE;
    IF v_app_revision_id IS NULL THEN
      RAISE EXCEPTION 'managed Office revision evidence is unavailable' USING ERRCODE='BZ327',
        HINT='{"type":"providerUnavailable","detail":"install the exact managed revision before qualification"}';
    END IF;
  END IF;
  INSERT INTO public.office_provider_qualifications(
    provider_id,provider_generation,config_sha256,status,profile,checks,
    discovery_fingerprint,build_digest,route_revision,synthetic_receipt_id,app_revision_id,
    created_by,expires_at
  ) VALUES(
    p_provider_id,p_expected_generation,p_config_sha256,'passed',p_profile,p_checks,
    p_discovery_fingerprint,p_build_digest,p_route_revision,p_synthetic_receipt_id,v_app_revision_id,
    p_user_id,v_expires_at
  ) ON CONFLICT(provider_id,provider_generation,config_sha256,profile)
    DO UPDATE SET status='passed',checks=EXCLUDED.checks,
      discovery_fingerprint=EXCLUDED.discovery_fingerprint,
      build_digest=EXCLUDED.build_digest,route_revision=EXCLUDED.route_revision,
      synthetic_receipt_id=EXCLUDED.synthetic_receipt_id,
      app_revision_id=EXCLUDED.app_revision_id,
      created_by=EXCLUDED.created_by,created_at=statement_timestamp(),
      expires_at=EXCLUDED.expires_at
  RETURNING id INTO v_id;
  UPDATE public.office_provider_policies
     SET active_qualification_id=v_id,route_state='connected_inactive',
         enabled=false,draining=false,updated_by=p_user_id,updated_at=statement_timestamp()
   WHERE provider_id=p_provider_id;
  IF v_app_revision_id IS NOT NULL THEN
    UPDATE public.office_app_revisions SET state='qualified',updated_at=statement_timestamp()
     WHERE id=v_app_revision_id;
  END IF;
  INSERT INTO public.office_provider_health_observations(
    provider_id,provider_generation,state,capacity_state,facts,expires_at
  ) VALUES(p_provider_id,p_expected_generation,'healthy','available',
    jsonb_build_object('source','qualification','qualificationId',v_id::text),
    LEAST(v_expires_at,statement_timestamp()+interval '5 minutes'));
  PERFORM public.audit_write(p_user_id,'office.provider.qualified','office_provider',NULL,NULL,
    jsonb_build_object('providerId',p_provider_id,'generation',p_expected_generation,
      'qualificationId',v_id::text,'configSha256',p_config_sha256),NULL,p_reason,'core');
  PERFORM public.app_notify('office_provider_changed',json_build_object(
    'provider_id',p_provider_id,'generation',p_expected_generation,
    'route_state','connected_inactive','qualification_id',v_id)::text);
  RETURN jsonb_build_object('providerId',p_provider_id,'generation',p_expected_generation,
    'routeState','connected_inactive','qualificationId',v_id::text,
    'expiresAt',v_expires_at,'qualified',true);
END;
$$;
SELECT apply_worker_ownership('office_provider_qualify(bigint,text,bigint,text,text,jsonb,text,text,bigint,bigint,text)'::regprocedure);
