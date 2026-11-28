-- Keep the finite registry authoritative while accepting a registered key
-- that predates the dotted feature-key convention (device_telemetry).
CREATE OR REPLACE FUNCTION public.feature_toggle_set(
  p_key text, p_enabled boolean, p_actor bigint, p_ip inet, p_reason text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
  v_mode text;
  v_classification text;
  v_before jsonb;
  v_after jsonb;
BEGIN
  IF p_key IS NULL OR octet_length(p_key) NOT BETWEEN 1 AND 128
     OR (public.feature_registry_classify(p_key) = 'unknown'
         AND p_key !~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$') THEN
    RAISE EXCEPTION 'invalid feature key' USING ERRCODE='BZ261',
      HINT=jsonb_build_object('type','invalid_feature_key')::text;
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = '' OR octet_length(p_reason) > 1024
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid audit reason' USING ERRCODE='BZ261',
      HINT=jsonb_build_object('type','invalid_audit_reason')::text;
  END IF;
  IF p_key = 'dengbao.sod_mode' THEN
    RAISE EXCEPTION 'protected feature key requires its dedicated reducer'
      USING ERRCODE='BZ263', HINT=jsonb_build_object(
        'type','protected_feature_key','key',p_key)::text;
  END IF;

  PERFORM public.feature_registry_lock();
  SELECT mode INTO STRICT v_mode FROM public.feature_toggle_registry_state
    WHERE singleton FOR UPDATE;
  v_classification := public.feature_registry_classify(p_key);
  IF v_mode = 'enforce' AND v_classification = 'unknown' THEN
    RAISE EXCEPTION 'unknown feature key is forbidden while registry enforcement is active'
      USING ERRCODE='BZ262', HINT=jsonb_build_object(
        'type','unknown_feature_forbidden','key',p_key)::text;
  END IF;

  SELECT to_jsonb(ft) INTO v_before FROM public.feature_toggles ft WHERE key=p_key;
  INSERT INTO public.feature_toggles(key, enabled, updated_at)
    VALUES (p_key, p_enabled, now())
    ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled, updated_at=now();
  SELECT to_jsonb(ft) INTO v_after FROM public.feature_toggles ft WHERE key=p_key;
  PERFORM public.audit_write(p_actor, 'feature_toggle.set', 'feature_toggle', NULL,
    v_before, v_after, p_ip, btrim(p_reason), 'core');
  PERFORM public.app_notify('config_changed', jsonb_build_object(
    'key',p_key,'enabled',p_enabled,'classification',v_classification)::text);
  RETURN jsonb_build_object('key',p_key,'enabled',p_enabled,
    'classification',v_classification,'registryMode',v_mode);
END;
$$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (223, now())
ON CONFLICT (version) DO NOTHING;
