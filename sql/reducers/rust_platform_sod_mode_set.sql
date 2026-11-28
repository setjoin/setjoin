-- Frozen Go's PUT /admin/dengbao/sod-mode (admin.SodModeHandler.Set): turning ON runs
-- admin_sod_precheck() and the dengbao.sod_mode flip in ONE transaction, and any violation
-- leaves the toggle untouched; turning OFF is unconditional; both write the core audit row
-- inside that transaction. Go's multi-statement transaction as one reducer call.
-- p_actor is the verified token's user. Returns {"violations":[...]} (nothing written) or
-- {"enabled":bool}. The feature_toggles trigger raises config_changed as for any flip.
CREATE OR REPLACE FUNCTION rust_platform_sod_mode_set(
 p_actor bigint,p_enabled boolean,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_violations jsonb;
BEGIN
 IF p_enabled THEN
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
          'violationType', violation_type, 'subject', subject, 'detail', detail)), '[]'::jsonb)
    INTO v_violations FROM admin_sod_precheck();
  IF jsonb_array_length(v_violations) > 0 THEN
   RETURN jsonb_build_object('violations', v_violations);
  END IF;
 END IF;
 INSERT INTO feature_toggles (key, enabled, updated_at)
 VALUES ('dengbao.sod_mode', p_enabled, now())
 ON CONFLICT (key) DO UPDATE SET enabled = p_enabled, updated_at = now();
 PERFORM audit_write(p_actor,
  CASE WHEN p_enabled THEN 'sod_mode_enable' ELSE 'sod_mode_disable' END,
  'feature_toggle', NULL, NULL,
  jsonb_build_object('key', 'dengbao.sod_mode'), NULLIF(p_ip, '')::inet, '', 'core');
 RETURN jsonb_build_object('enabled', p_enabled);
END;
$$;
