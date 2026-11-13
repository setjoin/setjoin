-- mailserver/sql/reducers/drive_space_set_classification.sql
CREATE OR REPLACE FUNCTION drive_space_set_classification(
  p_user_id BIGINT, p_space_id BIGINT, p_new TEXT
) RETURNS VOID AS $$
DECLARE v_authorized BOOLEAN; v_old TEXT;
BEGIN
  v_authorized:=public.drive_runtime_has_space_root_capability(
    p_user_id,p_space_id,'manage_acl');
  IF NOT v_authorized AND NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF p_new NOT IN ('regular','secure','gxp') THEN
    RAISE EXCEPTION 'invalid classification' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"classification must be regular|secure|gxp"}';
  END IF;
  SELECT classification INTO v_old FROM drive_spaces WHERE id = p_space_id;
  IF p_new = v_old THEN RETURN; END IF;
  IF p_new = 'gxp' THEN
    IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.drive_compliance'), FALSE) THEN
      RAISE EXCEPTION 'gxp requires drive compliance' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"gxp requires feature.drive_compliance"}';
    END IF;
    IF (SELECT retention_days IS NULL OR worm_mode IS NULL FROM drive_spaces WHERE id = p_space_id) THEN
      RAISE EXCEPTION 'gxp knobs required first' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"set retention_days and worm_mode before the gxp upgrade"}';
    END IF;
  END IF;
  UPDATE drive_spaces SET classification = p_new WHERE id = p_space_id;  -- trigger backstops BZ142
  PERFORM drive_access_audit(p_user_id, p_space_id, 'classification.change', 'space', p_space_id,
    jsonb_build_object('classification', v_old), jsonb_build_object('classification', p_new), NULL, NULL);
  PERFORM drive_notify_change(p_space_id, 0, 'space');
END;
$$ LANGUAGE plpgsql;
