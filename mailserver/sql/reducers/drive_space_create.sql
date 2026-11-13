-- mailserver/sql/reducers/drive_space_create.sql
CREATE OR REPLACE FUNCTION drive_space_create(
  p_user_id        BIGINT,
  p_name           TEXT,
  p_classification TEXT,
  p_is_personal    BOOLEAN DEFAULT FALSE,
  p_retention_days INT     DEFAULT NULL,
  p_worm_mode      TEXT    DEFAULT NULL,
  p_export_policy  JSONB   DEFAULT '{}'
) RETURNS BIGINT AS $$
DECLARE v_id BIGINT;
BEGIN
  -- Guest door (guest-accounts G0, codex C-3 belt): the route is already
  -- allowlist-denied; this survives a G4 route re-add and keeps this file
  -- honest under Task 16's §1 guard (it INSERTs the owner's own
  -- drive_space_members row).
  IF is_guest_account(p_user_id) THEN
    RAISE EXCEPTION 'not available to guest accounts'
      USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"not available to guest accounts"}';
  END IF;
  IF NULLIF(btrim(COALESCE(p_name,'')), '') IS NULL OR length(p_name) > 200 THEN
    RAISE EXCEPTION 'invalid space name' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"name must be 1-200 chars"}';
  END IF;
  IF p_classification NOT IN ('regular','secure','gxp') THEN
    RAISE EXCEPTION 'invalid classification' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"classification must be regular|secure|gxp"}';
  END IF;
  IF p_classification = 'gxp' THEN
    IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.drive_compliance'), FALSE) THEN
      RAISE EXCEPTION 'gxp requires drive compliance' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"gxp requires feature.drive_compliance"}';
    END IF;
    IF p_retention_days IS NULL OR p_worm_mode IS NULL THEN
      RAISE EXCEPTION 'gxp knobs required' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"gxp requires retention_days and worm_mode"}';
    END IF;
  END IF;
  IF p_is_personal THEN
    -- idempotent per the partial unique index (§2.1.3): return the existing space.
    SELECT id INTO v_id FROM drive_spaces WHERE owner_user_id = p_user_id AND is_personal;
    IF FOUND THEN RETURN v_id; END IF;
  ELSIF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='drive.space_creation'), TRUE)
        AND NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'space creation disabled' USING ERRCODE='BZ140',   -- G6
      HINT='{"type":"forbidden","detail":"space creation is restricted to drive admins"}';
  END IF;

  INSERT INTO drive_spaces (name, is_personal, classification, owner_user_id,
                            retention_days, worm_mode, export_policy)
  VALUES (p_name, p_is_personal, p_classification, p_user_id,
          p_retention_days, p_worm_mode, COALESCE(p_export_policy, '{}'::jsonb))
  RETURNING id INTO v_id;
  INSERT INTO drive_space_members (space_id, user_id, role, granted_by)
  VALUES (v_id, p_user_id, 'manager', p_user_id);

  PERFORM drive_access_audit(p_user_id, v_id, 'space.create', 'space', v_id, NULL,
    jsonb_build_object('name', p_name, 'classification', p_classification, 'isPersonal', p_is_personal),
    NULL, NULL);
  PERFORM drive_notify_change(v_id, 0, 'space');   -- node_id 0 sentinel (R3)
  RETURN v_id;
EXCEPTION WHEN unique_violation THEN
  -- personal-create race under the partial unique index: converge on the winner.
  SELECT id INTO v_id FROM drive_spaces WHERE owner_user_id = p_user_id AND is_personal;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql;
