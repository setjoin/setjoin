-- mailserver/sql/reducers/drive_space_set_quota.sql
-- Admin knob on ALL space kinds incl. personal (§0.1-2). NULL = unlimited.
CREATE OR REPLACE FUNCTION drive_space_set_quota(
  p_user_id BIGINT, p_space_id BIGINT, p_quota_bytes BIGINT
) RETURNS VOID AS $$
DECLARE v_old BIGINT;
BEGIN
  IF NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'drive.manage required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"quota is a drive.manage admin knob"}';
  END IF;
  IF p_quota_bytes IS NOT NULL AND p_quota_bytes <= 0 THEN
    RAISE EXCEPTION 'invalid quota' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"quota_bytes must be positive or null"}';
  END IF;
  SELECT quota_bytes INTO v_old FROM drive_spaces WHERE id = p_space_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  UPDATE drive_spaces SET quota_bytes = p_quota_bytes WHERE id = p_space_id;
  PERFORM drive_access_audit(p_user_id, p_space_id, 'quota.change', 'space', p_space_id,
    jsonb_build_object('quotaBytes', v_old), jsonb_build_object('quotaBytes', p_quota_bytes), NULL, NULL);
  PERFORM drive_notify_change(p_space_id, 0, 'space');
END;
$$ LANGUAGE plpgsql;
