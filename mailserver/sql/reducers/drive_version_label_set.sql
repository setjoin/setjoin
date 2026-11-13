-- mailserver/sql/reducers/drive_version_label_set.sql
-- Idempotent tag-set on a version (LR-11: the space is resolved THROUGH
-- drive_file_versions since drive_version_labels has no space_id of its own).
CREATE OR REPLACE FUNCTION drive_version_label_set(
  p_user_id BIGINT, p_version_id BIGINT, p_label TEXT
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_file BIGINT; v_label TEXT; v_ins BOOLEAN;
BEGIN
  SELECT space_id, file_node_id INTO v_space, v_file FROM drive_file_versions WHERE id = p_version_id;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'version not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"version not found"}';
  END IF;
  PERFORM public.drive_require_node_capability(p_user_id,v_file,'modify_content');

  v_label := btrim(COALESCE(p_label, ''));
  IF v_label = '' OR length(v_label) > 60 THEN
    RAISE EXCEPTION 'invalid label' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"label must be 1-60 chars"}';
  END IF;

  INSERT INTO drive_version_labels (version_id, label, created_by)
  VALUES (p_version_id, v_label, p_user_id)
  ON CONFLICT (version_id, label) DO NOTHING
  RETURNING true INTO v_ins;

  IF v_ins THEN   -- duplicate set is a silent no-op: no second audit row (idempotent)
    PERFORM drive_access_audit(p_user_id, v_space, 'label.set', 'version', p_version_id,
      NULL, jsonb_build_object('label', v_label), NULL, NULL);
    PERFORM drive_notify_change(v_space, v_file, 'update');
  END IF;
END;
$$ LANGUAGE plpgsql;
