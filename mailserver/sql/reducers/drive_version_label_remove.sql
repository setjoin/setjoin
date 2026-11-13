-- mailserver/sql/reducers/drive_version_label_remove.sql
CREATE OR REPLACE FUNCTION drive_version_label_remove(
  p_user_id BIGINT, p_version_id BIGINT, p_label TEXT
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_file BIGINT;
BEGIN
  SELECT space_id, file_node_id INTO v_space, v_file FROM drive_file_versions WHERE id = p_version_id;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'version not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"version not found"}';
  END IF;
  PERFORM public.drive_require_node_capability(p_user_id,v_file,'modify_content');

  DELETE FROM drive_version_labels WHERE version_id = p_version_id AND label = btrim(COALESCE(p_label, ''));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'label not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"label not found"}';
  END IF;

  PERFORM drive_access_audit(p_user_id, v_space, 'label.remove', 'version', p_version_id,
    NULL, jsonb_build_object('label', p_label), NULL, NULL);
  PERFORM drive_notify_change(v_space, v_file, 'update');
END;
$$ LANGUAGE plpgsql;
