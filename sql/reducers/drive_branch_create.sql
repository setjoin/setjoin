-- mailserver/sql/reducers/drive_branch_create.sql
-- Creates a named movable ref forked from an existing version of the same
-- file (§5.1). Case-insensitive name collision -> BZ150 (the
-- drive_file_branches_ci_name_uniq index is the race backstop).
CREATE OR REPLACE FUNCTION drive_branch_create(
  p_user_id BIGINT, p_file_node_id BIGINT, p_name TEXT, p_from_version_id BIGINT
) RETURNS BIGINT AS $$
DECLARE v_space BIGINT; v_from_file BIGINT; v_id BIGINT; v_name TEXT;
BEGIN
  SELECT n.space_id
    INTO v_space
    FROM drive_nodes n WHERE n.id = p_file_node_id AND n.kind = 'file' AND n.deleted_at IS NULL;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'file not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"file not found"}';
  END IF;
  PERFORM public.drive_require_node_capability(
    p_user_id,p_file_node_id,'modify_content');

  SELECT file_node_id INTO v_from_file FROM drive_file_versions WHERE id = p_from_version_id;
  IF v_from_file IS NULL OR v_from_file <> p_file_node_id THEN
    RAISE EXCEPTION 'from-version does not belong to this file' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"fromVersionId must belong to this file"}';
  END IF;

  v_name := btrim(COALESCE(p_name, ''));
  IF v_name = '' OR length(v_name) > 100 THEN
    RAISE EXCEPTION 'invalid branch name' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"name must be 1-100 chars"}';
  END IF;
  IF EXISTS (SELECT 1 FROM drive_file_branches b
              WHERE b.file_node_id = p_file_node_id AND lower(b.name) = lower(v_name)) THEN
    RAISE EXCEPTION 'branch name taken' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"a branch with this name already exists on this file"}';
  END IF;

  BEGIN
    INSERT INTO drive_file_branches (file_node_id, space_id, name, head_version_id,
        forked_from_version_id, auto_created, created_by)
    VALUES (p_file_node_id, v_space, v_name, p_from_version_id, p_from_version_id, false, p_user_id)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'branch name taken' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"a branch with this name already exists on this file"}';
  END;

  PERFORM drive_access_audit(p_user_id, v_space, 'branch.create', 'branch', v_id, NULL,
    jsonb_build_object('name', v_name, 'fileNodeId', p_file_node_id,
                       'fromVersionId', p_from_version_id), NULL, NULL);
  PERFORM drive_notify_change(v_space, p_file_node_id, 'update');
  RETURN v_id;
END;
$$ LANGUAGE plpgsql;
