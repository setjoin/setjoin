-- mailserver/sql/reducers/drive_branch_rename.sql
CREATE OR REPLACE FUNCTION drive_branch_rename(
  p_user_id BIGINT, p_branch_id BIGINT, p_new_name TEXT
) RETURNS VOID AS $$
DECLARE v_space BIGINT; v_file BIGINT; v_status TEXT; v_name TEXT;
BEGIN
  SELECT space_id, file_node_id, status INTO v_space, v_file, v_status
    FROM drive_file_branches WHERE id = p_branch_id;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'branch not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"branch not found"}';
  END IF;
  PERFORM public.drive_require_node_capability(
    p_user_id,v_file,'modify_content');
  IF v_status NOT IN ('open','review') THEN
    RAISE EXCEPTION 'branch is closed' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"branch is no longer open"}';
  END IF;

  v_name := btrim(COALESCE(p_new_name, ''));
  IF v_name = '' OR length(v_name) > 100 THEN
    RAISE EXCEPTION 'invalid branch name' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"name must be 1-100 chars"}';
  END IF;
  IF EXISTS (SELECT 1 FROM drive_file_branches b WHERE b.file_node_id = v_file
              AND b.id <> p_branch_id AND lower(b.name) = lower(v_name)) THEN
    RAISE EXCEPTION 'branch name taken' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"a branch with this name already exists on this file"}';
  END IF;

  BEGIN
    UPDATE drive_file_branches SET name = v_name WHERE id = p_branch_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'branch name taken' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"a branch with this name already exists on this file"}';
  END;

  PERFORM drive_access_audit(p_user_id, v_space, 'branch.rename', 'branch', p_branch_id, NULL,
    jsonb_build_object('name', v_name), NULL, NULL);
  PERFORM drive_notify_change(v_space, v_file, 'update');
END;
$$ LANGUAGE plpgsql;
