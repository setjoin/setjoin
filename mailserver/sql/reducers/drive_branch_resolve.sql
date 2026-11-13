-- mailserver/sql/reducers/drive_branch_resolve.sql
--       drive_access_audit, drive_notify_change
-- The four resolve verbs (§5.1/§5.2, I-13). Every verb is a pointer move +
-- parentage record — bytes are NEVER synthesized; adopt/keep_both COPY an
-- already-proven manifest (branches reference already-proven manifests,
-- §5.1 — no anti-oracle re-check needed).
CREATE OR REPLACE FUNCTION drive_branch_resolve(
  p_user_id BIGINT, p_branch_id BIGINT, p_verb TEXT, p_new_name TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_branch drive_file_branches%ROWTYPE;
  v_main_head BIGINT;
  v_node_parent BIGINT; v_node_name TEXT; v_node_space BIGINT;
  v_is_admin BOOLEAN; v_has_fa BOOLEAN;
  v_head drive_file_versions%ROWTYPE;
  v_new_id BIGINT; v_new_node_id BIGINT; v_kept_node_id BIGINT;
  v_ext TEXT; v_base_name TEXT; v_stem TEXT; v_candidate TEXT; v_n INT;
BEGIN
  IF p_verb NOT IN ('ff','adopt','keep_both','discard') THEN
    RAISE EXCEPTION 'unknown resolve verb' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"verb must be ff|adopt|keep_both|discard"}';
  END IF;

  SELECT * INTO v_branch FROM drive_file_branches WHERE id = p_branch_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'branch not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"branch not found"}';
  END IF;
  PERFORM public.drive_require_node_capability(
    p_user_id,v_branch.file_node_id,'modify_content');
  IF v_branch.status NOT IN ('open','review') THEN
    RAISE EXCEPTION 'branch is closed' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"branch is no longer open"}';
  END IF;

  -- Authorization matrix (locked, §5.2/§5.5): manager or subtree folder-admin
  -- may always resolve; the branch creator may resolve their OWN branch only
  -- when no folder admin is set anywhere on the file's ancestor chain.
  v_is_admin := public.drive_runtime_has_node_capability(
                  p_user_id,v_branch.file_node_id,'manage_acl');
  v_has_fa   := EXISTS (
    SELECT 1
      FROM drive_node_closure c
      JOIN drive_folder_admins fa
        ON fa.space_id = c.space_id AND fa.node_id = c.ancestor_id
     WHERE c.space_id = v_branch.space_id
       AND c.descendant_id = v_branch.file_node_id)
    OR EXISTS (
      SELECT 1
        FROM public.drive_node_closure c
        JOIN public.drive_acl_grants g
          ON g.space_id=c.space_id AND g.node_id=c.ancestor_id
       WHERE c.space_id=v_branch.space_id
         AND c.descendant_id=v_branch.file_node_id
         AND g.state='active' AND 'manage_acl'=ANY(g.capabilities)
         AND (g.starts_at IS NULL OR g.starts_at<=now())
         AND (g.expires_at IS NULL OR g.expires_at>now()));
  IF NOT (v_is_admin OR (v_branch.created_by = p_user_id AND NOT v_has_fa)) THEN
    RAISE EXCEPTION 'insufficient role to resolve this branch' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"manager, subtree folder-admin, or the branch creator (when no folder admin is set) may resolve"}';
  END IF;

  SELECT f.head_version_id, n.parent_id, n.name, n.space_id
    INTO v_main_head, v_node_parent, v_node_name, v_node_space
    FROM drive_files f JOIN drive_nodes n ON n.id = f.node_id
   WHERE f.node_id = v_branch.file_node_id FOR UPDATE OF f;
  SELECT * INTO v_head FROM drive_file_versions WHERE id = v_branch.head_version_id;

  CASE p_verb
  WHEN 'ff' THEN
    IF v_main_head IS DISTINCT FROM v_branch.forked_from_version_id THEN
      RAISE EXCEPTION 'main moved since fork' USING ERRCODE='BZ150',
        HINT='{"type":"branchError","detail":"fast-forward not possible: main has moved"}';
    END IF;
    UPDATE drive_files SET head_version_id = v_branch.head_version_id,
           size_bytes = v_head.size_bytes, content_type = v_head.content_type
     WHERE node_id = v_branch.file_node_id;

  WHEN 'adopt' THEN
    IF NOT drive_space_quota_charge(v_branch.space_id, v_head.size_bytes) THEN
      RAISE EXCEPTION 'space quota exceeded' USING ERRCODE='BZ148',
        HINT='{"type":"overQuota","detail":"space quota exceeded"}';
    END IF;
    INSERT INTO drive_file_versions (file_node_id, space_id, parent_version_id,
        merged_from_version_id, branch_id, content_sha256, size_bytes, chunk_size,
        content_type, author_user_id, device_label, note)
    VALUES (v_branch.file_node_id, v_branch.space_id, v_main_head, v_branch.head_version_id,
        NULL, v_head.content_sha256, v_head.size_bytes, v_head.chunk_size,
        v_head.content_type, p_user_id, 'resolve', 'merge: ' || v_branch.name)
    RETURNING id INTO v_new_id;
    INSERT INTO drive_version_chunks (version_id, stream, ordinal, scope_key, chunk_sha256)
    SELECT v_new_id, stream, ordinal, scope_key, chunk_sha256
      FROM drive_version_chunks WHERE version_id = v_branch.head_version_id;
    UPDATE drive_files SET head_version_id = v_new_id, size_bytes = v_head.size_bytes,
           content_type = v_head.content_type
     WHERE node_id = v_branch.file_node_id;

  WHEN 'keep_both' THEN
    PERFORM drive_tree_lock(v_branch.space_id);
    -- The sibling inherits the original file's current parent. Re-read that
    -- placement under the same structural lock used by move/create so a
    -- concurrent reparent cannot leave the new node outside closure.
    SELECT n.space_id, n.parent_id, n.name
      INTO v_node_space, v_node_parent, v_node_name
      FROM drive_nodes n
     WHERE n.id = v_branch.file_node_id
     FOR UPDATE;
    IF (v_node_parent IS NULL AND NOT public.drive_runtime_has_space_root_capability(
          p_user_id,v_node_space,'create_child'))
       OR (v_node_parent IS NOT NULL AND NOT public.drive_runtime_has_node_capability(
          p_user_id,v_node_parent,'create_child')) THEN
      RAISE EXCEPTION 'keep-both destination not found' USING ERRCODE='BZ139',
        HINT='{"type":"notFound","detail":"keep-both destination not found"}';
    END IF;
    IF NOT drive_space_quota_charge(v_branch.space_id, v_head.size_bytes) THEN
      RAISE EXCEPTION 'space quota exceeded' USING ERRCODE='BZ148',
        HINT='{"type":"overQuota","detail":"space quota exceeded"}';
    END IF;
    v_ext := CASE WHEN position('.' IN v_node_name) > 0
                  THEN '.' || reverse(split_part(reverse(v_node_name), '.', 1)) ELSE '' END;
    v_base_name := CASE WHEN v_ext <> '' THEN left(v_node_name, length(v_node_name) - length(v_ext))
                        ELSE v_node_name END;
    v_stem := COALESCE(NULLIF(btrim(p_new_name), ''), v_base_name || ' — ' || v_branch.name);
    v_n := 1; v_candidate := v_stem || v_ext;
    WHILE EXISTS (SELECT 1 FROM drive_nodes n2
                   WHERE n2.space_id = v_node_space
                     AND n2.parent_id IS NOT DISTINCT FROM v_node_parent
                     AND n2.deleted_at IS NULL
                     AND lower(n2.name) = lower(v_candidate)) LOOP
      v_n := v_n + 1;
      v_candidate := v_stem || ' -' || v_n || v_ext;   -- G4, case-insensitive (LR-7), never BZ147
    END LOOP;

    INSERT INTO drive_nodes (space_id, parent_id, kind, name, created_by)
    VALUES (v_node_space, v_node_parent, 'file', v_candidate, p_user_id)
    RETURNING id INTO v_new_node_id;
    PERFORM drive_closure_insert_node(v_node_space, v_new_node_id, v_node_parent);
    INSERT INTO drive_files (node_id, space_id, size_bytes, content_type)
    VALUES (v_new_node_id, v_node_space, v_head.size_bytes, v_head.content_type);
    INSERT INTO drive_file_versions (file_node_id, space_id, parent_version_id,
        merged_from_version_id, branch_id, content_sha256, size_bytes, chunk_size,
        content_type, author_user_id, device_label, note)
    VALUES (v_new_node_id, v_node_space, NULL, v_branch.head_version_id, NULL,
        v_head.content_sha256, v_head.size_bytes, v_head.chunk_size,
        v_head.content_type, p_user_id, 'resolve', 'kept both: ' || v_branch.name)
    RETURNING id INTO v_new_id;
    INSERT INTO drive_version_chunks (version_id, stream, ordinal, scope_key, chunk_sha256)
    SELECT v_new_id, stream, ordinal, scope_key, chunk_sha256
      FROM drive_version_chunks WHERE version_id = v_branch.head_version_id;
    UPDATE drive_files SET head_version_id = v_new_id WHERE node_id = v_new_node_id;
    v_kept_node_id := v_new_node_id;
    PERFORM drive_access_audit(p_user_id, v_branch.space_id, 'node.create', 'node', v_new_node_id,
      NULL, jsonb_build_object('name', v_candidate, 'kind', 'file', 'parentId', v_node_parent),
      NULL, 'keep-both');
    PERFORM drive_notify_change(v_branch.space_id, v_new_node_id, 'create');

  WHEN 'discard' THEN
    NULL;   -- status flip below is everything
  END CASE;

  UPDATE drive_file_branches SET status = CASE WHEN p_verb = 'discard' THEN 'discarded' ELSE 'merged' END,
         resolved_by = p_user_id, resolved_at = now() WHERE id = p_branch_id;
  PERFORM drive_access_audit(p_user_id, v_branch.space_id,
          CASE WHEN p_verb = 'discard' THEN 'branch.discard' ELSE 'branch.merge' END,
          'branch', p_branch_id, NULL, jsonb_build_object('verb', p_verb, 'name', v_branch.name), NULL, NULL);
  PERFORM drive_notify_change(v_branch.space_id, v_branch.file_node_id, 'update');

  RETURN jsonb_build_object('verb', p_verb,
    'headVersionId', (SELECT head_version_id FROM drive_files WHERE node_id = v_branch.file_node_id),
    'newNodeId', v_kept_node_id);
END;
$$ LANGUAGE plpgsql;
