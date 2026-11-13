-- mailserver/sql/reducers/drive_file_unlock.sql
-- Holder releases their own lock, or an authorized break (LR-4: space
-- manager OR subtree folder-admin OR a drive.manage admin -- always audited
-- lock.break + the holder notified). SECURITY DEFINER (LR-12): the RLS
-- DELETE policy on drive_file_locks is own-row OR manager OR expired+member
-- -- folder-admin/drive.manage break must cross that, so this reducer
-- re-checks its own authority rather than relying on the policy.
CREATE OR REPLACE FUNCTION drive_file_unlock(
  p_user_id bigint, p_node_id bigint, p_break boolean DEFAULT false
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_lock drive_file_locks%ROWTYPE; v_space bigint; v_authorized boolean;
BEGIN
  SELECT * INTO v_lock FROM drive_file_locks WHERE node_id = p_node_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;   -- idempotent: unlock on an already-unlocked file is a no-op (viewer-close race)
  END IF;
  v_space := v_lock.space_id;

  IF v_lock.user_id = p_user_id THEN
    DELETE FROM drive_file_locks WHERE node_id = p_node_id;
    PERFORM drive_access_audit(p_user_id, v_space, 'lock.release', 'node', p_node_id,
      NULL, jsonb_build_object('mode', v_lock.mode), NULL, NULL);
  ELSIF p_break THEN
    v_authorized := public.drive_runtime_has_node_capability(
                      p_user_id,p_node_id,'manage_acl')
                 OR drive_has_admin_perm(p_user_id, 'drive.manage');
    IF NOT v_authorized THEN
      RAISE EXCEPTION 'insufficient role to break lock' USING ERRCODE='BZ140',
        HINT='{"type":"forbidden","detail":"manager, subtree folder-admin, or drive.manage required to break a lock"}';
    END IF;
    DELETE FROM drive_file_locks WHERE node_id = p_node_id;
    PERFORM drive_access_audit(p_user_id, v_space, 'lock.break', 'node', p_node_id,
      NULL, jsonb_build_object('mode', v_lock.mode, 'holderId', v_lock.user_id), NULL, NULL);
    -- Fan-out (Task 8): best-effort, never unwinds the break.
    BEGIN
      PERFORM drive_notify_event('lock.break', p_user_id, v_space, p_node_id, NULL, v_lock.user_id);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  ELSE
    RAISE EXCEPTION 'lock held by another user' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"lock is held by another user"}';
  END IF;

  PERFORM app_notify('drive', json_build_object('spaceId', v_space,
    'kind', 'lock', 'nodeId', p_node_id)::text);
END;
$$;

SELECT apply_worker_ownership('drive_file_unlock(BIGINT, BIGINT, BOOLEAN)'::regprocedure);
