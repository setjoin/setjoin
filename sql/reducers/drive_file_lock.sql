-- mailserver/sql/reducers/drive_file_lock.sql
-- Acquire/heartbeat/presence (§5.4, §6.3). The lock row is ALSO the
-- open-from provenance record (§5.3): (branch_id|NULL=main, version_id).
-- Invoker-rights: INSERT/UPDATE own rows pass the V115 RLS write policies.
--
-- AUTOPLAN batch-1 #1 (lock-acquire race): a bare "check row, then INSERT
-- ... ON CONFLICT DO UPDATE ... WHERE user_id=p_user_id" leaves a window
-- where two concurrent acquires both read "free" and both think they won.
-- FIX: serialize every acquire attempt on THIS file through drive_files'
-- own row (SELECT ... FOR UPDATE) -- a concurrent call for the SAME node_id
-- blocks here until this call commits, so by the time it reads
-- drive_file_locks the state is guaranteed current. The INSERT ... ON
-- CONFLICT ... RETURNING check below is defense in depth (batch-1 #1's
-- "verify the write landed"), not the primary guard.
CREATE OR REPLACE FUNCTION drive_file_lock(
  p_user_id      bigint,
  p_node_id      bigint,
  p_mode         text    DEFAULT 'soft',
  p_branch_id    bigint  DEFAULT NULL,
  p_version_id   bigint  DEFAULT NULL,
  p_device_label text    DEFAULT NULL,
  p_ttl_minutes  int     DEFAULT 480
) RETURNS jsonb AS $$
DECLARE
  v_space_id bigint; v_ttl int; v_existing drive_file_locks%ROWTYPE;
  v_version_id bigint; v_fresh boolean := false; v_effective_mode text; v_ok boolean;
BEGIN
  IF p_mode NOT IN ('soft','hard') THEN
    RAISE EXCEPTION 'invalid lock mode' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"mode must be soft or hard"}';
  END IF;
  v_ttl := LEAST(GREATEST(COALESCE(p_ttl_minutes, 480), 5), 1440);

  SELECT n.space_id INTO v_space_id FROM drive_nodes n
   WHERE n.id = p_node_id AND n.kind = 'file' AND n.deleted_at IS NULL;
  IF v_space_id IS NULL THEN
    RAISE EXCEPTION 'not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"file not found"}';
  END IF;
  PERFORM public.drive_require_node_mutation_capability(
    p_user_id,p_node_id,'modify_content');
  IF p_branch_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM drive_file_branches b
       WHERE b.id = p_branch_id AND b.file_node_id = p_node_id AND b.status IN ('open','review')) THEN
    RAISE EXCEPTION 'unknown branch' USING ERRCODE='BZ150',
      HINT='{"type":"branchError","detail":"branch not open on this file"}';
  END IF;

  -- Serialize (batch-1 #1): every concurrent drive_file_lock call for this
  -- exact node_id blocks here until this call's transaction ends.
  PERFORM 1 FROM drive_files WHERE node_id = p_node_id FOR UPDATE;

  v_version_id := COALESCE(p_version_id,
    (SELECT COALESCE(b.head_version_id, f.head_version_id)
       FROM drive_files f LEFT JOIN drive_file_branches b ON b.id = p_branch_id
      WHERE f.node_id = p_node_id));
  IF v_version_id IS NULL THEN
    RAISE EXCEPTION 'file has no version to lock' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"file has no saved version yet"}';
  END IF;

  SELECT * INTO v_existing FROM drive_file_locks WHERE node_id = p_node_id;

  IF FOUND AND v_existing.user_id <> p_user_id AND v_existing.expires_at > now() THEN
    RETURN jsonb_build_object('status','held','holderId',v_existing.user_id,
      'mode',v_existing.mode,'since',v_existing.acquired_at,'expiresAt',v_existing.expires_at,
      'branchId',v_existing.branch_id);
  END IF;

  IF FOUND AND v_existing.user_id <> p_user_id THEN          -- expired: takeover
    DELETE FROM drive_file_locks WHERE node_id = p_node_id;
    v_fresh := true;
  ELSIF NOT FOUND THEN
    v_fresh := true;
  END IF;

  -- Same-holder re-acquire (AUTOPLAN batch-3 #2, supersedes batch-1 #8's
  -- literal "renew expires_at only"): ALWAYS renew + refresh branch/version/
  -- device_label; mode may only ESCALATE. soft->hard is a fresh checkout
  -- (audited like an acquire); hard + p_mode='soft' keeps 'hard' and just
  -- renews -- never a silent downgrade. The response always carries the
  -- EFFECTIVE mode.
  IF NOT v_fresh AND v_existing.mode = 'soft' AND p_mode = 'hard' THEN
    v_fresh := true;   -- escalation: audited exactly like a fresh acquire
  END IF;
  v_effective_mode := CASE
    WHEN v_fresh THEN p_mode
    WHEN v_existing.mode = 'hard' THEN 'hard'
    ELSE p_mode
  END;

  INSERT INTO drive_file_locks (node_id, space_id, user_id, branch_id, version_id,
                                device_label, mode, acquired_at, expires_at)
  VALUES (p_node_id, v_space_id, p_user_id, p_branch_id, v_version_id,
          p_device_label, v_effective_mode,
          CASE WHEN v_fresh THEN now() ELSE v_existing.acquired_at END,
          now() + make_interval(mins => v_ttl))
  ON CONFLICT (node_id) DO UPDATE SET
      mode = v_effective_mode, branch_id = EXCLUDED.branch_id,
      version_id = EXCLUDED.version_id, device_label = EXCLUDED.device_label,
      expires_at = EXCLUDED.expires_at
    WHERE drive_file_locks.user_id = p_user_id
  RETURNING true INTO v_ok;
  IF NOT v_ok THEN
    -- Defense in depth: under the FOR UPDATE serialization above this arm is
    -- unreachable, but never silently succeed if it somehow is (batch-1 #1).
    SELECT * INTO v_existing FROM drive_file_locks WHERE node_id = p_node_id;
    RETURN jsonb_build_object('status','held','holderId',v_existing.user_id,
      'mode',v_existing.mode,'since',v_existing.acquired_at,'expiresAt',v_existing.expires_at,
      'branchId',v_existing.branch_id);
  END IF;

  IF v_fresh THEN
    PERFORM drive_access_audit(p_user_id, v_space_id, 'lock.acquire', 'node', p_node_id,
      NULL, jsonb_build_object('mode', v_effective_mode, 'branchId', p_branch_id), NULL, NULL);
    PERFORM app_notify('drive', json_build_object('spaceId', v_space_id,
      'kind', 'lock', 'nodeId', p_node_id)::text);             -- presence nudge, not journaled
  END IF;
  RETURN jsonb_build_object('status', CASE WHEN v_fresh THEN 'acquired' ELSE 'renewed' END,
    'expiresAt', now() + make_interval(mins => v_ttl), 'mode', v_effective_mode);
END;
$$ LANGUAGE plpgsql;
