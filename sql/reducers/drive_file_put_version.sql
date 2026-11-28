-- mailserver/sql/reducers/drive_file_put_version.sql
-- THE core write (spec §6.2). P4 upgrade: per-ref saves (p_branch_id), same-
-- txn lock enforcement (§5.4, I-12), conflict -> auto-branch (§5.2, I-9).
-- WORM storage wiring is P5 (Locked resolution R5): retain_until bookkeeping
-- here, wormPending always false.
CREATE OR REPLACE FUNCTION drive_file_put_version(
  p_user_id        BIGINT,
  p_file_node_id   BIGINT,
  p_content_sha256 TEXT,
  p_size           BIGINT,
  p_content_type   TEXT,
  p_base_version_id BIGINT,
  p_manifest       JSONB,
  p_note           TEXT,
  p_device_label   TEXT,
  p_branch_id      BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_space  BIGINT; v_class TEXT; v_ret INT; v_acl_mode TEXT; v_acl_epoch BIGINT;
  v_scope  TEXT;   v_policy JSONB;
  v_vid    BIGINT; v_conflict BOOLEAN := FALSE;
  v_n      INT;    v_sum BIGINT;
  v_branch drive_file_branches%ROWTYPE;
  v_ref_head BIGINT;
  v_lock   drive_file_locks%ROWTYPE;
  v_force_branch BOOLEAN := FALSE;
  v_auto_branch_id BIGINT;
  v_bname TEXT; v_candidate TEXT; v_bn INT;
BEGIN
  SELECT n.space_id,s.classification,s.retention_days,s.acl_mode,g.epoch,
         CASE WHEN s.classification = 'regular' THEN 'g' ELSE 's' || s.id END
    INTO v_space,v_class,v_ret,v_acl_mode,v_acl_epoch,v_scope
    FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id
    JOIN drive_acl_generations g ON g.space_id=s.id
   WHERE n.id = p_file_node_id AND n.kind = 'file' AND n.deleted_at IS NULL;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'file not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"file not found"}';
  END IF;
  PERFORM public.drive_require_node_mutation_capability(
    p_user_id,p_file_node_id,'modify_content');
  IF v_acl_mode='acl' THEN
    SELECT epoch INTO v_acl_epoch FROM public.drive_acl_generations
     WHERE space_id=v_space;
  END IF;
  -- Chat A2 Task 5b (DES-009 D4, BZ175): a node already referenced by
  -- chat_message_attachments is an immutable point-in-time chat record — no
  -- new versions via the Drive app (checked before any manifest/quota work).
  -- Meet B2 Task 3 parity: a node referenced by meeting_recordings is an
  -- immutable point-in-time meeting record — same guard, same code.
  IF EXISTS (SELECT 1 FROM chat_message_attachments WHERE file_node_id = p_file_node_id)
     OR EXISTS (SELECT 1 FROM meeting_recordings WHERE file_node_id = p_file_node_id) THEN
    RAISE EXCEPTION 'immutable record via Drive' USING ERRCODE='BZ175',
      HINT='{"type":"forbidden","detail":"chat attachments and meeting recordings are immutable point-in-time records"}';
  END IF;
  IF p_content_sha256 !~ '^[0-9a-f]{64}$' OR p_size IS NULL OR p_size < 0 THEN
    RAISE EXCEPTION 'invalid version arguments' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"bad content_sha256 or size"}';
  END IF;

  -- (a) Resolve + FOR-UPDATE-lock the target ref (P4; AUTOPLAN batch-1 #3
  -- lost-update fix): a branch ref locks its own row, main locks
  -- drive_files. A concurrent same-ref save blocks here until this call
  -- commits, then re-reads the ADVANCED head/branch — no window for two
  -- savers to both see a stale base as "clean" (P1's version only avoided
  -- this by accident, via the quota-charge row lock happening to run first).
  IF p_branch_id IS NOT NULL THEN
    SELECT * INTO v_branch FROM drive_file_branches
     WHERE id = p_branch_id AND file_node_id = p_file_node_id FOR UPDATE;
    IF NOT FOUND OR v_branch.status NOT IN ('open','review') THEN
      RAISE EXCEPTION 'branch not open' USING ERRCODE='BZ150',
        HINT='{"type":"branchError","detail":"branch is not open on this file"}';
    END IF;
    v_ref_head := v_branch.head_version_id;
  ELSE
    SELECT head_version_id INTO v_ref_head FROM drive_files WHERE node_id = p_file_node_id FOR UPDATE;
  END IF;

  -- (b) Lock enforcement, same txn (§5.4, I-12, no TOCTOU). Per-ref match:
  -- NULL branch = main.
  SELECT * INTO v_lock FROM drive_file_locks
   WHERE node_id = p_file_node_id AND user_id <> p_user_id AND expires_at > now()
     AND branch_id IS NOT DISTINCT FROM p_branch_id
   FOR UPDATE;
  IF FOUND THEN
    IF v_lock.mode = 'hard' THEN
      RAISE EXCEPTION 'file checked out by another user' USING ERRCODE='BZ149',
        HINT=json_build_object('type','locked','detail','file is checked out',
                               'holderId', v_lock.user_id)::text;
    END IF;
    v_force_branch := TRUE;   -- soft: allow-but-auto-branch, even from a current base
  END IF;

  -- Idempotency (retry-safe resume, §4.2). AUTOPLAN batch-1 #5: a mirror
  -- retrying a conflicted save re-sends p_branch_id=NULL (it never learned
  -- the auto-branch id) — match the stored conflict-sibling shape too, not
  -- just the exact (branch,base) pair.
  SELECT id INTO v_vid FROM drive_file_versions
   WHERE file_node_id = p_file_node_id AND content_sha256 = p_content_sha256
     AND ((branch_id IS NOT DISTINCT FROM p_branch_id
           AND parent_version_id IS NOT DISTINCT FROM p_base_version_id)
       OR (p_branch_id IS NULL AND conflict_of IS NOT NULL
           AND parent_version_id IS NOT DISTINCT FROM p_base_version_id));
  IF FOUND THEN
    RETURN jsonb_build_object('versionId', v_vid,
      'conflict', (SELECT conflict_of IS NOT NULL FROM drive_file_versions WHERE id = v_vid),
      'branchId', (SELECT branch_id FROM drive_file_versions WHERE id = v_vid),
      'headVersionId', (SELECT head_version_id FROM drive_files WHERE node_id = p_file_node_id),
      'wormPending', false);
  END IF;

  -- Manifest shape (BZ141): array of {sha256,size}; Σsize = p_size; every chunk
  -- exactly 4 MiB except the last; 0-byte file = empty manifest.
  IF p_manifest IS NULL OR jsonb_typeof(p_manifest) <> 'array' THEN
    RAISE EXCEPTION 'manifest must be an array' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"manifest must be an array"}';
  END IF;
  v_n := jsonb_array_length(p_manifest);
  SELECT COALESCE(SUM((c->>'size')::bigint), 0) INTO v_sum FROM jsonb_array_elements(p_manifest) c;
  IF v_sum <> p_size OR (p_size = 0 AND v_n <> 0) THEN
    RAISE EXCEPTION 'manifest sizes disagree with size' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"manifest chunk sizes must sum to size"}';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_manifest) WITH ORDINALITY AS m(c, ord)
              WHERE (c->>'sha256') !~ '^[0-9a-f]{64}$'
                 OR (ord < v_n AND (c->>'size')::bigint <> 4194304)
                 OR (c->>'size')::bigint NOT BETWEEN 1 AND 4194304) THEN
    RAISE EXCEPTION 'bad manifest chunk' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"every chunk must be 4 MiB except the last"}';
  END IF;

  -- Anti-oracle proof (I-4, BZ144): claim by this user in THIS space scope, or
  -- already referenced by a version the exact download capability exposes.
  -- The non-ACL claim branch preserves legacy/bound-space compatibility;
  -- ACL mode requires the target+epoch authorization minted by chunk PUT.
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_manifest) AS m(c)
    WHERE NOT EXISTS (
      SELECT 1 FROM drive_upload_claims uc
       WHERE v_acl_mode<>'acl' AND uc.scope_key=v_scope
         AND uc.sha256=m.c->>'sha256' AND uc.user_id=p_user_id
      UNION ALL
      SELECT 1 FROM drive_upload_authorizations ua
       WHERE v_acl_mode='acl' AND ua.scope_key=v_scope
         AND ua.sha256=m.c->>'sha256' AND ua.user_id=p_user_id
         AND ua.space_id=v_space AND ua.target_node_id=p_file_node_id
         AND ua.acl_epoch=v_acl_epoch AND ua.expires_at>now()
    )
      AND NOT EXISTS (SELECT 1 FROM drive_version_chunks vc
                       JOIN drive_file_versions fv ON fv.id = vc.version_id
                      WHERE vc.scope_key = v_scope AND vc.chunk_sha256 = m.c->>'sha256'
                        AND public.drive_runtime_has_node_capability(
                              p_user_id,fv.file_node_id,'download'))) THEN
    RAISE EXCEPTION 'manifest chunk not proven' USING ERRCODE='BZ144',
      HINT='{"type":"chunkNotProven","detail":"chunk not uploaded by you and not readable by you"}';
  END IF;

  -- Upload-size policy + atomic quota charge (I-14; BZ148 → HTTP 413).
  v_policy := drive_policy_resolve(v_space);
  IF (v_policy->>'upload_max_bytes') IS NOT NULL AND p_size > (v_policy->>'upload_max_bytes')::bigint THEN
    RAISE EXCEPTION 'file exceeds upload limit' USING ERRCODE='BZ148',
      HINT='{"type":"overQuota","detail":"file exceeds the space upload size limit"}';
  END IF;
  IF NOT drive_space_quota_charge(v_space, p_size) THEN
    RAISE EXCEPTION 'space quota exceeded' USING ERRCODE='BZ148',
      HINT='{"type":"overQuota","detail":"space quota exceeded"}';
  END IF;

  -- (c) Conflict decision (ref-agnostic, LR-5): the FOR-UPDATE-locked ref
  -- read in (a) is the truth; a soft-lock holder always forces the branch
  -- path, even from a current base (§5.4).
  v_conflict := v_force_branch OR (p_base_version_id IS DISTINCT FROM v_ref_head);

  INSERT INTO drive_file_versions (file_node_id, space_id, parent_version_id, conflict_of,
                                   branch_id, content_sha256, size_bytes, content_type,
                                   author_user_id, device_label, note)
  VALUES (p_file_node_id, v_space, COALESCE(p_base_version_id, v_ref_head),
          CASE WHEN v_conflict THEN v_ref_head END,
          CASE WHEN v_conflict THEN NULL ELSE p_branch_id END,
          p_content_sha256, p_size, p_content_type, p_user_id, p_device_label, p_note)
  RETURNING id INTO v_vid;

  INSERT INTO drive_version_chunks (version_id, ordinal, scope_key, chunk_sha256)
  SELECT v_vid, (m.ord - 1)::int, v_scope, m.c->>'sha256'
    FROM jsonb_array_elements(p_manifest) WITH ORDINALITY AS m(c, ord);

  IF v_conflict THEN
    -- Auto-branch (P4, §5.2/§5.4): the saver's work is NEVER lost. Forked at
    -- the caller's stated base (or the ref head if base omitted). The
    -- version->branch link is a set-once-from-NULL UPDATE (the WORM carve in
    -- V115 exempts exactly this transition — AUTOPLAN batch-1 #2/batch-3
    -- #2) because the branch row needs v_vid (just minted) as its head
    -- while the version needs the branch's id — the two rows are mutually
    -- dependent and can't be created in one INSERT.
    v_bname := COALESCE(NULLIF(btrim(p_device_label), ''), 'web') || ' ' || to_char(now(), 'YYYY-MM-DD');
    v_candidate := v_bname; v_bn := 1;
    WHILE EXISTS (SELECT 1 FROM drive_file_branches b
                  WHERE b.file_node_id = p_file_node_id AND lower(b.name) = lower(v_candidate)) LOOP
      v_bn := v_bn + 1; v_candidate := v_bname || ' -' || v_bn;      -- G4, case-insensitive (LR-7)
    END LOOP;
    INSERT INTO drive_file_branches (file_node_id, space_id, name, head_version_id,
        forked_from_version_id, auto_created, created_by)
    VALUES (p_file_node_id, v_space, v_candidate, v_vid,
            COALESCE(p_base_version_id, v_ref_head), true, p_user_id)
    RETURNING id INTO v_auto_branch_id;
    UPDATE drive_file_versions SET branch_id = v_auto_branch_id WHERE id = v_vid;
    PERFORM drive_access_audit(p_user_id, v_space, 'branch.create', 'branch', v_auto_branch_id,
      NULL, jsonb_build_object('name', v_candidate, 'fileNodeId', p_file_node_id, 'auto', true),
      NULL, 'auto');
    -- Fan-out (Task 8): best-effort, never unwinds the save.
    BEGIN
      PERFORM drive_notify_event('branch.conflict', p_user_id, v_space, p_file_node_id, v_auto_branch_id);
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
  ELSIF p_branch_id IS NOT NULL THEN
    UPDATE drive_file_branches SET head_version_id = v_vid WHERE id = p_branch_id;
  ELSE
    UPDATE drive_files SET head_version_id = v_vid, size_bytes = p_size,
           content_type = COALESCE(p_content_type, content_type)
     WHERE node_id = p_file_node_id;
  END IF;

  IF v_class = 'gxp' THEN   -- retain_until bookkeeping now; Object-Lock call is P5 (R5)
    PERFORM drive_chunks_extend_retention(v_scope,
      ARRAY(SELECT c->>'sha256' FROM jsonb_array_elements(p_manifest) c),
      now() + make_interval(days => v_ret));
  END IF;

  DELETE FROM drive_upload_claims
   WHERE user_id = p_user_id AND scope_key = v_scope
     AND sha256 IN (SELECT c->>'sha256' FROM jsonb_array_elements(p_manifest) c);
  DELETE FROM drive_upload_authorizations
   WHERE user_id=p_user_id AND space_id=v_space AND target_node_id=p_file_node_id
     AND scope_key=v_scope
     AND sha256 IN (SELECT c->>'sha256' FROM jsonb_array_elements(p_manifest) c);

  PERFORM drive_access_audit(p_user_id, v_space, 'version.create', 'version', v_vid, NULL,
    jsonb_build_object('fileNodeId', p_file_node_id, 'sha256', p_content_sha256,
                       'size', p_size, 'conflict', v_conflict,
                       'branchId', CASE WHEN v_conflict THEN v_auto_branch_id ELSE p_branch_id END),
    NULL, NULL);
  PERFORM drive_notify_change(v_space, p_file_node_id,
    CASE WHEN p_branch_id IS NULL AND v_ref_head IS NULL THEN 'create' ELSE 'update' END);

  RETURN jsonb_build_object('versionId', v_vid, 'conflict', v_conflict,
    'branchId', CASE WHEN v_conflict THEN v_auto_branch_id ELSE p_branch_id END,
    'headVersionId', (SELECT head_version_id FROM drive_files WHERE node_id = p_file_node_id),
    'wormPending', false);
END;
$$ LANGUAGE plpgsql;
