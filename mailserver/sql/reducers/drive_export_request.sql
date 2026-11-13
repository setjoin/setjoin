-- mailserver/sql/reducers/drive_export_request.sql
-- drive_export_request: request a download/print of a version (spec §6.4, §9.2).
-- Policy 'allow' → mint a single-use grant NOW (expires_at = now()+ttl).
-- Policy 'approval' (ALWAYS on gxp — hard floor, skip policies ignored) → route
-- through the engine seam; the grant is minted by drive_export_approval_decide
-- at DECIDE time (G2). WORM-pending version → BZ145 (G1: export blocked while
-- pending). All failure modes for bad version/membership are BZ139 (no oracle).
--
-- Deliberately diverges from hr_request_create's "no policy matched → RETURN
-- NULL (skip, no request)" shape: gxp export/print is a hard compliance floor
-- (drive_policy_resolve always resolves 'approval' for gxp), so a caller here
-- must NEVER see a bypass. When approval_match_policies finds nothing (or only
-- skip policies), we do NOT return/skip like hr — we re-resolve a fail-closed
-- default approver (requester's manager) and still create a pending request.
CREATE OR REPLACE FUNCTION drive_export_request(
  p_user_id     bigint,
  p_version_id  bigint,
  p_action      text,
  p_token_hash  text,
  p_ttl_minutes int DEFAULT 60
) RETURNS jsonb AS $$
DECLARE
  v_space     drive_spaces%ROWTYPE;
  v_policy    jsonb;
  v_mode      text;
  v_match     record;
  v_resolved  record;
  v_grant_id  bigint;
  v_req_id    bigint;
BEGIN
  IF p_action NOT IN ('download','print') THEN
    RAISE EXCEPTION 'invalid export action' USING ERRCODE = 'BZ141',
      HINT = '{"type":"invalidArguments","detail":"action must be download or print"}';
  END IF;
  IF p_token_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid token hash' USING ERRCODE = 'BZ141',
      HINT = '{"type":"invalidArguments","detail":"token_hash must be a sha256 hex digest"}';
  END IF;
  IF p_ttl_minutes IS NULL OR p_ttl_minutes NOT BETWEEN 1 AND 10080 THEN
    RAISE EXCEPTION 'invalid ttl' USING ERRCODE = 'BZ141',
      HINT = '{"type":"invalidArguments","detail":"ttl_minutes must be 1..10080"}';
  END IF;

  -- R1: version + space resolved THROUGH the caller's membership in one statement.
  SELECT s.* INTO v_space
    FROM drive_file_versions v
    JOIN drive_spaces s ON s.id = v.space_id
   WHERE v.id = p_version_id
     AND public.drive_runtime_has_node_capability(
       p_user_id,v.file_node_id,'download');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'not found' USING ERRCODE = 'BZ139',
      HINT = '{"type":"notFound","detail":"version not found"}';
  END IF;

  -- G1: export blocked while any of THIS version's chunks awaits its object lock.
  IF v_space.classification = 'gxp' AND EXISTS (
       SELECT 1 FROM drive_version_chunks vc
         JOIN drive_chunks c ON (c.scope_key, c.sha256) = (vc.scope_key, vc.chunk_sha256)
        WHERE vc.version_id = p_version_id AND vc.stream = 'content'
          AND c.worm_pending) THEN
    RAISE EXCEPTION 'version WORM lock pending' USING ERRCODE = 'BZ145',
      HINT = '{"type":"immutable","detail":"export blocked until the retention lock is applied"}';
  END IF;

  v_policy := drive_policy_resolve(v_space.id);
  v_mode := CASE p_action WHEN 'download' THEN v_policy->>'export' ELSE v_policy->>'print' END;

  IF v_mode = 'allow' AND v_space.classification <> 'gxp' THEN
    INSERT INTO drive_export_grants (version_id, space_id, grantee, action, token_hash, minted_by, expires_at)
    VALUES (p_version_id, v_space.id, p_user_id, p_action, p_token_hash, p_user_id,
            now() + (p_ttl_minutes || ' minutes')::interval)
    RETURNING id INTO v_grant_id;
    PERFORM drive_access_audit(p_user_id, v_space.id, 'export.request', 'version', p_version_id,
                               NULL, jsonb_build_object('action', p_action, 'granted', true), NULL, NULL);
    RETURN jsonb_build_object('status', 'granted', 'grantId', v_grant_id);
  END IF;

  -- Approval path (gxp always lands here — §9.2 hard-codes export/print 'approval').
  SELECT * INTO v_match FROM approval_match_policies('drive.export',
    jsonb_build_object('classification', v_space.classification,
                       'action', p_action, 'space_id', v_space.id));
  IF v_match.required THEN
    SELECT * INTO v_resolved FROM approval_resolve_approver(p_user_id, v_match.approver_spec);
  ELSE
    -- Fail-closed: no policy (or only skip policies) may NEVER open a gxp export.
    -- Resolve the requester's manager chain / default approver instead (I-7).
    SELECT * INTO v_resolved FROM approval_resolve_approver(p_user_id, '{"kind":"manager"}'::jsonb);
  END IF;
  -- approval_resolve_approver is fail-closed (never raises; falls back to
  -- approval.default_approver_user_id). A 'skip' terminal is ignored on gxp by
  -- the same fail-closed manager re-resolution:
  IF v_resolved.skip THEN
    SELECT * INTO v_resolved FROM approval_resolve_approver(p_user_id, '{"kind":"manager"}'::jsonb);
  END IF;

  v_req_id := approval_request_create(
    'drive.export', p_user_id,
    format('Drive export: version %s (%s)', p_version_id, p_action),
    jsonb_build_object('version_id', p_version_id, 'action', p_action,
                       'space_id', v_space.id, 'token_hash', p_token_hash,
                       'ttl_minutes', p_ttl_minutes),
    v_match.winner_policy_id, v_resolved.kind, v_resolved.ref,
    coalesce((SELECT (value)::int FROM system_config WHERE key = 'approval.request_ttl_minutes'), 2880));

  PERFORM drive_access_audit(p_user_id, v_space.id, 'export.request', 'version', p_version_id,
                             NULL, jsonb_build_object('action', p_action, 'granted', false,
                                                      'request_id', v_req_id), NULL, NULL);
  RETURN jsonb_build_object('status', 'pending', 'requestId', v_req_id);
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
