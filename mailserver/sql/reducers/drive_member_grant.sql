-- mailserver/sql/reducers/drive_member_grant.sql
--       approval_match_policies, approval_resolve_approver, approval_request_create
-- Manager-only (no drive.manage admin bypass — matches the V114 §C
-- drive_space_members_write policy, which has no admin arm either).
-- Upserts the roster row (re-grant = role change in place) on the direct
-- path. When the resolved policy routes share through approval (always on
-- gxp — §9.2 hard floor; optionally on secure via export_policy.share), P5
-- routes through the engine seam exactly like drive_export_request: no
-- policy (or only skip policies) fails CLOSED to the requester's manager,
-- never a direct grant. The actual member row is applied by
-- drive_share_approval_decide at decide time.
CREATE OR REPLACE FUNCTION drive_member_grant(
  p_user_id BIGINT, p_space_id BIGINT, p_grantee BIGINT, p_role TEXT
) RETURNS JSONB AS $$
DECLARE
  v_role     TEXT;
  v_space    drive_spaces%ROWTYPE;
  v_match    record;
  v_resolved record;
  v_req_id   bigint;
  v_bump     record;
BEGIN
  IF NOT public.drive_user_has_space_access(p_user_id,p_space_id) THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF NOT public.drive_runtime_has_space_root_capability(
       p_user_id,p_space_id,'manage_acl') THEN
    RAISE EXCEPTION 'manager role required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"manager role required"}';
  END IF;
  IF p_role NOT IN ('manager','editor','viewer') THEN
    RAISE EXCEPTION 'invalid role' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"role must be manager|editor|viewer"}';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_grantee) THEN
    RAISE EXCEPTION 'grantee not found' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"grantee does not exist"}';
  END IF;

  -- Guest door (guest-accounts G0, codex C-3): no explicit Drive grant may
  -- name a guest. Guest Drive reach is derived live from chat/meeting scope;
  -- G4 added preview/download tiers without opening ad-hoc grants. Fires before the
  -- approval routing; drive_share_approval_decide therefore never sees a
  -- guest grantee (and BZ221 forbids member->guest conversion in flight, so
  -- a pending request cannot MUTATE into one — the decide-time belt is
  -- deliberately omitted).
  IF is_guest_account(p_grantee) THEN
    RAISE EXCEPTION 'guest accounts cannot be granted drive space membership'
      USING ERRCODE='BZ215', HINT='{"type":"forbidden","detail":"guest accounts cannot receive direct Drive grants"}';
  END IF;

  SELECT * INTO v_space FROM drive_spaces WHERE id = p_space_id;

  -- BZ175 belt (DES-009 D2, meeting-space parity Meet B2): chat-bound and
  -- meeting-bound spaces derive membership from chat_channel_members /
  -- meeting_participants; ad-hoc drive_space_members grants are blocked at
  -- RLS (drive_space_members_write WITH CHECK, V120/V129) — this
  -- reducer-level check is defense in depth for any caller on a connection
  -- RLS doesn't constrain (e.g. a BYPASSRLS worker-pool connection).
  IF v_space.chat_channel_id IS NOT NULL OR v_space.meeting_id IS NOT NULL THEN
    RAISE EXCEPTION 'bound space rejects ad-hoc member grants' USING ERRCODE='BZ175',
      HINT='{"type":"forbidden","detail":"space membership is derived (chat channel / meeting attendance)"}';
  END IF;

  -- G1: share blocked while the space has WORM locks pending.
  IF v_space.classification = 'gxp' AND EXISTS (
       SELECT 1 FROM drive_chunks c
        WHERE c.scope_key = 's' || v_space.id
          AND c.worm_pending) THEN
    RAISE EXCEPTION 'space WORM locks pending' USING ERRCODE='BZ145',
      HINT='{"type":"immutable","detail":"share blocked until the retention lock is applied"}';
  END IF;

  IF drive_policy_resolve(p_space_id)->>'share' = 'approval' THEN
    SELECT * INTO v_match FROM approval_match_policies('drive.share',
      jsonb_build_object('classification', v_space.classification, 'space_id', v_space.id));
    IF v_match.required THEN
      SELECT * INTO v_resolved FROM approval_resolve_approver(p_user_id, v_match.approver_spec);
    ELSE
      -- Fail-closed: no policy (or only skip policies) may NEVER share directly.
      SELECT * INTO v_resolved FROM approval_resolve_approver(p_user_id, '{"kind":"manager"}'::jsonb);
    END IF;
    IF v_resolved.skip THEN
      SELECT * INTO v_resolved FROM approval_resolve_approver(p_user_id, '{"kind":"manager"}'::jsonb);
    END IF;

    v_req_id := approval_request_create(
      'drive.share', p_user_id,
      format('Drive share: space %s -> user %s (%s)', p_space_id, p_grantee, p_role),
      jsonb_build_object('space_id', p_space_id, 'grantee', p_grantee, 'role', p_role),
      v_match.winner_policy_id, v_resolved.kind, v_resolved.ref,
      coalesce((SELECT (value)::int FROM system_config WHERE key = 'approval.request_ttl_minutes'), 2880));

    PERFORM drive_access_audit(p_user_id, p_space_id, 'share.requested', 'member', p_grantee, NULL,
      jsonb_build_object('userId', p_grantee, 'role', p_role, 'requestId', v_req_id), NULL, NULL);
    RETURN jsonb_build_object('status', 'pending', 'requestId', v_req_id);
  END IF;

  PERFORM public.drive_tree_lock(p_space_id);
  PERFORM public.drive_require_space_root_mutation_capability(
    p_user_id,p_space_id,'manage_acl');

  INSERT INTO drive_space_members (space_id, user_id, role, granted_by)
  VALUES (p_space_id, p_grantee, p_role, p_user_id)
  ON CONFLICT (space_id, user_id) DO UPDATE SET role = EXCLUDED.role, granted_by = EXCLUDED.granted_by;

  PERFORM drive_access_audit(p_user_id, p_space_id, 'member.grant', 'member', p_grantee, NULL,
    jsonb_build_object('userId', p_grantee, 'role', p_role), NULL, NULL);
  IF v_space.acl_mode='acl' THEN
    SELECT * INTO v_bump FROM public.drive_acl_bump(
      p_space_id,'user',p_grantee,NULL,'member_grant');
  END IF;
  PERFORM drive_notify_change(p_space_id, 0, 'member');
  RETURN jsonb_build_object('status', 'granted');
END;
$$ LANGUAGE plpgsql;
