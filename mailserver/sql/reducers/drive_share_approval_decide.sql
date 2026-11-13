-- mailserver/sql/reducers/drive_share_approval_decide.sql
-- drive.share consumer decide wrapper. SECURITY DEFINER, owned by
-- setjoin_worker (BYPASSRLS) via the V115-genre DO block footer (AUTOPLAN
-- batch-2 #1, BLOCKER — the exact drive_folder_member_grant posture): the
-- approver is usually not a member of the space being shared, so the member
-- INSERT below fails drive_space_members_write's WITH CHECK (manager-of-THIS-
-- space OR self) under an un-escalated run. Authorization is entirely
-- approval_decide's SoD/approver-auth (BZ106/107/108); every statement is
-- scoped by the request row's own payload.
-- Apply = upsert the member row from the payload {space_id, grantee, role}.
CREATE OR REPLACE FUNCTION drive_share_approval_decide(
  p_request_id bigint,
  p_actor      bigint,
  p_decision   text,
  p_comment    text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status text;
  v_req    record;
  v_space_id bigint;
  v_grantee bigint;
  v_acl_mode text;
  v_bump record;
BEGIN
  v_status := approval_decide(p_request_id, p_actor, p_decision, p_comment);

  SELECT requester_user_id, payload INTO v_req
    FROM approval_requests WHERE id = p_request_id;

  IF v_status = 'approved' THEN
    IF (v_req.payload->>'role') NOT IN ('manager','editor','viewer') THEN
      RAISE EXCEPTION 'invalid role in payload' USING ERRCODE = 'BZ141',
        HINT = '{"type":"invalidArguments","detail":"role must be manager|editor|viewer"}';
    END IF;
    v_space_id:=(v_req.payload->>'space_id')::bigint;
    v_grantee:=(v_req.payload->>'grantee')::bigint;
    SELECT acl_mode INTO v_acl_mode FROM public.drive_spaces WHERE id=v_space_id;
    PERFORM public.drive_tree_lock(v_space_id);
    INSERT INTO drive_space_members (space_id, user_id, role, granted_by)
    VALUES (v_space_id, v_grantee,
            v_req.payload->>'role', v_req.requester_user_id)
    ON CONFLICT (space_id, user_id) DO UPDATE SET role = EXCLUDED.role;

    IF v_acl_mode='acl' THEN
      SELECT * INTO v_bump FROM public.drive_acl_bump(
        v_space_id,'user',v_grantee,NULL,'member_grant');
    END IF;

    UPDATE approval_requests SET status = 'applied' WHERE id = p_request_id;
    PERFORM drive_access_audit(p_actor, v_space_id, 'share.approved',
                               'user', v_grantee,
                               NULL, jsonb_build_object('role', v_req.payload->>'role',
                                                        'request_id', p_request_id),
                               NULL, p_comment);
    PERFORM drive_notify_change(v_space_id, 0, 'member');
    RETURN 'applied';
  END IF;

  PERFORM drive_access_audit(p_actor, (v_req.payload->>'space_id')::bigint, 'share.denied',
                             'user', (v_req.payload->>'grantee')::bigint,
                             NULL, jsonb_build_object('request_id', p_request_id), NULL, p_comment);
  RETURN v_status;
END;
$$;

SELECT apply_worker_ownership('drive_share_approval_decide(BIGINT, BIGINT, TEXT, TEXT)'::regprocedure);
