-- mailserver/sql/reducers/drive_export_approval_decide.sql
-- drive.export consumer decide wrapper (the hr_approval_decide shape, escalated
-- to the drive_folder_member_grant posture — AUTOPLAN batch-2 #1, BLOCKER):
-- SECURITY DEFINER, owned by setjoin_worker (BYPASSRLS) via the V115-genre DO
-- block footer below. The approver is virtually never a space member, so an
-- INVOKER-rights run would fail: drive_export_grants' INSERT is fine (minted_by
-- = the approver = current user), but nothing here relies on approver
-- membership to be correct — the footer exists because setjoin_owner (the
-- migration-loading role) is NOBYPASSRLS and FORCE binds owners too (P1 Locked
-- resolution R1), so a DEFINER function left un-ALTER'd runs under whatever
-- role loaded it, not a BYPASSRLS identity. Authorization is entirely
-- approval_decide's SoD/approver-auth (BZ106/107/108); every statement below
-- is scoped by the request row's OWN payload — nothing here reads a
-- caller-supplied id beyond p_request_id/p_actor, both bound by approval_decide.
-- G2: expires_at = now() (DECIDE time) + payload ttl_minutes — a request aged
-- past its original TTL still yields a live grant on approval.
CREATE OR REPLACE FUNCTION drive_export_approval_decide(
  p_request_id bigint,
  p_actor      bigint,
  p_decision   text,
  p_comment    text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_status text;
  v_req    record;
BEGIN
  v_status := approval_decide(p_request_id, p_actor, p_decision, p_comment);

  SELECT requester_user_id, payload INTO v_req
    FROM approval_requests WHERE id = p_request_id;

  IF v_status = 'approved' THEN
    INSERT INTO drive_export_grants
      (version_id, space_id, grantee, action, token_hash, approval_id, minted_by, expires_at)
    VALUES ((v_req.payload->>'version_id')::bigint,
            (v_req.payload->>'space_id')::bigint,
            v_req.requester_user_id,
            v_req.payload->>'action',
            v_req.payload->>'token_hash',
            p_request_id,
            p_actor,
            now() + ((v_req.payload->>'ttl_minutes')::int || ' minutes')::interval);  -- G2

    UPDATE approval_requests SET status = 'applied' WHERE id = p_request_id;
    PERFORM drive_access_audit(p_actor, (v_req.payload->>'space_id')::bigint, 'export.approve',
                               'version', (v_req.payload->>'version_id')::bigint,
                               NULL, jsonb_build_object('request_id', p_request_id,
                                                        'action', v_req.payload->>'action'),
                               NULL, p_comment);
    RETURN 'applied';
  END IF;

  PERFORM drive_access_audit(p_actor, (v_req.payload->>'space_id')::bigint, 'export.deny',
                             'version', (v_req.payload->>'version_id')::bigint,
                             NULL, jsonb_build_object('request_id', p_request_id), NULL, p_comment);
  RETURN v_status;
END;
$$;

SELECT apply_worker_ownership('drive_export_approval_decide(BIGINT, BIGINT, TEXT, TEXT)'::regprocedure);
