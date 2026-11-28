-- Guest G1 approval consumer. Member request creation is deliberately separate
-- from token minting: approval payloads contain only review evidence, never a
-- credential. Both functions are worker-owned because approval policies and
-- guest-account provisioning cross FORCE-RLS system tables.
CREATE OR REPLACE FUNCTION guest_invite_request_create(
  p_requester bigint,
  p_email     text,
  p_message   text DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  v_email       text := lower(btrim(coalesce(p_email, '')));
  v_message     text := nullif(btrim(coalesce(p_message, '')), '');
  v_domain      text;
  v_host_domain bigint;
  v_requester_name text;
  v_match       record;
  v_resolved    record;
  v_ttl         int;
  v_id          bigint;
BEGIN
  IF v_email !~ '^[^@[:space:]]+@[a-z0-9][a-z0-9.-]*[.][a-z]{2,}$'
     OR length(v_email) > 254 OR v_email LIKE '%..%' THEN
    RAISE EXCEPTION 'invalid guest invite email'
      USING ERRCODE='BZ222', HINT='{"type":"invalid_arguments","field":"email"}';
  END IF;
  IF v_message IS NOT NULL AND length(v_message) > 2000 THEN
    RAISE EXCEPTION 'guest invite message exceeds 2000 characters'
      USING ERRCODE='BZ222', HINT='{"type":"invalid_arguments","field":"message"}';
  END IF;

  SELECT u.domain_id, coalesce(nullif(u.display_name,''),u.email)
    INTO v_host_domain, v_requester_name
    FROM users u
   WHERE u.id=p_requester AND u.enabled AND NOT is_guest_account(u.id);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'guest invite requester not found'
      USING ERRCODE='BZ001', HINT='{"type":"not_found"}';
  END IF;

  IF EXISTS (SELECT 1 FROM users u WHERE lower(u.email)=v_email
              AND NOT is_guest_account(u.id)) THEN
    RAISE EXCEPTION 'email belongs to an existing member account'
      USING ERRCODE='BZ221', HINT='{"type":"conflict","detail":"email belongs to an existing member account"}';
  END IF;

  v_domain := split_part(v_email,'@',2);
  IF EXISTS (SELECT 1 FROM guest_invite_domains)
     AND NOT EXISTS (SELECT 1 FROM guest_invite_domains WHERE domain=v_domain) THEN
    RAISE EXCEPTION 'invited domain is not in the guest invite allowlist'
      USING ERRCODE='BZ218', HINT='{"type":"forbidden"}';
  END IF;

  SELECT * INTO v_match
    FROM approval_match_policies('guest.invite',
      jsonb_build_object('host_domain_id',v_host_domain,'invited_domain',v_domain));
  IF NOT v_match.required THEN
    RETURN NULL;
  END IF;

  SELECT * INTO v_resolved
    FROM approval_resolve_approver(p_requester,v_match.approver_spec);
  IF v_resolved.skip THEN
    PERFORM audit_write(p_requester,'approval_skipped','approval_request',NULL,NULL,
      jsonb_build_object('consumer_type','guest.invite','invited_email',v_email),NULL,NULL,'core');
    RETURN NULL;
  END IF;

  v_ttl := coalesce((SELECT (value)::int FROM system_config
                      WHERE key='approval.request_ttl_minutes'),2880);
  v_id := approval_request_create(
    'guest.invite',p_requester,'Invite guest ' || v_email,
    jsonb_strip_nulls(jsonb_build_object(
      'invited_email',v_email,'requester_name',v_requester_name,'message',v_message)),
    v_match.winner_policy_id,v_resolved.kind,v_resolved.ref,v_ttl,v_host_domain);
  RETURN v_id;
END;
$$;
SELECT apply_worker_ownership('guest_invite_request_create(bigint,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION guest_invite_approval_decide(
  p_request_id bigint,
  p_actor      bigint,
  p_decision   text,
  p_comment    text
) RETURNS TABLE(status text, guest_user_id bigint, invited_email text, requester_user_id bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  v_status    text;
  v_consumer  text;
  v_payload   jsonb;
  v_provision jsonb;
  v_domain    text;
BEGIN
  v_status := approval_decide(p_request_id,p_actor,p_decision,p_comment);
  SELECT ar.consumer_type,ar.payload,ar.requester_user_id
    INTO v_consumer,v_payload,requester_user_id
    FROM approval_requests ar WHERE ar.id=p_request_id;
  IF v_consumer IS DISTINCT FROM 'guest.invite' THEN
    RAISE EXCEPTION 'approval is not a guest invite request'
      USING ERRCODE='BZ108', HINT='{"type":"conflict"}';
  END IF;

  IF v_status <> 'approved' THEN
    status := v_status;
    guest_user_id := NULL;
    invited_email := NULL;
    requester_user_id := NULL;
    RETURN NEXT;
    RETURN;
  END IF;

  -- Approval is not authority to bypass a later safety/toggle change. Any
  -- failure below rolls approval_decide back, leaving the request pending.
  IF NOT coalesce((SELECT enabled FROM feature_toggles
                    WHERE key='feature.guest_accounts'),FALSE) THEN
    RAISE EXCEPTION 'guest accounts are unavailable'
      USING ERRCODE='BZ223', HINT='{"type":"forbidden"}';
  END IF;

  invited_email := lower(v_payload->>'invited_email');
  v_domain := split_part(invited_email,'@',2);
  IF EXISTS (SELECT 1 FROM guest_invite_domains)
     AND NOT EXISTS (SELECT 1 FROM guest_invite_domains WHERE domain=v_domain) THEN
    RAISE EXCEPTION 'invited domain is not in the guest invite allowlist'
      USING ERRCODE='BZ218', HINT='{"type":"forbidden"}';
  END IF;

  v_provision := provision_account(
    p_email=>invited_email,
    p_display_name=>invited_email,
    p_guest=>TRUE,
    p_invited_by=>requester_user_id);
  guest_user_id := (v_provision->>'user_id')::bigint;

  UPDATE approval_requests SET status='applied' WHERE id=p_request_id;
  PERFORM audit_write(p_actor,'approval_applied','approval_request',p_request_id,NULL,
    jsonb_build_object('consumer_type','guest.invite','requester',requester_user_id,
                       'guest_user_id',guest_user_id,'invited_email',invited_email),
    NULL,p_comment,'core');
  status := 'applied';
  RETURN NEXT;
END;
$$;
SELECT apply_worker_ownership('guest_invite_approval_decide(bigint,bigint,text,text)'::regprocedure);
