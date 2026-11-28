-- drive_access_governance.sql -- A5 consumer of the existing approval engine.

CREATE OR REPLACE FUNCTION drive_access_propagation_rank(p_value text)
RETURNS integer LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path=pg_catalog,public AS $$
  SELECT CASE p_value WHEN 'self' THEN 1 WHEN 'children' THEN 2
                      WHEN 'subtree' THEN 3 END
$$;
SELECT apply_worker_ownership('drive_access_propagation_rank(text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_request_policy_set(
  p_actor_user_id bigint,p_id bigint,p_approval_policy_id bigint,
  p_space_id bigint,p_anchor_node_id bigint,p_subject_kind text,
  p_capabilities text[],p_max_propagation text,p_max_duration_minutes integer,
  p_max_uses integer,p_emergency_allowed boolean,p_enabled boolean
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_id bigint;
BEGIN
  IF NOT public.drive_has_admin_perm(p_actor_user_id,'drive.manage') THEN
    RAISE EXCEPTION 'Drive access policy management forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  IF p_subject_kind NOT IN ('user','group','any')
     OR NOT public.drive_acl_capabilities_valid(p_capabilities)
     OR public.drive_access_propagation_rank(p_max_propagation) IS NULL
     OR p_max_duration_minutes NOT BETWEEN 1 AND 525600
     OR (p_max_uses IS NOT NULL AND p_max_uses NOT BETWEEN 1 AND 1000000)
     OR NOT EXISTS(SELECT 1 FROM public.drive_spaces WHERE id=p_space_id)
     OR (p_anchor_node_id IS NOT NULL AND NOT EXISTS(
       SELECT 1 FROM public.drive_nodes WHERE id=p_anchor_node_id AND space_id=p_space_id
     )) THEN
    RAISE EXCEPTION 'invalid Drive access request policy'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid"}';
  END IF;
  IF p_id IS NULL THEN
    INSERT INTO public.drive_access_request_policies(
      approval_policy_id,space_id,anchor_node_id,subject_kind,capabilities,
      max_propagation,max_duration_minutes,max_uses,emergency_allowed,
      enabled,created_by
    ) VALUES(p_approval_policy_id,p_space_id,p_anchor_node_id,p_subject_kind,
      p_capabilities,p_max_propagation,p_max_duration_minutes,p_max_uses,
      p_emergency_allowed,p_enabled,p_actor_user_id) RETURNING id INTO v_id;
  ELSE
    UPDATE public.drive_access_request_policies SET
      approval_policy_id=p_approval_policy_id,space_id=p_space_id,
      anchor_node_id=p_anchor_node_id,subject_kind=p_subject_kind,
      capabilities=p_capabilities,max_propagation=p_max_propagation,
      max_duration_minutes=p_max_duration_minutes,max_uses=p_max_uses,
      emergency_allowed=p_emergency_allowed,enabled=p_enabled,
      updated_at=clock_timestamp()
     WHERE id=p_id RETURNING id INTO v_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Drive access request policy not found'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"policyId"}';
    END IF;
  END IF;
  PERFORM public.drive_access_audit(p_actor_user_id,p_space_id,'policy.change',
    'drive_access_policy',v_id,NULL,jsonb_build_object(
      'anchorNodeId',CASE WHEN p_anchor_node_id IS NULL THEN NULL ELSE p_anchor_node_id::text END,
      'subjectKind',p_subject_kind,'maxPropagation',p_max_propagation,
      'maxDurationMinutes',p_max_duration_minutes,'emergencyAllowed',p_emergency_allowed,
      'enabled',p_enabled),NULL,NULL);
  RETURN v_id;
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_request_policy_set(bigint,bigint,bigint,bigint,bigint,text,text[],text,integer,integer,boolean,boolean)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_request_preview(
  p_actor_user_id bigint,p_node_id bigint,p_subject_kind text,p_subject_id bigint,
  p_capabilities text[],p_propagation text,p_duration_minutes integer,
  p_max_uses integer,p_emergency boolean,p_mfa_session_id text,p_reason text
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_space drive_spaces%ROWTYPE; v_policy record; v_context jsonb;
  v_subject_user bigint; v_subject_group bigint; v_epoch bigint;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM public.feature_toggles
                    WHERE key='feature.drive_access_governance'),false)
     OR NOT public.drive_acl_capabilities_valid(p_capabilities)
     OR public.drive_access_propagation_rank(p_propagation) IS NULL
     OR p_duration_minutes NOT BETWEEN 1 AND 525600
     OR (p_max_uses IS NOT NULL AND p_max_uses NOT BETWEEN 1 AND 1000000)
     OR p_reason IS NULL OR p_reason<>btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 8 AND 1000 THEN
    RETURN jsonb_build_object('requestable',false);
  END IF;
  SELECT s.* INTO v_space FROM public.drive_nodes n
    JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_node_id AND n.purged_at IS NULL AND s.acl_mode='acl'
     AND s.chat_channel_id IS NULL AND s.meeting_id IS NULL;
  IF NOT FOUND OR NOT (
      public.drive_runtime_has_node_capability(p_actor_user_id,p_node_id,'traverse')
      OR public.drive_runtime_has_node_capability(p_actor_user_id,p_node_id,'read_metadata')
    ) THEN
    RETURN jsonb_build_object('requestable',false);
  END IF;
  IF p_subject_kind='user' AND p_subject_id=p_actor_user_id
     AND EXISTS(SELECT 1 FROM public.users WHERE id=p_subject_id AND enabled) THEN
    v_subject_user:=p_subject_id;
  ELSIF p_subject_kind='group'
     AND public.directory_group_effective_member(p_actor_user_id,p_subject_id) THEN
    v_subject_group:=p_subject_id;
  ELSE
    RETURN jsonb_build_object('requestable',false);
  END IF;
  IF NOT EXISTS(SELECT 1 FROM unnest(p_capabilities) c
    WHERE NOT public.drive_runtime_has_node_capability(p_actor_user_id,p_node_id,c)) THEN
    RETURN jsonb_build_object('requestable',false,'alreadyAllowed',true);
  END IF;
  IF p_emergency THEN
    IF NOT COALESCE((SELECT enabled FROM public.feature_toggles
                      WHERE key='feature.drive_emergency_access'),false)
       OR p_subject_kind<>'user' OR p_duration_minutes>60
       OR NOT (p_capabilities <@ ARRAY[
         'traverse','list_children','read_metadata','preview','download'
       ]::text[])
       OR NOT EXISTS(
         SELECT 1 FROM public.sessions s
          WHERE s.id=p_mfa_session_id AND s.user_id=p_actor_user_id
            AND s.auth_method IN ('webauthn','totp','push','certificate')
            AND s.created_at>=now()-interval '5 minutes' AND s.expires_at>now()
       ) THEN
      RETURN jsonb_build_object('requestable',false,'freshMfaRequired',true);
    END IF;
  END IF;
  v_context:=jsonb_build_object('classification',v_space.classification,
    'space_id',v_space.id,'subject_kind',p_subject_kind,
    'emergency',p_emergency,'capabilities',to_jsonb(p_capabilities));
  SELECT rp.*,ap.approver_spec,ap.conditions INTO v_policy
    FROM public.drive_access_request_policies rp
    JOIN public.approval_policies ap ON ap.id=rp.approval_policy_id
    LEFT JOIN public.drive_node_closure c
      ON c.space_id=rp.space_id AND c.ancestor_id=rp.anchor_node_id
     AND c.descendant_id=p_node_id
   WHERE rp.space_id=v_space.id AND rp.enabled AND ap.enabled
     AND ap.consumer_type='drive.access' AND ap.requires_approval
     AND (rp.anchor_node_id IS NULL OR c.descendant_id IS NOT NULL)
     AND rp.subject_kind IN ('any',p_subject_kind)
     AND p_capabilities<@rp.capabilities
     AND public.drive_access_propagation_rank(p_propagation)
         <=public.drive_access_propagation_rank(rp.max_propagation)
     AND p_duration_minutes<=rp.max_duration_minutes
     AND (rp.max_uses IS NULL OR (p_max_uses IS NOT NULL AND p_max_uses<=rp.max_uses))
     AND (NOT p_emergency OR rp.emergency_allowed)
     AND NOT EXISTS(SELECT 1 FROM jsonb_each(ap.conditions) cond
       WHERE v_context->cond.key IS DISTINCT FROM cond.value)
   ORDER BY c.depth ASC NULLS LAST,rp.id ASC LIMIT 1;
  IF NOT FOUND THEN RETURN jsonb_build_object('requestable',false); END IF;
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=v_space.id;
  RETURN jsonb_build_object('requestable',true,'policyId',v_policy.id::text,
    'approvalPolicyId',v_policy.approval_policy_id::text,
    'spaceId',v_space.id::text,'nodeId',p_node_id::text,
    'subjectKind',p_subject_kind,
    'subjectUserId',CASE WHEN v_subject_user IS NULL THEN NULL ELSE v_subject_user::text END,
    'subjectGroupId',CASE WHEN v_subject_group IS NULL THEN NULL ELSE v_subject_group::text END,
    'capabilities',to_jsonb(p_capabilities),'propagation',p_propagation,
    'expiresAt',now()+make_interval(mins=>p_duration_minutes),
    'maxUses',p_max_uses,'emergency',p_emergency,'epoch',v_epoch::text,
    'approverSpec',v_policy.approver_spec);
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_request_preview(bigint,bigint,text,bigint,text[],text,integer,integer,boolean,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_request(
  p_actor_user_id bigint,p_node_id bigint,p_subject_kind text,p_subject_id bigint,
  p_capabilities text[],p_propagation text,p_duration_minutes integer,
  p_max_uses integer,p_emergency boolean,p_mfa_session_id text,p_reason text,
  p_idempotency_key text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_preview jsonb; v_resolved record; v_request_id bigint; v_digest text;
  v_existing record; v_ttl integer;
BEGIN
  IF p_idempotency_key IS NULL OR p_idempotency_key<>btrim(p_idempotency_key)
     OR octet_length(p_idempotency_key) NOT BETWEEN 8 AND 200 THEN
    RAISE EXCEPTION 'invalid Drive access request idempotency key'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"idempotencyKey"}';
  END IF;
  v_preview:=public.drive_access_request_preview(
    p_actor_user_id,p_node_id,p_subject_kind,p_subject_id,p_capabilities,
    p_propagation,p_duration_minutes,p_max_uses,p_emergency,p_mfa_session_id,p_reason);
  IF NOT COALESCE((v_preview->>'requestable')::boolean,false) THEN
    RAISE EXCEPTION 'Drive access is not requestable'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden","requestable":false}';
  END IF;
  v_digest:=encode(digest(jsonb_build_object(
    'nodeId',p_node_id::text,'subjectKind',p_subject_kind,'subjectId',p_subject_id::text,
    'capabilities',p_capabilities,'propagation',p_propagation,
    'durationMinutes',p_duration_minutes,'maxUses',p_max_uses,
    'emergency',p_emergency,'reason',p_reason)::text,'sha256'),'hex');
  SELECT d.request_id,d.request_digest,r.status INTO v_existing
    FROM public.drive_access_request_details d
    JOIN public.approval_requests r ON r.id=d.request_id
   WHERE d.requester_user_id=p_actor_user_id
     AND d.idempotency_key=p_idempotency_key FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest<>v_digest THEN
      RAISE EXCEPTION 'Drive access request idempotency conflict'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"idempotencyKey"}';
    END IF;
    RETURN jsonb_build_object('requestId',v_existing.request_id::text,
      'status',v_existing.status,'replayed',true);
  END IF;
  SELECT * INTO v_resolved FROM public.approval_resolve_approver(
    p_actor_user_id,v_preview->'approverSpec');
  IF v_resolved.skip OR v_resolved.kind IS NULL OR v_resolved.ref IS NULL
     OR (v_resolved.kind='user' AND v_resolved.ref=p_actor_user_id) THEN
    RAISE EXCEPTION 'Drive access approver resolution failed closed'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"approver"}';
  END IF;
  v_ttl:=CASE WHEN p_emergency THEN 15 ELSE LEAST(COALESCE(
    (SELECT (value)::int FROM public.system_config
      WHERE key='approval.request_ttl_minutes'),2880),2880) END;
  v_request_id:=public.approval_request_create('drive.access',p_actor_user_id,
    format('Drive access request %s',p_node_id),
    jsonb_build_object('detail','stored in drive_access_request_details'),
    (v_preview->>'approvalPolicyId')::bigint,v_resolved.kind,v_resolved.ref,v_ttl);
  INSERT INTO public.drive_access_request_details(
    request_id,requester_user_id,policy_id,space_id,node_id,subject_kind,
    subject_user_id,subject_group_id,requested_capabilities,
    requested_propagation,requested_expires_at,requested_max_uses,emergency,
    mfa_session_id,reason,expected_epoch,idempotency_key,request_digest
  ) VALUES(v_request_id,p_actor_user_id,(v_preview->>'policyId')::bigint,
    (v_preview->>'spaceId')::bigint,p_node_id,p_subject_kind,
    NULLIF(v_preview->>'subjectUserId','')::bigint,
    NULLIF(v_preview->>'subjectGroupId','')::bigint,p_capabilities,p_propagation,
    (v_preview->>'expiresAt')::timestamptz,p_max_uses,p_emergency,
    CASE WHEN p_emergency THEN p_mfa_session_id ELSE NULL END,p_reason,
    (v_preview->>'epoch')::bigint,p_idempotency_key,v_digest);
  PERFORM public.drive_access_audit(p_actor_user_id,(v_preview->>'spaceId')::bigint,
    'acl.request','node',p_node_id,NULL,jsonb_build_object(
      'requestId',v_request_id::text,'subjectKind',p_subject_kind,
      'subjectId',p_subject_id::text,'emergency',p_emergency),NULL,p_reason);
  PERFORM public.app_notify('drive_access_request',json_build_object(
    'requestId',v_request_id::text,'status','pending')::text);
  RETURN jsonb_build_object('requestId',v_request_id::text,'status','pending',
    'replayed',false);
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_request(bigint,bigint,text,bigint,text[],text,integer,integer,boolean,text,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_approval_decide(
  p_request_id bigint,p_actor_user_id bigint,p_decision text,p_comment text,
  p_applied_capabilities text[],p_applied_propagation text,
  p_applied_expires_at timestamptz,p_applied_max_uses integer,
  p_expected_epoch bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_req approval_requests%ROWTYPE; v_detail drive_access_request_details%ROWTYPE;
  v_status text; v_caps text[]; v_prop text; v_expires timestamptz;
  v_uses integer; v_epoch bigint; v_grant_id bigint; v_group_generation bigint;
  v_bump record; v_idempotency text; v_action text;
BEGIN
  SELECT * INTO v_req FROM public.approval_requests WHERE id=p_request_id FOR UPDATE;
  SELECT * INTO v_detail FROM public.drive_access_request_details
   WHERE request_id=p_request_id FOR UPDATE;
  IF NOT FOUND OR v_req.consumer_type<>'drive.access' THEN
    RAISE EXCEPTION 'Drive access approval not found'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict"}';
  END IF;
  IF v_req.status='applied' AND v_detail.grant_id IS NOT NULL
     AND v_req.decided_by_user_id=p_actor_user_id AND p_decision='approve' THEN
    RETURN jsonb_build_object('requestId',p_request_id::text,'status','applied',
      'grantId',v_detail.grant_id::text,'replayed',true);
  ELSIF v_req.status='denied' AND v_req.decided_by_user_id=p_actor_user_id
        AND p_decision='deny' THEN
    RETURN jsonb_build_object('requestId',p_request_id::text,'status','denied',
      'replayed',true);
  END IF;
  IF v_req.status='pending' AND v_req.expires_at<=now() THEN
    RAISE EXCEPTION 'Drive access approval expired'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"approvalExpiry"}';
  END IF;
  v_status:=public.approval_decide(p_request_id,p_actor_user_id,p_decision,p_comment);
  IF v_status='denied' THEN
    PERFORM public.drive_access_audit(p_actor_user_id,v_detail.space_id,'acl.deny',
      'approval_request',p_request_id,NULL,jsonb_build_object('status','denied'),
      NULL,p_comment);
    PERFORM public.app_notify('drive_access_request',json_build_object(
      'requestId',p_request_id::text,'status','denied')::text);
    RETURN jsonb_build_object('requestId',p_request_id::text,'status','denied',
      'replayed',false);
  END IF;
  v_caps:=COALESCE(p_applied_capabilities,v_detail.requested_capabilities);
  v_prop:=COALESCE(p_applied_propagation,v_detail.requested_propagation);
  v_expires:=COALESCE(p_applied_expires_at,v_detail.requested_expires_at);
  v_uses:=COALESCE(p_applied_max_uses,v_detail.requested_max_uses);
  IF NOT public.drive_acl_capabilities_valid(v_caps)
     OR NOT (v_caps<@v_detail.requested_capabilities)
     OR public.drive_access_propagation_rank(v_prop) IS NULL
     OR public.drive_access_propagation_rank(v_prop)>
        public.drive_access_propagation_rank(v_detail.requested_propagation)
     OR v_expires<=now() OR v_expires>v_detail.requested_expires_at
     OR (v_detail.requested_max_uses IS NOT NULL
         AND (v_uses IS NULL OR v_uses>v_detail.requested_max_uses)) THEN
    RAISE EXCEPTION 'Drive access approval may only narrow the request'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"appliedPayload"}';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM public.feature_toggles
                    WHERE key='feature.drive_access_governance'),false)
     OR NOT EXISTS(SELECT 1 FROM public.drive_access_request_policies p
                    WHERE p.id=v_detail.policy_id AND p.enabled
                      AND v_caps<@p.capabilities
                      AND public.drive_access_propagation_rank(v_prop)
                          <=public.drive_access_propagation_rank(p.max_propagation)
                      AND (p.max_uses IS NULL OR (v_uses IS NOT NULL AND v_uses<=p.max_uses))
                      AND (NOT v_detail.emergency OR p.emergency_allowed))
     OR (v_detail.emergency AND (
       NOT COALESCE((SELECT enabled FROM public.feature_toggles
                      WHERE key='feature.drive_emergency_access'),false)
       OR NOT EXISTS(SELECT 1 FROM public.sessions s
         WHERE s.id=v_detail.mfa_session_id AND s.user_id=v_detail.requester_user_id
           AND s.auth_method IN ('webauthn','totp','push','certificate')
           AND s.created_at>=now()-interval '15 minutes' AND s.expires_at>now())
     )) THEN
    RAISE EXCEPTION 'Drive access policy or fresh MFA is no longer valid'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"policy"}';
  END IF;
  PERFORM public.drive_tree_lock(v_detail.space_id);
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=v_detail.space_id FOR UPDATE;
  IF v_epoch<>p_expected_epoch THEN
    RAISE EXCEPTION 'Drive ACL epoch conflict'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"epoch"}';
  END IF;
  IF p_expected_epoch IS NULL OR p_expected_epoch<>v_detail.expected_epoch
     OR v_epoch<>v_detail.expected_epoch THEN
    RAISE EXCEPTION 'Drive access request epoch is stale'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"requestEpoch"}';
  END IF;
  IF v_detail.subject_kind='user' THEN
    IF NOT EXISTS(SELECT 1 FROM public.users WHERE id=v_detail.subject_user_id AND enabled) THEN
      RAISE EXCEPTION 'Drive access subject no longer valid'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"subject"}';
    END IF;
  ELSE
    SELECT generation INTO v_group_generation FROM public.directory_groups
     WHERE id=v_detail.subject_group_id AND state='active';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Drive access group no longer valid'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"subject"}';
    END IF;
  END IF;
  v_idempotency:=format('drive-access-request:%s',p_request_id);
  INSERT INTO public.drive_acl_grants(
    space_id,node_id,subject_kind,subject_user_id,subject_group_id,
    subject_generation,preset,capabilities,propagation,source,expires_at,
    max_uses,created_by,reason,idempotency_key,request_digest,approval_request_id
  ) VALUES(v_detail.space_id,v_detail.node_id,v_detail.subject_kind,
    v_detail.subject_user_id,v_detail.subject_group_id,v_group_generation,
    'custom',v_caps,v_prop,CASE WHEN v_detail.emergency THEN 'emergency' ELSE 'approval' END,
    v_expires,v_uses,p_actor_user_id,v_detail.reason,v_idempotency,
    v_detail.request_digest,p_request_id) RETURNING id INTO v_grant_id;
  IF v_detail.subject_kind='group' THEN
    SELECT * INTO v_bump FROM public.drive_acl_bump_group(
      v_detail.space_id,v_detail.subject_group_id,v_detail.node_id,'grant');
  ELSE
    SELECT * INTO v_bump FROM public.drive_acl_bump(
      v_detail.space_id,'user',v_detail.subject_user_id,v_detail.node_id,'grant');
  END IF;
  UPDATE public.drive_access_request_details SET
    applied_capabilities=v_caps,applied_propagation=v_prop,
    applied_expires_at=v_expires,applied_max_uses=v_uses,
    grant_id=v_grant_id,applied_at=clock_timestamp()
   WHERE request_id=p_request_id;
  UPDATE public.approval_requests SET status='applied' WHERE id=p_request_id;
  v_action:=CASE WHEN v_detail.emergency THEN 'acl.emergency.grant' ELSE 'acl.approve' END;
  PERFORM public.drive_access_audit(p_actor_user_id,v_detail.space_id,v_action,
    'acl_grant',v_grant_id,NULL,jsonb_build_object('requestId',p_request_id::text,
      'nodeId',v_detail.node_id::text,'subjectKind',v_detail.subject_kind,
      'emergency',v_detail.emergency,'expiresAt',v_expires),NULL,p_comment);
  PERFORM public.app_notify('drive_access_request',json_build_object(
    'requestId',p_request_id::text,'status','applied','epoch',v_bump.epoch::text)::text);
  RETURN jsonb_build_object('requestId',p_request_id::text,'status','applied',
    'grantId',v_grant_id::text,'epoch',v_bump.epoch::text,'replayed',false);
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_approval_decide(bigint,bigint,text,text,text[],text,timestamptz,integer,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_use_lease_reserve(
  p_user_id bigint,p_grant_id bigint,p_capability text,p_idempotency_key text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_grant drive_acl_grants%ROWTYPE; v_existing drive_access_use_leases%ROWTYPE;
  v_digest text; v_lease_id uuid; v_created timestamptz;
BEGIN
  IF p_capability NOT IN ('preview','download','create_child','modify_content','delete')
     OR p_idempotency_key IS NULL OR p_idempotency_key<>btrim(p_idempotency_key)
     OR octet_length(p_idempotency_key) NOT BETWEEN 8 AND 200 THEN
    RAISE EXCEPTION 'invalid Drive access lease request'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid"}';
  END IF;
  v_digest:=encode(digest(jsonb_build_object('grantId',p_grant_id::text,
    'userId',p_user_id::text,'capability',p_capability)::text,'sha256'),'hex');
  SELECT * INTO v_grant FROM public.drive_acl_grants WHERE id=p_grant_id FOR UPDATE;
  IF NOT FOUND OR v_grant.state<>'active' OR v_grant.max_uses IS NULL
     OR v_grant.expires_at<=now() OR NOT (p_capability=ANY(v_grant.capabilities))
     OR NOT public.drive_acl_grant_subject_applies(p_user_id,p_grant_id)
     OR NOT public.drive_runtime_has_node_capability(
       p_user_id,v_grant.node_id,p_capability) THEN
    RAISE EXCEPTION 'Drive access lease is unavailable'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"grant"}';
  END IF;
  SELECT * INTO v_existing FROM public.drive_access_use_leases
   WHERE grant_id=p_grant_id AND user_id=p_user_id
     AND idempotency_key=p_idempotency_key FOR UPDATE;
  IF FOUND THEN
    IF v_existing.request_digest<>v_digest THEN
      RAISE EXCEPTION 'Drive lease idempotency conflict'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"idempotencyKey"}';
    END IF;
    RETURN jsonb_build_object('leaseId',v_existing.id::text,'state',v_existing.state,
      'expiresAt',v_existing.expires_at,'replayed',true);
  END IF;
  IF v_grant.used_count+(SELECT count(*) FROM public.drive_access_use_leases
      WHERE grant_id=p_grant_id AND state='reserved' AND expires_at>now())
     >=v_grant.max_uses THEN
    RAISE EXCEPTION 'Drive access uses are exhausted'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"maxUses"}';
  END IF;
  v_created:=clock_timestamp();
  INSERT INTO public.drive_access_use_leases(
    grant_id,user_id,capability,idempotency_key,request_digest,created_at,expires_at
  ) VALUES(p_grant_id,p_user_id,p_capability,p_idempotency_key,v_digest,
    v_created,v_created+interval '5 minutes') RETURNING id INTO v_lease_id;
  RETURN jsonb_build_object('leaseId',v_lease_id::text,'state','reserved',
    'expiresAt',v_created+interval '5 minutes','replayed',false);
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_use_lease_reserve(bigint,bigint,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_use_lease_consume(
  p_user_id bigint,p_lease_id uuid
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_lease drive_access_use_leases%ROWTYPE; v_grant drive_acl_grants%ROWTYPE;
  v_bump record;
BEGIN
  SELECT * INTO v_lease FROM public.drive_access_use_leases
   WHERE id=p_lease_id AND user_id=p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Drive access lease unavailable'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"lease"}';
  END IF;
  IF v_lease.state='consumed' THEN
    RETURN jsonb_build_object('leaseId',p_lease_id::text,'state','consumed','replayed',true);
  END IF;
  SELECT * INTO v_grant FROM public.drive_acl_grants
   WHERE id=v_lease.grant_id FOR UPDATE;
  IF v_lease.state<>'reserved' OR v_lease.expires_at<=now()
     OR v_grant.state<>'active' OR v_grant.expires_at<=now()
     OR v_grant.used_count>=v_grant.max_uses
     OR NOT public.drive_acl_grant_subject_applies(p_user_id,v_grant.id)
     OR NOT public.drive_runtime_has_node_capability(
       p_user_id,v_grant.node_id,v_lease.capability) THEN
    UPDATE public.drive_access_use_leases SET state='abandoned'
     WHERE id=p_lease_id AND state='reserved';
    RAISE EXCEPTION 'Drive access lease expired or authorization changed'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"lease"}';
  END IF;
  UPDATE public.drive_acl_grants SET used_count=used_count+1 WHERE id=v_grant.id;
  UPDATE public.drive_access_use_leases SET state='consumed',consumed_at=clock_timestamp()
   WHERE id=p_lease_id;
  IF v_grant.used_count+1>=v_grant.max_uses THEN
    IF v_grant.subject_kind='group' THEN
      SELECT * INTO v_bump FROM public.drive_acl_bump_group(
        v_grant.space_id,v_grant.subject_group_id,v_grant.node_id,'expire');
    ELSE
      SELECT * INTO v_bump FROM public.drive_acl_bump(
        v_grant.space_id,'user',v_grant.subject_user_id,v_grant.node_id,'expire');
    END IF;
  END IF;
  PERFORM public.drive_access_audit(p_user_id,v_grant.space_id,'acl.lease.consume',
    'acl_grant',v_grant.id,NULL,jsonb_build_object('leaseId',p_lease_id::text,
      'capability',v_lease.capability),NULL,NULL);
  RETURN jsonb_build_object('leaseId',p_lease_id::text,'state','consumed',
    'remainingUses',(v_grant.max_uses-v_grant.used_count-1)::text,'replayed',false);
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_use_lease_consume(bigint,uuid)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_use_lease_abandon_due(
  p_limit integer DEFAULT 1000
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_count integer;
BEGIN
  IF p_limit NOT BETWEEN 1 AND 10000 THEN
    RAISE EXCEPTION 'invalid Drive lease sweep limit' USING ERRCODE='BZ252',
      HINT='{"type":"drive_acl_invalid","field":"limit"}';
  END IF;
  WITH due AS (
    SELECT id FROM public.drive_access_use_leases
     WHERE state='reserved' AND expires_at<=now()
     ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT p_limit
  ), changed AS (
    UPDATE public.drive_access_use_leases l SET state='abandoned'
      FROM due WHERE l.id=due.id RETURNING 1
  ) SELECT count(*)::integer INTO v_count FROM changed;
  RETURN v_count;
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_use_lease_abandon_due(integer)'::regprocedure);
