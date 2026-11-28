CREATE OR REPLACE FUNCTION identity_source_rebind_preview(
  p_actor bigint,p_user_id bigint,p_target_link_id bigint,p_reason text,p_idempotency_key uuid
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_a user_lifecycle_authorities%ROWTYPE; v_old user_identity_links%ROWTYPE;
  v_target user_identity_links%ROWTYPE; v_os identity_sources%ROWTYPE; v_ts identity_sources%ROWTYPE;
  v_snapshot jsonb; v_digest bytea; v_request bytea; v_id uuid; v_existing identity_transitions%ROWTYPE;
  v_protected boolean; v_expires timestamptz:=statement_timestamp()+interval '15 minutes'; v_replayed boolean:=false;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'),false)
     OR NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.identity_transitions'),false)
     OR NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.cae_runtime'),false) THEN
    RAISE EXCEPTION 'identity transition admission prerequisites are disabled'
      USING ERRCODE='BZ234';
  END IF;
  IF p_actor IS NULL OR p_user_id IS NULL OR p_target_link_id IS NULL OR p_idempotency_key IS NULL
     OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024 OR p_reason~'[[:cntrl:]]'
     OR NOT admin_can_reach(p_actor,p_user_id) THEN
    RAISE EXCEPTION 'invalid identity transition preview'
      USING ERRCODE='BZ241';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id,0));
  SELECT * INTO v_a FROM user_lifecycle_authorities WHERE user_id=p_user_id FOR UPDATE;
  IF NOT FOUND OR v_a.authority_kind<>'source' THEN
    RAISE EXCEPTION 'person is not directory lifecycle-owned'
      USING ERRCODE='BZ234';
  END IF;
  SELECT * INTO v_old FROM user_identity_links WHERE id=v_a.link_id AND user_id=p_user_id FOR UPDATE;
  SELECT * INTO v_target FROM user_identity_links WHERE id=p_target_link_id AND user_id=p_user_id FOR UPDATE;
  IF v_old.id IS NULL OR v_target.id IS NULL OR v_old.state<>'active' OR v_target.state<>'active'
     OR NOT ('provision'=ANY(v_old.purposes)) OR NOT ('provision'=ANY(v_target.purposes))
     OR v_old.id=v_target.id OR v_old.source_id=v_target.source_id THEN
    RAISE EXCEPTION 'target must be a different active provisioning link for the same person' USING ERRCODE='BZ233';
  END IF;
  SELECT * INTO v_os FROM identity_sources WHERE id=v_old.source_id AND state='active' FOR UPDATE;
  SELECT * INTO v_ts FROM identity_sources WHERE id=v_target.source_id AND state='active' FOR UPDATE;
  IF v_os.id IS NULL OR v_ts.id IS NULL
     OR v_os.kind NOT IN ('ad','ldap','scim') OR v_ts.kind NOT IN ('ad','ldap','scim') THEN
    RAISE EXCEPTION 'source pair is not supported'
      USING ERRCODE='BZ234';
  END IF;
  IF NOT identity_recovery_available(p_user_id,v_old.id) THEN
    RAISE EXCEPTION 'alternate authentication and recovery are required' USING ERRCODE='BZ237';
  END IF;
  v_protected:=EXISTS(SELECT 1 FROM admin_role_assignments a JOIN admin_role_groups g ON g.id=a.role_group_id
    WHERE a.user_id=p_user_id AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
      AND admin_assignment_active(a.eligible,a.activated_until)
      AND EXISTS(SELECT 1 FROM admin_permissions p WHERE p.permission_key=ANY(g.permissions) AND p.is_sensitive));
  v_snapshot:=jsonb_build_object('version',1,'type','source_to_source','personId',p_user_id::text,
    'oldSourceId',v_os.id::text,'oldLinkId',v_old.id::text,'targetSourceId',v_ts.id::text,
    'targetLinkId',v_target.id::text,'mailboxInvariant',identity_mailbox_invariant_snapshot(p_user_id),
    'generations',jsonb_build_object('source',v_os.generation::text,'mapping',v_os.mapping_version::text,'link',v_old.generation::text,
      'targetSource',v_ts.generation::text,'targetLink',v_target.generation::text,'lifecycle',v_a.generation::text),
    'attributeChanges','[]'::jsonb,'sourceGrantIds','[]'::jsonb,
    'sessions',jsonb_build_object('oauthFamilies',(SELECT count(*) FROM oauth_tokens WHERE user_id=p_user_id AND revoked_at IS NULL),
      'webSessions',(SELECT count(*) FROM sessions WHERE user_id=p_user_id),'livekitTargets',0),
    'ownershipIdsPreserved',true,'protected',v_protected,'recoveryReady',true,'expiresAt',v_expires);
  v_digest:=digest(v_snapshot::text,'sha256');
  v_request:=digest(jsonb_build_object('type','source_to_source','actor',p_actor::text,'personId',p_user_id::text,
    'oldSourceId',v_os.id::text,'oldSourceGeneration',v_os.generation::text,
    'oldLinkId',v_old.id::text,'oldLinkGeneration',v_old.generation::text,
    'targetSourceId',v_ts.id::text,'targetSourceGeneration',v_ts.generation::text,
    'targetLinkId',p_target_link_id::text,'targetLinkGeneration',v_target.generation::text,
    'lifecycleGeneration',v_a.generation::text,'reason',p_reason)::text,'sha256');
  INSERT INTO identity_transitions(user_id,kind,state,source_id,link_id,source_generation,link_generation,
    target_source_id,target_link_id,target_source_generation,target_link_generation,lifecycle_generation,
    preview_digest,preview_snapshot,preview_expires_at,actor_user_id,reason,idempotency_key,request_digest,protected)
  VALUES(p_user_id,'source_to_source','draft',v_os.id,v_old.id,v_os.generation,v_old.generation,
    v_ts.id,v_target.id,v_ts.generation,v_target.generation,v_a.generation,v_digest,v_snapshot,v_expires,
    p_actor,p_reason,p_idempotency_key,v_request,v_protected)
  ON CONFLICT(actor_user_id,kind,idempotency_key) DO NOTHING RETURNING id INTO v_id;
  IF v_id IS NULL THEN
    SELECT * INTO v_existing FROM identity_transitions WHERE actor_user_id=p_actor AND kind='source_to_source'
      AND idempotency_key=p_idempotency_key FOR UPDATE;
    IF NOT FOUND OR v_existing.user_id<>p_user_id OR v_existing.target_link_id<>p_target_link_id
       OR v_existing.request_digest<>v_request THEN
      RAISE EXCEPTION 'identity transition idempotency key was reused with different input' USING ERRCODE='BZ240';
    END IF;
    v_id:=v_existing.id; v_replayed:=true;
  ELSE
    PERFORM identity_transition_set_state(v_id,'draft','previewed',NULL);
    INSERT INTO identity_transition_steps(transition_id,ordinal,stage,state,attempt_count,input_digest,output_digest,started_at,finished_at)
    VALUES(v_id,1,'preview','completed',1,v_request,v_digest,statement_timestamp(),statement_timestamp());
    INSERT INTO identity_link_events(actor_user_id,user_id,source_id,link_id,transition_id,action,reason,after_digest,metadata)
    VALUES(p_actor,p_user_id,v_os.id,v_old.id,v_id,'transition_previewed',p_reason,v_digest,
      jsonb_build_object('kind','source_to_source','targetSourceId',v_ts.id,'targetLinkId',v_target.id));
  END IF;
  RETURN (SELECT jsonb_build_object('transitionId',t.id,'state',t.state,
    'transitionGeneration',t.transition_generation::text,'previewVersion',t.preview_version::text,
    'previewDigest',encode(t.preview_digest,'hex'),'previewExpiresAt',t.preview_expires_at,
    'protected',t.protected,'recoveryReady',t.preview_snapshot->'recoveryReady',
    'sourceGeneration',t.source_generation::text,'linkGeneration',t.link_generation::text,
    'targetSourceGeneration',t.target_source_generation::text,'targetLinkGeneration',t.target_link_generation::text,
    'lifecycleGeneration',t.lifecycle_generation::text,'preview',t.preview_snapshot,'replayed',v_replayed)
    FROM identity_transitions t WHERE t.id=v_id);
END $$;

ALTER FUNCTION identity_source_rebind_preview(bigint,bigint,bigint,text,uuid) OWNER TO setjoin_worker;
