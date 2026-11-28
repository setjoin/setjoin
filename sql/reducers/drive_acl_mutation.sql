-- drive_acl_mutation.sql -- A4's only interactive ACL mutation module.
-- Validation, authority, epoch fencing, audit, invalidation, and notification
-- stay in the committing transaction; Go handlers remain wire translators.

CREATE OR REPLACE FUNCTION drive_acl_grant_preview(
  p_actor_user_id bigint,p_node_id bigint,p_subject_kind text,p_subject_id bigint,
  p_preset text,p_capabilities text[],p_propagation text,
  p_starts_at timestamptz,p_expires_at timestamptz,p_max_uses integer,
  p_reason text
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_space drive_spaces%ROWTYPE; v_owner_domain bigint; v_caps text[];
  v_subject_user bigint; v_subject_group bigint; v_subject_generation bigint;
  v_is_guest boolean;
BEGIN
  SELECT s.* INTO v_space FROM public.drive_nodes n
    JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_node_id AND n.purged_at IS NULL;
  IF NOT FOUND OR v_space.acl_mode<>'acl'
     OR NOT COALESCE((SELECT enabled FROM public.feature_toggles
                       WHERE key='feature.drive_node_acl_writes'),false)
     OR NOT public.drive_runtime_has_node_capability(
       p_actor_user_id,p_node_id,'manage_acl') THEN
    RAISE EXCEPTION 'Drive ACL target is unavailable or forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  IF v_space.chat_channel_id IS NOT NULL OR v_space.meeting_id IS NOT NULL THEN
    RAISE EXCEPTION 'bound Drive spaces reject ad-hoc ACL grants'
      USING ERRCODE='BZ256',HINT='{"type":"drive_acl_bound_space"}';
  END IF;
  IF p_preset NOT IN ('viewer','contributor','editor','folder_manager','custom')
     OR p_propagation NOT IN ('self','children','subtree') THEN
    RAISE EXCEPTION 'invalid Drive ACL preset or propagation'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid"}';
  END IF;
  v_caps:=CASE WHEN p_preset='custom' THEN p_capabilities
               ELSE public.drive_acl_preset_capabilities(p_preset) END;
  IF NOT public.drive_acl_capabilities_valid(v_caps)
     OR (p_preset<>'custom' AND p_capabilities IS NOT NULL
         AND p_capabilities<>v_caps)
     OR NOT (v_caps <@ public.drive_effective_capabilities(
       p_actor_user_id,p_node_id)) THEN
    RAISE EXCEPTION 'Drive ACL delegation exceeds actor authority'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden","field":"capabilities"}';
  END IF;
  SELECT u.domain_id INTO v_owner_domain FROM public.users u
   WHERE u.id=v_space.owner_user_id;
  IF p_subject_kind='user' THEN
    SELECT u.id,public.is_guest_account(u.id)
      INTO v_subject_user,v_is_guest FROM public.users u
     WHERE u.id=p_subject_id AND u.enabled AND u.domain_id=v_owner_domain;
    IF NOT FOUND OR p_subject_id=p_actor_user_id THEN
      RAISE EXCEPTION 'invalid or self Drive ACL subject'
        USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"subjectId"}';
    END IF;
    IF v_is_guest AND (
      NOT (v_caps <@ ARRAY[
        'traverse','list_children','read_metadata','preview','download'
      ]::text[])
      OR ('download'=ANY(v_caps)
          AND NOT public.guest_profile_flag(v_subject_user,'allow_download'))
    ) THEN
      RAISE EXCEPTION 'Guest Drive ACL exceeds profile caps'
        USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden","field":"guestCapabilities"}';
    END IF;
  ELSIF p_subject_kind='group' THEN
    IF NOT COALESCE((SELECT enabled FROM public.feature_toggles
                      WHERE key='feature.directory_group_authority'),false) THEN
      RAISE EXCEPTION 'directory-group ACL authority is disabled'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"groupFeature"}';
    END IF;
    SELECT g.id,g.generation INTO v_subject_group,v_subject_generation
      FROM public.directory_groups g
     WHERE g.id=p_subject_id AND g.domain_id=v_owner_domain AND g.state='active';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'invalid Drive ACL group subject'
        USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"subjectId"}';
    END IF;
  ELSE
    RAISE EXCEPTION 'invalid Drive ACL subject kind'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"subjectKind"}';
  END IF;
  IF (p_starts_at IS NOT NULL AND p_starts_at<now()-interval '5 minutes')
     OR (p_expires_at IS NOT NULL AND p_expires_at<=COALESCE(p_starts_at,now()))
     OR (p_expires_at IS NOT NULL AND p_expires_at>now()+interval '365 days')
     OR (p_max_uses IS NOT NULL AND p_max_uses NOT BETWEEN 1 AND 1000000)
     OR (p_reason IS NOT NULL AND (p_reason<>btrim(p_reason)
         OR octet_length(p_reason) NOT BETWEEN 1 AND 1000)) THEN
    RAISE EXCEPTION 'invalid Drive ACL validity bounds'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"validity"}';
  END IF;
  RETURN jsonb_build_object(
    'spaceId',v_space.id::text,'nodeId',p_node_id::text,
    'subjectKind',p_subject_kind,
    'subjectUserId',CASE WHEN v_subject_user IS NULL THEN NULL ELSE v_subject_user::text END,
    'subjectGroupId',CASE WHEN v_subject_group IS NULL THEN NULL ELSE v_subject_group::text END,
    'subjectGeneration',CASE WHEN v_subject_generation IS NULL THEN NULL ELSE v_subject_generation::text END,
    'preset',p_preset,'capabilities',to_jsonb(v_caps),'propagation',p_propagation,
    'startsAt',p_starts_at,'expiresAt',p_expires_at,'maxUses',p_max_uses
  );
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_grant_preview(bigint,bigint,text,bigint,text,text[],text,timestamptz,timestamptz,integer,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_grant(
  p_actor_user_id bigint,p_node_id bigint,p_subject_kind text,p_subject_id bigint,
  p_preset text,p_capabilities text[],p_propagation text,
  p_starts_at timestamptz,p_expires_at timestamptz,p_max_uses integer,
  p_reason text,p_expected_epoch bigint,p_idempotency_key text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_preview jsonb; v_space_id bigint; v_epoch bigint; v_grant_id bigint;
  v_caps text[]; v_digest text; v_existing drive_acl_grants%ROWTYPE;
  v_user_id bigint; v_group_id bigint; v_group_generation bigint; v_source text;
  v_bump record;
BEGIN
  v_preview:=public.drive_acl_grant_preview(
    p_actor_user_id,p_node_id,p_subject_kind,p_subject_id,p_preset,p_capabilities,
    p_propagation,p_starts_at,p_expires_at,p_max_uses,p_reason);
  v_space_id:=(v_preview->>'spaceId')::bigint;
  SELECT array_agg(capability ORDER BY array_position(
           public.drive_acl_capability_catalog(),capability)) INTO v_caps
    FROM jsonb_array_elements_text(v_preview->'capabilities') x(capability);
  v_user_id:=NULLIF(v_preview->>'subjectUserId','')::bigint;
  v_group_id:=NULLIF(v_preview->>'subjectGroupId','')::bigint;
  v_group_generation:=NULLIF(v_preview->>'subjectGeneration','')::bigint;
  v_source:=CASE WHEN p_subject_kind='group' THEN 'group' ELSE 'direct' END;
  IF p_idempotency_key IS NULL OR p_idempotency_key<>btrim(p_idempotency_key)
     OR octet_length(p_idempotency_key) NOT BETWEEN 8 AND 200 THEN
    RAISE EXCEPTION 'invalid Drive ACL idempotency key'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"idempotencyKey"}';
  END IF;
  v_digest:=encode(digest(jsonb_build_object(
    'nodeId',p_node_id::text,'subjectKind',p_subject_kind,
    'subjectId',p_subject_id::text,'preset',p_preset,'capabilities',v_caps,
    'propagation',p_propagation,'startsAt',p_starts_at,'expiresAt',p_expires_at,
    'maxUses',p_max_uses,'reason',p_reason)::text,'sha256'),'hex');

  PERFORM public.drive_tree_lock(v_space_id);
  SELECT * INTO v_existing FROM public.drive_acl_grants
   WHERE space_id=v_space_id AND idempotency_key=p_idempotency_key
   FOR UPDATE;
  IF FOUND THEN
    IF v_existing.created_by<>p_actor_user_id THEN
      RAISE EXCEPTION 'Drive ACL idempotency key belongs to another actor'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"idempotencyKey"}';
    END IF;
    IF v_existing.request_digest<>v_digest THEN
      RAISE EXCEPTION 'Drive ACL idempotency conflict'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"idempotencyKey"}';
    END IF;
    RETURN jsonb_build_object('grantId',v_existing.id::text,
      'spaceId',v_existing.space_id::text,'nodeId',v_existing.node_id::text,
      'epoch',public.drive_acl_epoch(v_existing.space_id)::text,'replayed',true);
  END IF;
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=v_space_id FOR UPDATE;
  IF v_epoch IS NULL OR v_epoch<>p_expected_epoch THEN
    RAISE EXCEPTION 'Drive ACL epoch conflict'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"epoch"}';
  END IF;
  INSERT INTO public.drive_acl_grants(
    space_id,node_id,subject_kind,subject_user_id,subject_group_id,
    subject_generation,preset,capabilities,propagation,source,starts_at,
    expires_at,max_uses,created_by,reason,idempotency_key,request_digest
  ) VALUES(
    v_space_id,p_node_id,p_subject_kind,v_user_id,v_group_id,v_group_generation,
    p_preset,v_caps,p_propagation,v_source,p_starts_at,p_expires_at,p_max_uses,
    p_actor_user_id,p_reason,p_idempotency_key,v_digest
  ) RETURNING id INTO v_grant_id;
  IF p_subject_kind='group' THEN
    SELECT * INTO v_bump FROM public.drive_acl_bump_group(
      v_space_id,v_group_id,p_node_id,'grant');
  ELSE
    SELECT * INTO v_bump FROM public.drive_acl_bump(
      v_space_id,'user',v_user_id,p_node_id,'grant');
  END IF;
  PERFORM public.drive_access_audit(
    p_actor_user_id,v_space_id,'acl.grant','acl_grant',v_grant_id,NULL,
    jsonb_build_object('nodeId',p_node_id::text,'subjectKind',p_subject_kind,
      'subjectId',p_subject_id::text,'preset',p_preset,
      'propagation',p_propagation,'expiresAt',p_expires_at),NULL,p_reason);
  RETURN jsonb_build_object('grantId',v_grant_id::text,'spaceId',v_space_id::text,
    'nodeId',p_node_id::text,'epoch',v_bump.epoch::text,
    'invalidationCursor',v_bump.invalidation_cursor::text,'replayed',false);
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_grant(bigint,bigint,text,bigint,text,text[],text,timestamptz,timestamptz,integer,text,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_revoke(
  p_actor_user_id bigint,p_grant_id bigint,p_expected_epoch bigint,p_reason text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_grant drive_acl_grants%ROWTYPE; v_epoch bigint; v_bump record; v_action text;
BEGIN
  SELECT * INTO v_grant FROM public.drive_acl_grants WHERE id=p_grant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Drive ACL grant is unavailable or forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  IF p_reason IS NULL OR p_reason<>btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'Drive ACL revoke reason is required'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"reason"}';
  END IF;
  PERFORM public.drive_tree_lock(v_grant.space_id);
  SELECT * INTO v_grant FROM public.drive_acl_grants
   WHERE id=p_grant_id FOR UPDATE;
  IF NOT FOUND OR NOT public.drive_runtime_has_node_capability(
       p_actor_user_id,v_grant.node_id,'manage_acl') THEN
    RAISE EXCEPTION 'Drive ACL grant is unavailable or forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=v_grant.space_id FOR UPDATE;
  IF v_grant.state='revoked' AND v_grant.revoked_by=p_actor_user_id THEN
    RETURN jsonb_build_object('grantId',p_grant_id::text,'state','revoked',
      'epoch',v_epoch::text,'replayed',true);
  END IF;
  IF v_grant.state<>'active' THEN
    RAISE EXCEPTION 'Drive ACL grant changed concurrently'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"grant"}';
  END IF;
  IF v_epoch<>p_expected_epoch THEN
    RAISE EXCEPTION 'Drive ACL epoch conflict'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"epoch"}';
  END IF;
  UPDATE public.drive_acl_grants SET state='revoked',revoked_by=p_actor_user_id,
    revoked_at=clock_timestamp(),reason=p_reason WHERE id=p_grant_id AND state='active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Drive ACL grant changed concurrently'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"grant"}';
  END IF;
  IF v_grant.subject_kind='group' THEN
    SELECT * INTO v_bump FROM public.drive_acl_bump_group(
      v_grant.space_id,v_grant.subject_group_id,v_grant.node_id,'revoke');
  ELSE
    SELECT * INTO v_bump FROM public.drive_acl_bump(
      v_grant.space_id,'user',v_grant.subject_user_id,v_grant.node_id,'revoke');
  END IF;
  v_action:=CASE WHEN v_grant.source='emergency'
                 THEN 'acl.emergency.revoke' ELSE 'acl.revoke' END;
  PERFORM public.drive_access_audit(p_actor_user_id,v_grant.space_id,v_action,
    'acl_grant',p_grant_id,jsonb_build_object('state','active'),
    jsonb_build_object('state','revoked'),NULL,p_reason);
  RETURN jsonb_build_object('grantId',p_grant_id::text,'state','revoked',
    'epoch',v_bump.epoch::text,'invalidationCursor',v_bump.invalidation_cursor::text,
    'replayed',false);
END;
$$;
SELECT apply_worker_ownership('drive_acl_revoke(bigint,bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_inheritance_set(
  p_actor_user_id bigint,p_node_id bigint,p_break boolean,p_expected_epoch bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_space_id bigint; v_epoch bigint; v_bump record; v_rows integer:=0;
BEGIN
  SELECT n.space_id INTO v_space_id FROM public.drive_nodes n
   JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_node_id AND n.purged_at IS NULL AND s.acl_mode='acl'
     AND s.chat_channel_id IS NULL AND s.meeting_id IS NULL;
  IF NOT FOUND OR NOT COALESCE((SELECT enabled FROM public.feature_toggles
                                WHERE key='feature.drive_node_acl_writes'),false)
     OR NOT (
       public.drive_runtime_has_node_capability(p_actor_user_id,p_node_id,'manage_acl')
       OR (NOT p_break AND public.drive_runtime_has_space_root_capability(
             p_actor_user_id,v_space_id,'manage_acl'))
     ) THEN
    RAISE EXCEPTION 'Drive ACL inheritance target is unavailable or forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  PERFORM public.drive_tree_lock(v_space_id);
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=v_space_id FOR UPDATE;
  IF v_epoch<>p_expected_epoch THEN
    RAISE EXCEPTION 'Drive ACL epoch conflict'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"epoch"}';
  END IF;
  IF p_break THEN
    INSERT INTO public.drive_acl_breaks(space_id,node_id,created_by,expected_epoch)
    VALUES(v_space_id,p_node_id,p_actor_user_id,v_epoch) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
  ELSE
    DELETE FROM public.drive_acl_breaks WHERE space_id=v_space_id AND node_id=p_node_id;
    GET DIAGNOSTICS v_rows=ROW_COUNT;
  END IF;
  IF v_rows=0 THEN
    RETURN jsonb_build_object('nodeId',p_node_id::text,'break',p_break,
      'epoch',v_epoch::text,'changed',false);
  END IF;
  SELECT * INTO v_bump FROM public.drive_acl_bump(
    v_space_id,'all',NULL,p_node_id,
    CASE WHEN p_break THEN 'inheritance_break' ELSE 'inheritance_resume' END);
  PERFORM public.drive_access_audit(p_actor_user_id,v_space_id,
    CASE WHEN p_break THEN 'acl.inheritance.break' ELSE 'acl.inheritance.resume' END,
    'node',p_node_id,NULL,jsonb_build_object('break',p_break),NULL,NULL);
  RETURN jsonb_build_object('nodeId',p_node_id::text,'break',p_break,
    'epoch',v_bump.epoch::text,'invalidationCursor',v_bump.invalidation_cursor::text,
    'changed',true);
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_inheritance_set(bigint,bigint,boolean,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_expire_due(
  p_space_id bigint,p_limit integer DEFAULT 500
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_grant drive_acl_grants%ROWTYPE; v_count integer:=0; v_bump record;
BEGIN
  IF p_limit NOT BETWEEN 1 AND 5000 THEN
    RAISE EXCEPTION 'invalid Drive ACL expiry limit' USING ERRCODE='BZ252',
      HINT='{"type":"drive_acl_invalid","field":"limit"}';
  END IF;
  PERFORM public.drive_tree_lock(p_space_id);
  PERFORM 1 FROM public.drive_acl_generations WHERE space_id=p_space_id FOR UPDATE;
  FOR v_grant IN
    SELECT * FROM public.drive_acl_grants
     WHERE space_id=p_space_id AND state='active' AND expires_at<=now()
     ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT p_limit
  LOOP
    UPDATE public.drive_acl_grants SET state='expired' WHERE id=v_grant.id;
    IF v_grant.subject_kind='group' THEN
      SELECT * INTO v_bump FROM public.drive_acl_bump_group(
        p_space_id,v_grant.subject_group_id,v_grant.node_id,'expire');
    ELSE
      SELECT * INTO v_bump FROM public.drive_acl_bump(
        p_space_id,'user',v_grant.subject_user_id,v_grant.node_id,'expire');
    END IF;
    PERFORM public.drive_access_audit(v_grant.created_by,p_space_id,'acl.expire',
      'acl_grant',v_grant.id,jsonb_build_object('state','active'),
      jsonb_build_object('state','expired'),NULL,'automatic bounded expiry');
    v_count:=v_count+1;
  END LOOP;
  RETURN v_count;
END;
$$;
SELECT apply_worker_ownership('drive_acl_expire_due(bigint,integer)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_migrate_folder_admins(
  p_actor_user_id bigint,p_space_id bigint,p_expected_epoch bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_row record; v_epoch bigint; v_migrated int:=0; v_dropped int:=0; v_bump record;
  v_key text; v_digest text;
BEGIN
  IF NOT public.drive_runtime_has_space_root_capability(
       p_actor_user_id,p_space_id,'manage_acl')
     OR NOT COALESCE((SELECT enabled FROM public.feature_toggles
                       WHERE key='feature.drive_node_acl_writes'),false)
     OR NOT EXISTS(SELECT 1 FROM public.drive_spaces WHERE id=p_space_id
                    AND acl_mode='acl' AND chat_channel_id IS NULL AND meeting_id IS NULL) THEN
    RAISE EXCEPTION 'folder-admin migration forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  PERFORM public.drive_tree_lock(p_space_id);
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=p_space_id FOR UPDATE;
  IF v_epoch<>p_expected_epoch THEN
    RAISE EXCEPTION 'Drive ACL epoch conflict'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"epoch"}';
  END IF;
  FOR v_row IN SELECT fa.* FROM public.drive_folder_admins fa
    WHERE fa.space_id=p_space_id ORDER BY fa.node_id,fa.user_id FOR UPDATE
  LOOP
    IF NOT public.drive_user_has_space_access(v_row.user_id,p_space_id) THEN
      DELETE FROM public.drive_folder_admins
       WHERE node_id=v_row.node_id AND user_id=v_row.user_id;
      PERFORM public.drive_access_audit(p_actor_user_id,p_space_id,'folderadmin.revoke',
        'node',v_row.node_id,jsonb_build_object('userId',v_row.user_id::text),NULL,
        NULL,'stale folder-admin dropped during ACL migration');
      v_dropped:=v_dropped+1;
      CONTINUE;
    END IF;
    v_key:=format('folderadmin-migrate:%s:%s',v_row.node_id,v_row.user_id);
    v_digest:=encode(digest(v_key,'sha256'),'hex');
    INSERT INTO public.drive_acl_grants(
      space_id,node_id,subject_kind,subject_user_id,preset,capabilities,
      propagation,source,created_by,reason,idempotency_key,request_digest
    ) VALUES(p_space_id,v_row.node_id,'user',v_row.user_id,'folder_manager',
      public.drive_acl_preset_capabilities('folder_manager'),'subtree',
      'legacy_folder_admin',p_actor_user_id,'migrated legacy folder admin',v_key,v_digest)
    ON CONFLICT(space_id,idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING;
    DELETE FROM public.drive_folder_admins
     WHERE node_id=v_row.node_id AND user_id=v_row.user_id;
    PERFORM public.drive_access_audit(p_actor_user_id,p_space_id,'folderadmin.grant',
      'node',v_row.node_id,NULL,jsonb_build_object('userId',v_row.user_id::text,
      'source','legacy_folder_admin'),NULL,'migrated to scoped ACL grant');
    v_migrated:=v_migrated+1;
  END LOOP;
  IF v_migrated+v_dropped>0 THEN
    SELECT * INTO v_bump FROM public.drive_acl_bump(
      p_space_id,'all',NULL,NULL,'full_reconcile');
    v_epoch:=v_bump.epoch;
  END IF;
  RETURN jsonb_build_object('spaceId',p_space_id::text,'migrated',v_migrated,
    'droppedStale',v_dropped,'epoch',v_epoch::text);
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_migrate_folder_admins(bigint,bigint,bigint)'::regprocedure);

-- Compatibility adapter for the historical ?folder= member endpoint.  In an
-- ACL-mode space its editor/viewer vocabulary becomes one scoped subtree
-- grant.  Replacement and revocation bump the same epoch/invalidation stream
-- as the native ACL API, so old clients cannot create untracked authority.
CREATE OR REPLACE FUNCTION drive_acl_compat_folder_member_set(
  p_actor_user_id bigint,p_space_id bigint,p_folder_node_id bigint,
  p_grantee bigint,p_role text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_preset text; v_preview jsonb; v_caps text[]; v_epoch bigint; v_old record;
  v_grant_id bigint; v_bump record; v_key text; v_digest text;
BEGIN
  IF p_role NOT IN ('viewer','editor') THEN
    RAISE EXCEPTION 'folder grants support viewer or editor'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"role"}';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM public.drive_nodes n
                 WHERE n.id=p_folder_node_id AND n.space_id=p_space_id
                   AND n.kind='folder' AND n.deleted_at IS NULL) THEN
    RAISE EXCEPTION 'folder unavailable'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  v_preset:=p_role;
  v_preview:=public.drive_acl_grant_preview(
    p_actor_user_id,p_folder_node_id,'user',p_grantee,v_preset,NULL,
    'subtree',NULL,NULL,NULL,'legacy folder member compatibility');
  SELECT array_agg(capability ORDER BY array_position(
           public.drive_acl_capability_catalog(),capability)) INTO v_caps
    FROM jsonb_array_elements_text(v_preview->'capabilities') x(capability);

  PERFORM public.drive_tree_lock(p_space_id);
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=p_space_id FOR UPDATE;
  -- The preview is UX evidence only.  Re-evaluate authority after the same
  -- tree/generation locks used by revoke so a stale manager cannot write.
  v_preview:=public.drive_acl_grant_preview(
    p_actor_user_id,p_folder_node_id,'user',p_grantee,v_preset,NULL,
    'subtree',NULL,NULL,NULL,'legacy folder member compatibility');
  SELECT * INTO v_old FROM public.drive_acl_grants
   WHERE node_id=p_folder_node_id AND subject_user_id=p_grantee
     AND source='compat_folder_member' AND state='active' FOR UPDATE;
  IF FOUND AND v_old.preset=v_preset AND v_old.capabilities=v_caps THEN
    RETURN jsonb_build_object('status','granted','grantId',v_old.id::text,
      'epoch',v_epoch::text,'replayed',true);
  END IF;
  IF FOUND THEN
    UPDATE public.drive_acl_grants SET state='revoked',revoked_by=p_actor_user_id,
      revoked_at=clock_timestamp(),reason='replaced by compatibility endpoint'
     WHERE id=v_old.id;
  END IF;
  v_key:=format('compat-folder:%s:%s:%s',p_folder_node_id,p_grantee,v_epoch+1);
  v_digest:=encode(digest(jsonb_build_object('nodeId',p_folder_node_id::text,
    'subjectId',p_grantee::text,'preset',v_preset,'epoch',v_epoch::text)::text,
    'sha256'),'hex');
  INSERT INTO public.drive_acl_grants(
    space_id,node_id,subject_kind,subject_user_id,preset,capabilities,
    propagation,source,created_by,reason,idempotency_key,request_digest
  ) VALUES(p_space_id,p_folder_node_id,'user',p_grantee,v_preset,v_caps,
    'subtree','compat_folder_member',p_actor_user_id,
    'legacy folder member compatibility',v_key,v_digest)
  RETURNING id INTO v_grant_id;
  SELECT * INTO v_bump FROM public.drive_acl_bump(
    p_space_id,'user',p_grantee,p_folder_node_id,'grant');
  PERFORM public.drive_access_audit(p_actor_user_id,p_space_id,'acl.grant',
    'acl_grant',v_grant_id,NULL,jsonb_build_object('nodeId',p_folder_node_id::text,
      'subjectId',p_grantee::text,'preset',v_preset,
      'source','compat_folder_member'),NULL,'compatibility endpoint');
  RETURN jsonb_build_object('status','granted','grantId',v_grant_id::text,
    'epoch',v_bump.epoch::text,'replayed',false);
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_compat_folder_member_set(bigint,bigint,bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_compat_folder_member_revoke(
  p_actor_user_id bigint,p_space_id bigint,p_folder_node_id bigint,p_grantee bigint
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_grant drive_acl_grants%ROWTYPE; v_bump record;
BEGIN
  IF NOT public.drive_runtime_has_node_capability(
       p_actor_user_id,p_folder_node_id,'manage_acl') THEN
    RAISE EXCEPTION 'folder grant unavailable'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  PERFORM public.drive_tree_lock(p_space_id);
  PERFORM 1 FROM public.drive_acl_generations
   WHERE space_id=p_space_id FOR UPDATE;
  IF NOT public.drive_runtime_has_node_capability(
       p_actor_user_id,p_folder_node_id,'manage_acl') THEN
    RAISE EXCEPTION 'folder grant unavailable'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  SELECT * INTO v_grant FROM public.drive_acl_grants
   WHERE space_id=p_space_id AND node_id=p_folder_node_id
     AND subject_user_id=p_grantee AND source='compat_folder_member'
     AND state='active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'folder grant not found'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  UPDATE public.drive_acl_grants SET state='revoked',revoked_by=p_actor_user_id,
    revoked_at=clock_timestamp(),reason='revoked by compatibility endpoint'
   WHERE id=v_grant.id;
  SELECT * INTO v_bump FROM public.drive_acl_bump(
    p_space_id,'user',p_grantee,p_folder_node_id,'revoke');
  PERFORM public.drive_access_audit(p_actor_user_id,p_space_id,'acl.revoke',
    'acl_grant',v_grant.id,jsonb_build_object('state','active'),
    jsonb_build_object('state','revoked'),NULL,'compatibility endpoint');
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_compat_folder_member_revoke(bigint,bigint,bigint,bigint)'::regprocedure);
