-- drive_acl_projection.sql -- A8 read projections for the public Drive ACL UX.
--
-- These functions are deliberately wire-oriented but remain data-authoritative:
-- Go validates shape/size and forwards parameters, while this module decides
-- visibility, configured/effective source disclosure, quick-view membership,
-- and inheritance impact.  IDs are emitted as decimal strings so browser
-- clients never lose bigint precision.

CREATE OR REPLACE FUNCTION drive_acl_node_detail(
  p_actor_user_id bigint,p_node_id bigint
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_node drive_nodes%ROWTYPE; v_space drive_spaces%ROWTYPE;
  v_epoch bigint; v_caps text[]; v_can_manage boolean;
  v_grants jsonb; v_sources jsonb;
BEGIN
  SELECT n.* INTO v_node
   FROM public.drive_nodes n
   WHERE n.id=p_node_id AND n.purged_at IS NULL
     AND (public.drive_runtime_has_node_capability(
            p_actor_user_id,n.id,'read_metadata')
       OR public.drive_runtime_has_node_capability(
            p_actor_user_id,n.id,'traverse'));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Drive node not found'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden","opaque":true}';
  END IF;
  SELECT * INTO v_space FROM public.drive_spaces WHERE id=v_node.space_id;
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=v_node.space_id;
  SELECT COALESCE(array_agg(DISTINCT s.capability ORDER BY s.capability),ARRAY[]::text[])
    INTO v_caps FROM public.drive_runtime_capability_sources(
      p_actor_user_id,v_node.space_id,p_node_id) s;
  v_can_manage:='manage_acl'=ANY(v_caps);

  IF v_can_manage THEN
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'grantId',g.id::text,'anchorNodeId',g.node_id::text,
      'anchorName',anchor.name,'subjectKind',g.subject_kind,
      'subjectId',COALESCE(g.subject_user_id,g.subject_group_id)::text,
      'subjectLabel',CASE WHEN g.subject_kind='user' THEN u.display_name ELSE dg.name END,
      'subjectSecondary',CASE WHEN g.subject_kind='user' THEN u.email ELSE NULL END,
      'preset',g.preset,'capabilities',to_jsonb(g.capabilities),
      'propagation',g.propagation,'source',g.source,
      'relation',CASE WHEN g.node_id=p_node_id THEN 'direct' ELSE 'inherited' END,
      'startsAt',g.starts_at,'expiresAt',g.expires_at,
      'maxUses',g.max_uses,'usedCount',g.used_count,
      'createdAt',g.created_at
    ) ORDER BY CASE WHEN g.node_id=p_node_id THEN 0 ELSE 1 END,c.depth,g.created_at DESC,g.id),
      '[]'::jsonb) INTO v_grants
      FROM public.drive_node_closure c
      JOIN public.drive_acl_grants g
        ON g.space_id=c.space_id AND g.node_id=c.ancestor_id
      JOIN public.drive_nodes anchor ON anchor.id=g.node_id
      LEFT JOIN public.users u ON u.id=g.subject_user_id
      LEFT JOIN public.directory_groups dg ON dg.id=g.subject_group_id
     WHERE c.space_id=v_node.space_id AND c.descendant_id=p_node_id
       AND g.state='active' AND (g.starts_at IS NULL OR g.starts_at<=now())
       AND (g.expires_at IS NULL OR g.expires_at>now())
       AND (g.max_uses IS NULL OR g.used_count<g.max_uses)
       AND CASE g.propagation WHEN 'self' THEN c.depth=0
             WHEN 'children' THEN c.depth BETWEEN 0 AND 1
             WHEN 'subtree' THEN true ELSE false END
       AND NOT EXISTS(
         SELECT 1 FROM public.drive_acl_breaks b
         JOIN public.drive_node_closure gb ON gb.space_id=g.space_id
          AND gb.ancestor_id=g.node_id AND gb.descendant_id=b.node_id
         JOIN public.drive_node_closure bt ON bt.space_id=b.space_id
          AND bt.ancestor_id=b.node_id AND bt.descendant_id=p_node_id
         WHERE b.space_id=g.space_id AND b.node_id<>g.node_id);
  ELSE
    v_grants:='[]'::jsonb;
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'capability',s.capability,'sourceKind',s.source_kind,
    'sourceId',CASE WHEN s.source_id IS NULL THEN NULL ELSE s.source_id::text END,
    'anchorNodeId',CASE WHEN s.anchor_node_id IS NULL THEN NULL ELSE s.anchor_node_id::text END
  ) ORDER BY s.capability,s.source_kind,s.source_id),'[]'::jsonb)
    INTO v_sources
    FROM public.drive_runtime_capability_sources(
      p_actor_user_id,v_node.space_id,p_node_id) s;

  RETURN jsonb_build_object(
    'nodeId',p_node_id::text,'spaceId',v_node.space_id::text,
    'nodeName',v_node.name,'nodeKind',v_node.kind,'aclMode',v_space.acl_mode,
    'epoch',v_epoch::text,'capabilities',to_jsonb(v_caps),
    'traverseOnly','traverse'=ANY(v_caps) AND NOT ('read_metadata'=ANY(v_caps)),
    'canManage',v_can_manage,
    'writesEnabled',COALESCE((SELECT enabled FROM public.feature_toggles
      WHERE key='feature.drive_node_acl_writes'),false),
    'governanceEnabled',COALESCE((SELECT enabled FROM public.feature_toggles
      WHERE key='feature.drive_access_governance'),false),
    'inheritanceBroken',EXISTS(SELECT 1 FROM public.drive_acl_breaks b
      WHERE b.space_id=v_node.space_id AND b.node_id=p_node_id),
    'grants',v_grants,'sources',v_sources,
    'presets',jsonb_build_array('viewer','contributor','editor','folder_manager')
  );
END;
$$;
SELECT apply_worker_ownership('drive_acl_node_detail(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_inheritance_preview(
  p_actor_user_id bigint,p_node_id bigint,p_break boolean
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_space_id bigint; v_epoch bigint; v_current boolean;
  v_nodes bigint; v_principals bigint; v_managers bigint;
BEGIN
  SELECT n.space_id INTO v_space_id FROM public.drive_nodes n
   JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_node_id AND n.purged_at IS NULL AND s.acl_mode='acl'
     AND s.chat_channel_id IS NULL AND s.meeting_id IS NULL
     AND public.drive_runtime_has_node_capability(
       p_actor_user_id,p_node_id,'manage_acl');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Drive inheritance preview is unavailable or forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden","opaque":true}';
  END IF;
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations WHERE space_id=v_space_id;
  SELECT EXISTS(SELECT 1 FROM public.drive_acl_breaks
    WHERE space_id=v_space_id AND node_id=p_node_id) INTO v_current;
  SELECT count(*) INTO v_nodes FROM public.drive_node_closure
   WHERE space_id=v_space_id AND ancestor_id=p_node_id;
  SELECT count(DISTINCT (g.subject_kind,COALESCE(g.subject_user_id,g.subject_group_id)))
    INTO v_principals
    FROM public.drive_node_closure c JOIN public.drive_acl_grants g
      ON g.space_id=c.space_id AND g.node_id=c.ancestor_id
   WHERE c.space_id=v_space_id AND c.descendant_id=p_node_id AND c.depth>0
     AND g.state='active' AND (g.expires_at IS NULL OR g.expires_at>now());
  SELECT count(DISTINCT s.source_id) INTO v_managers
    FROM public.drive_runtime_capability_sources(p_actor_user_id,v_space_id,p_node_id) s
   WHERE s.capability='manage_acl';
  RETURN jsonb_build_object(
    'nodeId',p_node_id::text,'spaceId',v_space_id::text,'epoch',v_epoch::text,
    'requestedBreak',p_break,'currentBreak',v_current,
    'changed',v_current IS DISTINCT FROM p_break,
    'affectedNodeCount',v_nodes,'affectedPrincipalCount',COALESCE(v_principals,0),
    'currentManagerSourceCount',COALESCE(v_managers,0),
    'mayRemoveOfflineContent',p_break AND COALESCE(v_principals,0)>0
  );
END;
$$;
SELECT apply_worker_ownership('drive_acl_inheritance_preview(bigint,bigint,boolean)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_quick_view(
  p_actor_user_id bigint,p_view text,p_max integer
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_result jsonb;
BEGIN
  IF p_view NOT IN ('shared','shares','requests') OR p_max NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'invalid Drive quick view'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"view"}';
  END IF;
  IF p_view='shared' THEN
    SELECT COALESCE(jsonb_agg(x.item ORDER BY x.created_at DESC,x.node_id),'[]'::jsonb)
      INTO v_result FROM (
      SELECT y.* FROM (
      SELECT DISTINCT ON (g.node_id) g.node_id,g.created_at,jsonb_build_object(
        'kind','shared','nodeId',g.node_id::text,'spaceId',g.space_id::text,
        'name',n.name,'nodeKind',n.kind,'spaceName',s.name,
        'source',CASE WHEN g.subject_kind='group' THEN 'group' ELSE 'direct' END,
        'preset',g.preset,'sharedAt',g.created_at,
        'capabilities',to_jsonb(public.drive_effective_capabilities(p_actor_user_id,g.node_id))
      ) AS item
      FROM public.drive_acl_grants g
      JOIN public.drive_nodes n ON n.id=g.node_id AND n.purged_at IS NULL
      JOIN public.drive_spaces s ON s.id=g.space_id AND s.acl_mode='acl'
      WHERE g.state='active' AND (g.starts_at IS NULL OR g.starts_at<=now())
        AND (g.expires_at IS NULL OR g.expires_at>now())
        AND ((g.subject_kind='user' AND g.subject_user_id=p_actor_user_id)
          OR (g.subject_kind='group' AND public.directory_group_effective_member(
            p_actor_user_id,g.subject_group_id)))
        AND public.drive_runtime_has_node_capability(p_actor_user_id,g.node_id,'read_metadata')
      ORDER BY g.node_id,g.created_at DESC
      ) y ORDER BY y.created_at DESC,y.node_id LIMIT p_max
    ) x;
  ELSIF p_view='shares' THEN
    SELECT COALESCE(jsonb_agg(x.item ORDER BY x.created_at DESC,x.node_id),'[]'::jsonb)
      INTO v_result FROM (
      SELECT y.* FROM (
      SELECT DISTINCT ON (g.node_id) g.node_id,g.created_at,jsonb_build_object(
        'kind','share','nodeId',g.node_id::text,'spaceId',g.space_id::text,
        'name',n.name,'nodeKind',n.kind,'spaceName',s.name,
        'activeGrantCount',(SELECT count(*) FROM public.drive_acl_grants a
          WHERE a.node_id=g.node_id AND a.state='active'),
        'sharedAt',g.created_at
      ) AS item
      FROM public.drive_acl_grants g
      JOIN public.drive_nodes n ON n.id=g.node_id AND n.purged_at IS NULL
      JOIN public.drive_spaces s ON s.id=g.space_id AND s.acl_mode='acl'
      WHERE g.state='active' AND public.drive_runtime_has_node_capability(
        p_actor_user_id,g.node_id,'manage_acl')
      ORDER BY g.node_id,g.created_at DESC
      ) y ORDER BY y.created_at DESC,y.node_id LIMIT p_max
    ) x;
  ELSE
    IF NOT COALESCE((SELECT enabled FROM public.feature_toggles
                      WHERE key='feature.drive_access_governance'),false) THEN
      RETURN '[]'::jsonb;
    END IF;
    SELECT COALESCE(jsonb_agg(x.item ORDER BY x.created_at DESC,x.request_id DESC),'[]'::jsonb)
      INTO v_result FROM (
      SELECT r.id AS request_id,r.created_at,jsonb_build_object(
        'kind','request','requestId',r.id::text,'nodeId',d.node_id::text,
        'spaceId',d.space_id::text,'name',n.name,'nodeKind',n.kind,
        'spaceName',s.name,'status',r.status,'capabilities',to_jsonb(d.requested_capabilities),
        'propagation',d.requested_propagation,'expiresAt',d.requested_expires_at,
        'createdAt',r.created_at,'grantId',CASE WHEN d.grant_id IS NULL THEN NULL ELSE d.grant_id::text END
      ) AS item
        FROM public.approval_requests r
        JOIN public.drive_access_request_details d ON d.request_id=r.id
        JOIN public.drive_nodes n ON n.id=d.node_id
        JOIN public.drive_spaces s ON s.id=d.space_id
       WHERE r.consumer_type='drive.access' AND r.requester_user_id=p_actor_user_id
       ORDER BY r.created_at DESC,r.id DESC LIMIT p_max
      ) x;
  END IF;
  RETURN v_result;
END;
$$;
SELECT apply_worker_ownership('drive_acl_quick_view(bigint,text,integer)'::regprocedure);
