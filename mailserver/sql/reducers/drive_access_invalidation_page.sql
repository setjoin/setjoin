-- Opaque, independently paged ACL invalidations for managed Drive clients.
-- The numeric identity cursor never crosses the wire.  Pages advance to the
-- last row SCANNED in this space even when every row is irrelevant to the
-- caller, preventing hidden-only starvation.
CREATE OR REPLACE FUNCTION drive_access_invalidation_page(
  p_user_id bigint,
  p_space_id bigint,
  p_after_token uuid DEFAULT NULL,
  p_max integer DEFAULT 200
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_after bigint := 0;
  v_floor bigint;
  v_epoch bigint;
  v_token_known boolean := false;
  v_has_current_access boolean := false;
  v_scanned_to bigint;
  v_next_token uuid;
  v_events jsonb;
  v_relevant boolean := false;
BEGIN
  IF p_max IS NULL OR p_max<1 OR p_max>1000 THEN
    RAISE EXCEPTION 'invalid access invalidation page size'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"max"}';
  END IF;

  SELECT g.retained_after_cursor,g.epoch,
         public.drive_user_has_space_access(p_user_id,g.space_id)
    INTO v_floor,v_epoch,v_has_current_access
    FROM public.drive_acl_generations g WHERE g.space_id=p_space_id;

  IF p_after_token IS NOT NULL THEN
    SELECT i.cursor INTO v_after
      FROM public.drive_access_invalidations i
     WHERE i.space_id=p_space_id AND i.scan_token=p_after_token;
    v_token_known:=FOUND;
    -- An unknown/pruned opaque token contains no usable position.  Return the
    -- same content-free reconcile instruction for existing and unknown space
    -- ids; this lets a fully revoked offline client purge without creating a
    -- resource-existence oracle.
    IF NOT v_token_known THEN
      RETURN jsonb_build_object(
        'cursor',NULL,'epoch',NULL,'invalidations','[]'::jsonb,
        'hasMore',false,'fullReconcile',true,'reason','cursorUnavailable');
    END IF;
    IF v_after<v_floor THEN
      RETURN jsonb_build_object(
        'cursor',p_after_token::text,'epoch',v_epoch::text,
        'invalidations','[]'::jsonb,'hasMore',false,
        'fullReconcile',true,'reason','cursorExpired');
    END IF;
    -- A retained token is permission to finish one purge, not a durable
    -- subscription after the caller loses the whole space.  Return no epoch,
    -- anchor, reason, or successor token that could expose later activity.
    IF NOT v_has_current_access THEN
      RETURN jsonb_build_object(
        'cursor',NULL,'epoch',NULL,'invalidations','[]'::jsonb,
        'hasMore',false,'fullReconcile',true,'reason','accessRevoked');
    END IF;
  ELSIF v_floor IS NULL OR NOT v_has_current_access THEN
    RAISE EXCEPTION 'drive space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  ELSE
    v_after:=v_floor;
  END IF;

  WITH scanned AS MATERIALIZED (
    SELECT i.cursor,i.scan_token,i.principal_kind,i.principal_id,
           i.principal_group_id,i.anchor_node_id,i.resulting_epoch,i.reason
      FROM public.drive_access_invalidations i
     WHERE i.space_id=p_space_id AND i.cursor>v_after
     ORDER BY i.cursor LIMIT p_max
  ), relevant AS MATERIALIZED (
    SELECT s.* FROM scanned s
     WHERE (s.principal_kind='user' AND s.principal_id=p_user_id)
        OR (s.principal_kind='group' AND public.directory_group_effective_member(
              p_user_id,s.principal_group_id))
        OR (s.principal_kind='all' AND v_has_current_access)
  )
  SELECT COALESCE((SELECT max(cursor) FROM scanned),v_after),
         (SELECT scan_token FROM scanned ORDER BY cursor DESC LIMIT 1),
         COALESCE((SELECT jsonb_agg(jsonb_build_object(
           'anchorNodeId',anchor_node_id::text,
           'epoch',resulting_epoch::text,'reason',reason,
           'fullReconcile',(anchor_node_id IS NULL OR reason='full_reconcile')
         ) ORDER BY cursor) FROM relevant),'[]'::jsonb),
         EXISTS(SELECT 1 FROM relevant)
    INTO v_scanned_to,v_next_token,v_events,v_relevant;

  IF v_next_token IS NULL THEN v_next_token:=p_after_token; END IF;
  RETURN jsonb_build_object(
    'cursor',CASE WHEN v_next_token IS NULL THEN NULL ELSE v_next_token::text END,
    'epoch',v_epoch::text,
    'invalidations',v_events,
    'hasMore',EXISTS(SELECT 1 FROM public.drive_access_invalidations i
                      WHERE i.space_id=p_space_id AND i.cursor>v_scanned_to),
    'fullReconcile',false,
    'relevant',v_relevant);
END;
$$;
SELECT apply_worker_ownership(
  'drive_access_invalidation_page(bigint,bigint,uuid,integer)'::regprocedure);

-- Stable, id-ordered visibility pages.  Every page checks the same expected
-- ACL epoch; a concurrent ACL mutation aborts the snapshot rather than
-- allowing a mixed before/after visible set.
CREATE OR REPLACE FUNCTION drive_visibility_snapshot_page(
  p_user_id bigint,
  p_space_id bigint,
  p_after_node_id bigint DEFAULT 0,
  p_expected_epoch bigint DEFAULT NULL,
  p_max integer DEFAULT 500
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_epoch bigint; v_rows jsonb; v_last bigint;
BEGIN
  IF p_max IS NULL OR p_max<1 OR p_max>500 OR p_after_node_id<0 THEN
    RAISE EXCEPTION 'invalid visibility page arguments'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"page"}';
  END IF;
  SELECT g.epoch INTO v_epoch FROM public.drive_acl_generations g
   WHERE g.space_id=p_space_id
     AND public.drive_user_has_space_access(p_user_id,g.space_id);
  IF v_epoch IS NULL THEN
    RAISE EXCEPTION 'drive space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF p_expected_epoch IS NOT NULL AND p_expected_epoch<>v_epoch THEN
    RAISE EXCEPTION 'Drive ACL epoch changed during visibility snapshot'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"epoch"}';
  END IF;
  WITH page AS MATERIALIZED (
    SELECT n.id,n.space_id,
           CASE
             WHEN n.parent_id IS NULL
               OR public.drive_runtime_has_node_capability(
                    p_user_id,n.parent_id,'read_metadata')
             THEN n.parent_id
             ELSE NULL
           END AS parent_id,
           n.kind,n.name,n.deleted_at,
           f.head_version_id,v.content_sha256,f.size_bytes,f.content_type,
           COALESCE((SELECT count(*) FROM public.drive_file_branches b
                      WHERE b.file_node_id=n.id AND b.status IN ('open','review')),0) AS branch_count
      FROM public.drive_nodes n
      LEFT JOIN public.drive_files f ON f.node_id=n.id
      LEFT JOIN public.drive_file_versions v ON v.id=f.head_version_id
     WHERE n.space_id=p_space_id AND n.id>p_after_node_id
       AND n.deleted_at IS NULL
       AND public.drive_runtime_has_node_capability(p_user_id,n.id,'read_metadata')
     ORDER BY n.id LIMIT p_max
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'nodeId',id,'spaceId',space_id,'parentId',parent_id,'kind',kind,
           'name',name,'deletedAt',deleted_at,'headVersionId',head_version_id,
           'contentSha256',content_sha256,'sizeBytes',size_bytes,
           'contentType',content_type,'branchCount',branch_count,
           'capabilities',to_jsonb(ARRAY(
             SELECT capability FROM public.drive_runtime_capability_sources(
               p_user_id,p_space_id,id) ORDER BY capability)),
           'traverseOnly',(
             public.drive_runtime_has_node_capability(p_user_id,id,'traverse')
             AND NOT public.drive_runtime_has_node_capability(p_user_id,id,'read_metadata')
           )) ORDER BY id),'[]'::jsonb),
         COALESCE(max(id),p_after_node_id)
    INTO v_rows,v_last FROM page;
  RETURN jsonb_build_object(
    'epoch',v_epoch::text,
    'rootCapabilities',to_jsonb(ARRAY(
      SELECT c FROM unnest(public.drive_acl_capability_catalog()) c
       WHERE public.drive_runtime_has_space_root_capability(p_user_id,p_space_id,c)
      ORDER BY c)),
    'nodes',v_rows,'nextAfter',v_last::text,
    'hasMore',EXISTS(SELECT 1 FROM public.drive_nodes n
      WHERE n.space_id=p_space_id AND n.id>v_last AND n.deleted_at IS NULL
        AND public.drive_runtime_has_node_capability(p_user_id,n.id,'read_metadata')));
END;
$$;
SELECT apply_worker_ownership(
  'drive_visibility_snapshot_page(bigint,bigint,bigint,bigint,integer)'::regprocedure);
