-- drive_effective_access.sql -- canonical Drive node authorization facts.
--
-- This is the only module that combines legacy root roles, direct node grants,
-- inheritance breaks, bound-content immutability, and Guest outer caps. Exact
-- checks and set-returning list projections consume the same source relation so
-- policy cannot drift between a remembered-id lookup and a folder listing.

CREATE OR REPLACE FUNCTION drive_root_role_capabilities(p_role text)
RETURNS text[] LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT CASE p_role
    WHEN 'viewer' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download'
    ]::text[]
    WHEN 'editor' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete'
    ]::text[]
    WHEN 'manager' THEN ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete',
      'manage_acl','view_audit'
    ]::text[]
    ELSE ARRAY[]::text[]
  END
$$;
SELECT apply_worker_ownership('drive_root_role_capabilities(text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_effective_capability_sources_set(
  p_user_id bigint,
  p_space_id bigint,
  p_node_ids bigint[],
  p_capability text DEFAULT NULL
) RETURNS TABLE(
  node_id bigint,
  capability text,
  source_kind text,
  source_id bigint,
  anchor_node_id bigint
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
WITH actor AS MATERIALIZED (
  SELECT u.id,
         u.enabled,
         public.is_guest_account(u.id) AS is_guest,
         CASE WHEN public.is_guest_account(u.id)
              THEN public.check_user_app_entitlement(u.id, 'drive')
                   AND EXISTS (
                     SELECT 1
                       FROM public.guest_accounts ga
                      WHERE ga.user_id = u.id
                        AND ga.status = 'active'
                        AND (ga.expires_at IS NULL OR ga.expires_at >= now())
                   )
              ELSE true
          END AS app_eligible,
         CASE WHEN public.is_guest_account(u.id)
              THEN public.guest_profile_flag(u.id, 'allow_download')
              ELSE true
          END AS download_eligible
    FROM public.users u
   WHERE u.id = p_user_id
), space_fact AS MATERIALIZED (
  SELECT s.id, s.acl_mode, s.chat_channel_id, s.meeting_id,
         public.drive_member_role(s.id, p_user_id) AS root_role
    FROM public.drive_spaces s
   WHERE s.id = p_space_id
), targets AS MATERIALIZED (
  SELECT n.id
    FROM public.drive_nodes n
   WHERE n.space_id = p_space_id
     AND n.purged_at IS NULL
     AND (p_node_ids IS NULL OR n.id = ANY(p_node_ids))
), root_sources AS (
  SELECT t.id AS node_id,
         c.capability,
         'space_role'::text AS source_kind,
         p_space_id AS source_id,
         NULL::bigint AS anchor_node_id
    FROM targets t
    CROSS JOIN space_fact s
   CROSS JOIN LATERAL unnest(public.drive_root_role_capabilities(s.root_role)) c(capability)
   WHERE s.root_role IS NOT NULL
     AND (p_capability IS NULL OR c.capability = p_capability)
     AND NOT EXISTS (
       SELECT 1
         FROM public.drive_acl_breaks b
         JOIN public.drive_node_closure bt
           ON bt.space_id = b.space_id
          AND bt.ancestor_id = b.node_id
          AND bt.descendant_id = t.id
        WHERE b.space_id = p_space_id
     )
), direct_sources AS (
  SELECT t.id AS node_id,
         c.capability,
         CASE WHEN g.subject_kind='group' THEN 'group' ELSE 'direct' END::text AS source_kind,
         g.id AS source_id,
         g.node_id AS anchor_node_id
    FROM targets t
    JOIN public.drive_node_closure gt
      ON gt.space_id = p_space_id
     AND gt.descendant_id = t.id
    JOIN public.drive_acl_grants g
      ON g.space_id = gt.space_id
     AND g.node_id = gt.ancestor_id
     AND (
       (g.subject_kind='user' AND g.subject_user_id=p_user_id)
       OR
       (g.subject_kind='group'
        AND COALESCE((SELECT enabled FROM public.feature_toggles
                      WHERE key='feature.directory_group_authority'),false)
        AND public.directory_group_effective_member(p_user_id,g.subject_group_id))
     )
    CROSS JOIN space_fact s
    CROSS JOIN LATERAL unnest(g.capabilities) c(capability)
   WHERE s.acl_mode IN ('shadow','acl')
     AND (p_capability IS NULL OR c.capability = p_capability)
     AND s.chat_channel_id IS NULL
     AND s.meeting_id IS NULL
     AND g.state = 'active'
     AND (g.starts_at IS NULL OR g.starts_at <= now())
     AND (g.expires_at IS NULL OR g.expires_at > now())
     AND (g.max_uses IS NULL OR g.used_count < g.max_uses)
     AND CASE g.propagation
           WHEN 'self' THEN gt.depth = 0
           WHEN 'children' THEN gt.depth BETWEEN 0 AND 1
           WHEN 'subtree' THEN true
           ELSE false
         END
     AND NOT EXISTS (
       SELECT 1
         FROM public.drive_acl_breaks b
         JOIN public.drive_node_closure gb
           ON gb.space_id = g.space_id
          AND gb.ancestor_id = g.node_id
          AND gb.descendant_id = b.node_id
         JOIN public.drive_node_closure bt
           ON bt.space_id = b.space_id
          AND bt.ancestor_id = b.node_id
          AND bt.descendant_id = t.id
        WHERE b.space_id = g.space_id
          AND b.node_id <> g.node_id
     )
), ancestor_traverse_sources AS (
  -- A descendant grant must be reachable through its real folder path.  Give
  -- ancestors only the synthetic traverse capability: this reveals the
  -- breadcrumb names needed to walk A -> B -> granted C, while sibling rows
  -- and every content capability remain absent.
  SELECT t.id AS node_id,
         'traverse'::text AS capability,
         CASE WHEN g.subject_kind='group' THEN 'group' ELSE 'direct' END::text AS source_kind,
         g.id AS source_id,
         g.node_id AS anchor_node_id
    FROM targets t
    JOIN public.drive_node_closure path
      ON path.space_id = p_space_id
     AND path.ancestor_id = t.id
     AND path.depth > 0
    JOIN public.drive_acl_grants g
      ON g.space_id = path.space_id
     AND g.node_id = path.descendant_id
     AND (
       (g.subject_kind='user' AND g.subject_user_id=p_user_id)
       OR
       (g.subject_kind='group'
        AND COALESCE((SELECT enabled FROM public.feature_toggles
                      WHERE key='feature.directory_group_authority'),false)
        AND public.directory_group_effective_member(p_user_id,g.subject_group_id))
     )
    CROSS JOIN space_fact s
   WHERE s.acl_mode IN ('shadow','acl')
     AND (p_capability IS NULL OR p_capability='traverse')
     AND s.chat_channel_id IS NULL
     AND s.meeting_id IS NULL
     AND g.state='active'
     AND (g.starts_at IS NULL OR g.starts_at<=now())
     AND (g.expires_at IS NULL OR g.expires_at>now())
     AND (g.max_uses IS NULL OR g.used_count<g.max_uses)
), folder_admin_sources AS (
  -- Compatibility source until A4 migrates drive_folder_admins to grants.
  SELECT t.id AS node_id,
         c.capability,
         'folder_admin'::text AS source_kind,
         fa.node_id AS source_id,
         fa.node_id AS anchor_node_id
    FROM targets t
    JOIN public.drive_node_closure ft
      ON ft.space_id = p_space_id
     AND ft.descendant_id = t.id
    JOIN public.drive_folder_admins fa
      ON fa.space_id = ft.space_id
     AND fa.node_id = ft.ancestor_id
     AND fa.user_id = p_user_id
    CROSS JOIN LATERAL unnest(public.drive_acl_preset_capabilities('folder_manager')) c(capability)
   WHERE NOT EXISTS (
       SELECT 1
         FROM public.drive_acl_breaks b
         JOIN public.drive_node_closure fb
           ON fb.space_id = fa.space_id
          AND fb.ancestor_id = fa.node_id
          AND fb.descendant_id = b.node_id
         JOIN public.drive_node_closure bt
           ON bt.space_id = b.space_id
          AND bt.ancestor_id = b.node_id
          AND bt.descendant_id = t.id
        WHERE b.space_id = fa.space_id
         AND b.node_id <> fa.node_id
     )
     AND (p_capability IS NULL OR c.capability = p_capability)
), folder_admin_ancestor_traverse_sources AS (
  SELECT t.id AS node_id,
         'traverse'::text AS capability,
         'folder_admin'::text AS source_kind,
         fa.node_id AS source_id,
         fa.node_id AS anchor_node_id
    FROM targets t
    JOIN public.drive_node_closure path
      ON path.space_id=p_space_id
     AND path.ancestor_id=t.id
     AND path.depth>0
    JOIN public.drive_folder_admins fa
      ON fa.space_id=path.space_id
     AND fa.node_id=path.descendant_id
     AND fa.user_id=p_user_id
   WHERE p_capability IS NULL OR p_capability='traverse'
), raw_sources AS (
  SELECT * FROM root_sources
  UNION ALL
  SELECT * FROM direct_sources
  UNION ALL
  SELECT * FROM ancestor_traverse_sources
  UNION ALL
  SELECT * FROM folder_admin_sources
  UNION ALL
  SELECT * FROM folder_admin_ancestor_traverse_sources
), bounded AS (
  SELECT r.*,
         a.is_guest,
         a.download_eligible,
         EXISTS (
           SELECT 1 FROM public.chat_message_attachments ca
            WHERE ca.file_node_id = r.node_id
         ) OR EXISTS (
           SELECT 1 FROM public.meeting_recordings mr
            WHERE mr.file_node_id = r.node_id
         ) AS immutable_binding
    FROM raw_sources r
    CROSS JOIN actor a
   WHERE a.enabled AND a.app_eligible
)
SELECT DISTINCT b.node_id, b.capability, b.source_kind, b.source_id, b.anchor_node_id
  FROM bounded b
 WHERE (NOT b.is_guest OR b.capability IN (
          'traverse','list_children','read_metadata','preview','download'
       ))
   AND (NOT b.is_guest OR b.capability <> 'download' OR b.download_eligible)
   AND (NOT b.immutable_binding OR b.capability NOT IN (
          'modify_content','rename','move','delete'
       ))
$$;
SELECT apply_worker_ownership(
  'drive_effective_capability_sources_set(bigint,bigint,bigint[],text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_effective_capability_sources(
  p_user_id bigint,
  p_space_id bigint,
  p_node_id bigint DEFAULT NULL
) RETURNS TABLE(
  node_id bigint,
  capability text,
  source_kind text,
  source_id bigint,
  anchor_node_id bigint
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT * FROM public.drive_effective_capability_sources_set(
    p_user_id,p_space_id,
    CASE WHEN p_node_id IS NULL THEN NULL ELSE ARRAY[p_node_id]::bigint[] END,
    NULL
  )
$$;
SELECT apply_worker_ownership(
  'drive_effective_capability_sources(bigint,bigint,bigint)'::regprocedure);

-- Runtime list projection is deliberately separate from the canonical shadow
-- evaluator. In legacy/shadow mode it emits only the existing root-role facts;
-- direct grants and inheritance breaks cannot become live through a list API.
CREATE OR REPLACE FUNCTION drive_runtime_capability_sources_set(
  p_user_id bigint,
  p_space_id bigint,
  p_node_ids bigint[],
  p_capability text DEFAULT NULL
) RETURNS TABLE(
  node_id bigint,
  capability text,
  source_kind text,
  source_id bigint,
  anchor_node_id bigint
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
WITH space_fact AS MATERIALIZED (
  SELECT s.id, s.acl_mode,
         public.drive_member_role(s.id, p_user_id) AS root_role
    FROM public.drive_spaces s
   WHERE s.id = p_space_id
), actor AS MATERIALIZED (
  SELECT u.enabled,
         public.is_guest_account(u.id) AS is_guest,
         CASE WHEN public.is_guest_account(u.id)
              THEN public.check_user_app_entitlement(u.id, 'drive')
                   AND EXISTS (
                     SELECT 1 FROM public.guest_accounts ga
                      WHERE ga.user_id = u.id
                        AND ga.status = 'active'
                        AND (ga.expires_at IS NULL OR ga.expires_at >= now())
                   )
              ELSE true
          END AS app_eligible,
         CASE WHEN public.is_guest_account(u.id)
              THEN public.guest_profile_flag(u.id, 'allow_download')
              ELSE true
          END AS download_eligible
    FROM public.users u
   WHERE u.id = p_user_id
), canonical AS (
  SELECT x.*
    FROM space_fact s
    CROSS JOIN LATERAL public.drive_effective_capability_sources_set(
      p_user_id, p_space_id, p_node_ids, p_capability
    ) x
   WHERE s.acl_mode = 'acl'
), legacy AS (
  SELECT n.id AS node_id,
         c.capability,
         'space_role'::text AS source_kind,
         p_space_id AS source_id,
         NULL::bigint AS anchor_node_id
    FROM space_fact s
    CROSS JOIN actor a
    JOIN public.drive_nodes n
      ON n.space_id = p_space_id
     AND n.purged_at IS NULL
     AND (p_node_ids IS NULL OR n.id = ANY(p_node_ids))
    CROSS JOIN LATERAL unnest(public.drive_root_role_capabilities(s.root_role)) c(capability)
   WHERE s.acl_mode <> 'acl'
     AND (p_capability IS NULL OR c.capability = p_capability)
     AND s.root_role IS NOT NULL
     AND a.enabled AND a.app_eligible
     AND (NOT a.is_guest OR c.capability IN (
          'traverse','list_children','read_metadata','preview','download'
     ))
     AND (NOT a.is_guest OR c.capability <> 'download' OR a.download_eligible)
     AND (
       c.capability NOT IN ('modify_content','rename','move','delete')
       OR NOT (
         EXISTS (SELECT 1 FROM public.chat_message_attachments ca
                  WHERE ca.file_node_id = n.id)
         OR EXISTS (SELECT 1 FROM public.meeting_recordings mr
                     WHERE mr.file_node_id = n.id)
       )
     )
)
SELECT * FROM canonical
UNION ALL
SELECT * FROM legacy
$$;
SELECT apply_worker_ownership(
  'drive_runtime_capability_sources_set(bigint,bigint,bigint[],text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_runtime_capability_sources(
  p_user_id bigint,
  p_space_id bigint,
  p_node_id bigint DEFAULT NULL
) RETURNS TABLE(
  node_id bigint,
  capability text,
  source_kind text,
  source_id bigint,
  anchor_node_id bigint
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT * FROM public.drive_runtime_capability_sources_set(
    p_user_id,p_space_id,
    CASE WHEN p_node_id IS NULL THEN NULL ELSE ARRAY[p_node_id]::bigint[] END,
    NULL
  )
$$;
SELECT apply_worker_ownership(
  'drive_runtime_capability_sources(bigint,bigint,bigint)'::regprocedure);

-- Virtual-space-root operations (create a new top-level item, govern space
-- metadata) must come from the root adapter, never from an unrelated direct
-- grant elsewhere in the space.
CREATE OR REPLACE FUNCTION drive_runtime_has_space_root_capability(
  p_user_id bigint,p_space_id bigint,p_capability text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT CASE WHEN EXISTS(SELECT 1 FROM public.drive_nodes n
                           WHERE n.space_id=p_space_id AND n.parent_id IS NULL
                             AND n.purged_at IS NULL)
    THEN EXISTS(
      SELECT 1 FROM public.drive_nodes n
      CROSS JOIN LATERAL public.drive_runtime_capability_sources(
        p_user_id,p_space_id,n.id) s
       WHERE n.space_id=p_space_id AND n.parent_id IS NULL
         AND n.purged_at IS NULL
         AND s.capability=p_capability AND s.source_kind='space_role'
    )
    ELSE EXISTS(
      SELECT 1 FROM public.users u
       WHERE u.id=p_user_id AND u.enabled
         AND (
           NOT public.is_guest_account(u.id)
           OR (
             public.check_user_app_entitlement(u.id,'drive')
             AND EXISTS(SELECT 1 FROM public.guest_accounts ga
                         WHERE ga.user_id=u.id AND ga.status='active'
                           AND (ga.expires_at IS NULL OR ga.expires_at>=now()))
             AND (p_capability<>'download'
                  OR public.guest_profile_flag(u.id,'allow_download'))
           )
         )
         AND p_capability=ANY(public.drive_root_role_capabilities(
           public.drive_member_role(p_space_id,p_user_id)))
    )
  END
$$;
SELECT apply_worker_ownership(
  'drive_runtime_has_space_root_capability(bigint,bigint,text)'::regprocedure);

-- A bounded-use lease consumes one specific grant's budget.  Aggregate
-- capability is necessary but insufficient: the selected direct/group grant
-- must itself apply to this user or one principal could exhaust another's
-- allowance.
CREATE OR REPLACE FUNCTION drive_acl_grant_subject_applies(
  p_user_id bigint,p_grant_id bigint
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT COALESCE((
    SELECT CASE g.subject_kind
      WHEN 'user' THEN g.subject_user_id=p_user_id
      WHEN 'group' THEN
        COALESCE((SELECT enabled FROM public.feature_toggles
                   WHERE key='feature.directory_group_authority'),false)
        AND public.directory_group_effective_member(
          p_user_id,g.subject_group_id)
      ELSE false
    END
      FROM public.drive_acl_grants g WHERE g.id=p_grant_id
  ),false)
$$;
SELECT apply_worker_ownership(
  'drive_acl_grant_subject_applies(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_effective_capabilities(
  p_user_id bigint, p_node_id bigint
) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((
    SELECT array_agg(d.capability ORDER BY
             array_position(public.drive_acl_capability_catalog(), d.capability))
      FROM (
        SELECT DISTINCT s.capability
          FROM public.drive_effective_capability_sources(
            p_user_id, n.space_id, n.id
          ) s
      ) d
  ), ARRAY[]::text[])
    FROM public.drive_nodes n
   WHERE n.id = p_node_id
$$;
SELECT apply_worker_ownership('drive_effective_capabilities(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_has_node_capability(
  p_user_id bigint, p_node_id bigint, p_capability text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT p_capability = ANY(public.drive_acl_capability_catalog())
     AND p_capability = ANY(public.drive_effective_capabilities(p_user_id, p_node_id))
$$;
SELECT apply_worker_ownership('drive_has_node_capability(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_legacy_node_capabilities(
  p_user_id bigint, p_node_id bigint
) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
WITH fact AS (
  SELECT n.id,
         public.drive_member_role(n.space_id, p_user_id) AS role,
         public.is_guest_account(p_user_id) AS is_guest,
         u.enabled,
         EXISTS (SELECT 1 FROM public.chat_message_attachments ca
                  WHERE ca.file_node_id = n.id)
           OR EXISTS (SELECT 1 FROM public.meeting_recordings mr
                       WHERE mr.file_node_id = n.id) AS immutable_binding
    FROM public.drive_nodes n
    JOIN public.users u ON u.id = p_user_id
   WHERE n.id = p_node_id AND n.purged_at IS NULL
), caps AS (
  SELECT c.capability, f.*
    FROM fact f
    CROSS JOIN LATERAL unnest(
      public.drive_root_role_capabilities(f.role)
      || CASE WHEN public.drive_subtree_admin(p_user_id,p_node_id)
              THEN public.drive_acl_preset_capabilities('folder_manager')
              ELSE ARRAY[]::text[] END
    ) c(capability)
   WHERE f.enabled
     AND (NOT f.is_guest OR (
       public.check_user_app_entitlement(p_user_id, 'drive')
       AND EXISTS (SELECT 1 FROM public.guest_accounts ga
                    WHERE ga.user_id = p_user_id AND ga.status = 'active'
                      AND (ga.expires_at IS NULL OR ga.expires_at >= now()))
     ))
)
SELECT COALESCE(array_agg(capability ORDER BY
         array_position(public.drive_acl_capability_catalog(), capability)),
       ARRAY[]::text[])
  FROM caps
 WHERE (NOT is_guest OR capability IN (
          'traverse','list_children','read_metadata','preview','download'
       ))
   AND (NOT is_guest OR capability <> 'download'
        OR public.guest_profile_flag(p_user_id, 'allow_download'))
   AND (NOT immutable_binding OR capability NOT IN (
          'modify_content','rename','move','delete'
       ))
$$;
SELECT apply_worker_ownership('drive_legacy_node_capabilities(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_runtime_has_node_capability(
  p_user_id bigint, p_node_id bigint, p_capability text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT p_capability = ANY(public.drive_acl_capability_catalog())
     AND CASE s.acl_mode
           WHEN 'acl' THEN public.drive_has_node_capability(
                             p_user_id, p_node_id, p_capability)
           ELSE p_capability = ANY(public.drive_legacy_node_capabilities(
                                    p_user_id, p_node_id))
         END
    FROM public.drive_nodes n
    JOIN public.drive_spaces s ON s.id = n.space_id
   WHERE n.id = p_node_id
$$;
SELECT apply_worker_ownership(
  'drive_runtime_has_node_capability(bigint,bigint,text)'::regprocedure);

-- Uniform existence/authority projection for mutation reducers.  A caller
-- who may inspect the node receives a bounded forbidden response when an
-- exact capability is absent; an invisible/unknown node remains a 404.
CREATE OR REPLACE FUNCTION drive_require_node_capability(
  p_user_id bigint,p_node_id bigint,p_capability text
) RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF public.drive_runtime_has_node_capability(
       p_user_id,p_node_id,p_capability) THEN
    RETURN;
  END IF;
  IF public.drive_runtime_has_node_capability(
       p_user_id,p_node_id,'read_metadata') THEN
    RAISE EXCEPTION 'Drive capability required' USING ERRCODE='BZ140',
      HINT=jsonb_build_object('type','forbidden','capability',p_capability)::text;
  END IF;
  RAISE EXCEPTION 'Drive node not found' USING ERRCODE='BZ139',
    HINT='{"type":"notFound","detail":"node not found"}';
END;
$$;
SELECT apply_worker_ownership(
  'drive_require_node_capability(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_user_has_space_access(
  p_user_id bigint, p_space_id bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
WITH fact AS (
  SELECT s.*,
         public.drive_member_role(s.id, p_user_id) AS role,
         u.enabled,
         public.is_guest_account(p_user_id) AS is_guest
    FROM public.drive_spaces s
    JOIN public.users u ON u.id = p_user_id
   WHERE s.id = p_space_id
)
SELECT COALESCE((
  SELECT enabled
     AND (NOT is_guest OR (
       public.check_user_app_entitlement(p_user_id, 'drive')
       AND EXISTS (SELECT 1 FROM public.guest_accounts ga
                    WHERE ga.user_id = p_user_id AND ga.status = 'active'
                      AND (ga.expires_at IS NULL OR ga.expires_at >= now()))
     ))
     AND (
       role IS NOT NULL
       OR (acl_mode = 'acl' AND chat_channel_id IS NULL AND meeting_id IS NULL
           AND EXISTS (
             SELECT 1
               FROM public.drive_runtime_capability_sources(
                      p_user_id,p_space_id,NULL) c
           ))
       OR (chat_channel_id IS NULL AND meeting_id IS NULL
           AND owner_user_id = p_user_id)
     )
    FROM fact
), false)
OR public.drive_has_admin_perm(p_user_id, 'drive.view')
$$;
SELECT apply_worker_ownership('drive_user_has_space_access(bigint,bigint)'::regprocedure);

-- Compatibility display role for the existing space-list wire field.  It is
-- a projection only: authorization continues to consume exact capabilities.
CREATE OR REPLACE FUNCTION drive_space_access_role(
  p_user_id bigint,p_space_id bigint
) RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT COALESCE(public.drive_member_role(p_space_id,p_user_id),
    CASE
      WHEN EXISTS(SELECT 1 FROM public.drive_runtime_capability_sources(
        p_user_id,p_space_id,NULL) c WHERE c.capability='manage_acl') THEN 'manager'
      WHEN EXISTS(SELECT 1 FROM public.drive_runtime_capability_sources(
        p_user_id,p_space_id,NULL) c
        WHERE c.capability IN ('create_child','modify_content')) THEN 'editor'
      WHEN public.drive_user_has_space_access(p_user_id,p_space_id) THEN 'viewer'
      ELSE NULL
    END)
$$;
SELECT apply_worker_ownership(
  'drive_space_access_role(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_require_space_root_capability(
  p_user_id bigint,p_space_id bigint,p_capability text
) RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
BEGIN
  IF public.drive_runtime_has_space_root_capability(
       p_user_id,p_space_id,p_capability) THEN
    RETURN;
  END IF;
  IF public.drive_user_has_space_access(p_user_id,p_space_id) THEN
    RAISE EXCEPTION 'Drive root capability required' USING ERRCODE='BZ140',
      HINT=jsonb_build_object('type','forbidden','capability',p_capability)::text;
  END IF;
  RAISE EXCEPTION 'Drive space not found' USING ERRCODE='BZ139',
    HINT='{"type":"notFound","detail":"space not found"}';
END;
$$;
SELECT apply_worker_ownership(
  'drive_require_space_root_capability(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_authorize_node(
  p_user_id bigint, p_node_id bigint, p_requested_capabilities text[]
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  v_caps text[];
  v_space_id bigint;
  v_epoch bigint;
  v_protocol integer;
  v_acl_mode text;
BEGIN
  IF NOT public.drive_acl_capabilities_valid(p_requested_capabilities) THEN
    RAISE EXCEPTION 'invalid Drive capability request'
      USING ERRCODE='BZ252',
            HINT='{"type":"invalidArguments","detail":"unknown or duplicate capability"}';
  END IF;

  SELECT n.space_id, s.acl_protocol_version, s.acl_mode
    INTO v_space_id, v_protocol, v_acl_mode
    FROM public.drive_nodes n
    JOIN public.drive_spaces s ON s.id = n.space_id
   WHERE n.id = p_node_id AND n.purged_at IS NULL;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('allowed', false, 'capabilities', '[]'::jsonb);
  END IF;

  v_caps := CASE v_acl_mode
    WHEN 'acl' THEN public.drive_effective_capabilities(p_user_id, p_node_id)
    ELSE public.drive_legacy_node_capabilities(p_user_id, p_node_id)
  END;
  SELECT epoch INTO v_epoch
    FROM public.drive_acl_generations WHERE space_id = v_space_id;

  RETURN jsonb_build_object(
    'allowed', p_requested_capabilities <@ v_caps,
    'nodeId', p_node_id::text,
    'spaceId', v_space_id::text,
    'capabilities', to_jsonb(v_caps),
    'aclEpoch', COALESCE(v_epoch, 0)::text,
    'protocolVersion', v_protocol
  );
END;
$$;
SELECT apply_worker_ownership('drive_authorize_node(bigint,bigint,text[])'::regprocedure);

CREATE OR REPLACE FUNCTION drive_access_explain(
  p_user_id bigint, p_node_id bigint
) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
WITH node_fact AS (
  SELECT n.space_id FROM public.drive_nodes n WHERE n.id = p_node_id
), distinct_sources AS (
  SELECT DISTINCT s.source_kind, s.anchor_node_id, s.capability
    FROM node_fact n
    CROSS JOIN LATERAL public.drive_runtime_capability_sources(
      p_user_id, n.space_id, p_node_id
    ) s
), grouped AS (
  SELECT s.source_kind,
         s.anchor_node_id,
         array_agg(s.capability ORDER BY
           array_position(public.drive_acl_capability_catalog(), s.capability)) AS capabilities
    FROM distinct_sources s
   GROUP BY s.source_kind, s.anchor_node_id
   ORDER BY s.source_kind, s.anchor_node_id NULLS FIRST
   LIMIT 50
)
SELECT jsonb_build_object(
  'nodeId', p_node_id::text,
  'capabilities', COALESCE((
    SELECT to_jsonb(array_agg(capability ORDER BY
      array_position(public.drive_acl_capability_catalog(), capability)))
      FROM (SELECT DISTINCT capability FROM distinct_sources) c
  ), '[]'::jsonb),
  'sources', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'kind', source_kind,
      'anchorNodeId', CASE WHEN anchor_node_id IS NULL
                           THEN NULL ELSE anchor_node_id::text END,
      'capabilities', capabilities
    ) ORDER BY source_kind, anchor_node_id NULLS FIRST)
      FROM grouped
  ), '[]'::jsonb),
  'truncated', (SELECT count(*) > 50 FROM (
    SELECT 1 FROM distinct_sources
     GROUP BY source_kind, anchor_node_id
  ) q)
)
$$;
SELECT apply_worker_ownership('drive_access_explain(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_visible_nodes(
  p_user_id bigint,
  p_space_id bigint,
  p_after_node_id bigint DEFAULT 0,
  p_limit integer DEFAULT 200
) RETURNS TABLE(
  node_id bigint,
  parent_id bigint,
  kind text,
  name text,
  capabilities text[]
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
WITH candidate_nodes AS MATERIALIZED (
  SELECT n.id
    FROM public.drive_nodes n
   WHERE n.space_id=p_space_id
     AND n.id>GREATEST(COALESCE(p_after_node_id,0),0)
     AND n.purged_at IS NULL
), candidate_ids AS MATERIALIZED (
  SELECT COALESCE(array_agg(id ORDER BY id),ARRAY[]::bigint[]) AS ids
    FROM candidate_nodes
), fast_root AS MATERIALIZED (
  SELECT public.drive_runtime_has_space_root_capability(
           p_user_id,p_space_id,'read_metadata')
         AND NOT EXISTS(
           SELECT 1 FROM public.drive_acl_breaks b WHERE b.space_id=p_space_id
         ) AS applies
), readable AS MATERIALIZED (
  SELECT DISTINCT x.node_id
    FROM candidate_ids c
    CROSS JOIN LATERAL (
      SELECT s.node_id FROM public.drive_runtime_capability_sources_set(
        p_user_id,p_space_id,c.ids,'read_metadata') s
      UNION
      SELECT s.node_id FROM public.drive_runtime_capability_sources_set(
        p_user_id,p_space_id,c.ids,'traverse') s
    ) x
   WHERE NOT (SELECT applies FROM fast_root)
), page AS MATERIALIZED (
  SELECT q.node_id
    FROM (
      SELECT n.id AS node_id FROM candidate_nodes n
       WHERE (SELECT applies FROM fast_root)
      UNION ALL
      SELECT r.node_id FROM readable r
       WHERE NOT (SELECT applies FROM fast_root)
    ) q
   ORDER BY q.node_id
   LIMIT LEAST(GREATEST(COALESCE(p_limit,200),1),1000)
), caps AS MATERIALIZED (
  SELECT s.node_id,
         array_agg(s.capability ORDER BY
           array_position(public.drive_acl_capability_catalog(), s.capability)) AS capabilities
    FROM (
      SELECT DISTINCT x.node_id, x.capability
        FROM public.drive_runtime_capability_sources_set(
          p_user_id,p_space_id,
          COALESCE((SELECT array_agg(node_id) FROM page),ARRAY[]::bigint[]),
          NULL) x
    ) s
   GROUP BY s.node_id
)
SELECT n.id, n.parent_id, n.kind, n.name, c.capabilities
  FROM page p
  JOIN caps c ON c.node_id=p.node_id
  JOIN public.drive_nodes n ON n.id = c.node_id AND n.space_id = p_space_id
 ORDER BY n.id
$$;
SELECT apply_worker_ownership('drive_visible_nodes(bigint,bigint,bigint,integer)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_visible_children(
  p_user_id bigint,
  p_space_id bigint,
  p_parent_id bigint,
  p_after_node_id bigint DEFAULT 0,
  p_limit integer DEFAULT 200
) RETURNS TABLE(
  node_id bigint,
  parent_id bigint,
  kind text,
  name text,
  capabilities text[]
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
WITH candidate_nodes AS MATERIALIZED (
  SELECT n.id,n.name
    FROM public.drive_nodes n
   WHERE n.space_id=p_space_id
     AND n.parent_id IS NOT DISTINCT FROM p_parent_id
     AND n.id>GREATEST(COALESCE(p_after_node_id,0),0)
     AND n.deleted_at IS NULL
     AND n.purged_at IS NULL
), candidate_ids AS MATERIALIZED (
  SELECT COALESCE(array_agg(id ORDER BY id),ARRAY[]::bigint[]) AS ids
    FROM candidate_nodes
), fast_root AS MATERIALIZED (
  SELECT public.drive_runtime_has_space_root_capability(
           p_user_id,p_space_id,'read_metadata')
         AND NOT EXISTS(
           SELECT 1 FROM public.drive_acl_breaks b WHERE b.space_id=p_space_id
         ) AS applies
), readable AS MATERIALIZED (
  SELECT DISTINCT x.node_id
    FROM candidate_ids c
    CROSS JOIN LATERAL (
      SELECT s.node_id FROM public.drive_runtime_capability_sources_set(
        p_user_id,p_space_id,c.ids,'read_metadata') s
      UNION
      SELECT s.node_id FROM public.drive_runtime_capability_sources_set(
        p_user_id,p_space_id,c.ids,'traverse') s
    ) x
   WHERE NOT (SELECT applies FROM fast_root)
), page AS MATERIALIZED (
  SELECT q.node_id
    FROM (
      SELECT n.id AS node_id FROM candidate_nodes n
       WHERE (SELECT applies FROM fast_root)
      UNION ALL
      SELECT r.node_id FROM readable r
       WHERE NOT (SELECT applies FROM fast_root)
    ) q
    JOIN candidate_nodes n ON n.id=q.node_id
   ORDER BY lower(n.name),n.id
   LIMIT LEAST(GREATEST(COALESCE(p_limit,200),1),1000)
), caps AS MATERIALIZED (
  SELECT s.node_id,
         array_agg(s.capability ORDER BY
           array_position(public.drive_acl_capability_catalog(), s.capability)) AS capabilities
    FROM (
      SELECT DISTINCT x.node_id, x.capability
        FROM public.drive_runtime_capability_sources_set(
          p_user_id,p_space_id,
          COALESCE((SELECT array_agg(node_id) FROM page),ARRAY[]::bigint[]),
          NULL) x
    ) s
   GROUP BY s.node_id
)
SELECT n.id, n.parent_id, n.kind, n.name, c.capabilities
  FROM page p
  JOIN caps c ON c.node_id=p.node_id
  JOIN public.drive_nodes n ON n.id = c.node_id AND n.space_id = p_space_id
 ORDER BY lower(n.name), n.id
$$;
SELECT apply_worker_ownership(
  'drive_visible_children(bigint,bigint,bigint,bigint,integer)'::regprocedure);
