-- V185__drive_effective_access.sql
-- Canonical Drive effective-access read seam and node-aware RLS backstop.
-- The separately gated ACL behavior remains OFF. Reducer reload replaces the
-- conservative bootstrap bodies below with the deep implementation in
-- reducers/drive_effective_access.sql.

INSERT INTO public.feature_toggles (key, enabled, description) VALUES
  ('feature.drive_node_acl_reads', false,
   'Drive node ACL canonical read cutover. DEFAULT OFF; per-space acl_mode remains the final authority.'),
  ('feature.drive_node_acl_writes', false,
   'Drive node ACL mutation routes. DEFAULT OFF; no grant API is exposed until the verified cutover.')
ON CONFLICT (key) DO NOTHING;

-- These bootstrap definitions preserve legacy behavior during a live schema
-- apply before the reducer fixed-point reload. No space can enter acl mode in
-- this migration, so the temporary bodies never widen access.
CREATE OR REPLACE FUNCTION public.drive_runtime_has_node_capability(
  p_user_id bigint, p_node_id bigint, p_capability text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT CASE public.drive_member_role(n.space_id, p_user_id)
    WHEN 'viewer' THEN p_capability = ANY(ARRAY[
      'traverse','list_children','read_metadata','preview','download'
    ]::text[])
    WHEN 'editor' THEN p_capability = ANY(ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete'
    ]::text[])
    WHEN 'manager' THEN p_capability = ANY(ARRAY[
      'traverse','list_children','read_metadata','preview','download',
      'create_child','modify_content','rename','move','delete',
      'manage_acl','view_audit'
    ]::text[])
    ELSE false
  END
    FROM public.drive_nodes n
    JOIN public.users u ON u.id = p_user_id AND u.enabled
   WHERE n.id = p_node_id AND n.purged_at IS NULL
$$;
SELECT public.apply_worker_ownership(
  'drive_runtime_has_node_capability(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION public.drive_user_has_space_access(
  p_user_id bigint, p_space_id bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.drive_spaces s
      JOIN public.users u ON u.id = p_user_id AND u.enabled
     WHERE s.id = p_space_id
       AND (
         public.drive_member_role(s.id, p_user_id) IS NOT NULL
         OR (s.chat_channel_id IS NULL AND s.meeting_id IS NULL
             AND s.owner_user_id = p_user_id)
         OR public.drive_has_admin_perm(p_user_id, 'drive.view')
       )
  )
$$;
SELECT public.apply_worker_ownership(
  'drive_user_has_space_access(bigint,bigint)'::regprocedure);

-- Space discovery now has one seam. With every space still legacy/shadow,
-- this is behavior-identical to V129; the reducer body adds direct-grantee
-- discovery only after a space explicitly enters acl mode.
DROP POLICY IF EXISTS drive_spaces_read ON public.drive_spaces;
CREATE POLICY drive_spaces_read ON public.drive_spaces FOR SELECT TO public
  USING (public.drive_user_has_space_access(
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint), id));

-- Exact node/content reads use the same remembered-id authorization seam as
-- future list APIs. Write policies intentionally remain on the legacy adapter
-- until A6 converts every mutating reducer to exact capability checks.
DROP POLICY IF EXISTS drive_nodes_read ON public.drive_nodes;
CREATE POLICY drive_nodes_read ON public.drive_nodes FOR SELECT TO public
  USING (purged_at IS NULL AND (
    public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      id, 'read_metadata')
    OR public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      id, 'traverse')));

DROP POLICY IF EXISTS drive_files_read ON public.drive_files;
CREATE POLICY drive_files_read ON public.drive_files FOR SELECT TO public
  USING (
    public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      node_id, 'read_metadata')
    OR public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      node_id, 'preview')
    OR public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      node_id, 'download'));

DROP POLICY IF EXISTS drive_file_versions_read ON public.drive_file_versions;
CREATE POLICY drive_file_versions_read ON public.drive_file_versions FOR SELECT TO public
  USING (
    public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      file_node_id, 'read_metadata')
    OR public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      file_node_id, 'preview')
    OR public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      file_node_id, 'download'));

DROP POLICY IF EXISTS drive_version_chunks_read ON public.drive_version_chunks;
CREATE POLICY drive_version_chunks_read ON public.drive_version_chunks FOR SELECT TO public
  USING (EXISTS (
    SELECT 1 FROM public.drive_file_versions v
     WHERE v.id = version_id
       AND (
         public.drive_runtime_has_node_capability(
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
           v.file_node_id, 'preview')
         OR public.drive_runtime_has_node_capability(
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
           v.file_node_id, 'download')
       )
  ));

DROP POLICY IF EXISTS drive_chunks_read ON public.drive_chunks;
CREATE POLICY drive_chunks_read ON public.drive_chunks FOR SELECT TO public
  USING (
    EXISTS (
      SELECT 1 FROM public.drive_upload_claims c
       WHERE c.scope_key = drive_chunks.scope_key
         AND c.sha256 = drive_chunks.sha256
         AND c.user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    )
    OR EXISTS (
      SELECT 1
        FROM public.drive_version_chunks vc
        JOIN public.drive_file_versions v ON v.id = vc.version_id
       WHERE vc.scope_key = drive_chunks.scope_key
         AND vc.chunk_sha256 = drive_chunks.sha256
         AND (
           public.drive_runtime_has_node_capability(
             (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
             v.file_node_id, 'preview')
           OR public.drive_runtime_has_node_capability(
             (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
             v.file_node_id, 'download')
         )
    )
  );

DROP POLICY IF EXISTS drive_file_branches_read ON public.drive_file_branches;
CREATE POLICY drive_file_branches_read ON public.drive_file_branches FOR SELECT TO public
  USING (public.drive_runtime_has_node_capability(
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
    file_node_id, 'read_metadata'));

DROP POLICY IF EXISTS drive_version_labels_read ON public.drive_version_labels;
CREATE POLICY drive_version_labels_read ON public.drive_version_labels FOR SELECT TO public
  USING (EXISTS (
    SELECT 1 FROM public.drive_file_versions v
     WHERE v.id = version_id
       AND public.drive_runtime_has_node_capability(
         (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
         v.file_node_id, 'read_metadata')
  ));

DROP POLICY IF EXISTS drive_file_locks_read ON public.drive_file_locks;
CREATE POLICY drive_file_locks_read ON public.drive_file_locks FOR SELECT TO public
  USING (public.drive_runtime_has_node_capability(
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
    node_id, 'read_metadata'));

-- V184 expand-table policies become capability-aware without exposing the
-- internal closure relation or all-principal invalidations to outsiders.
DROP POLICY IF EXISTS drive_acl_grants_read ON public.drive_acl_grants;
CREATE POLICY drive_acl_grants_read ON public.drive_acl_grants FOR SELECT TO public
  USING (
    subject_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
    OR public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      node_id, 'manage_acl')
  );

DROP POLICY IF EXISTS drive_acl_breaks_read ON public.drive_acl_breaks;
CREATE POLICY drive_acl_breaks_read ON public.drive_acl_breaks FOR SELECT TO public
  USING (public.drive_runtime_has_node_capability(
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
    node_id, 'manage_acl'));

DROP POLICY IF EXISTS drive_acl_generations_read ON public.drive_acl_generations;
CREATE POLICY drive_acl_generations_read ON public.drive_acl_generations FOR SELECT TO public
  USING (public.drive_user_has_space_access(
    (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
    space_id));

DROP POLICY IF EXISTS drive_access_invalidations_read ON public.drive_access_invalidations;
CREATE POLICY drive_access_invalidations_read ON public.drive_access_invalidations FOR SELECT TO public
  USING (
    (principal_kind = 'user'
      AND principal_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
    OR (principal_kind = 'all' AND public.drive_user_has_space_access(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      space_id))
    OR (anchor_node_id IS NOT NULL AND public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint),
      anchor_node_id, 'manage_acl'))
  );

INSERT INTO public.schema_migrations (version, applied_at) VALUES (185, now())
ON CONFLICT (version) DO NOTHING;
