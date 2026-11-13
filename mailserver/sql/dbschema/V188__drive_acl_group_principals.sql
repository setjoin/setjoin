-- V188__drive_acl_group_principals.sql
-- A4 expands the R1 direct-user grant row into the closed user/group principal
-- shape and bridges normalized directory-group invalidations into the Drive ACL
-- epoch journal.  All behavior remains behind the existing OFF write/read gates.

ALTER TABLE public.drive_acl_grants
  ALTER COLUMN subject_user_id DROP NOT NULL,
  ADD COLUMN subject_kind text NOT NULL DEFAULT 'user'
    CHECK (subject_kind IN ('user','group')),
  ADD COLUMN subject_group_id bigint
    REFERENCES public.directory_groups(id) ON DELETE RESTRICT,
  ADD COLUMN subject_generation bigint CHECK (subject_generation IS NULL OR subject_generation>0);

ALTER TABLE public.drive_acl_grants
  DROP CONSTRAINT drive_acl_grants_preset_check,
  DROP CONSTRAINT drive_acl_grants_preset_capabilities_match,
  DROP CONSTRAINT drive_acl_grants_source_check,
  ADD CONSTRAINT drive_acl_grants_preset_check CHECK (
    preset IN ('viewer','contributor','editor','folder_manager','custom')
  ),
  ADD CONSTRAINT drive_acl_grants_preset_capabilities_match CHECK (
    preset='custom' OR capabilities=public.drive_acl_preset_capabilities(preset)
  ),
  ADD CONSTRAINT drive_acl_grants_source_check CHECK (
    source IN ('direct','group','legacy_folder_admin','approval','emergency')
  ),
  ADD CONSTRAINT drive_acl_grants_subject_shape CHECK (
    (subject_kind='user' AND subject_user_id IS NOT NULL
                         AND subject_group_id IS NULL
                         AND subject_generation IS NULL)
    OR
    (subject_kind='group' AND subject_user_id IS NULL
                          AND subject_group_id IS NOT NULL
                          AND subject_generation IS NOT NULL)
  );

DROP INDEX public.drive_acl_grants_subject_active_idx;
DROP INDEX public.drive_acl_grants_anchor_active_idx;
CREATE INDEX drive_acl_grants_user_active_idx
  ON public.drive_acl_grants(subject_user_id,space_id,node_id)
  WHERE state='active' AND subject_kind='user';
CREATE INDEX drive_acl_grants_group_active_idx
  ON public.drive_acl_grants(subject_group_id,space_id,node_id)
  WHERE state='active' AND subject_kind='group';
CREATE INDEX drive_acl_grants_anchor_active_idx
  ON public.drive_acl_grants(space_id,node_id,subject_kind,subject_user_id,subject_group_id)
  WHERE state='active';

ALTER TABLE public.drive_access_invalidations
  ADD COLUMN principal_group_id bigint
    REFERENCES public.directory_groups(id) ON DELETE SET NULL;
ALTER TABLE public.drive_access_invalidations
  DROP CONSTRAINT drive_access_invalidations_principal_kind_check,
  DROP CONSTRAINT drive_access_invalidations_principal_shape,
  DROP CONSTRAINT drive_access_invalidations_reason_check,
  ADD CONSTRAINT drive_access_invalidations_principal_kind_check
    CHECK (principal_kind IN ('user','group','all')),
  ADD CONSTRAINT drive_access_invalidations_principal_shape CHECK (
    (principal_kind='user' AND principal_id IS NOT NULL AND principal_group_id IS NULL)
    OR (principal_kind='group' AND principal_id IS NULL AND principal_group_id IS NOT NULL)
    OR (principal_kind='all' AND principal_id IS NULL AND principal_group_id IS NULL)
  ),
  ADD CONSTRAINT drive_access_invalidations_reason_check CHECK (reason IN (
    'grant','revoke','expire','inheritance_break','inheritance_resume',
    'tree_move','group_membership','member_grant','member_revoke','full_reconcile'
  ));
CREATE INDEX drive_access_invalidations_group_cursor_idx
  ON public.drive_access_invalidations(principal_group_id,cursor)
  WHERE principal_kind='group';

-- Bootstrap body needed during schema apply before the reducer fixed-point
-- reload replaces it with the same normalized authority implementation.
CREATE OR REPLACE FUNCTION public.directory_group_effective_member(
  p_user_id bigint,p_group_id bigint
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.directory_groups g
      JOIN public.users u ON u.id=p_user_id AND u.enabled
      JOIN public.directory_group_members m
        ON m.group_id=g.id AND m.user_id=u.id
      LEFT JOIN public.identity_sources s ON s.id=g.source_id
     WHERE g.id=p_group_id AND g.state='active' AND g.domain_id=u.domain_id
       AND (g.kind<>'source' OR s.state='active')
       AND (g.kind<>'dynamic' OR public.directory_group_dynamic_matches_fields(
         g.dynamic_filter,u.domain_id,u.department_id,u.enabled))
  )
$$;
SELECT public.apply_worker_ownership(
  'directory_group_effective_member(bigint,bigint)'::regprocedure);

DROP POLICY drive_acl_grants_read ON public.drive_acl_grants;
CREATE POLICY drive_acl_grants_read ON public.drive_acl_grants FOR SELECT TO public
  USING (
    (subject_kind='user' AND subject_user_id=(SELECT NULLIF(
      current_setting('app.current_user_id',true),'')::bigint))
    OR (subject_kind='group' AND public.directory_group_can_read(
      (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),
      subject_group_id))
    OR public.drive_runtime_has_node_capability(
      (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),
      node_id,'manage_acl')
  );

DROP POLICY drive_access_invalidations_read ON public.drive_access_invalidations;
CREATE POLICY drive_access_invalidations_read ON public.drive_access_invalidations
  FOR SELECT TO public USING (
    (principal_kind='user' AND principal_id=(SELECT NULLIF(
      current_setting('app.current_user_id',true),'')::bigint))
    OR (principal_kind='group' AND public.directory_group_effective_member(
      (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),
      principal_group_id))
    OR (principal_kind='all' AND public.drive_user_has_space_access(
      (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),space_id))
  );

-- The bridge is deliberately deepest: every static, dynamic, source, identity,
-- and source-state membership transition already appends this journal row.
CREATE OR REPLACE FUNCTION public.trg_drive_acl_group_invalidate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_grant record; v_epoch bigint; v_principal_kind text;
BEGIN
  FOR v_grant IN
    SELECT DISTINCT g.space_id,g.node_id
      FROM public.drive_acl_grants g
     WHERE g.subject_kind='group' AND g.subject_group_id=NEW.group_id
       AND g.state='active'
  LOOP
    UPDATE public.drive_acl_generations
       SET epoch=epoch+1,updated_at=clock_timestamp()
     WHERE space_id=v_grant.space_id RETURNING epoch INTO v_epoch;
    v_principal_kind:=CASE WHEN NEW.user_id IS NULL THEN 'all' ELSE 'user' END;
    INSERT INTO public.drive_access_invalidations(
      space_id,principal_kind,principal_id,anchor_node_id,resulting_epoch,reason
    ) VALUES(
      v_grant.space_id,v_principal_kind,NEW.user_id,v_grant.node_id,v_epoch,
      'group_membership'
    );
    PERFORM public.app_notify('drive_access',json_build_object(
      'spaceId',v_grant.space_id::text,'epoch',v_epoch::text,
      'principalKind',v_principal_kind
    )::text);
  END LOOP;
  RETURN NEW;
END;
$$;
SELECT public.apply_worker_ownership('trg_drive_acl_group_invalidate()'::regprocedure);
CREATE TRIGGER drive_acl_group_invalidate
AFTER INSERT ON public.directory_group_invalidations
FOR EACH ROW EXECUTE FUNCTION public.trg_drive_acl_group_invalidate();

INSERT INTO public.schema_migrations (version, applied_at) VALUES (188, now())
ON CONFLICT(version) DO NOTHING;
