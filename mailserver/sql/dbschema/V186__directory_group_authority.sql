-- V186__directory_group_authority.sql
-- Reusable, user-keyed directory group authority for Drive ACL R2. This does
-- not replace distribution groups, CA user_group_members, Chat, Meet, or RBAC.

CREATE OR REPLACE FUNCTION public.directory_group_filter_valid(p_filter jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT jsonb_typeof(p_filter) = 'object'
     AND p_filter <> '{}'::jsonb
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_object_keys(p_filter) k
        WHERE k NOT IN ('domainId','departmentId','enabled')
     )
     AND (NOT (p_filter ? 'domainId')
          OR jsonb_typeof(p_filter->'domainId') = 'number')
     AND (NOT (p_filter ? 'departmentId')
          OR jsonb_typeof(p_filter->'departmentId') = 'number')
     AND (NOT (p_filter ? 'enabled')
          OR jsonb_typeof(p_filter->'enabled') = 'boolean')
$$;

CREATE TABLE public.directory_groups (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  domain_id        bigint NOT NULL REFERENCES public.domains(id),
  source_id        bigint REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
  external_anchor  text,
  name             text NOT NULL,
  kind             text NOT NULL CHECK (kind IN ('static','dynamic','source')),
  state            text NOT NULL DEFAULT 'active' CHECK (state IN ('active','deleted')),
  visibility       text NOT NULL DEFAULT 'members'
                   CHECK (visibility IN ('org','members','hidden')),
  dynamic_filter   jsonb,
  generation       bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_by       bigint REFERENCES public.users(id) ON DELETE SET NULL,
  updated_by       bigint REFERENCES public.users(id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT directory_groups_name_check CHECK (
    name = btrim(name) AND octet_length(name) BETWEEN 1 AND 128
    AND name !~ '[[:cntrl:]]'
  ),
  CONSTRAINT directory_groups_anchor_check CHECK (
    external_anchor IS NULL OR (
      external_anchor = btrim(external_anchor)
      AND octet_length(external_anchor) BETWEEN 1 AND 2048
      AND external_anchor !~ '[[:cntrl:]]'
    )
  ),
  CONSTRAINT directory_groups_source_shape CHECK (
    (kind = 'source' AND source_id IS NOT NULL AND external_anchor IS NOT NULL
                     AND dynamic_filter IS NULL)
    OR (kind = 'dynamic' AND source_id IS NULL AND external_anchor IS NULL
                         AND public.directory_group_filter_valid(dynamic_filter))
    OR (kind = 'static' AND source_id IS NULL AND external_anchor IS NULL
                        AND dynamic_filter IS NULL)
  )
);
CREATE UNIQUE INDEX directory_groups_source_anchor_uniq
  ON public.directory_groups(source_id, external_anchor)
  WHERE source_id IS NOT NULL;
CREATE UNIQUE INDEX directory_groups_local_name_uniq
  ON public.directory_groups(domain_id, lower(name))
  WHERE source_id IS NULL AND state='active';
CREATE INDEX directory_groups_picker_idx
  ON public.directory_groups(domain_id, state, visibility, lower(name), id);

CREATE TABLE public.directory_group_members (
  group_id           bigint NOT NULL REFERENCES public.directory_groups(id) ON DELETE CASCADE,
  user_id            bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  membership_source  text NOT NULL CHECK (membership_source IN ('static','dynamic','source')),
  source_anchor      text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(group_id,user_id,membership_source),
  CONSTRAINT directory_group_members_anchor_shape CHECK (
    (membership_source='source' AND source_anchor IS NOT NULL
      AND source_anchor=btrim(source_anchor)
      AND octet_length(source_anchor) BETWEEN 1 AND 2048)
    OR (membership_source<>'source' AND source_anchor IS NULL)
  )
);
CREATE INDEX directory_group_members_user_idx
  ON public.directory_group_members(user_id,group_id);

CREATE TABLE public.directory_group_generation (
  singleton_id            boolean PRIMARY KEY DEFAULT true CHECK (singleton_id),
  generation              bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  retained_after_cursor   bigint NOT NULL DEFAULT 0 CHECK (retained_after_cursor >= 0),
  updated_at              timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.directory_group_generation(singleton_id) VALUES(true);

CREATE TABLE public.directory_group_invalidations (
  cursor       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  group_id     bigint REFERENCES public.directory_groups(id) ON DELETE SET NULL,
  user_id      bigint REFERENCES public.users(id) ON DELETE CASCADE,
  generation   bigint NOT NULL CHECK (generation > 0),
  reason       text NOT NULL CHECK (reason IN (
    'member_add','member_remove','user_state','user_scope','group_update',
    'group_delete','source_state','source_generation','dynamic_reconcile'
  )),
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX directory_group_invalidations_user_cursor_idx
  ON public.directory_group_invalidations(user_id,cursor)
  WHERE user_id IS NOT NULL;
CREATE INDEX directory_group_invalidations_group_cursor_idx
  ON public.directory_group_invalidations(group_id,cursor);

CREATE OR REPLACE FUNCTION public.directory_group_dynamic_matches_fields(
  p_filter jsonb, p_domain_id bigint, p_department_id bigint, p_enabled boolean
) RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, public AS $$
  SELECT public.directory_group_filter_valid(p_filter)
     AND (NOT (p_filter ? 'domainId')
          OR (p_filter->>'domainId')::bigint = p_domain_id)
     AND (NOT (p_filter ? 'departmentId')
          OR (p_filter->>'departmentId')::bigint = p_department_id)
     AND (NOT (p_filter ? 'enabled')
          OR (p_filter->>'enabled')::boolean = p_enabled)
$$;

CREATE OR REPLACE FUNCTION public.directory_group_invalidate(
  p_group_id bigint, p_user_id bigint, p_reason text
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_generation bigint;
BEGIN
  IF p_reason NOT IN (
    'member_add','member_remove','user_state','user_scope','group_update',
    'group_delete','source_state','source_generation','dynamic_reconcile'
  ) THEN
    RAISE EXCEPTION 'invalid directory group invalidation reason'
      USING ERRCODE='BZ257', HINT='{"type":"directory_group_invalid","field":"reason"}';
  END IF;

  UPDATE public.directory_group_generation
     SET generation=generation+1, updated_at=clock_timestamp()
   WHERE singleton_id
   RETURNING generation INTO v_generation;
  UPDATE public.directory_groups
     SET generation=generation+1, updated_at=clock_timestamp()
   WHERE id=p_group_id;
  INSERT INTO public.directory_group_invalidations(group_id,user_id,generation,reason)
  VALUES(p_group_id,p_user_id,v_generation,p_reason);
  RETURN v_generation;
END;
$$;

CREATE OR REPLACE FUNCTION public.trg_directory_group_member_invalidate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    PERFORM public.directory_group_invalidate(NEW.group_id,NEW.user_id,'member_add');
    RETURN NEW;
  END IF;
  PERFORM public.directory_group_invalidate(OLD.group_id,OLD.user_id,'member_remove');
  RETURN OLD;
END;
$$;
CREATE TRIGGER directory_group_member_invalidate
AFTER INSERT OR DELETE ON public.directory_group_members
FOR EACH ROW EXECUTE FUNCTION public.trg_directory_group_member_invalidate();

CREATE OR REPLACE FUNCTION public.trg_directory_group_metadata_invalidate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.name IS DISTINCT FROM OLD.name
     OR NEW.state IS DISTINCT FROM OLD.state
     OR NEW.visibility IS DISTINCT FROM OLD.visibility
     OR NEW.dynamic_filter IS DISTINCT FROM OLD.dynamic_filter THEN
    PERFORM public.directory_group_invalidate(
      NEW.id,NULL,CASE WHEN NEW.state='deleted' THEN 'group_delete' ELSE 'group_update' END);
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER directory_group_metadata_invalidate
AFTER UPDATE OF name,state,visibility,dynamic_filter ON public.directory_groups
FOR EACH ROW EXECUTE FUNCTION public.trg_directory_group_metadata_invalidate();

-- Deepest seam for every admin, SCIM, identity-transition, and local user
-- update. Static/source memberships are invalidated; dynamic rows are
-- materialized to the new user facts in the same transaction.
CREATE OR REPLACE FUNCTION public.trg_directory_group_user_change()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_group record; v_old_match boolean; v_new_match boolean;
BEGIN
  IF NEW.enabled IS NOT DISTINCT FROM OLD.enabled
     AND NEW.domain_id IS NOT DISTINCT FROM OLD.domain_id
     AND NEW.department_id IS NOT DISTINCT FROM OLD.department_id THEN
    RETURN NEW;
  END IF;

  FOR v_group IN
    SELECT DISTINCT m.group_id
      FROM public.directory_group_members m
     WHERE m.user_id=NEW.id AND m.membership_source<>'dynamic'
  LOOP
    PERFORM public.directory_group_invalidate(
      v_group.group_id,NEW.id,
      CASE WHEN NEW.enabled IS DISTINCT FROM OLD.enabled
           THEN 'user_state' ELSE 'user_scope' END);
  END LOOP;

  FOR v_group IN
    SELECT g.id,g.dynamic_filter FROM public.directory_groups g
     WHERE g.kind='dynamic' AND g.state='active'
  LOOP
    v_old_match := public.directory_group_dynamic_matches_fields(
      v_group.dynamic_filter,OLD.domain_id,OLD.department_id,OLD.enabled);
    v_new_match := public.directory_group_dynamic_matches_fields(
      v_group.dynamic_filter,NEW.domain_id,NEW.department_id,NEW.enabled);
    IF v_new_match THEN
      INSERT INTO public.directory_group_members(group_id,user_id,membership_source)
      VALUES(v_group.id,NEW.id,'dynamic') ON CONFLICT DO NOTHING;
      IF v_old_match THEN
        PERFORM public.directory_group_invalidate(
          v_group.id,NEW.id,
          CASE WHEN NEW.enabled IS DISTINCT FROM OLD.enabled
               THEN 'user_state' ELSE 'user_scope' END);
      END IF;
    ELSE
      DELETE FROM public.directory_group_members
       WHERE group_id=v_group.id AND user_id=NEW.id AND membership_source='dynamic';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER directory_group_user_change
AFTER UPDATE OF enabled,domain_id,department_id ON public.users
FOR EACH ROW EXECUTE FUNCTION public.trg_directory_group_user_change();

CREATE OR REPLACE FUNCTION public.trg_directory_group_source_change()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_row record; v_reason text;
BEGIN
  IF NEW.state IS NOT DISTINCT FROM OLD.state
     AND NEW.generation IS NOT DISTINCT FROM OLD.generation THEN
    RETURN NEW;
  END IF;
  v_reason := CASE WHEN NEW.state IS DISTINCT FROM OLD.state
                   THEN 'source_state' ELSE 'source_generation' END;
  FOR v_row IN
    SELECT g.id AS group_id,m.user_id
      FROM public.directory_groups g
      LEFT JOIN public.directory_group_members m ON m.group_id=g.id
     WHERE g.source_id=NEW.id
  LOOP
    PERFORM public.directory_group_invalidate(v_row.group_id,v_row.user_id,v_reason);
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER directory_group_source_change
AFTER UPDATE OF state,generation ON public.identity_sources
FOR EACH ROW EXECUTE FUNCTION public.trg_directory_group_source_change();

CREATE OR REPLACE FUNCTION public.directory_group_can_read(
  p_user_id bigint,p_group_id bigint
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.directory_groups g
    JOIN public.users u ON u.id=p_user_id AND u.enabled
    WHERE g.id=p_group_id AND g.state='active'
      AND (
        (g.domain_id=u.domain_id AND (
          g.visibility='org'
          OR EXISTS (SELECT 1 FROM public.directory_group_members m
                      WHERE m.group_id=g.id AND m.user_id=p_user_id)
        ))
        OR EXISTS (
          SELECT 1 FROM public.admin_role_assignments ra
          JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id
          WHERE ra.user_id=p_user_id
            AND 'directory.groups.read'=ANY(rg.permissions)
            AND (ra.expires_at IS NULL OR ra.expires_at>now())
            AND (NOT COALESCE((SELECT enabled FROM public.feature_toggles
                                WHERE key='rbac.jit'),false)
                 OR ra.eligible=false
                 OR (ra.activated_until IS NOT NULL AND ra.activated_until>now()))
            AND ra.scope_type IS NULL
            AND (COALESCE(ra.domain_override,rg.domain_scope) IS NULL
                 OR COALESCE(ra.domain_override,rg.domain_scope)=g.domain_id)
        )
      )
  )
$$;

DO $$
DECLARE v_fn regprocedure;
BEGIN
  FOREACH v_fn IN ARRAY ARRAY[
    'directory_group_filter_valid(jsonb)'::regprocedure,
    'directory_group_dynamic_matches_fields(jsonb,bigint,bigint,boolean)'::regprocedure,
    'directory_group_invalidate(bigint,bigint,text)'::regprocedure,
    'trg_directory_group_member_invalidate()'::regprocedure,
    'trg_directory_group_metadata_invalidate()'::regprocedure,
    'trg_directory_group_user_change()'::regprocedure,
    'trg_directory_group_source_change()'::regprocedure,
    'directory_group_can_read(bigint,bigint)'::regprocedure
  ] LOOP
    PERFORM public.apply_worker_ownership(v_fn);
  END LOOP;
END $$;

ALTER TABLE public.directory_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.directory_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_groups_read ON public.directory_groups FOR SELECT TO public
  USING(public.directory_group_can_read(
    (SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint),id));

ALTER TABLE public.directory_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.directory_group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_group_members_self_read ON public.directory_group_members
  FOR SELECT TO public USING(user_id=(SELECT NULLIF(
    current_setting('app.current_user_id',true),'')::bigint));

ALTER TABLE public.directory_group_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.directory_group_generation FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_group_generation_authenticated_read
  ON public.directory_group_generation FOR SELECT TO public
  USING(EXISTS(SELECT 1 FROM public.users u WHERE u.id=(SELECT NULLIF(
    current_setting('app.current_user_id',true),'')::bigint) AND u.enabled));

ALTER TABLE public.directory_group_invalidations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.directory_group_invalidations FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_group_invalidations_read
  ON public.directory_group_invalidations FOR SELECT TO public
  USING(
    user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint)
    OR (user_id IS NULL AND EXISTS(
      SELECT 1 FROM public.directory_group_members m
       WHERE m.group_id=directory_group_invalidations.group_id
         AND m.user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint)
    ))
  );

INSERT INTO public.feature_toggles(key,enabled,description) VALUES
  ('feature.directory_group_authority',false,
   'Normalized user-keyed directory groups for authorization consumers. DEFAULT OFF; does not replace delivery or Conditional Access groups.')
ON CONFLICT(key) DO NOTHING;

INSERT INTO public.admin_permissions(permission_key,category,description,is_sensitive) VALUES
  ('directory.groups.read','Directory','Read reachable normalized directory groups',false),
  ('directory.groups.manage','Directory','Create and reconcile normalized directory groups',true)
ON CONFLICT(permission_key) DO NOTHING;
UPDATE public.admin_role_groups SET permissions=(
  SELECT array_agg(DISTINCT p ORDER BY p)
    FROM unnest(permissions||ARRAY['directory.groups.read','directory.groups.manage']) p
) WHERE id=1;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (186, now())
ON CONFLICT(version) DO NOTHING;
