-- directory_group_authority.sql -- normalized user-keyed group authority.

CREATE OR REPLACE FUNCTION directory_group_manage_authorized(
  p_actor_user_id bigint,p_domain_id bigint,p_permission text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.admin_role_assignments ra
      JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id
     WHERE ra.user_id=p_actor_user_id
       AND p_permission=ANY(rg.permissions)
       AND (ra.expires_at IS NULL OR ra.expires_at>now())
       AND public.admin_assignment_active(ra.eligible,ra.activated_until)
       AND ra.scope_type IS NULL
       AND (COALESCE(ra.domain_override,rg.domain_scope) IS NULL
            OR COALESCE(ra.domain_override,rg.domain_scope)=p_domain_id)
  )
$$;
SELECT apply_worker_ownership(
  'directory_group_manage_authorized(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_can_read(
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
        OR public.directory_group_manage_authorized(
          p_user_id,g.domain_id,'directory.groups.read')
      )
  )
$$;
SELECT apply_worker_ownership('directory_group_can_read(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_effective_member(
  p_user_id bigint,p_group_id bigint
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.directory_groups g
      JOIN public.users u ON u.id=p_user_id AND u.enabled
      JOIN public.directory_group_members m
        ON m.group_id=g.id AND m.user_id=u.id
      LEFT JOIN public.identity_sources s ON s.id=g.source_id
     WHERE g.id=p_group_id
       AND g.state='active'
       AND g.domain_id=u.domain_id
       AND (g.kind<>'source' OR s.state='active')
       AND (g.kind<>'dynamic' OR public.directory_group_dynamic_matches_fields(
         g.dynamic_filter,u.domain_id,u.department_id,u.enabled))
  )
$$;
SELECT apply_worker_ownership(
  'directory_group_effective_member(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_source_upsert(
  p_source_id bigint,
  p_expected_source_generation bigint,
  p_external_anchor text,
  p_domain_id bigint,
  p_name text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_group_id bigint;
BEGIN
  IF p_external_anchor IS NULL OR p_external_anchor<>btrim(p_external_anchor)
     OR octet_length(p_external_anchor) NOT BETWEEN 1 AND 2048
     OR p_name IS NULL OR p_name<>btrim(p_name)
     OR octet_length(p_name) NOT BETWEEN 1 AND 128
     OR NOT EXISTS(SELECT 1 FROM public.domains WHERE id=p_domain_id) THEN
    RAISE EXCEPTION 'invalid directory group source payload'
      USING ERRCODE='BZ257',HINT='{"type":"directory_group_invalid"}';
  END IF;
  PERFORM 1 FROM public.identity_sources
   WHERE id=p_source_id AND state='active'
     AND generation=p_expected_source_generation FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'directory group source is stale or inactive'
      USING ERRCODE='BZ259',HINT='{"type":"directory_group_conflict","field":"sourceGeneration"}';
  END IF;

  SELECT id INTO v_group_id FROM public.directory_groups
   WHERE source_id=p_source_id AND external_anchor=p_external_anchor FOR UPDATE;
  IF FOUND THEN
    UPDATE public.directory_groups
       SET name=p_name,domain_id=p_domain_id,updated_at=clock_timestamp()
     WHERE id=v_group_id
       AND (name IS DISTINCT FROM p_name OR domain_id IS DISTINCT FROM p_domain_id);
    RETURN v_group_id;
  END IF;
  INSERT INTO public.directory_groups(
    domain_id,source_id,external_anchor,name,kind,visibility
  ) VALUES(p_domain_id,p_source_id,p_external_anchor,p_name,'source','members')
  RETURNING id INTO v_group_id;
  RETURN v_group_id;
END;
$$;
SELECT apply_worker_ownership(
  'directory_group_source_upsert(bigint,bigint,text,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_source_reconcile_members(
  p_source_id bigint,
  p_expected_source_generation bigint,
  p_group_external_anchor text,
  p_member_external_anchors text[]
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_group_id bigint; v_requested int; v_resolved int;
BEGIN
  IF p_member_external_anchors IS NULL OR EXISTS(
    SELECT 1 FROM unnest(p_member_external_anchors) x
     WHERE x IS NULL OR x<>btrim(x) OR octet_length(x) NOT BETWEEN 1 AND 2048
  ) OR cardinality(p_member_external_anchors)<>(
    SELECT count(DISTINCT x) FROM unnest(p_member_external_anchors) x
  ) THEN
    RAISE EXCEPTION 'invalid directory group member anchors'
      USING ERRCODE='BZ257',HINT='{"type":"directory_group_invalid","field":"memberAnchors"}';
  END IF;
  PERFORM 1 FROM public.identity_sources
   WHERE id=p_source_id AND state='active'
     AND generation=p_expected_source_generation FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'directory group source is stale or inactive'
      USING ERRCODE='BZ259',HINT='{"type":"directory_group_conflict","field":"sourceGeneration"}';
  END IF;
  SELECT id INTO v_group_id FROM public.directory_groups
   WHERE source_id=p_source_id AND external_anchor=p_group_external_anchor
     AND state='active' FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'directory group not found'
      USING ERRCODE='BZ259',HINT='{"type":"directory_group_conflict","field":"group"}';
  END IF;

  v_requested:=cardinality(p_member_external_anchors);
  SELECT count(DISTINCT l.external_subject)::int INTO v_resolved
    FROM public.user_identity_links l
    JOIN public.users u ON u.id=l.user_id
   WHERE l.source_id=p_source_id AND l.state='active'
     AND 'provision'=ANY(l.purposes)
     AND l.external_subject=ANY(p_member_external_anchors)
     AND u.domain_id=(SELECT domain_id FROM public.directory_groups WHERE id=v_group_id)
     AND NOT public.is_guest_account(u.id);
  IF v_resolved<>v_requested THEN
    RAISE EXCEPTION 'directory group member anchor is unresolved or out of scope'
      USING ERRCODE='BZ257',HINT='{"type":"directory_group_invalid","field":"memberAnchors"}';
  END IF;

  DELETE FROM public.directory_group_members m
   WHERE m.group_id=v_group_id AND m.membership_source='source'
     AND NOT EXISTS(
       SELECT 1 FROM public.user_identity_links l
        WHERE l.source_id=p_source_id AND l.user_id=m.user_id
          AND l.state='active' AND 'provision'=ANY(l.purposes)
          AND l.external_subject=ANY(p_member_external_anchors)
     );
  INSERT INTO public.directory_group_members(
    group_id,user_id,membership_source,source_anchor
  )
  SELECT v_group_id,l.user_id,'source',l.external_subject
    FROM public.user_identity_links l
   WHERE l.source_id=p_source_id AND l.state='active'
     AND 'provision'=ANY(l.purposes)
     AND l.external_subject=ANY(p_member_external_anchors)
  ON CONFLICT DO NOTHING;
  RETURN (SELECT count(*) FROM public.directory_group_members
           WHERE group_id=v_group_id AND membership_source='source');
END;
$$;
SELECT apply_worker_ownership(
  'directory_group_source_reconcile_members(bigint,bigint,text,text[])'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_static_set(
  p_actor_user_id bigint,
  p_group_id bigint,
  p_domain_id bigint,
  p_name text,
  p_visibility text,
  p_member_user_ids bigint[],
  p_expected_generation bigint DEFAULT NULL
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_group_id bigint; v_count int;
BEGIN
  IF NOT public.directory_group_manage_authorized(
    p_actor_user_id,p_domain_id,'directory.groups.manage') THEN
    RAISE EXCEPTION 'directory group management forbidden'
      USING ERRCODE='BZ258',HINT='{"type":"directory_group_forbidden"}';
  END IF;
  IF p_name IS NULL OR p_name<>btrim(p_name)
     OR octet_length(p_name) NOT BETWEEN 1 AND 128
     OR p_visibility NOT IN ('org','members','hidden')
     OR p_member_user_ids IS NULL
     OR cardinality(p_member_user_ids)<>(SELECT count(DISTINCT x) FROM unnest(p_member_user_ids) x) THEN
    RAISE EXCEPTION 'invalid static directory group'
      USING ERRCODE='BZ257',HINT='{"type":"directory_group_invalid"}';
  END IF;
  SELECT count(*)::int INTO v_count FROM public.users u
   WHERE u.id=ANY(p_member_user_ids) AND u.domain_id=p_domain_id
     AND NOT public.is_guest_account(u.id);
  IF v_count<>cardinality(p_member_user_ids) THEN
    RAISE EXCEPTION 'directory group member is missing or cross-domain'
      USING ERRCODE='BZ257',HINT='{"type":"directory_group_invalid","field":"members"}';
  END IF;

  IF p_group_id IS NULL THEN
    INSERT INTO public.directory_groups(
      domain_id,name,kind,visibility,created_by,updated_by
    ) VALUES(p_domain_id,p_name,'static',p_visibility,p_actor_user_id,p_actor_user_id)
    RETURNING id INTO v_group_id;
  ELSE
    SELECT id INTO v_group_id FROM public.directory_groups
     WHERE id=p_group_id AND domain_id=p_domain_id AND kind='static' AND state='active'
       AND generation=p_expected_generation FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'directory group generation conflict'
        USING ERRCODE='BZ259',HINT='{"type":"directory_group_conflict","field":"generation"}';
    END IF;
    UPDATE public.directory_groups SET name=p_name,visibility=p_visibility,
      updated_by=p_actor_user_id,updated_at=clock_timestamp() WHERE id=v_group_id;
  END IF;
  DELETE FROM public.directory_group_members m
   WHERE m.group_id=v_group_id AND m.membership_source='static'
     AND NOT (m.user_id=ANY(p_member_user_ids));
  INSERT INTO public.directory_group_members(group_id,user_id,membership_source)
  SELECT v_group_id,x,'static' FROM unnest(p_member_user_ids) x
  ON CONFLICT DO NOTHING;
  RETURN v_group_id;
END;
$$;
SELECT apply_worker_ownership(
  'directory_group_static_set(bigint,bigint,bigint,text,text,bigint[],bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_dynamic_set(
  p_actor_user_id bigint,
  p_group_id bigint,
  p_domain_id bigint,
  p_name text,
  p_visibility text,
  p_filter jsonb,
  p_expected_generation bigint DEFAULT NULL
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_group_id bigint;
BEGIN
  IF NOT public.directory_group_manage_authorized(
    p_actor_user_id,p_domain_id,'directory.groups.manage') THEN
    RAISE EXCEPTION 'directory group management forbidden'
      USING ERRCODE='BZ258',HINT='{"type":"directory_group_forbidden"}';
  END IF;
  IF p_name IS NULL OR p_name<>btrim(p_name)
     OR octet_length(p_name) NOT BETWEEN 1 AND 128
     OR p_visibility NOT IN ('org','members','hidden')
     OR NOT public.directory_group_filter_valid(p_filter)
     OR ((p_filter?'domainId') AND (p_filter->>'domainId')::bigint<>p_domain_id) THEN
    RAISE EXCEPTION 'invalid dynamic directory group'
      USING ERRCODE='BZ257',HINT='{"type":"directory_group_invalid"}';
  END IF;
  IF p_group_id IS NULL THEN
    INSERT INTO public.directory_groups(
      domain_id,name,kind,visibility,dynamic_filter,created_by,updated_by
    ) VALUES(p_domain_id,p_name,'dynamic',p_visibility,p_filter,p_actor_user_id,p_actor_user_id)
    RETURNING id INTO v_group_id;
  ELSE
    SELECT id INTO v_group_id FROM public.directory_groups
     WHERE id=p_group_id AND domain_id=p_domain_id AND kind='dynamic' AND state='active'
       AND generation=p_expected_generation FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'directory group generation conflict'
        USING ERRCODE='BZ259',HINT='{"type":"directory_group_conflict","field":"generation"}';
    END IF;
    UPDATE public.directory_groups SET name=p_name,visibility=p_visibility,
      dynamic_filter=p_filter,updated_by=p_actor_user_id,updated_at=clock_timestamp()
     WHERE id=v_group_id;
  END IF;
  DELETE FROM public.directory_group_members m
   WHERE m.group_id=v_group_id AND m.membership_source='dynamic'
     AND NOT EXISTS(
       SELECT 1 FROM public.users u WHERE u.id=m.user_id
         AND public.directory_group_dynamic_matches_fields(
           p_filter,u.domain_id,u.department_id,u.enabled)
     );
  INSERT INTO public.directory_group_members(group_id,user_id,membership_source)
  SELECT v_group_id,u.id,'dynamic' FROM public.users u
   WHERE public.directory_group_dynamic_matches_fields(
     p_filter,u.domain_id,u.department_id,u.enabled)
     AND NOT public.is_guest_account(u.id)
  ON CONFLICT DO NOTHING;
  PERFORM public.directory_group_invalidate(v_group_id,NULL,'dynamic_reconcile');
  RETURN v_group_id;
END;
$$;
SELECT apply_worker_ownership(
  'directory_group_dynamic_set(bigint,bigint,bigint,text,text,jsonb,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_delete(
  p_actor_user_id bigint,p_group_id bigint,p_expected_generation bigint
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_domain_id bigint;
BEGIN
  SELECT domain_id INTO v_domain_id FROM public.directory_groups
   WHERE id=p_group_id AND state='active' AND generation=p_expected_generation FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'directory group generation conflict'
      USING ERRCODE='BZ259',HINT='{"type":"directory_group_conflict","field":"generation"}';
  END IF;
  IF NOT public.directory_group_manage_authorized(
    p_actor_user_id,v_domain_id,'directory.groups.manage') THEN
    RAISE EXCEPTION 'directory group management forbidden'
      USING ERRCODE='BZ258',HINT='{"type":"directory_group_forbidden"}';
  END IF;
  UPDATE public.directory_groups SET state='deleted',updated_by=p_actor_user_id,
    updated_at=clock_timestamp() WHERE id=p_group_id;
  DELETE FROM public.directory_group_members WHERE group_id=p_group_id;
END;
$$;
SELECT apply_worker_ownership('directory_group_delete(bigint,bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION directory_group_picker(
  p_user_id bigint,p_query text DEFAULT NULL,p_limit integer DEFAULT 50
) RETURNS TABLE(group_id bigint,name text,kind text,visibility text,generation bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
  SELECT g.id,g.name,g.kind,g.visibility,g.generation
    FROM public.directory_groups g
   WHERE g.state='active'
     AND public.directory_group_can_read(p_user_id,g.id)
     AND (p_query IS NULL OR g.name ILIKE '%'||replace(replace(p_query,'%','\%'),'_','\_')||'%' ESCAPE '\')
   ORDER BY lower(g.name),g.id
   LIMIT LEAST(GREATEST(COALESCE(p_limit,50),1),200)
$$;
SELECT apply_worker_ownership('directory_group_picker(bigint,text,integer)'::regprocedure);
