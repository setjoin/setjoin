-- Wave 1.8 Phase 546d: worker-only p_actor-first admin reducer wrappers for
-- conditional-access (F03) so every admin write runs through
-- AdminWriteTx::execute_audited_reducer_contract (SqlAuditPosture::ReducerWritesCoreAudit)
-- with compile-time $1 = p_actor binding and zero double-auditing.
--
-- Every function enforces rls_caller_is_privileged() (setjoin_worker) and is
-- revoked from PUBLIC and setjoin_app.

CREATE OR REPLACE FUNCTION rust_ca_policy_soft_delete(
    p_actor bigint,
    p_id    bigint
) RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    PERFORM public.ca_policy_soft_delete(p_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_restore(
    p_actor bigint,
    p_id    bigint
) RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    PERFORM public.ca_policy_restore(p_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_restore_from_audit(
    p_actor    bigint,
    p_audit_id bigint
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_policy_restore_from_audit(p_audit_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_promote(
    p_actor bigint,
    p_id    bigint
) RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_policy_promote(p_id, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_policy_import(
    p_actor bigint,
    p_doc   jsonb,
    p_mode  text
) RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_policy_import(p_doc, p_actor, p_mode);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_template_instantiate(
    p_actor bigint,
    p_slug  text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_template_instantiate(p_slug, p_actor);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_named_location_set(
    p_actor       bigint,
    p_id          bigint,
    p_name        text,
    p_description text,
    p_cidrs       text[],
    p_countries   text[],
    p_trusted     boolean,
    p_delete      boolean,
    p_ip          text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_cidrs cidr[];
    v_raw   text;
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    IF p_cidrs IS NOT NULL THEN
        FOREACH v_raw IN ARRAY p_cidrs LOOP
            IF v_raw IS NULL OR position('/' IN v_raw) = 0 THEN
                RAISE EXCEPTION 'invalid CIDR value: %', COALESCE(v_raw, '<null>')
                    USING ERRCODE = 'BZ085',
                          HINT = 'cidrs must contain valid CIDR ranges (e.g. 10.0.0.0/8)';
            END IF;
        END LOOP;
        BEGIN
            v_cidrs := p_cidrs::cidr[];
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'invalid CIDR value in cidrs'
                USING ERRCODE = 'BZ085',
                      HINT = 'cidrs must contain valid CIDR ranges (e.g. 10.0.0.0/8)';
        END;
    END IF;
    RETURN public.ca_named_location_set(
        p_id,
        p_name,
        p_description,
        v_cidrs,
        p_countries,
        p_trusted,
        p_delete,
        p_actor,
        NULLIF(p_ip, '')::inet
    );
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_named_location_restore(
    p_actor bigint,
    p_id    bigint,
    p_ip    text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_named_location_restore(p_id, p_actor, NULLIF(p_ip, '')::inet);
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_auth_strength_set(
    p_actor        bigint,
    p_id           bigint,
    p_slug         text,
    p_name         text,
    p_combinations jsonb,
    p_min_acr      text,
    p_delete       boolean,
    p_ip           text
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.ca_auth_strength_set(
        p_id,
        p_slug,
        p_name,
        p_combinations,
        p_min_acr,
        p_delete,
        p_actor,
        NULLIF(p_ip, '')::inet
    );
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_revoke_user_sessions(
    p_actor   bigint,
    p_user_id bigint
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN public.revoke_user_sessions(p_user_id, 'all', 'admin_revoke_all', p_actor, NULL, NULL);
END;
$$;

REVOKE ALL ON FUNCTION public.rust_ca_policy_soft_delete(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_restore(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_restore_from_audit(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_promote(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_policy_import(bigint, jsonb, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_template_instantiate(bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_named_location_set(bigint, bigint, text, text, text[], text[], boolean, boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_named_location_restore(bigint, bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_auth_strength_set(bigint, bigint, text, text, jsonb, text, boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_ca_revoke_user_sessions(bigint, bigint) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_soft_delete(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_restore(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_restore_from_audit(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_promote(bigint, bigint) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_policy_import(bigint, jsonb, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_template_instantiate(bigint, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_named_location_set(bigint, bigint, text, text, text[], text[], boolean, boolean, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_named_location_restore(bigint, bigint, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_auth_strength_set(bigint, bigint, text, text, jsonb, text, boolean, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_ca_revoke_user_sessions(bigint, bigint) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_soft_delete(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_restore(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_restore_from_audit(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_promote(bigint, bigint) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_policy_import(bigint, jsonb, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_template_instantiate(bigint, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_named_location_set(bigint, bigint, text, text, text[], text[], boolean, boolean, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_named_location_restore(bigint, bigint, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_auth_strength_set(bigint, bigint, text, text, jsonb, text, boolean, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_ca_revoke_user_sessions(bigint, bigint) TO setjoin_worker;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION rust_ca_resolve_user_groups(
  p_ids BIGINT[]
) RETURNS TABLE(id BIGINT, name TEXT) AS $$
BEGIN
  IF NOT public.rls_caller_is_privileged() THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT g.id, COALESCE(g.name, '')
      FROM public.directory_groups g
     WHERE g.id = ANY(p_ids)
       AND g.state = 'active'
    UNION
    SELECT DISTINCT ugm.group_id, ''::text
      FROM public.user_group_members ugm
     WHERE ugm.group_id = ANY(p_ids)
       AND NOT EXISTS (
         SELECT 1 FROM public.directory_groups dg
          WHERE dg.id = ugm.group_id
            AND dg.state = 'active'
       )
    ORDER BY 1;
END;
$$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION public.rust_ca_resolve_user_groups(bigint[]) FROM PUBLIC, setjoin_app;
GRANT EXECUTE ON FUNCTION public.rust_ca_resolve_user_groups(bigint[]) TO setjoin_worker;
