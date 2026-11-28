CREATE OR REPLACE FUNCTION upgrade_actor_authorized(p_actor BIGINT)
RETURNS BOOLEAN
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM users u
          CROSS JOIN LATERAL admin_effective_authority(u.id,true) a
         WHERE u.id=p_actor
           AND u.enabled
           AND 'system.upgrade'=ANY(a.perms)
           AND a.scope IS NULL
           AND a.is_unconfined
    );
$$;
SELECT apply_upgrade_ownership(
    'upgrade_actor_authorized(bigint)'::regprocedure,true,false
);
