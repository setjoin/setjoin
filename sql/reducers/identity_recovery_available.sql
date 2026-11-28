CREATE OR REPLACE FUNCTION identity_recovery_available(
    p_user_id BIGINT,
    p_excluded_link_id BIGINT DEFAULT NULL
) RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM users u
         WHERE u.id=p_user_id
           AND u.enabled
           AND u.password_hash IS NOT NULL
           AND u.password_hash<>''
    ) OR EXISTS (
        SELECT 1
          FROM passkey_credentials p
         WHERE p.user_id=p_user_id
           AND p.revoked_at IS NULL
    ) OR EXISTS (
        SELECT 1
          FROM user_identity_links l
          JOIN identity_sources s ON s.id=l.source_id
         WHERE l.user_id=p_user_id
           AND l.id IS DISTINCT FROM p_excluded_link_id
           AND l.state='active'
           AND 'authenticate'=ANY(l.purposes)
           AND s.state='active'
    );
$$;

SELECT apply_worker_ownership(
    'identity_recovery_available(bigint,bigint)'::regprocedure
);
