-- Operator inventory for SCIM token verifiers. Includes unbound legacy rows so
-- they are visible for remediation even though auth never accepts them.
CREATE OR REPLACE FUNCTION scim_token_list()
RETURNS TABLE(
    token_id BIGINT,
    name TEXT,
    source_key TEXT,
    source_state TEXT,
    created_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    deletion_policy TEXT,
    token_hash_prefix TEXT
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT st.id,st.name,COALESCE(src.source_key,'(unbound)'),
           COALESCE(src.state,'unbound'),st.created_at,st.last_used_at,
           st.expires_at,st.revoked_at,st.deletion_policy,left(st.token_hash,8)
      FROM scim_tokens st
      LEFT JOIN identity_sources src ON src.id=st.source_id
     ORDER BY st.id
$$;

SELECT apply_worker_ownership(
    'scim_token_list()'::regprocedure
);
