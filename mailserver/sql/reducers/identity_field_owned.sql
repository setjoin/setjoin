CREATE OR REPLACE FUNCTION identity_field_owned(
    p_user_id BIGINT,
    p_field TEXT,
    p_source_id BIGINT,
    p_link_id BIGINT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1 FROM identity_attribute_authority a
         WHERE a.user_id=p_user_id AND a.field=p_field
           AND a.authority_kind='source'
           AND a.source_id=p_source_id AND a.link_id=p_link_id
           AND a.local_override_state <> 'active'
    )
$$;

SELECT apply_worker_ownership(
    'identity_field_owned(bigint,text,bigint,bigint)'::regprocedure
);
