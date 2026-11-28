-- Create one source-bound SCIM bearer token verifier. The plaintext token never
-- reaches PostgreSQL; callers pass only its bcrypt hash plus the lowercase hex
-- SHA-256 of the raw token (p_token_lookup_hash) as the non-secret indexed
-- lookup key used by scim_token_lookup() at auth time. The lookup hash is NOT a
-- verifier — bcrypt comparison against p_token_hash remains mandatory on every
-- request — and cannot be reversed into the 256-bit random token.
CREATE OR REPLACE FUNCTION scim_token_create(
    p_source_key TEXT,
    p_name TEXT,
    p_token_hash TEXT,
    p_expires_at TIMESTAMPTZ,
    p_deletion_policy TEXT,
    p_created_by TEXT,
    p_token_lookup_hash TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_token_id BIGINT;
BEGIN
    IF p_source_key IS NULL OR p_source_key <> btrim(p_source_key)
       OR octet_length(p_source_key) NOT BETWEEN 1 AND 64
       OR p_name IS NULL OR p_name <> btrim(p_name)
       OR octet_length(p_name) NOT BETWEEN 1 AND 128
       OR p_name ~ '[[:cntrl:]]'
       OR p_token_hash IS NULL
       OR octet_length(p_token_hash) NOT BETWEEN 20 AND 256
       OR p_token_lookup_hash IS NULL
       OR p_token_lookup_hash !~ '^[0-9a-f]{64}$'
       OR p_deletion_policy NOT IN ('soft','hard')
       OR p_created_by IS NULL OR p_created_by <> btrim(p_created_by)
       OR octet_length(p_created_by) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'invalid SCIM token request'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"scimToken"}';
    END IF;

    SELECT * INTO v_source
      FROM identity_sources
     WHERE source_key = p_source_key
     FOR SHARE;
    IF NOT FOUND OR v_source.kind <> 'scim' OR v_source.state <> 'active' THEN
        RAISE EXCEPTION 'SCIM token requires an active SCIM identity source'
            USING ERRCODE = 'BZ228',
                  HINT = jsonb_build_object(
                      'type','identity_source_invalid',
                      'field','sourceKey',
                      'sourceKey',p_source_key,
                      'remediation','bind the token to an active SCIM source'
                  )::text;
    END IF;

    INSERT INTO scim_tokens (
        name, token_hash, token_lookup_hash, expires_at, deletion_policy,
        created_by, source_id
    ) VALUES (
        p_name, p_token_hash, p_token_lookup_hash, p_expires_at,
        p_deletion_policy, p_created_by, v_source.id
    )
    RETURNING id INTO v_token_id;

    RETURN jsonb_build_object(
        'tokenId',v_token_id::text,
        'sourceId',v_source.id::text,
        'sourceKey',v_source.source_key,
        'sourceGeneration',v_source.generation::text
    );
END;
$$;

SELECT apply_worker_ownership(
    'scim_token_create(text,text,text,timestamptz,text,text,text)'::regprocedure
);
