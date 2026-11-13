CREATE OR REPLACE FUNCTION identity_source_provider_bind(
    p_kind TEXT,
    p_provider TEXT,
    p_provider_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source_key TEXT;
    v_source identity_sources%ROWTYPE;
BEGIN
    IF p_kind NOT IN ('oidc','saml')
       OR p_provider IS NULL OR octet_length(p_provider) NOT BETWEEN 1 AND 2048
       OR p_provider ~ '[[:cntrl:]]'
       OR p_provider_key IS NULL
       OR p_provider_key !~ ('^'||p_kind||':[A-Za-z0-9._:-]+$')
       OR octet_length(p_provider_key) > 255 THEN
        RAISE EXCEPTION 'invalid federated provider binding'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid"}';
    END IF;
    v_source_key := p_kind||':'||
        substr(encode(digest(p_provider,'sha256'),'hex'),1,48);
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-source:'||v_source_key,0
    ));
    INSERT INTO identity_sources(
        source_key,display_name,kind,capabilities,state,provider_key
    ) VALUES(
        v_source_key,upper(p_kind)||' authentication '||
        substr(encode(digest(p_provider,'sha256'),'hex'),1,12),p_kind,
        '{"authenticate":true,"provision_lifecycle":false,"stable_immutable_subject":true}'::jsonb,
        'active',p_provider_key
    )
    ON CONFLICT(source_key) DO UPDATE
       SET provider_key=COALESCE(identity_sources.provider_key,EXCLUDED.provider_key),
           updated_at=statement_timestamp()
     WHERE identity_sources.kind=EXCLUDED.kind
       AND (identity_sources.provider_key IS NULL
            OR identity_sources.provider_key=EXCLUDED.provider_key);
    SELECT * INTO v_source FROM identity_sources
     WHERE source_key=v_source_key AND kind=p_kind
       AND provider_key=p_provider_key FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'provider binding conflicts with an existing source'
            USING ERRCODE='BZ230',
                  HINT='{"type":"identity_subject_conflict"}';
    END IF;
    RETURN jsonb_build_object(
        'sourceId',v_source.id::text,'sourceKey',v_source.source_key,
        'generation',v_source.generation::text
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_source_provider_bind(text,text,text)'::regprocedure
);
