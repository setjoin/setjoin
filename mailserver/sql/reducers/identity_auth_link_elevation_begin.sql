CREATE OR REPLACE FUNCTION identity_auth_link_elevation_begin(
    p_user_id BIGINT,
    p_flow_id UUID,
    p_session_jti TEXT,
    p_session_hash BYTEA,
    p_kind TEXT,
    p_provider_key TEXT,
    p_expires_at TIMESTAMPTZ
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_created TIMESTAMPTZ := statement_timestamp();
BEGIN
    IF p_user_id IS NULL OR p_flow_id IS NULL
       OR p_session_jti IS NULL
       OR octet_length(p_session_jti) NOT BETWEEN 1 AND 255
       OR p_session_jti ~ '[[:cntrl:]]'
       OR p_session_hash IS NULL OR octet_length(p_session_hash)<>32
       OR p_kind NOT IN ('oidc','saml')
       OR p_provider_key IS NULL
       OR octet_length(p_provider_key) NOT BETWEEN 3 AND 255
       OR p_provider_key<>btrim(p_provider_key)
       OR p_provider_key ~ '[[:cntrl:]]'
       OR p_expires_at IS NULL
       OR p_expires_at<=v_created
       OR p_expires_at>v_created+interval '10 minutes 5 seconds' THEN
        RAISE EXCEPTION 'invalid identity link elevation'
            USING ERRCODE='BZ241';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_user_id::text,0
    ));

    IF NOT EXISTS (
        SELECT 1
          FROM users u
          JOIN sessions s ON s.user_id=u.id
         WHERE u.id=p_user_id AND u.enabled
           AND NOT is_guest_account(u.id)
           AND s.id=p_session_jti
           AND s.token_hash=p_session_hash
           AND s.expires_at>v_created
         FOR KEY SHARE OF s
    ) OR EXISTS (
        SELECT 1 FROM session_revocations r
         WHERE r.user_id=p_user_id
           AND r.not_before<=v_created
           AND (
               r.scope='all'
               OR (r.scope='jti' AND r.jti=p_session_jti)
           )
           AND r.not_before>=(
               SELECT s.created_at FROM sessions s
                WHERE s.id=p_session_jti
                  AND s.user_id=p_user_id
                  AND s.token_hash=p_session_hash
           )
    ) THEN
        RAISE EXCEPTION 'identity link session is not active'
            USING ERRCODE='BZ234';
    END IF;

    DELETE FROM identity_auth_link_elevations
     WHERE user_id=p_user_id
       AND (
           expires_at<=v_created
           OR consumed_at IS NOT NULL
       );

    INSERT INTO identity_auth_link_elevations(
        flow_id,user_id,session_jti,session_hash,kind,provider_key,expires_at
    ) VALUES(
        p_flow_id,p_user_id,p_session_jti,p_session_hash,p_kind,
        p_provider_key,p_expires_at
    );

    RETURN jsonb_build_object(
        'started',true,'flowId',p_flow_id::text,'expiresAt',p_expires_at
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_auth_link_elevation_begin(bigint,uuid,text,bytea,text,text,timestamptz)'::regprocedure
);
