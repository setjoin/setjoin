CREATE OR REPLACE FUNCTION identity_auth_link_authorized(
    p_actor BIGINT,
    p_user_id BIGINT,
    p_kind TEXT,
    p_provider TEXT,
    p_subject TEXT,
    p_provider_key TEXT,
    p_reason TEXT,
    p_flow_id UUID,
    p_session_hash BYTEA
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_elevation identity_auth_link_elevations%ROWTYPE;
    v_result JSONB;
BEGIN
    IF p_actor IS NULL OR p_actor<>p_user_id THEN
        RAISE EXCEPTION 'invalid authorized identity link'
            USING ERRCODE='BZ234';
    END IF;
    IF p_flow_id IS NULL
       OR p_session_hash IS NULL OR octet_length(p_session_hash)<>32 THEN
        RAISE EXCEPTION 'invalid authorized identity link'
            USING ERRCODE='BZ241';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_user_id::text,0
    ));

    SELECT * INTO v_elevation
      FROM identity_auth_link_elevations
     WHERE flow_id=p_flow_id
       AND user_id=p_user_id
       AND kind=p_kind
       AND provider_key=p_provider_key
       AND session_hash=p_session_hash
       AND consumed_at IS NULL
       AND expires_at>statement_timestamp()
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity link authorization is unavailable'
            USING ERRCODE='BZ234';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM sessions s
         WHERE s.id=v_elevation.session_jti
           AND s.user_id=p_user_id
           AND s.token_hash=p_session_hash
           AND s.expires_at>statement_timestamp()
         FOR KEY SHARE
    ) OR EXISTS (
        SELECT 1 FROM session_revocations r
         WHERE r.user_id=p_user_id
           AND r.not_before>=v_elevation.created_at
           AND (
               r.scope='all'
               OR (
                   r.scope='jti'
                   AND r.jti=v_elevation.session_jti
               )
           )
    ) THEN
        RAISE EXCEPTION 'identity link session was revoked'
            USING ERRCODE='BZ234';
    END IF;

    UPDATE identity_auth_link_elevations
       SET consumed_at=statement_timestamp()
     WHERE flow_id=v_elevation.flow_id
       AND consumed_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity link authorization was already consumed'
            USING ERRCODE='BZ234';
    END IF;

    v_result := identity_auth_link(
        p_actor,p_user_id,p_kind,p_provider,p_subject,p_provider_key,p_reason
    );
    RETURN v_result || jsonb_build_object('flowId',p_flow_id::text);
END;
$$;
SELECT apply_worker_ownership(
    'identity_auth_link_authorized(bigint,bigint,text,text,text,text,text,uuid,bytea)'::regprocedure
);
