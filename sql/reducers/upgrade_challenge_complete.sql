CREATE OR REPLACE FUNCTION upgrade_challenge_complete(
    p_actor BIGINT,
    p_challenge_id UUID,
    p_session_digest BYTEA,
    p_factor_digest BYTEA,
    p_amr TEXT[],
    p_acr TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_challenge upgrade_challenges%ROWTYPE;
    v_amr TEXT[];
    v_elevation_id UUID;
    v_request_digest BYTEA;
BEGIN
    IF p_actor IS NULL OR p_challenge_id IS NULL
       OR p_session_digest IS NULL OR octet_length(p_session_digest)<>32
       OR p_factor_digest IS NULL OR octet_length(p_factor_digest)<>32
       OR p_amr IS NULL OR cardinality(p_amr) NOT BETWEEN 2 AND 16
       OR p_acr<>'aal2' THEN
        RAISE EXCEPTION 'fresh AAL2 system-upgrade step-up is required'
            USING ERRCODE='BZ250',
                  HINT='{"type":"upgrade_authorization_invalid","remediation":"complete a fresh challenge with two verified factors"}';
    END IF;
    SELECT array_agg(DISTINCT factor ORDER BY factor) INTO v_amr
      FROM unnest(p_amr) factor;
    IF EXISTS (
        SELECT 1 FROM unnest(v_amr) factor
         WHERE factor NOT IN ('pwd','otp','hwk','swk','user','mfa')
    ) OR NOT ('mfa'=ANY(v_amr)) OR (
        SELECT count(*)<2 FROM unnest(v_amr) factor
         WHERE factor IN ('pwd','otp','hwk','swk')
    ) THEN
        RAISE EXCEPTION 'fresh AAL2 system-upgrade step-up is required'
            USING ERRCODE='BZ250',
                  HINT='{"type":"upgrade_authorization_invalid","remediation":"complete a fresh challenge with two verified factors"}';
    END IF;

    v_request_digest := digest(jsonb_build_object(
        'operation','upgrade_challenge_complete',
        'actorId',p_actor::text,
        'challengeId',p_challenge_id::text,
        'sessionDigest',encode(p_session_digest,'hex'),
        'factorDigest',encode(p_factor_digest,'hex'),
        'amr',to_jsonb(v_amr),'acr',p_acr
    )::text,'sha256');

    SELECT * INTO v_challenge
      FROM upgrade_challenges
     WHERE id=p_challenge_id AND actor_user_id=p_actor
     FOR UPDATE;
    IF NOT FOUND OR v_challenge.invalidated_at IS NOT NULL
       OR v_challenge.expires_at<=statement_timestamp() THEN
        RAISE EXCEPTION 'upgrade challenge is missing, stale, or expired'
            USING ERRCODE='BZ250',HINT='{"type":"upgrade_authorization_invalid"}';
    END IF;
    IF v_challenge.completed_at IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM upgrade_elevations
             WHERE id=v_challenge.elevation_id
               AND request_digest=v_request_digest
        ) THEN
            RAISE EXCEPTION 'upgrade challenge replay evidence changed'
                USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"challenge_complete"}';
        END IF;
        RETURN (
            SELECT jsonb_build_object(
                'challengeId',v_challenge.id,'elevationId',e.id,
                'expiresAt',e.expires_at,'replayed',true
            ) FROM upgrade_elevations e WHERE e.id=v_challenge.elevation_id
        );
    END IF;
    IF NOT upgrade_actor_authorized(p_actor)
       OR NOT EXISTS (
            SELECT 1
              FROM upgrade_readiness r
              JOIN upgrade_release_catalog c USING(release_id)
              CROSS JOIN upgrade_control_state s
             WHERE r.release_id=v_challenge.release_id
               AND r.readiness_generation=v_challenge.readiness_generation
               AND s.singleton
               AND s.policy_generation=v_challenge.policy_generation
               AND c.status='available'
               AND c.manifest_digest=r.manifest_digest
               AND c.metadata_expires_at>statement_timestamp()
               AND r.status='ready' AND r.blocker_count=0
               AND r.expires_at>statement_timestamp()
       ) THEN
        RAISE EXCEPTION 'upgrade challenge authority or preview state is stale'
            USING ERRCODE='BZ243',HINT='{"type":"upgrade_readiness_stale"}';
    END IF;

    INSERT INTO upgrade_elevations(
        actor_user_id,challenge_id,release_id,preview_digest,
        readiness_generation,policy_generation,session_digest,factor_digest,
        amr,acr,expires_at,request_digest
    ) VALUES(
        p_actor,p_challenge_id,v_challenge.release_id,v_challenge.preview_digest,
        v_challenge.readiness_generation,v_challenge.policy_generation,
        p_session_digest,p_factor_digest,v_amr,p_acr,
        statement_timestamp()+interval '5 minutes',v_request_digest
    ) RETURNING id INTO v_elevation_id;
    UPDATE upgrade_challenges
       SET completed_at=statement_timestamp(),elevation_id=v_elevation_id
     WHERE id=p_challenge_id AND completed_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upgrade challenge completed concurrently'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"challenge_complete"}';
    END IF;
    PERFORM audit_write(
        p_actor,'upgrade_step_up_completed','upgrade_release',NULL,NULL,
        jsonb_build_object(
            'releaseId',v_challenge.release_id,
            'challengeId',p_challenge_id::text,
            'elevationId',v_elevation_id::text
        ),NULL,NULL,'core'
    );
    RETURN jsonb_build_object(
        'challengeId',p_challenge_id,'elevationId',v_elevation_id,
        'expiresAt',statement_timestamp()+interval '5 minutes','replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_challenge_complete(bigint,uuid,bytea,bytea,text[],text)'::regprocedure,
    true,false
);
