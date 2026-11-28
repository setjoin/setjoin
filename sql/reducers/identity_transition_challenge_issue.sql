CREATE OR REPLACE FUNCTION identity_transition_challenge_issue(
    p_actor BIGINT,
    p_transition_id UUID,
    p_preview_digest TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_existing identity_transition_challenges%ROWTYPE;
    v_digest BYTEA;
    v_request_digest BYTEA;
    v_id UUID;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_preview_digest IS NULL
       OR p_preview_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity transition challenge'
            USING ERRCODE='BZ236';
    END IF;
    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
     FOR UPDATE;
    IF NOT FOUND
       OR NOT EXISTS (SELECT 1 FROM users WHERE id=p_actor AND enabled)
       OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition challenge is not authorized'
            USING ERRCODE='BZ236';
    END IF;
    v_digest := decode(lower(p_preview_digest),'hex');
    IF (v_t.state='rollback_previewed'
        AND (v_t.rollback_preview_digest<>v_digest
             OR v_t.rollback_preview_expires_at<=statement_timestamp()))
       OR (v_t.state<>'rollback_previewed'
           AND (v_t.state NOT IN (
                    'previewed','awaiting_approval','authorized'
                )
                OR v_t.preview_digest<>v_digest
                OR v_t.preview_expires_at<=statement_timestamp())) THEN
        RAISE EXCEPTION 'identity transition preview is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    v_request_digest := digest(jsonb_build_object(
        'operation','challenge_issue',
        'actor',p_actor::text,
        'transitionId',p_transition_id::text,
        'transitionGeneration',v_t.transition_generation::text,
        'previewDigest',lower(p_preview_digest)
    )::text,'sha256');

    INSERT INTO identity_transition_challenges(
        actor_user_id,transition_id,transition_generation,preview_digest,
        expires_at,idempotency_key,request_digest
    ) VALUES(
        p_actor,p_transition_id,v_t.transition_generation,v_digest,
        statement_timestamp()+interval '5 minutes',
        p_idempotency_key,v_request_digest
    )
    ON CONFLICT(actor_user_id,idempotency_key) DO NOTHING
    RETURNING id INTO v_id;
    IF v_id IS NULL THEN
        SELECT * INTO v_existing
          FROM identity_transition_challenges
         WHERE actor_user_id=p_actor
           AND idempotency_key=p_idempotency_key
         FOR UPDATE;
        IF NOT FOUND
           OR v_existing.transition_id<>p_transition_id
           OR v_existing.request_digest<>v_request_digest THEN
            RAISE EXCEPTION 'identity challenge idempotency key was reused with different input'
                USING ERRCODE='BZ240',
                      HINT='{"type":"identity_idempotency_conflict","operation":"transition_challenge"}';
        END IF;
        v_id := v_existing.id;
    END IF;

    RETURN (
        SELECT jsonb_build_object(
            'challengeId',c.id,
            'transitionId',c.transition_id,
            'transitionGeneration',c.transition_generation::text,
            'previewDigest',encode(c.preview_digest,'hex'),
            'expiresAt',c.expires_at,
            'handoffMethod',c.handoff_method,
            'displayCode',upper(substr(replace(c.id::text,'-',''),1,8)),
            'completed',c.completed_at IS NOT NULL,
            'invalidated',c.invalidated_at IS NOT NULL
        )
          FROM identity_transition_challenges c
         WHERE c.id=v_id
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_challenge_issue(bigint,uuid,text,uuid)'::regprocedure
);
