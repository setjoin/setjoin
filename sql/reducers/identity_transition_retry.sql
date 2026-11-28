CREATE OR REPLACE FUNCTION identity_transition_retry(
    p_actor BIGINT,
    p_transition_id UUID,
    p_expected_generation BIGINT,
    p_effect_id UUID,
    p_reason TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_effect identity_transition_effects%ROWTYPE;
    v_request_digest BYTEA;
BEGIN
    IF p_actor IS NULL OR p_transition_id IS NULL
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_effect_id IS NULL
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'invalid identity transition retry'
            USING ERRCODE='BZ241';
    END IF;
    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
     FOR UPDATE;
    IF NOT FOUND
       OR v_t.state NOT IN (
           'effects_pending','failed_recoverable','completed',
           'rolling_back','rolled_back'
       )
       OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition is not retryable'
            USING ERRCODE='BZ234';
    END IF;
    IF v_t.transition_generation<>p_expected_generation THEN
        RAISE EXCEPTION 'identity transition generation is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale","operation":"retry"}';
    END IF;
    SELECT * INTO v_effect
      FROM identity_transition_effects
     WHERE transition_id=p_transition_id
       AND effect_id=p_effect_id
     FOR UPDATE;
    IF NOT FOUND OR v_effect.state<>'failed'
       OR v_effect.attempt_count>=20 THEN
        RAISE EXCEPTION 'named identity transition effect is not retryable'
            USING ERRCODE='BZ238',
                  HINT='{"type":"identity_effect_terminal","remediation":"use rollback preview when eligible or export an escalation bundle"}';
    END IF;
    IF v_t.rollback_execution_elevation_id IS NOT NULL
       AND v_effect.effect_kind IN (
           'auth_sessions','livekit_sessions','subscriber_notice'
       ) THEN
        RAISE EXCEPTION 'forward effect cannot be retried after rollback authority committed'
            USING ERRCODE='BZ238',
                  HINT='{"type":"identity_effect_terminal","remediation":"retry the matching rollback effect"}';
    END IF;
    IF v_t.rollback_execution_elevation_id IS NULL
       AND v_effect.effect_kind IN (
           'rollback_auth_sessions','rollback_livekit_sessions',
           'rollback_subscriber_notice'
       ) THEN
        RAISE EXCEPTION 'rollback effect cannot be retried before rollback authority committed'
            USING ERRCODE='BZ238';
    END IF;
    v_request_digest := digest(jsonb_build_object(
        'operation','retry',
        'transitionId',p_transition_id::text,
        'transitionGeneration',p_expected_generation::text,
        'effectId',p_effect_id::text,
        'effectKind',v_effect.effect_kind,
        'attemptCount',v_effect.attempt_count,
        'reason',p_reason
    )::text,'sha256');
    IF NOT identity_transition_idempotency_claim(
        p_actor,'retry:'||p_effect_id::text,p_idempotency_key,
        p_transition_id,v_request_digest
    ) THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;
    UPDATE identity_transition_effects
       SET state='pending',
           next_attempt_at=statement_timestamp(),
           last_error_code=NULL,
           updated_at=statement_timestamp()
     WHERE transition_id=p_transition_id
       AND effect_id=p_effect_id
       AND state='failed'
       AND attempt_count=v_effect.attempt_count;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'named identity transition effect changed concurrently'
            USING ERRCODE='BZ235';
    END IF;
    UPDATE identity_transition_steps
       SET state='pending',
           retry_at=statement_timestamp(),
           error_code=NULL,
           error_detail=NULL
     WHERE transition_id=p_transition_id
       AND stage=v_effect.effect_kind;
    IF v_t.state='failed_recoverable'
       AND v_effect.effect_kind IN (
           'auth_sessions','livekit_sessions',
           'rollback_auth_sessions','rollback_livekit_sessions'
       )
       AND NOT EXISTS (
           SELECT 1 FROM identity_transition_effects
            WHERE transition_id=p_transition_id
              AND state='failed'
              AND effect_kind IN (
                  CASE
                    WHEN v_effect.effect_kind LIKE 'rollback\_%' ESCAPE '\'
                    THEN 'rollback_auth_sessions'
                    ELSE 'auth_sessions'
                  END,
                  CASE
                    WHEN v_effect.effect_kind LIKE 'rollback\_%' ESCAPE '\'
                    THEN 'rollback_livekit_sessions'
                    ELSE 'livekit_sessions'
                  END
              )
       ) THEN
        PERFORM identity_transition_set_state(
            p_transition_id,'failed_recoverable',
            CASE
              WHEN v_t.rollback_execution_elevation_id IS NOT NULL
              THEN 'rolling_back'
              ELSE 'effects_pending'
            END,
            NULL
        );
    END IF;
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,metadata
    ) VALUES(
        p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_effect_retried',p_reason,
        jsonb_build_object(
            'effectId',p_effect_id,
            'effectKind',v_effect.effect_kind,
            'attemptCount',v_effect.attempt_count
        )
    );
    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_retry(bigint,uuid,bigint,uuid,text,uuid)'::regprocedure
);
