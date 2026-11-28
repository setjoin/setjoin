CREATE OR REPLACE FUNCTION identity_transition_effect_complete(
    p_worker_id TEXT,
    p_transition_id UUID,
    p_effect_id UUID,
    p_output_digest BYTEA DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_effect identity_transition_effects%ROWTYPE;
    v_terminal TEXT;
BEGIN
    IF p_worker_id IS NULL OR p_transition_id IS NULL OR p_effect_id IS NULL
       OR octet_length(p_worker_id) NOT BETWEEN 1 AND 255
       OR p_worker_id ~ '[[:cntrl:]]'
       OR (p_output_digest IS NOT NULL
           AND octet_length(p_output_digest)<>32) THEN
        RAISE EXCEPTION 'invalid identity transition effect completion'
            USING ERRCODE='BZ241';
    END IF;
    SELECT * INTO v_t FROM identity_transitions
     WHERE id=p_transition_id FOR UPDATE;
    SELECT * INTO v_effect FROM identity_transition_effects
     WHERE transition_id=p_transition_id AND effect_id=p_effect_id
     FOR UPDATE;
    IF NOT FOUND
       OR v_effect.state<>'running'
       OR v_effect.worker_id<>p_worker_id
       OR (
           (v_t.state='effects_pending'
            AND v_effect.effect_kind LIKE 'rollback\_%' ESCAPE '\')
           OR
           (v_t.state='rolling_back'
            AND v_effect.effect_kind NOT LIKE 'rollback\_%' ESCAPE '\')
           OR (
               v_t.state NOT IN (
                   'effects_pending','rolling_back','failed_recoverable'
               )
               AND NOT (
                   v_t.state='completed'
                   AND v_effect.effect_kind='subscriber_notice'
               )
               AND NOT (
                   v_t.state='rolled_back'
                   AND v_effect.effect_kind='rollback_subscriber_notice'
               )
           )
       ) THEN
        RAISE EXCEPTION 'identity transition effect claim is stale'
            USING ERRCODE='BZ235';
    END IF;
    UPDATE identity_transition_effects
       SET state='completed',
           worker_id=NULL,
           lease_expires_at=NULL,
           completed_at=statement_timestamp(),
           last_error_code=NULL,
           updated_at=statement_timestamp()
     WHERE transition_id=p_transition_id AND effect_id=p_effect_id;
    UPDATE identity_transition_steps
       SET state='completed',
           output_digest=COALESCE(p_output_digest,input_digest),
           finished_at=statement_timestamp(),
           error_code=NULL,error_detail=NULL
     WHERE transition_id=p_transition_id
       AND stage=v_effect.effect_kind;

    IF v_t.state IN ('effects_pending','rolling_back')
       AND NOT EXISTS (
        SELECT 1 FROM identity_transition_effects e
         WHERE e.transition_id=p_transition_id
           AND (
               (v_t.state='effects_pending'
                AND e.effect_kind NOT LIKE 'rollback\_%' ESCAPE '\')
               OR
               (v_t.state='rolling_back'
                AND e.effect_kind LIKE 'rollback\_%' ESCAPE '\')
           )
           AND e.effect_kind IN (
               'auth_sessions','livekit_sessions',
               'rollback_auth_sessions','rollback_livekit_sessions'
           )
           AND e.state NOT IN ('completed','disposed')
       ) THEN
        v_terminal := CASE WHEN v_t.state='rolling_back'
                           THEN 'rolled_back' ELSE 'completed' END;
        PERFORM identity_transition_set_state(
            p_transition_id,v_t.state,v_terminal,NULL
        );
        IF v_terminal='rolled_back' THEN
            UPDATE identity_transitions
               SET rollback_boundary='rolled_back'
             WHERE id=p_transition_id;
        END IF;
        INSERT INTO identity_link_events(
            actor_user_id,user_id,source_id,link_id,transition_id,
            action,reason,metadata
        ) VALUES(
            NULL,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
            CASE WHEN v_terminal='rolled_back'
                 THEN 'transition_rolled_back'
                 ELSE 'transition_completed' END,
            'identity transition effects converged',
            jsonb_build_object('terminalState',v_terminal)
        );
    END IF;
    RETURN jsonb_build_object(
        'transitionId',p_transition_id,
        'effectId',p_effect_id,
        'kind',v_effect.effect_kind,
        'effectState','completed',
        'transitionState',(
            SELECT state FROM identity_transitions
             WHERE id=p_transition_id
        )
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_effect_complete(text,uuid,uuid,bytea)'::regprocedure
);
