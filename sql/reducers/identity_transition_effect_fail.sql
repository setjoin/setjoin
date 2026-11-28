CREATE OR REPLACE FUNCTION identity_transition_effect_fail(
    p_worker_id TEXT,
    p_transition_id UUID,
    p_effect_id UUID,
    p_error_code TEXT,
    p_error_detail TEXT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_effect identity_transition_effects%ROWTYPE;
BEGIN
    IF p_worker_id IS NULL OR p_transition_id IS NULL OR p_effect_id IS NULL
       OR octet_length(p_worker_id) NOT BETWEEN 1 AND 255
       OR p_worker_id ~ '[[:cntrl:]]'
       OR p_error_code IS NULL
       OR octet_length(p_error_code) NOT BETWEEN 1 AND 128
       OR p_error_code ~ '[[:cntrl:]]'
       OR (p_error_detail IS NOT NULL
           AND octet_length(p_error_detail)>2048) THEN
        RAISE EXCEPTION 'invalid identity transition effect failure'
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
       SET state='failed',
           worker_id=NULL,
           lease_expires_at=NULL,
           last_error_code=p_error_code,
           updated_at=statement_timestamp()
     WHERE transition_id=p_transition_id AND effect_id=p_effect_id;
    UPDATE identity_transition_steps
       SET state='failed',
           finished_at=statement_timestamp(),
           error_code=p_error_code,
           error_detail=p_error_detail
     WHERE transition_id=p_transition_id
       AND stage=v_effect.effect_kind;
    IF v_t.state IN ('effects_pending','rolling_back')
       AND v_effect.effect_kind IN (
           'auth_sessions','livekit_sessions',
           'rollback_auth_sessions','rollback_livekit_sessions'
       ) THEN
        PERFORM identity_transition_set_state(
            p_transition_id,v_t.state,'failed_recoverable',p_error_code
        );
    END IF;
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,metadata
    ) VALUES(
        NULL,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_failed','identity transition effect failed',
        jsonb_build_object(
            'effectId',p_effect_id,
            'effectKind',v_effect.effect_kind,
            'errorCode',p_error_code
        )
    );
    RETURN jsonb_build_object(
        'transitionId',p_transition_id,
        'effectId',p_effect_id,
        'kind',v_effect.effect_kind,
        'effectState','failed',
        'transitionState',(
            SELECT state FROM identity_transitions
             WHERE id=p_transition_id
        ),
        'errorCode',p_error_code
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_effect_fail(text,uuid,uuid,text,text)'::regprocedure
);
