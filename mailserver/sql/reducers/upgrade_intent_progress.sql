CREATE OR REPLACE FUNCTION upgrade_intent_progress(
    p_intent_id BIGINT,
    p_expected_generation BIGINT,
    p_executor_id TEXT,
    p_lease_id UUID,
    p_to_state TEXT,
    p_evidence_digest TEXT,
    p_evidence JSONB DEFAULT '{}'::jsonb
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
    v_generation BIGINT;
    v_allowed BOOLEAN;
    v_digest BYTEA;
BEGIN
    IF p_intent_id IS NULL OR p_intent_id<=0
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_executor_id IS NULL OR octet_length(p_executor_id) NOT BETWEEN 1 AND 128
       OR p_executor_id !~ '^[A-Za-z0-9._:-]+$' OR p_lease_id IS NULL
       OR p_evidence_digest IS NULL OR p_evidence_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_evidence IS NULL OR jsonb_typeof(p_evidence)<>'object'
       OR octet_length(p_evidence::text)>65536 THEN
        RAISE EXCEPTION 'invalid upgrade progress input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    SELECT * INTO v_intent
      FROM upgrade_intents WHERE id=p_intent_id FOR UPDATE;
    IF FOUND AND v_intent.state=p_to_state
       AND v_intent.state_generation=p_expected_generation+1
       AND v_intent.executor_id=p_executor_id AND v_intent.lease_id=p_lease_id
       AND EXISTS (
            SELECT 1 FROM upgrade_intent_events e
             WHERE e.intent_id=p_intent_id
               AND e.state_generation=v_intent.state_generation
               AND e.to_state=p_to_state
               AND e.executor_id=p_executor_id
               AND e.evidence_digest=decode(lower(p_evidence_digest),'hex')
               AND e.evidence=p_evidence
       ) THEN
        RETURN jsonb_build_object(
            'intentId',v_intent.id::text,'state',v_intent.state,
            'stateGeneration',v_intent.state_generation::text,'replayed',true
        );
    END IF;
    IF NOT FOUND OR v_intent.state_generation<>p_expected_generation
       OR v_intent.executor_id<>p_executor_id OR v_intent.lease_id<>p_lease_id THEN
        RAISE EXCEPTION 'upgrade progress target is stale or held by another executor'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"progress"}';
    END IF;
    v_allowed := CASE v_intent.state
        WHEN 'claimed' THEN p_to_state IN ('preflight','rolling_back')
        WHEN 'preflight' THEN p_to_state IN ('recovery_point','rolling_back')
        WHEN 'recovery_point' THEN p_to_state IN ('staged','rolling_back')
        WHEN 'staged' THEN p_to_state IN ('maintenance','rolling_back')
        WHEN 'maintenance' THEN p_to_state IN ('migrations','rolling_back')
        WHEN 'migrations' THEN p_to_state IN ('switched','rolling_back')
        WHEN 'switched' THEN p_to_state IN ('readiness','rolling_back')
        WHEN 'readiness' THEN p_to_state IN ('committed','rolling_back')
        ELSE false END;
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'illegal upgrade progress transition'
            USING ERRCODE='BZ242',HINT=jsonb_build_object(
                'type','upgrade_intent_state_conflict',
                'from',v_intent.state,'to',p_to_state
            )::text;
    END IF;
    v_digest := decode(lower(p_evidence_digest),'hex');
    UPDATE upgrade_intents
       SET state=p_to_state,state_generation=state_generation+1,
           completed_at=CASE WHEN p_to_state IN ('cancelled','rolled_back')
                             THEN statement_timestamp() ELSE completed_at END,
           updated_at=statement_timestamp()
     WHERE id=p_intent_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
    INSERT INTO upgrade_intent_events(
        intent_id,state_generation,from_state,to_state,executor_id,
        evidence_digest,evidence
    ) VALUES(
        p_intent_id,v_generation,v_intent.state,p_to_state,p_executor_id,
        v_digest,p_evidence
    );
    PERFORM app_notify('upgrade_intent_changed',json_build_object(
        'intent_id',p_intent_id,'state',p_to_state,'generation',v_generation
    )::text);
    RETURN jsonb_build_object(
        'intentId',p_intent_id::text,'state',p_to_state,
        'stateGeneration',v_generation::text,'replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_progress(bigint,bigint,text,uuid,text,text,jsonb)'::regprocedure,
    false,true
);
