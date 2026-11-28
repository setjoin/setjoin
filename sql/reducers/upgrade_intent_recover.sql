CREATE OR REPLACE FUNCTION upgrade_intent_recover(
    p_intent_id BIGINT,
    p_expected_generation BIGINT,
    p_executor_id TEXT,
    p_lease_id UUID,
    p_evidence_digest TEXT,
    p_result JSONB
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_intent upgrade_intents%ROWTYPE;
    v_generation BIGINT;
BEGIN
    IF p_intent_id IS NULL OR p_intent_id<=0
       OR p_expected_generation IS NULL OR p_expected_generation<=0
       OR p_executor_id IS NULL OR octet_length(p_executor_id) NOT BETWEEN 1 AND 128
       OR p_executor_id !~ '^[A-Za-z0-9._:-]+$' OR p_lease_id IS NULL
       OR p_evidence_digest IS NULL OR p_evidence_digest !~ '^[0-9a-fA-F]{64}$'
       OR p_result IS NULL OR jsonb_typeof(p_result)<>'object'
       OR octet_length(p_result::text)>262144 THEN
        RAISE EXCEPTION 'invalid upgrade recovery input'
            USING ERRCODE='BZ251',HINT='{"type":"upgrade_argument_invalid"}';
    END IF;
    SELECT * INTO v_intent FROM upgrade_intents
     WHERE id=p_intent_id FOR UPDATE;
    IF FOUND AND v_intent.state='rolled_back'
       AND v_intent.executor_id=p_executor_id AND v_intent.lease_id=p_lease_id
       AND EXISTS(
           SELECT 1 FROM upgrade_intent_events e
            WHERE e.intent_id=p_intent_id
              AND e.state_generation=v_intent.state_generation
              AND e.from_state='recovery_required' AND e.to_state='rolled_back'
              AND e.executor_id=p_executor_id
              AND e.evidence_digest=decode(lower(p_evidence_digest),'hex')
              AND e.evidence=p_result
       ) THEN
        RETURN jsonb_build_object(
            'intentId',v_intent.id::text,'state',v_intent.state,
            'stateGeneration',v_intent.state_generation::text,'replayed',true
        );
    END IF;
    IF NOT FOUND OR v_intent.state<>'recovery_required'
       OR v_intent.state_generation<>p_expected_generation
       OR v_intent.executor_id<>p_executor_id OR v_intent.lease_id<>p_lease_id THEN
        RAISE EXCEPTION 'illegal or stale upgrade recovery'
            USING ERRCODE='BZ242',HINT='{"type":"upgrade_intent_state_conflict","operation":"recover"}';
    END IF;
    UPDATE upgrade_intents
       SET state='rolled_back',state_generation=state_generation+1,
           completed_at=statement_timestamp(),result=p_result,
           updated_at=statement_timestamp()
     WHERE id=p_intent_id AND state_generation=p_expected_generation
    RETURNING state_generation INTO v_generation;
    INSERT INTO upgrade_intent_events(
        intent_id,state_generation,from_state,to_state,executor_id,
        evidence_digest,evidence
    ) VALUES(
        p_intent_id,v_generation,'recovery_required','rolled_back',p_executor_id,
        decode(lower(p_evidence_digest),'hex'),p_result
    );
    PERFORM audit_write(
        NULL,'upgrade_intent_recovery_reconciled','upgrade_intent',p_intent_id,
        jsonb_build_object('state','recovery_required'),
        jsonb_build_object('state','rolled_back','evidenceDigest',lower(p_evidence_digest)),
        NULL,NULL,'core'
    );
    PERFORM app_notify('upgrade_intent_changed',json_build_object(
        'intent_id',p_intent_id,'state','rolled_back','generation',v_generation
    )::text);
    RETURN jsonb_build_object(
        'intentId',p_intent_id::text,'state','rolled_back',
        'stateGeneration',v_generation::text,'replayed',false
    );
END;
$$;
SELECT apply_upgrade_ownership(
    'upgrade_intent_recover(bigint,bigint,text,uuid,text,jsonb)'::regprocedure,
    false,true
);
