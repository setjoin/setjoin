-- Generation-CAS, idempotent source lifecycle authority.  State changes fence
-- new discovery.  Already-staged batches retain their accepted generation and
-- drain through the connector reducers independently of the current state.
CREATE OR REPLACE FUNCTION identity_source_lifecycle(
    p_actor BIGINT,
    p_source_key TEXT,
    p_action TEXT,
    p_expected_generation BIGINT,
    p_idempotency_key UUID,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_target TEXT;
    v_digest BYTEA;
    v_receipt identity_source_operations%ROWTYPE;
    v_result JSONB;
BEGIN
    IF p_actor IS NULL OR p_idempotency_key IS NULL
       OR p_expected_generation IS NULL OR p_expected_generation <= 0
       OR p_action NOT IN ('validate','activate','pause','resume','retire')
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity source lifecycle request'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","field":"lifecycle"}';
    END IF;
    v_digest := digest(concat_ws(':',p_source_key,p_action,
        p_expected_generation::text,p_reason),'sha256');
    PERFORM pg_advisory_xact_lock(
        hashtextextended('identity-source-operation:' || p_idempotency_key::text, 0)
    );
    SELECT * INTO v_receipt FROM identity_source_operations
     WHERE idempotency_key=p_idempotency_key;
    IF FOUND THEN
        IF v_receipt.operation <> p_action
           OR v_receipt.request_digest <> v_digest THEN
            RAISE EXCEPTION 'identity source idempotency key was reused'
                USING ERRCODE='BZ240',
                      HINT='{"type":"identity_idempotency_conflict","field":"Idempotency-Key"}';
        END IF;
        RETURN v_receipt.result || jsonb_build_object('replayed',true);
    END IF;

    SELECT * INTO v_source FROM identity_sources
     WHERE source_key=p_source_key FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source not found'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","field":"sourceKey"}';
    END IF;
    IF v_source.generation <> p_expected_generation THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE='BZ229',
                  HINT=jsonb_build_object(
                      'type','identity_generation_stale',
                      'expectedGeneration',p_expected_generation,
                      'actualGeneration',v_source.generation
                  )::text;
    END IF;

    v_target := CASE p_action
        WHEN 'validate' THEN 'validated'
        WHEN 'activate' THEN 'active'
        WHEN 'pause' THEN 'paused'
        WHEN 'resume' THEN 'active'
        WHEN 'retire' THEN 'retired'
    END;
    IF NOT (
        (p_action='validate' AND v_source.state IN ('draft','error'))
        OR (p_action='activate' AND v_source.state='validated')
        OR (p_action='pause' AND v_source.state='active')
        OR (p_action='resume' AND v_source.state='paused')
        OR (p_action='retire' AND v_source.state IN ('draft','validated','paused'))
    ) THEN
        RAISE EXCEPTION 'illegal identity source lifecycle transition'
            USING ERRCODE='BZ238',
                  HINT=jsonb_build_object(
                      'type','identity_transition_illegal',
                      'state',v_source.state,'action',p_action
                  )::text;
    END IF;

    UPDATE identity_sources
       SET state=v_target,generation=generation+1,updated_by=p_actor,
           updated_at=statement_timestamp()
     WHERE id=v_source.id AND generation=p_expected_generation
     RETURNING generation INTO v_source.generation;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source generation changed'
            USING ERRCODE='BZ229',
                  HINT='{"type":"identity_generation_stale"}';
    END IF;

    INSERT INTO identity_link_events(
        actor_user_id,source_id,action,reason,before_digest,after_digest,metadata
    ) VALUES (
        p_actor,v_source.id,
        CASE p_action
          WHEN 'validate' THEN 'source_validated'
          WHEN 'activate' THEN 'source_activated'
          WHEN 'pause' THEN 'source_paused'
          WHEN 'resume' THEN 'source_resumed'
          WHEN 'retire' THEN 'source_retired'
        END,
        p_reason,
        digest(concat_ws(':',v_source.id::text,p_expected_generation::text,
                         v_source.state),'sha256'),
        digest(concat_ws(':',v_source.id::text,v_source.generation::text,
                         v_target),'sha256'),
        jsonb_build_object('generation',v_source.generation)
    );
    DELETE FROM identity_source_leases WHERE source_id=v_source.id;
    v_result := jsonb_build_object(
        'sourceId',v_source.id::text,'sourceKey',p_source_key,
        'state',v_target,'generation',v_source.generation::text
    );
    INSERT INTO identity_source_operations(
        idempotency_key,source_id,actor_user_id,operation,request_digest,result
    ) VALUES (
        p_idempotency_key,v_source.id,p_actor,p_action,v_digest,v_result
    );
    PERFORM app_notify('config_changed',jsonb_build_object(
        'key','identity.source.' || v_source.id::text,
        'source_id',v_source.id,'generation',v_source.generation
    )::text);
    RETURN v_result || jsonb_build_object('replayed',false);
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_lifecycle(bigint,text,text,bigint,uuid,text)'::regprocedure
);
