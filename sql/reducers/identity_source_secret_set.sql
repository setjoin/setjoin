-- Persist a gateway-produced encrypted configuration envelope.  Rotation
-- retains one prior ciphertext for at most 24 hours; plaintext never enters
-- PostgreSQL, audit metadata, NOTIFY, or the result.
CREATE OR REPLACE FUNCTION identity_source_secret_set(
    p_actor BIGINT,
    p_source_key TEXT,
    p_secret_name TEXT,
    p_config_envelope BYTEA,
    p_config_key_version BIGINT,
    p_expected_generation BIGINT,
    p_rotate BOOLEAN,
    p_grace_seconds INTEGER,
    p_idempotency_key UUID,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_operation TEXT;
    v_digest BYTEA;
    v_receipt identity_source_operations%ROWTYPE;
    v_result JSONB;
BEGIN
    IF p_actor IS NULL OR p_idempotency_key IS NULL
       OR p_secret_name IS NULL
       OR p_secret_name !~ '^[A-Za-z][A-Za-z0-9]{0,63}$'
       OR p_config_envelope IS NULL
       OR octet_length(p_config_envelope) NOT BETWEEN 1 AND 262144
       OR p_config_key_version IS NULL OR p_config_key_version <= 0
       OR p_expected_generation IS NULL OR p_expected_generation <= 0
       OR p_rotate IS NULL
       OR p_grace_seconds NOT BETWEEN 0 AND 86400
       OR (p_rotate AND p_grace_seconds = 0)
       OR (NOT p_rotate AND p_grace_seconds <> 0)
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity source secret request'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","field":"secret"}';
    END IF;
    v_operation := CASE WHEN p_rotate THEN 'rotate_secret' ELSE 'set_secret' END;
    v_digest := digest(concat_ws(':',p_source_key,p_secret_name,
        encode(digest(p_config_envelope,'sha256'),'hex'),
        p_config_key_version::text,p_expected_generation::text,
        p_rotate::text,p_grace_seconds::text,p_reason),'sha256');
    PERFORM pg_advisory_xact_lock(
        hashtextextended('identity-source-operation:' || p_idempotency_key::text,0)
    );
    SELECT * INTO v_receipt FROM identity_source_operations
     WHERE idempotency_key=p_idempotency_key;
    IF FOUND THEN
        IF v_receipt.operation<>v_operation
           OR v_receipt.request_digest<>v_digest THEN
            RAISE EXCEPTION 'identity source idempotency key was reused'
                USING ERRCODE='BZ240',
                      HINT='{"type":"identity_idempotency_conflict","field":"Idempotency-Key"}';
        END IF;
        RETURN v_receipt.result || jsonb_build_object('replayed',true);
    END IF;

    SELECT * INTO v_source FROM identity_sources
     WHERE source_key=p_source_key FOR UPDATE;
    IF NOT FOUND OR v_source.generation<>p_expected_generation THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE='BZ229',
                  HINT=jsonb_build_object(
                      'type','identity_generation_stale',
                      'expectedGeneration',p_expected_generation,
                      'actualGeneration',v_source.generation
                  )::text;
    END IF;
    IF v_source.state='retired' THEN
        RAISE EXCEPTION 'retired identity source is terminal'
            USING ERRCODE='BZ238',
                  HINT='{"type":"identity_transition_illegal","state":"retired"}';
    END IF;

    UPDATE identity_sources
       SET previous_config_envelope=CASE WHEN p_rotate THEN config_envelope END,
           previous_config_key_version=CASE WHEN p_rotate THEN config_key_version END,
           previous_config_expires_at=CASE
             WHEN p_rotate AND p_grace_seconds>0
             THEN statement_timestamp()+make_interval(secs=>p_grace_seconds)
           END,
           config_envelope=p_config_envelope,
           config_key_version=p_config_key_version,
           generation=generation+1,updated_by=p_actor,
           updated_at=statement_timestamp()
     WHERE id=v_source.id AND generation=p_expected_generation
     RETURNING generation INTO v_source.generation;

    INSERT INTO identity_link_events(
        actor_user_id,source_id,action,reason,metadata
    ) VALUES (
        p_actor,v_source.id,
        CASE WHEN p_rotate THEN 'source_secret_rotated' ELSE 'source_secret_set' END,
        p_reason,jsonb_build_object(
            'secretName',p_secret_name,'generation',v_source.generation,
            'graceSeconds',CASE WHEN p_rotate THEN p_grace_seconds ELSE 0 END
        )
    );
    v_result := jsonb_build_object(
        'sourceId',v_source.id::text,'sourceKey',p_source_key,
        'state',v_source.state,'generation',v_source.generation::text,
        'secretName',p_secret_name,'secretConfigured',true
    );
    INSERT INTO identity_source_operations(
        idempotency_key,source_id,actor_user_id,operation,request_digest,result
    ) VALUES (
        p_idempotency_key,v_source.id,p_actor,v_operation,v_digest,v_result
    );
    PERFORM app_notify('config_changed',jsonb_build_object(
        'key','identity.source.' || v_source.id::text,
        'source_id',v_source.id,'generation',v_source.generation
    )::text);
    RETURN v_result || jsonb_build_object('replayed',false);
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_secret_set(bigint,text,text,bytea,bigint,bigint,boolean,integer,uuid,text)'::regprocedure
);
