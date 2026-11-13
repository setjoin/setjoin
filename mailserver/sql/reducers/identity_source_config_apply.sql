-- Idempotent, draft-only source-document apply.  The gateway has already
-- encrypted the canonical secret-free document into p_config_envelope.
CREATE OR REPLACE FUNCTION identity_source_config_apply(
    p_actor BIGINT,
    p_source_key TEXT,
    p_display_name TEXT,
    p_kind TEXT,
    p_capabilities JSONB,
    p_config_envelope BYTEA,
    p_config_key_version BIGINT,
    p_mapping_version BIGINT,
    p_expected_generation BIGINT,
    p_idempotency_key UUID,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source_id BIGINT;
    v_existing_generation BIGINT;
    v_existing_state TEXT;
    v_digest BYTEA;
    v_receipt identity_source_operations%ROWTYPE;
    v_result JSONB;
BEGIN
    IF p_idempotency_key IS NULL OR p_config_envelope IS NULL
       OR octet_length(p_config_envelope) NOT BETWEEN 1 AND 262144 THEN
        RAISE EXCEPTION 'invalid identity source apply request'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","field":"config"}';
    END IF;

    v_digest := digest(
        concat_ws(':', p_source_key, p_display_name, p_kind,
            p_capabilities::text, encode(digest(p_config_envelope,'sha256'),'hex'),
            p_config_key_version::text, p_mapping_version::text,
            COALESCE(p_expected_generation::text,''), p_reason),
        'sha256'
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended('identity-source-operation:' || p_idempotency_key::text, 0)
    );
    SELECT * INTO v_receipt
      FROM identity_source_operations
     WHERE idempotency_key=p_idempotency_key;
    IF FOUND THEN
        IF v_receipt.operation <> 'apply'
           OR v_receipt.request_digest <> v_digest THEN
            RAISE EXCEPTION 'identity source idempotency key was reused'
                USING ERRCODE='BZ240',
                      HINT='{"type":"identity_idempotency_conflict","field":"Idempotency-Key"}';
        END IF;
        RETURN v_receipt.result || jsonb_build_object('replayed',true);
    END IF;

    SELECT id,generation,state
      INTO v_source_id,v_existing_generation,v_existing_state
      FROM identity_sources
     WHERE source_key=p_source_key;
    IF FOUND AND v_existing_state IN ('active','paused','retired') THEN
        RAISE EXCEPTION 'active, paused, or retired source configuration cannot be replaced'
            USING ERRCODE='BZ238',
                  HINT=jsonb_build_object(
                      'type','identity_transition_illegal',
                      'state',v_existing_state,
                      'remediation','pause or retire through the explicit lifecycle; retired sources are terminal'
                  )::text;
    END IF;

    v_result := identity_source_upsert(
        p_actor, v_source_id, p_source_key, p_display_name, p_kind,
        p_capabilities, 'draft', p_config_envelope, p_config_key_version,
        p_mapping_version, p_expected_generation, p_reason
    );
    v_result := v_result || jsonb_build_object('sourceKey',p_source_key);
    INSERT INTO identity_source_operations(
        idempotency_key,source_id,actor_user_id,operation,request_digest,result
    ) VALUES (
        p_idempotency_key,(v_result->>'sourceId')::bigint,p_actor,
        'apply',v_digest,v_result
    );
    RETURN v_result || jsonb_build_object('replayed',false);
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_config_apply(bigint,text,text,text,jsonb,bytea,bigint,bigint,bigint,uuid,text)'::regprocedure
);
