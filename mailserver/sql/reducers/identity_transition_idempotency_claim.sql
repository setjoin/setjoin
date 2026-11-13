CREATE OR REPLACE FUNCTION identity_transition_idempotency_claim(
    p_actor BIGINT,
    p_operation TEXT,
    p_idempotency_key UUID,
    p_transition_id UUID,
    p_request_digest BYTEA
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_existing identity_transition_idempotency%ROWTYPE;
BEGIN
    IF p_actor IS NULL
       OR p_operation IS NULL
       OR octet_length(p_operation) NOT BETWEEN 1 AND 128
       OR p_operation ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL
       OR p_transition_id IS NULL
       OR p_request_digest IS NULL
       OR octet_length(p_request_digest)<>32 THEN
        RAISE EXCEPTION 'invalid identity transition idempotency claim'
            USING ERRCODE='BZ240';
    END IF;

    INSERT INTO identity_transition_idempotency(
        actor_user_id,operation,idempotency_key,transition_id,request_digest
    ) VALUES(
        p_actor,p_operation,p_idempotency_key,p_transition_id,p_request_digest
    ) ON CONFLICT DO NOTHING;
    IF FOUND THEN
        RETURN true;
    END IF;

    SELECT * INTO v_existing
      FROM identity_transition_idempotency
     WHERE actor_user_id=p_actor
       AND operation=p_operation
       AND idempotency_key=p_idempotency_key
     FOR UPDATE;
    IF NOT FOUND
       OR v_existing.transition_id<>p_transition_id
       OR v_existing.request_digest<>p_request_digest THEN
        RAISE EXCEPTION 'identity transition idempotency key was reused with different input'
            USING ERRCODE='BZ240',
                  HINT=jsonb_build_object(
                      'type','identity_idempotency_conflict',
                      'operation',p_operation
                  )::text;
    END IF;
    RETURN false;
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_idempotency_claim(bigint,text,uuid,uuid,bytea)'::regprocedure
);
