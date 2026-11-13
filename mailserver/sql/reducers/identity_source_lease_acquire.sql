-- Compare-and-set lease for remote discovery. Inbox drains do not require this
-- lease; only one process may acknowledge new remote pages for a source.
CREATE OR REPLACE FUNCTION identity_source_lease_acquire(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_process_instance_id UUID,
    p_lease_seconds INTEGER DEFAULT 45
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_generation BIGINT;
    v_state TEXT;
BEGIN
    IF p_source_id IS NULL OR p_expected_generation IS NULL
       OR p_process_instance_id IS NULL
       OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'invalid identity source lease request'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"lease"}';
    END IF;

    SELECT generation, state INTO v_generation, v_state
    FROM identity_sources
    WHERE id = p_source_id
    FOR UPDATE;

    IF NOT FOUND OR v_generation <> p_expected_generation THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = jsonb_build_object(
                      'type','identity_generation_stale',
                      'expectedGeneration',p_expected_generation,
                      'actualGeneration',v_generation
                  )::text;
    END IF;
    IF v_state <> 'active' THEN
        RETURN FALSE;
    END IF;

    INSERT INTO identity_source_leases (
        source_id, process_instance_id, source_generation,
        lease_until, heartbeat_at
    ) VALUES (
        p_source_id, p_process_instance_id, p_expected_generation,
        statement_timestamp() + make_interval(secs => p_lease_seconds),
        statement_timestamp()
    )
    ON CONFLICT (source_id) DO UPDATE
       SET process_instance_id = EXCLUDED.process_instance_id,
           source_generation = EXCLUDED.source_generation,
           lease_until = EXCLUDED.lease_until,
           heartbeat_at = EXCLUDED.heartbeat_at
     WHERE identity_source_leases.lease_until <= statement_timestamp()
        OR (
            identity_source_leases.process_instance_id = EXCLUDED.process_instance_id
            AND identity_source_leases.source_generation = EXCLUDED.source_generation
        );

    RETURN FOUND;
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_lease_acquire(bigint,bigint,uuid,integer)'::regprocedure
);
