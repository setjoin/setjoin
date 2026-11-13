-- Record a retryable application failure in a separate transaction after the
-- failed reducer call has rolled back. Stale generations are themselves fenced:
-- an old worker cannot rewrite the current source's health evidence.
CREATE OR REPLACE FUNCTION identity_source_entry_fail(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_batch_id UUID,
    p_object_key TEXT,
    p_error_code TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_generation BIGINT;
BEGIN
    IF p_error_code IS NULL OR p_error_code !~ '^[A-Z0-9_.:-]{1,64}$' THEN
        p_error_code := 'INTERNAL';
    END IF;

    SELECT b.source_generation INTO v_generation
    FROM identity_source_batches b
    WHERE b.source_id=p_source_id AND b.batch_id=p_batch_id
    FOR UPDATE;
    IF NOT FOUND OR v_generation <> p_expected_generation THEN
        RAISE EXCEPTION 'identity source batch generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale"}';
    END IF;

    PERFORM 1
    FROM identity_sources
    WHERE id = p_source_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source not found'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"sourceId"}';
    END IF;

    UPDATE identity_source_inbox
       SET attempt_count = attempt_count + 1,
           last_error_code = p_error_code,
           next_attempt_at = statement_timestamp()
               + make_interval(secs => LEAST(3600, 30 * (2 ^ LEAST(attempt_count, 7))))
     WHERE source_id = p_source_id AND batch_id = p_batch_id
       AND object_key = p_object_key AND state = 'pending';

    UPDATE identity_source_batches
       SET state = 'blocked', last_error_code = p_error_code,
           updated_at = statement_timestamp()
     WHERE source_id = p_source_id AND batch_id = p_batch_id
       AND state <> 'completed';

    UPDATE identity_sources
       SET last_failure_at = statement_timestamp(),
           last_error_code = p_error_code,
           updated_at = statement_timestamp()
     WHERE id = p_source_id;
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_entry_fail(bigint,bigint,uuid,text,text)'::regprocedure
);
