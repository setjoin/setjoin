-- Persist one bounded remote page before the connector acknowledges it.
CREATE OR REPLACE FUNCTION identity_source_batch_begin(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_batch_id UUID,
    p_remote_cursor JSONB,
    p_entries JSONB,
    p_process_instance_id UUID DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_generation BIGINT;
    v_state TEXT;
    v_kind TEXT;
    v_cursor_digest BYTEA;
    v_count INTEGER;
    v_entry JSONB;
    v_existing identity_source_inbox%ROWTYPE;
BEGIN
    IF p_source_id IS NULL OR p_expected_generation IS NULL
       OR p_batch_id IS NULL OR p_remote_cursor IS NULL
       OR p_entries IS NULL OR jsonb_typeof(p_entries) <> 'array' THEN
        RAISE EXCEPTION 'invalid identity source batch'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"batch"}';
    END IF;
    -- The cursor is directory-derived input persisted up to ~502 times per
    -- page (batch row, one inbox row per entry, pending/committed source
    -- columns), so it carries the same bounds discipline as every other
    -- connector field. Mirrors MaxCursorBytes in identitysource/pipeline.go
    -- and the V236 CHECK constraints.
    IF octet_length(p_remote_cursor::text) > 4096 THEN
        RAISE EXCEPTION 'identity source cursor exceeds 4096 bytes'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"cursor","limit":4096}';
    END IF;

    v_count := jsonb_array_length(p_entries);
    IF v_count > 500 THEN
        RAISE EXCEPTION 'identity source batch exceeds 500 entries'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"entries","limit":500}';
    END IF;
    v_cursor_digest := digest(p_remote_cursor::text, 'sha256');

    SELECT generation, state, kind INTO v_generation, v_state, v_kind
    FROM identity_sources
    WHERE id = p_source_id
    FOR UPDATE;
    IF NOT FOUND OR v_generation <> p_expected_generation THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale"}';
    END IF;
    IF v_state <> 'active' THEN
        RAISE EXCEPTION 'identity source is not active'
            USING ERRCODE = 'BZ228',
                  HINT = jsonb_build_object(
                      'type','identity_source_invalid','state',v_state,
                      'remediation','activate the source before discovery'
                  )::text;
    END IF;
    IF v_kind IN ('ad','ldap') AND NOT EXISTS (
        SELECT 1
          FROM identity_source_leases l
         WHERE l.source_id = p_source_id
           AND l.source_generation = p_expected_generation
           AND l.process_instance_id = p_process_instance_id
           AND l.lease_until > statement_timestamp()
    ) THEN
        RAISE EXCEPTION 'identity source discovery lease was lost'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_lease_lost","remediation":"discard the fetched page, reacquire the source lease, and rediscover"}';
    END IF;

    IF EXISTS (
        SELECT 1 FROM identity_source_batches
        WHERE source_id = p_source_id
          AND state <> 'completed'
          AND batch_id <> p_batch_id
    ) THEN
        RAISE EXCEPTION 'identity source already has an unfinished batch'
            USING ERRCODE = 'BZ240',
                  HINT = '{"type":"identity_idempotency_conflict","remediation":"drain or resolve the existing batch before discovering another page"}';
    END IF;

    INSERT INTO identity_source_batches (
        source_id, batch_id, source_generation, remote_cursor,
        remote_cursor_digest, entry_count
    ) VALUES (
        p_source_id, p_batch_id, p_expected_generation, p_remote_cursor,
        v_cursor_digest, v_count
    )
    ON CONFLICT (source_id, batch_id) DO NOTHING;

    IF EXISTS (
        SELECT 1 FROM identity_source_batches
        WHERE source_id = p_source_id AND batch_id = p_batch_id
          AND (
              source_generation <> p_expected_generation
              OR remote_cursor_digest <> v_cursor_digest
              OR entry_count <> v_count
          )
    ) THEN
        RAISE EXCEPTION 'identity source batch id was reused with different input'
            USING ERRCODE = 'BZ240',
                  HINT = '{"type":"identity_idempotency_conflict","field":"batchId"}';
    END IF;

    FOR v_entry IN SELECT value FROM jsonb_array_elements(p_entries)
    LOOP
        IF jsonb_typeof(v_entry) <> 'object'
           OR NULLIF(btrim(v_entry->>'objectKey'), '') IS NULL
           OR NULLIF(btrim(v_entry->>'immutableSubject'), '') IS NULL
           OR jsonb_typeof(v_entry->'payload') <> 'object' THEN
            RAISE EXCEPTION 'invalid identity source entry'
                USING ERRCODE = 'BZ228',
                      HINT = '{"type":"identity_source_invalid","field":"entries"}';
        END IF;

        SELECT * INTO v_existing
        FROM identity_source_inbox
        WHERE source_id = p_source_id
          AND batch_id = p_batch_id
          AND object_key = v_entry->>'objectKey';

        IF FOUND AND (
            v_existing.source_generation <> p_expected_generation
            OR v_existing.remote_cursor_digest <> v_cursor_digest
            OR v_existing.immutable_subject <> v_entry->>'immutableSubject'
            OR v_existing.sanitized_payload <> v_entry->'payload'
        ) THEN
            RAISE EXCEPTION 'identity source entry key was reused with different input'
                USING ERRCODE = 'BZ240',
                      HINT = '{"type":"identity_idempotency_conflict","field":"objectKey"}';
        END IF;

        INSERT INTO identity_source_inbox (
            source_id, batch_id, object_key, source_generation,
            remote_cursor, remote_cursor_digest, immutable_subject,
            sanitized_payload
        ) VALUES (
            p_source_id, p_batch_id, v_entry->>'objectKey',
            p_expected_generation, p_remote_cursor, v_cursor_digest,
            v_entry->>'immutableSubject', v_entry->'payload'
        )
        ON CONFLICT (source_id, batch_id, object_key) DO NOTHING;
    END LOOP;

    UPDATE identity_sources
       SET pending_cursor = p_remote_cursor,
           pending_cursor_digest = v_cursor_digest,
           updated_at = statement_timestamp()
     WHERE id = p_source_id;

    RETURN jsonb_build_object(
        'sourceId',p_source_id::text,
        'batchId',p_batch_id,
        'generation',p_expected_generation::text,
        'entries',v_count,
        'replayed',EXISTS (
            SELECT 1 FROM identity_source_batches
            WHERE source_id = p_source_id AND batch_id = p_batch_id
              AND discovered_at < statement_timestamp()
        )
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_batch_begin(bigint,bigint,uuid,jsonb,jsonb,uuid)'::regprocedure
);
