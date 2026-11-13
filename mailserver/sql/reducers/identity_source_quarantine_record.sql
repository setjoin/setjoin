-- Durable engine-side quarantine accounting for the normalized directory-sync
-- pipeline. The engine skips two object classes instead of staging them
-- (missing immutable subject; in-scope upsert without a usable mail
-- attribute). Skipping keeps one malformed object from wedging the source
-- cursor, but the owed review work must not survive only as a log line: the
-- engine calls this reducer BEFORE the page cursor is acknowledged, so a
-- crash or restart cannot lose the only durable evidence of the skip. One row
-- per (source, object key, reason); re-traversals accumulate occurrences
-- instead of duplicating evidence. Accounting is generation- and lease-fenced
-- exactly like discovery itself: a stale or lease-less process cannot write
-- evidence for a source it no longer owns.
CREATE OR REPLACE FUNCTION identity_source_quarantine_record(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_process_instance_id UUID,
    p_records JSONB
) RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_generation BIGINT;
    v_state TEXT;
    v_kind TEXT;
    v_count INTEGER;
    v_record JSONB;
    v_key TEXT;
    v_code TEXT;
    v_digest BYTEA;
    v_recorded INTEGER := 0;
BEGIN
    IF p_source_id IS NULL OR p_expected_generation IS NULL
       OR p_records IS NULL OR jsonb_typeof(p_records) <> 'array' THEN
        RAISE EXCEPTION 'invalid identity source quarantine request'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"quarantine"}';
    END IF;

    v_count := jsonb_array_length(p_records);
    IF v_count < 1 OR v_count > 500 THEN
        RAISE EXCEPTION 'identity source quarantine request exceeds bounds'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"records","limit":500}';
    END IF;

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
                      'type','identity_source_invalid','state',v_state
                  )::text;
    END IF;
    -- Discovery accounting inherits the discovery lease fence: the engine
    -- records quarantines mid-cycle, between lease acquisition and the cursor
    -- commit, so only the current lease holder may write the ledger.
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
                  HINT = '{"type":"identity_lease_lost","field":"quarantine"}';
    END IF;

    -- Validate every record before writing any: one malformed object must
    -- fail the whole accounting call loudly rather than partially record it.
    FOR v_record IN SELECT value FROM jsonb_array_elements(p_records)
    LOOP
        IF jsonb_typeof(v_record) <> 'object'
           OR NULLIF(btrim(v_record->>'objectKey'), '') IS NULL
           OR octet_length(v_record->>'objectKey') > 512
           OR v_record->>'objectKey' ~ '[[:cntrl:]]'
           OR v_record->>'reasonCode' !~ '^[A-Z0-9_.:-]{1,64}$'
           OR v_record->>'subjectDigest' !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'invalid identity source quarantine record'
                USING ERRCODE = 'BZ228',
                      HINT = '{"type":"identity_source_invalid","field":"records"}';
        END IF;
    END LOOP;

    -- Collapse duplicate (key, reason) pairs inside one page so a repeated
    -- skip still accounts exactly one occurrence per traversal.
    FOR v_key, v_code, v_digest IN
        SELECT DISTINCT ON (payload->>'objectKey', payload->>'reasonCode')
            payload->>'objectKey',
            payload->>'reasonCode',
            decode(payload->>'subjectDigest', 'hex')
        FROM jsonb_array_elements(p_records) AS elements(payload)
        ORDER BY payload->>'objectKey', payload->>'reasonCode'
    LOOP
        INSERT INTO identity_source_quarantines (
            source_id, object_key, reason_code, subject_digest, last_generation
        ) VALUES (
            p_source_id, v_key, v_code, v_digest, p_expected_generation
        )
        ON CONFLICT (source_id, object_key, reason_code) DO UPDATE SET
            occurrences = identity_source_quarantines.occurrences + 1,
            subject_digest = EXCLUDED.subject_digest,
            last_generation = EXCLUDED.last_generation,
            last_quarantined_at = statement_timestamp(),
            updated_at = statement_timestamp();

        v_recorded := v_recorded + 1;
    END LOOP;

    -- One append-only link event per accounting call (not per occurrence)
    -- keeps quarantine visible in the same event stream operators already
    -- watch, without unbounded event growth while a source stays broken.
    INSERT INTO identity_link_events (source_id, action, reason, metadata)
    VALUES (
        p_source_id,
        'source_entry_quarantined',
        'connector objects quarantined before staging',
        jsonb_build_object(
            'recorded', v_recorded,
            'generation', p_expected_generation
        )
    );

    RETURN v_recorded;
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_quarantine_record(bigint,bigint,uuid,jsonb)'::regprocedure
);
