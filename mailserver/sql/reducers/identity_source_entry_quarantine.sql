CREATE OR REPLACE FUNCTION identity_source_entry_quarantine(
    p_actor BIGINT,
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_batch_id UUID,
    p_object_key TEXT,
    p_error_code TEXT,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_generation BIGINT;
    v_event_id BIGINT;
BEGIN
    IF p_actor IS NULL OR p_error_code IS NULL
       OR p_error_code !~ '^[A-Z0-9_.:-]{1,64}$'
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity source quarantine request'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"quarantine"}';
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

    INSERT INTO identity_link_events (
        actor_user_id, source_id, action, reason, metadata
    ) VALUES (
        p_actor, p_source_id, 'source_entry_quarantined', p_reason,
        jsonb_build_object(
            'batchId',p_batch_id,
            'objectKeyDigest',encode(digest(p_object_key,'sha256'),'hex'),
            'errorCode',p_error_code
        )
    ) RETURNING id INTO v_event_id;

    UPDATE identity_source_inbox
       SET state = 'quarantined', applied_at = statement_timestamp(),
           last_error_code = p_error_code, applied_event_id = NULL
     WHERE source_id = p_source_id AND batch_id = p_batch_id
       AND object_key = p_object_key AND state = 'pending';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source entry is not pending'
            USING ERRCODE = 'BZ240',
                  HINT = '{"type":"identity_idempotency_conflict","field":"entryState"}';
    END IF;

    UPDATE identity_source_batches b
       SET quarantined_count = (
               SELECT count(*) FROM identity_source_inbox i
               WHERE i.source_id = b.source_id AND i.batch_id = b.batch_id
                 AND i.state = 'quarantined'
           ),
           state = 'draining', last_error_code = NULL,
           updated_at = statement_timestamp()
     WHERE b.source_id = p_source_id AND b.batch_id = p_batch_id;

    RETURN jsonb_build_object(
        'state','quarantined','eventId',v_event_id::text
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_entry_quarantine(bigint,bigint,bigint,uuid,text,text,text)'::regprocedure
);
