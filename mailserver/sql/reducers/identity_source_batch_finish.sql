CREATE OR REPLACE FUNCTION identity_source_batch_finish(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_batch_id UUID,
    p_duration_seconds INTEGER DEFAULT 0,
    p_process_instance_id UUID DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_batch identity_source_batches%ROWTYPE;
    v_pending INTEGER;
    v_event_id BIGINT;
BEGIN
    IF p_duration_seconds < 0 THEN
        RAISE EXCEPTION 'invalid identity source duration'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"durationSeconds"}';
    END IF;

    SELECT * INTO v_source
    FROM identity_sources
    WHERE id = p_source_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source not found'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"sourceId"}';
    END IF;

    SELECT * INTO v_batch
    FROM identity_source_batches
    WHERE source_id = p_source_id AND batch_id = p_batch_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source batch not found'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"batchId"}';
    END IF;
    -- Finish copies the stored batch cursor into the durable committed cursor,
    -- so the bound is re-checked here rather than trusted from the staging
    -- path. Mirrors MaxCursorBytes in identitysource/pipeline.go and the V236
    -- CHECK constraints; a row this large cannot be staged post-V236.
    IF octet_length(v_batch.remote_cursor::text) > 4096 THEN
        RAISE EXCEPTION 'identity source stored cursor exceeds 4096 bytes'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"cursor","limit":4096}';
    END IF;
    IF v_batch.source_generation <> p_expected_generation THEN
        RAISE EXCEPTION 'identity source batch generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale"}';
    END IF;
    IF v_batch.state = 'completed' THEN
        RETURN jsonb_build_object(
            'state','completed','replayed',true,
            'cursorAdvanced',true,
            'cursor',v_batch.remote_cursor,
            'applied',v_batch.applied_count,
            'quarantined',v_batch.quarantined_count
        );
    END IF;
    -- A lifecycle generation bump has already fenced new discovery.  An
    -- accepted batch remains authoritative by its stored source_generation
    -- and must be allowed to drain even though pause/retire removed the lease.
    IF v_source.generation = p_expected_generation
       AND v_source.kind IN ('ad','ldap') AND NOT EXISTS (
        SELECT 1
          FROM identity_source_leases l
         WHERE l.source_id = p_source_id
           AND l.source_generation = p_expected_generation
           AND l.process_instance_id = p_process_instance_id
           AND l.lease_until > statement_timestamp()
    ) THEN
        RAISE EXCEPTION 'identity source discovery lease was lost'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_lease_lost","remediation":"reacquire the source lease before committing its remote cursor"}';
    END IF;

    SELECT count(*) INTO v_pending
    FROM identity_source_inbox
    WHERE source_id = p_source_id AND batch_id = p_batch_id
      AND state = 'pending';
    IF v_pending <> 0 THEN
        UPDATE identity_source_batches
           SET state = 'blocked',
               last_error_code = COALESCE(last_error_code,'IDENTITY_PENDING'),
               updated_at = statement_timestamp()
         WHERE source_id = p_source_id AND batch_id = p_batch_id;
        RETURN jsonb_build_object(
            'state','blocked','pending',v_pending,
            'cursorAdvanced',false
        );
    END IF;

    -- Reporting relationships are source-owned authorization data. Reconcile
    -- them only after the entire page has applied so manager links created
    -- later in the page are visible. An absent or unresolved immutable manager
    -- subject clears stale authority instead of preserving a former manager.
    IF v_source.kind IN ('ad','ldap') THEN
        WITH relationships AS (
            SELECT self_link.user_id,
                   manager_link.user_id AS manager_id,
                   self_link.id AS self_link_id
              FROM identity_source_inbox inbox
              JOIN user_identity_links self_link
                ON self_link.source_id=inbox.source_id
               AND self_link.external_subject=inbox.immutable_subject
               AND self_link.state='active'
               AND 'provision'=ANY(self_link.purposes)
              LEFT JOIN user_identity_links manager_link
                ON manager_link.source_id=inbox.source_id
               AND manager_link.external_subject=
                   NULLIF(inbox.sanitized_payload->>'managerSubject','')
               AND manager_link.state='active'
               AND 'provision'=ANY(manager_link.purposes)
             WHERE inbox.source_id=p_source_id
               AND inbox.batch_id=p_batch_id
               AND inbox.source_generation=p_expected_generation
               AND inbox.state='applied'
        ), authority AS (
            INSERT INTO identity_attribute_authority(
                user_id,field,authority_kind,source_id,link_id,
                source_version,value_digest
            )
            SELECT user_id,'manager_id','source',p_source_id,self_link_id,
                   p_expected_generation::text,
                   digest(COALESCE(manager_id::text,''),'sha256')
              FROM relationships
            ON CONFLICT(user_id,field) DO UPDATE
              SET source_version=EXCLUDED.source_version,
                  value_digest=EXCLUDED.value_digest,
                  generation=identity_attribute_authority.generation+1,
                  updated_at=statement_timestamp()
            WHERE identity_attribute_authority.authority_kind='source'
              AND identity_attribute_authority.source_id=p_source_id
              AND identity_attribute_authority.link_id=EXCLUDED.link_id
            RETURNING user_id,source_id,link_id,local_override_state
        )
        UPDATE users u
           SET manager_id=r.manager_id,
               updated_at=statement_timestamp()
          FROM relationships r
          JOIN authority a
            ON a.user_id=r.user_id
           AND a.source_id=p_source_id
           AND a.link_id=r.self_link_id
           AND a.local_override_state <> 'active'
         WHERE u.id=r.user_id
           AND a.user_id=u.id;
    END IF;

    UPDATE identity_source_batches
       SET state = 'completed',
           applied_count = (
               SELECT count(*) FROM identity_source_inbox
               WHERE source_id = p_source_id AND batch_id = p_batch_id
                 AND state = 'applied'
           ),
           quarantined_count = (
               SELECT count(*) FROM identity_source_inbox
               WHERE source_id = p_source_id AND batch_id = p_batch_id
                 AND state = 'quarantined'
           ),
           last_error_code = NULL,
           completed_at = statement_timestamp(),
           updated_at = statement_timestamp()
     WHERE source_id = p_source_id AND batch_id = p_batch_id
     RETURNING * INTO v_batch;

    UPDATE identity_sources
       SET committed_cursor = v_batch.remote_cursor,
           committed_cursor_digest = v_batch.remote_cursor_digest,
           pending_cursor = NULL,
           pending_cursor_digest = NULL,
           last_success_at = statement_timestamp(),
           last_failure_at = NULL,
           last_error_code = NULL,
           updated_at = statement_timestamp()
     WHERE id = p_source_id;

    INSERT INTO identity_link_events (
        source_id, action, reason, after_digest, metadata
    ) VALUES (
        p_source_id, 'source_cursor_committed',
        'connector batch reached terminal state',
        v_batch.remote_cursor_digest,
        jsonb_build_object(
            'batchId',p_batch_id,
            'entries',v_batch.entry_count,
            'applied',v_batch.applied_count,
            'quarantined',v_batch.quarantined_count
        )
    ) RETURNING id INTO v_event_id;

    INSERT INTO identity_sync_log (
        source, source_id, users_checked, users_updated, users_created,
        users_disabled, fields_skipped, conflicts_found, duration_ms,
        error, details
    ) VALUES (
        v_source.kind, p_source_id, v_batch.entry_count, 0,
        v_batch.applied_count, 0, 0, v_batch.quarantined_count,
        p_duration_seconds * 1000, NULL,
        jsonb_build_object(
            'batchId',p_batch_id,
            'cursorDigest',encode(v_batch.remote_cursor_digest,'hex'),
            'quarantined',v_batch.quarantined_count
        )
    );

    RETURN jsonb_build_object(
        'state','completed','cursorAdvanced',true,
        'cursor',v_batch.remote_cursor,
        'applied',v_batch.applied_count,
        'quarantined',v_batch.quarantined_count,
        'eventId',v_event_id::text
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_batch_finish(bigint,bigint,uuid,integer,uuid)'::regprocedure
);
