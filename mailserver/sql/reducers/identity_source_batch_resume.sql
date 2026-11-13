-- Return the exact durable batch a restarted AD/LDAP worker must drain before
-- any new remote discovery. Reads cross-person inbox rows behind one narrow
-- SECURITY DEFINER seam so the runtime app role never needs table access.
CREATE OR REPLACE FUNCTION identity_source_batch_resume(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_process_instance_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_batch identity_source_batches%ROWTYPE;
    v_object_keys JSONB;
BEGIN
    SELECT * INTO v_source
      FROM identity_sources
     WHERE id=p_source_id
     FOR UPDATE;
    IF NOT FOUND OR v_source.generation <> p_expected_generation
       OR v_source.state <> 'active' THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE='BZ229',
                  HINT=jsonb_build_object(
                      'type','identity_generation_stale',
                      'expectedGeneration',p_expected_generation,
                      'actualGeneration',v_source.generation,
                      'sourceState',v_source.state
                  )::text;
    END IF;
    IF v_source.kind IN ('ad','ldap') AND NOT EXISTS (
        SELECT 1
          FROM identity_source_leases l
         WHERE l.source_id=p_source_id
           AND l.source_generation=p_expected_generation
           AND l.process_instance_id=p_process_instance_id
           AND l.lease_until>statement_timestamp()
    ) THEN
        RAISE EXCEPTION 'identity source recovery lease was lost'
            USING ERRCODE='BZ229',
                  HINT='{"type":"identity_lease_lost","remediation":"reacquire the source lease before resuming its durable batch"}';
    END IF;

    SELECT * INTO v_batch
      FROM identity_source_batches
     WHERE source_id=p_source_id AND state<>'completed'
     ORDER BY discovered_at
     LIMIT 1
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('found',false);
    END IF;
    IF v_batch.source_generation <> p_expected_generation THEN
        RAISE EXCEPTION 'unfinished identity source batch generation is stale'
            USING ERRCODE='BZ229',
                  HINT=jsonb_build_object(
                      'type','identity_generation_stale',
                      'batchId',v_batch.batch_id,
                      'batchGeneration',v_batch.source_generation,
                      'sourceGeneration',p_expected_generation
                  )::text;
    END IF;

    SELECT COALESCE(jsonb_agg(i.object_key ORDER BY i.discovered_at,i.object_key),'[]'::jsonb)
      INTO v_object_keys
      FROM identity_source_inbox i
     WHERE i.source_id=p_source_id
       AND i.batch_id=v_batch.batch_id
       AND i.state='pending';

    RETURN jsonb_build_object(
        'found',true,
        'batchId',v_batch.batch_id,
        'generation',v_batch.source_generation::text,
        'entryCount',v_batch.entry_count,
        'objectKeys',v_object_keys
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_batch_resume(bigint,bigint,uuid)'::regprocedure
);
