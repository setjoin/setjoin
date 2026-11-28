CREATE OR REPLACE FUNCTION identity_source_lease_release(
    p_source_id BIGINT,
    p_source_generation BIGINT,
    p_process_instance_id UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    DELETE FROM identity_source_leases
    WHERE source_id = p_source_id
      AND source_generation = p_source_generation
      AND process_instance_id = p_process_instance_id;
    RETURN FOUND;
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_lease_release(bigint,bigint,uuid)'::regprocedure
);
