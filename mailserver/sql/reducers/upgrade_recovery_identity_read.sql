CREATE OR REPLACE FUNCTION upgrade_recovery_identity_read()
RETURNS JSONB
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT jsonb_build_object(
        'installationId',installation_id::text,
        'timelineId',timeline_id::text
    )
      FROM upgrade_control_state
     WHERE singleton
$$;

SELECT apply_upgrade_ownership(
    'upgrade_recovery_identity_read()'::regprocedure,true,true
);
