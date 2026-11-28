CREATE OR REPLACE FUNCTION identity_upgrade_backfill_start(
    p_actor_user_id BIGINT,
    p_preflight_checksum TEXT,
    p_idempotency_key UUID,
    p_reason TEXT,
    p_expected_schema_version INTEGER,
    p_worker_dsn_ready BOOLEAN,
    p_owner_dsn_ready BOOLEAN,
    p_direct_dsn_ready BOOLEAN,
    p_authserver_configured BOOLEAN,
    p_secrets_decryptable BOOLEAN
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_preflight JSONB;
BEGIN
    IF p_preflight_checksum IS NULL
       OR p_preflight_checksum !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid identity preflight checksum'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","field":"preflightChecksum"}';
    END IF;
    v_preflight := identity_upgrade_preflight(
        p_expected_schema_version,p_worker_dsn_ready,p_owner_dsn_ready,
        p_direct_dsn_ready,p_authserver_configured,p_secrets_decryptable
    );
    IF v_preflight->>'sha256' <> p_preflight_checksum THEN
        RAISE EXCEPTION 'identity preflight is stale'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale","remediation":"run upgrade preflight again"}';
    END IF;
    IF NOT (v_preflight->>'safeToBackfill')::boolean THEN
        RAISE EXCEPTION 'identity backfill preflight has blockers'
            USING ERRCODE='BZ234',
                  HINT='{"type":"identity_transition_preflight","remediation":"resolve every preflight blocker"}';
    END IF;
    RETURN identity_job_create(
        p_actor_user_id,'upgrade_backfill',p_idempotency_key,NULL,NULL,
        jsonb_build_object(
            'preflightChecksum',p_preflight_checksum,
            'afterUserId','0',
            'batchSize',500
        ),
        p_reason
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_upgrade_backfill_start(bigint,text,uuid,text,integer,boolean,boolean,boolean,boolean,boolean)'::regprocedure
);
