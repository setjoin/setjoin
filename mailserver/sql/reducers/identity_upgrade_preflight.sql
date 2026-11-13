CREATE OR REPLACE FUNCTION identity_upgrade_preflight(
    p_expected_schema_version INTEGER,
    p_worker_dsn_ready BOOLEAN,
    p_owner_dsn_ready BOOLEAN,
    p_direct_dsn_ready BOOLEAN,
    p_authserver_configured BOOLEAN,
    p_secrets_decryptable BOOLEAN
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_schema_version INTEGER;
    v_backup_completed_at TIMESTAMPTZ;
    v_hard_collisions BIGINT;
    v_excluded BIGINT;
    v_partial_pairs BIGINT;
    v_source_invalid BIGINT;
    v_checks JSONB;
    v_blockers JSONB;
    v_report JSONB;
BEGIN
    SELECT max(version) INTO v_schema_version FROM public.schema_migrations;
    SELECT max(completed_at) INTO v_backup_completed_at
      FROM public.backup_runs WHERE status = 'completed';
    SELECT count(*) INTO v_hard_collisions
      FROM public.identity_match_candidates
     WHERE status IN ('pending','deferred') AND evidence_class = 'conflict';
    SELECT count(*) INTO v_excluded
      FROM public.users u
     WHERE is_guest_account(u.id)
        OR NOT EXISTS (
            SELECT 1 FROM public.mailboxes m
             WHERE m.user_id = u.id AND m.is_primary
        );
    SELECT count(*) INTO v_partial_pairs
      FROM public.identity_legacy_federation_pair_inventory;
    SELECT count(*) INTO v_source_invalid
      FROM public.identity_sources
     WHERE jsonb_typeof(capabilities) <> 'object'
        OR capabilities = '{}'::jsonb
        OR state = 'error';

    v_checks := jsonb_build_array(
        jsonb_build_object(
            'name','schema_binary_compatible','severity','blocker',
            'passed',v_schema_version = p_expected_schema_version,
            'facts',jsonb_build_object(
                'databaseSchemaVersion',v_schema_version,
                'binaryExpectedSchemaVersion',p_expected_schema_version
            ),
            'nextAction',CASE WHEN v_schema_version = p_expected_schema_version
                THEN 'none' ELSE 'deploy matching schema and binary versions' END
        ),
        jsonb_build_object(
            'name','database_role_dsns','severity','blocker',
            'passed',p_worker_dsn_ready AND p_owner_dsn_ready AND p_direct_dsn_ready,
            'facts',jsonb_build_object(
                'worker',p_worker_dsn_ready,'owner',p_owner_dsn_ready,
                'direct',p_direct_dsn_ready
            ),
            'nextAction',CASE WHEN p_worker_dsn_ready AND p_owner_dsn_ready
                                  AND p_direct_dsn_ready
                THEN 'none' ELSE 'configure DB_WORKER_DSN, DB_OWNER_DSN, and DB_DIRECT_DSN' END
        ),
        jsonb_build_object(
            'name','authserver_identity_capability','severity','blocker',
            'passed',p_authserver_configured,
            'facts',jsonb_build_object('configured',p_authserver_configured),
            'nextAction',CASE WHEN p_authserver_configured THEN 'none'
                ELSE 'configure and verify the authserver readiness endpoint' END
        ),
        jsonb_build_object(
            'name','identity_secrets_decryptable','severity','blocker',
            'passed',p_secrets_decryptable,
            'facts',jsonb_build_object('startupValidation',p_secrets_decryptable),
            'nextAction',CASE WHEN p_secrets_decryptable THEN 'none'
                ELSE 'restore the identity config keyring and restart validation' END
        ),
        jsonb_build_object(
            'name','recent_backup','severity','blocker',
            'passed',v_backup_completed_at IS NOT NULL
                     AND v_backup_completed_at >= statement_timestamp() - interval '24 hours',
            'facts',jsonb_build_object('lastCompletedAt',v_backup_completed_at),
            'nextAction',CASE WHEN v_backup_completed_at IS NOT NULL
                                  AND v_backup_completed_at >= statement_timestamp() - interval '24 hours'
                THEN 'none' ELSE 'complete and verify a backup less than 24 hours old' END
        ),
        jsonb_build_object(
            'name','source_capabilities_valid','severity','blocker',
            'passed',v_source_invalid = 0,
            'facts',jsonb_build_object('invalidSources',v_source_invalid),
            'nextAction',CASE WHEN v_source_invalid = 0 THEN 'none'
                ELSE 'repair or pause invalid identity sources' END
        ),
        jsonb_build_object(
            'name','hard_anchor_collisions_dispositioned','severity','blocker',
            'passed',v_hard_collisions = 0,
            'facts',jsonb_build_object('openHardCollisions',v_hard_collisions),
            'nextAction',CASE WHEN v_hard_collisions = 0 THEN 'none'
                ELSE 'decide every hard-anchor conflict before backfill' END
        ),
        jsonb_build_object(
            'name','excluded_accounts_inventoried','severity','info',
            'passed',TRUE,
            'facts',jsonb_build_object('excludedAccounts',v_excluded),
            'nextAction','none'
        ),
        jsonb_build_object(
            'name','legacy_partial_pairs_inventoried','severity','blocker',
            'passed',v_partial_pairs = 0,
            'facts',jsonb_build_object('partialPairs',v_partial_pairs),
            'nextAction',CASE WHEN v_partial_pairs = 0 THEN 'none'
                ELSE 'resolve or explicitly exclude every partial federation pair' END
        )
    );
    SELECT COALESCE(jsonb_agg(check_row->>'name' ORDER BY check_row->>'name'),
                    '[]'::jsonb)
      INTO v_blockers
      FROM jsonb_array_elements(v_checks) check_row
     WHERE check_row->>'severity' = 'blocker'
       AND NOT (check_row->>'passed')::boolean;

    v_report := jsonb_build_object(
        'manifestVersion','1',
        'generatedAt',statement_timestamp(),
        'phase','preflight',
        'checks',v_checks,
        'blockers',v_blockers,
        'safeToBackfill',jsonb_array_length(v_blockers) = 0,
        'featureFlags',jsonb_build_object(
            'identityModelV2',COALESCE((SELECT enabled FROM public.feature_toggles
                WHERE key='feature.identity_model_v2'),FALSE),
            'normalizedReads',COALESCE((SELECT enabled FROM public.feature_toggles
                WHERE key='feature.identity_normalized_reads'),FALSE),
            'transitions',COALESCE((SELECT enabled FROM public.feature_toggles
                WHERE key='feature.identity_transitions'),FALSE)
        ),
        'estimates',jsonb_build_object(
            'people',(SELECT count(*) FROM public.users),
            'maximumBatchSize',500,
            'maximumDurationSeconds',900
        )
    );
    RETURN v_report || jsonb_build_object(
        'sha256',encode(digest(
            convert_to((v_report - 'generatedAt')::text,'UTF8'),'sha256'
        ),'hex')
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_upgrade_preflight(integer,boolean,boolean,boolean,boolean,boolean)'::regprocedure
);
