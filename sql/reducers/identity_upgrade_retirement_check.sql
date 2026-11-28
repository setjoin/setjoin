CREATE OR REPLACE FUNCTION identity_upgrade_retirement_check()
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
WITH facts AS (
    SELECT
        EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema='public' AND table_name='users'
               AND column_name IN (
                   'oidc_subject','oidc_issuer','saml_name_id',
                   'saml_idp_entity_id','ad_object_guid','scim_external_id'
               )
        ) AS legacy_columns,
        EXISTS (
            SELECT 1 FROM identity_sources
             WHERE source_key LIKE 'legacy:%'
        ) AS legacy_sources,
        EXISTS (
            SELECT 1 FROM identity_sources
             WHERE read_mode <> 'normalized'
        ) AS rollback_readers,
        EXISTS (
            SELECT 1 FROM identity_shadow_divergences
             WHERE state='open'
        ) AS open_divergences,
        EXISTS (
            SELECT 1 FROM identity_transition_effects
             WHERE state<>'completed'
        ) AS pending_effects,
        EXISTS (
            SELECT 1 FROM identity_jobs
             WHERE state IN ('queued','running')
        ) AS pending_jobs
)
SELECT jsonb_build_object(
    -- A live reducer cannot prove the release-time code-graph/restore drill.
    -- Therefore this endpoint remains fail-closed even after every database
    -- dependency is gone; the destructive retirement is a separate release.
    'ready',FALSE,
    'destructiveMigrationIncluded',FALSE,
    'checks',jsonb_build_array(
        jsonb_build_object('name','legacy_columns_absent',
            'passed',NOT legacy_columns,
            'nextAction',CASE WHEN legacy_columns
                THEN 'retain rollback columns until a later retirement release'
                ELSE 'none' END),
        jsonb_build_object('name','legacy_sources_absent',
            'passed',NOT legacy_sources,
            'nextAction',CASE WHEN legacy_sources
                THEN 'retire legacy source configurations after inventory export'
                ELSE 'none' END),
        jsonb_build_object('name','normalized_readers_only',
            'passed',NOT rollback_readers,
            'nextAction',CASE WHEN rollback_readers
                THEN 'complete shadow and canary promotion for every source'
                ELSE 'none' END),
        jsonb_build_object('name','no_open_divergence',
            'passed',NOT open_divergences,
            'nextAction',CASE WHEN open_divergences
                THEN 'resolve or explicitly disposition every divergence'
                ELSE 'none' END),
        jsonb_build_object('name','no_pending_effects',
            'passed',NOT pending_effects,
            'nextAction',CASE WHEN pending_effects
                THEN 'drain accepted identity transition effects'
                ELSE 'none' END),
        jsonb_build_object('name','no_pending_jobs',
            'passed',NOT pending_jobs,
            'nextAction',CASE WHEN pending_jobs
                THEN 'wait for or cancel bounded identity jobs'
                ELSE 'none' END),
        jsonb_build_object('name','code_graph_restore_proof',
            'passed',FALSE,
            'nextAction','run release-time code, restore, and downgrade evidence checks')
    ),
    'nextAction','retirement remains a separate release after one rollback window'
)
FROM facts
$$;

SELECT apply_worker_ownership(
    'identity_upgrade_retirement_check()'::regprocedure
);
