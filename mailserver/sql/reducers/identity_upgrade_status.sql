CREATE OR REPLACE FUNCTION identity_upgrade_status()
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path=pg_catalog,public
AS $$
SELECT jsonb_build_object(
 'schemaVersion',(SELECT max(version) FROM schema_migrations),
 'masterEnabled',COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.identity_model_v2'),false),
 'normalizedReadsEnabled',COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.identity_normalized_reads'),false),
 'transitionsEnabled',COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.identity_transitions'),false),
 'sources',jsonb_build_object(
   'total',(SELECT count(*) FROM identity_sources),
   'shadow',(SELECT count(*) FROM identity_sources WHERE read_mode='shadow'),
   'canary',(SELECT count(*) FROM identity_sources WHERE read_mode='canary'),
   'normalized',(SELECT count(*) FROM identity_sources WHERE read_mode='normalized'),
   'cohortMembers',(SELECT count(*) FROM identity_read_cohort)
 ),
 'blockers',jsonb_build_object(
   'criticalDivergences',(SELECT count(*) FROM identity_shadow_divergences
      WHERE state='open' AND divergence_class<>'expected_legacy_ambiguity'),
   'pendingCandidates',(SELECT count(*) FROM identity_match_candidates
      WHERE status IN ('pending','deferred')),
   'pendingEffects',(SELECT count(*) FROM identity_transition_effects
      WHERE state<>'completed')
 )
)
$$;
SELECT apply_worker_ownership('identity_upgrade_status()'::regprocedure);
