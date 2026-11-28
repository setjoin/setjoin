CREATE OR REPLACE FUNCTION identity_doctor(
    p_expected_schema_version INTEGER,
    p_worker_dsn_ready BOOLEAN,
    p_owner_dsn_ready BOOLEAN,
    p_direct_dsn_ready BOOLEAN,
    p_authserver_configured BOOLEAN,
    p_secrets_decryptable BOOLEAN,
    p_source_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_preflight JSONB;
    v_source_id BIGINT;
    v_checks JSONB;
    v_extra JSONB;
    v_failed BIGINT;
BEGIN
    v_preflight := identity_upgrade_preflight(
        p_expected_schema_version, p_worker_dsn_ready, p_owner_dsn_ready,
        p_direct_dsn_ready, p_authserver_configured, p_secrets_decryptable
    );
    IF p_source_key IS NOT NULL THEN
        SELECT id INTO v_source_id FROM public.identity_sources
         WHERE source_key = p_source_key;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'identity source not found'
                USING ERRCODE='BZ228',
                      HINT='{"type":"identity_source_invalid","field":"sourceKey"}';
        END IF;
    END IF;
    v_extra := jsonb_build_array(
        jsonb_build_object(
            'name','source_lease_health','severity','blocker',
            'passed',NOT EXISTS (
                SELECT 1 FROM public.identity_source_leases l
                 WHERE (v_source_id IS NULL OR l.source_id=v_source_id)
                   AND l.lease_until <= statement_timestamp()
            ),
            'facts',jsonb_build_object(
                'staleLeases',(SELECT count(*) FROM public.identity_source_leases l
                    WHERE (v_source_id IS NULL OR l.source_id=v_source_id)
                      AND l.lease_until <= statement_timestamp())
            ),
            'nextAction',CASE WHEN NOT EXISTS (
                SELECT 1 FROM public.identity_source_leases l
                 WHERE (v_source_id IS NULL OR l.source_id=v_source_id)
                   AND l.lease_until <= statement_timestamp()
            ) THEN 'none' ELSE 'restart the named source worker or wait for lease expiry' END
        ),
        jsonb_build_object(
            'name','source_cursor_age','severity','warning',
            'passed',NOT EXISTS (
                SELECT 1 FROM public.identity_sources s
                 WHERE (v_source_id IS NULL OR s.id=v_source_id)
                   AND s.state='active'
                   AND (s.last_success_at IS NULL OR
                        s.last_success_at < statement_timestamp()-interval '30 minutes')
            ),
            'facts',jsonb_build_object(
                'staleActiveSources',(SELECT count(*) FROM public.identity_sources s
                    WHERE (v_source_id IS NULL OR s.id=v_source_id)
                      AND s.state='active'
                      AND (s.last_success_at IS NULL OR
                           s.last_success_at < statement_timestamp()-interval '30 minutes'))
            ),
            'nextAction','run source dry-run and inspect cursor/inbox health'
        ),
        jsonb_build_object(
            'name','inbox_quarantine_backlog','severity','blocker',
            'passed',NOT EXISTS (
                SELECT 1 FROM public.identity_source_inbox i
                 WHERE (v_source_id IS NULL OR i.source_id=v_source_id)
                   AND i.state='quarantined'
            ),
            'facts',jsonb_build_object(
                'pending',(SELECT count(*) FROM public.identity_source_inbox i
                    WHERE (v_source_id IS NULL OR i.source_id=v_source_id)
                      AND i.state='pending'),
                'quarantined',(SELECT count(*) FROM public.identity_source_inbox i
                    WHERE (v_source_id IS NULL OR i.source_id=v_source_id)
                      AND i.state='quarantined')
            ),
            'nextAction','inspect quarantined entries and decide their conflicts'
        ),
        jsonb_build_object(
            'name','shadow_gate','severity','blocker',
            'passed',NOT EXISTS (
                SELECT 1 FROM public.identity_shadow_divergences d
                 WHERE (v_source_id IS NULL OR d.source_id=v_source_id)
                   AND d.state='open'
                   AND d.divergence_class IN (
                       'person_mismatch','authority_mismatch','access_mismatch'
                   )
            ),
            'facts',jsonb_build_object(
                'criticalOpen',(SELECT count(*) FROM public.identity_shadow_divergences d
                    WHERE (v_source_id IS NULL OR d.source_id=v_source_id)
                      AND d.state='open'
                      AND d.divergence_class IN (
                          'person_mismatch','authority_mismatch','access_mismatch'
                      ))
            ),
            'nextAction','pause the source canary and resolve critical divergence'
        ),
        jsonb_build_object(
            'name','approval_consumer','severity','blocker',
            'passed',EXISTS (
                SELECT 1 FROM public.approval_policies
                 WHERE consumer_type='identity.transition' AND enabled
            ),
            'facts',jsonb_build_object(
                'enabledPolicies',(SELECT count(*) FROM public.approval_policies
                    WHERE consumer_type='identity.transition' AND enabled)
            ),
            'nextAction','enable the identity.transition approval policy'
        ),
        jsonb_build_object(
            'name','independent_break_glass_continuity','severity','blocker',
            'passed',(
                SELECT count(DISTINCT u.id) >= 2
                  FROM public.system_config c
                  CROSS JOIN LATERAL jsonb_array_elements_text(c.value) x(raw)
                  JOIN public.users u ON u.id=x.raw::bigint
                 WHERE c.key='ca_break_glass_user_ids'
                   AND u.enabled
            ),
            'facts',jsonb_build_object(
                'activeEligibleAdmins',(
                    SELECT count(DISTINCT u.id)
                      FROM public.system_config c
                      CROSS JOIN LATERAL jsonb_array_elements_text(c.value) x(raw)
                      JOIN public.users u ON u.id=x.raw::bigint
                     WHERE c.key='ca_break_glass_user_ids'
                       AND u.enabled
                ),
                'required',2
            ),
            'nextAction','configure two distinct enabled break-glass administrators'
        ),
        jsonb_build_object(
            'name','transition_effect_worker','severity','blocker',
            'passed',NOT EXISTS (
                SELECT 1 FROM public.identity_transition_effects
                 WHERE state IN ('pending','running')
                   AND updated_at < statement_timestamp()-interval '30 minutes'
            ),
            'facts',jsonb_build_object(
                'pending',(SELECT count(*) FROM public.identity_transition_effects
                    WHERE state<>'completed'),
                'oldestSeconds',COALESCE((SELECT extract(epoch FROM
                    statement_timestamp()-min(updated_at))::bigint
                    FROM public.identity_transition_effects
                    WHERE state<>'completed'),0)
            ),
            'nextAction','inspect and retry the exact failed transition effect'
        ),
        jsonb_build_object(
            'name','feature_flags_safe','severity','info',
            'passed',TRUE,
            'facts',jsonb_build_object(
                'identityModelV2',COALESCE((SELECT enabled FROM public.feature_toggles
                    WHERE key='feature.identity_model_v2'),FALSE),
                'normalizedReads',COALESCE((SELECT enabled FROM public.feature_toggles
                    WHERE key='feature.identity_normalized_reads'),FALSE),
                'transitions',COALESCE((SELECT enabled FROM public.feature_toggles
                    WHERE key='feature.identity_transitions'),FALSE)
            ),
            'nextAction','none'
        )
    );
    v_checks := (v_preflight->'checks') || v_extra;
    SELECT count(*) INTO v_failed
      FROM jsonb_array_elements(v_checks) c
     WHERE c->>'severity' = 'blocker' AND NOT (c->>'passed')::boolean;
    RETURN jsonb_build_object(
        'generatedAt',statement_timestamp(),
        'sourceKey',p_source_key,
        'passed',v_failed=0,
        'blockingCount',v_failed,
        'checks',v_checks
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_doctor(integer,boolean,boolean,boolean,boolean,boolean,text)'::regprocedure
);
