-- V174 — make the identity shadow gate reachable at normal connector cadence.
--
-- The original gate inspected only the newest seven completed batches. At the
-- default 15-minute cadence those rows can cover at most 90 minutes, so a
-- source could never satisfy the documented 24-hour observation requirement.
-- Evaluate the complete successful observation rail instead, while refusing
-- admission whenever any source batch remains non-terminal.

CREATE OR REPLACE FUNCTION public.identity_upgrade_shadow(
    p_source_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source_id BIGINT;
    v_completed_batches INTEGER;
    v_window_start TIMESTAMPTZ;
    v_window_end TIMESTAMPTZ;
    v_open_batches INTEGER;
    v_window_hours NUMERIC;
    v_critical BIGINT;
    v_missing BIGINT;
    v_ambiguity BIGINT;
    v_eligible BOOLEAN;
BEGIN
    SELECT id INTO v_source_id FROM public.identity_sources
     WHERE source_key=p_source_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source not found'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","field":"sourceKey"}';
    END IF;
    SELECT count(*)::integer,min(completed_at),max(completed_at)
      INTO v_completed_batches,v_window_start,v_window_end
      FROM public.identity_source_batches
     WHERE source_id=v_source_id AND state='completed';
    SELECT count(*)::integer
      INTO v_open_batches
      FROM public.identity_source_batches
     WHERE source_id=v_source_id AND state<>'completed';
    v_window_hours := CASE
        WHEN v_window_start IS NULL OR v_window_end IS NULL THEN 0
        ELSE round(extract(epoch FROM v_window_end-v_window_start)/3600,2)
    END;
    SELECT count(*) INTO v_critical
      FROM public.identity_shadow_divergences
     WHERE source_id=v_source_id AND state='open'
       AND divergence_class IN (
           'person_mismatch','authority_mismatch','access_mismatch'
       );
    SELECT count(*) INTO v_missing
      FROM public.identity_shadow_divergences
     WHERE source_id=v_source_id AND state='open'
       AND divergence_class='missing_projection';
    SELECT count(*) INTO v_ambiguity
      FROM public.identity_shadow_divergences
     WHERE source_id=v_source_id AND state='open'
       AND divergence_class='expected_legacy_ambiguity';
    v_eligible := v_completed_batches>=7
        AND v_open_batches=0
        AND v_window_end-v_window_start>=interval '24 hours'
        AND v_critical=0 AND v_missing=0 AND v_ambiguity=0;
    RETURN jsonb_build_object(
        'sourceKey',p_source_key,
        'eligible',v_eligible,
        'completedSyncs',least(v_completed_batches,7),
        'requiredSyncs',7,
        'windowStartedAt',v_window_start,
        'windowHours',v_window_hours,
        'requiredWindowHours',24,
        'criticalDivergences',v_critical,
        'missingProjections',v_missing,
        'undispositionedAmbiguities',v_ambiguity,
        'nextAction',CASE
            WHEN v_critical>0 THEN 'pause canary and resolve critical divergences'
            WHEN v_missing>0 THEN 'repair rollback projections'
            WHEN v_ambiguity>0 THEN 'disposition or exclude every expected ambiguity'
            WHEN v_open_batches>0 THEN 'let the current source sync reach terminal state'
            WHEN v_completed_batches<7 THEN 'complete seven consecutive full syncs'
            WHEN v_window_hours<24
                THEN 'continue completed source sync coverage across 24 hours'
            ELSE 'canary plan is permitted' END
    );
END;
$$;

SELECT public.apply_worker_ownership(
    'identity_upgrade_shadow(text)'::regprocedure
);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (174, now())
  ON CONFLICT (version) DO NOTHING;
