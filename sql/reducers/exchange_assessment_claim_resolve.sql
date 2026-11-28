CREATE OR REPLACE FUNCTION exchange_assessment_claim_resolve(
  p_actor_id bigint, p_run_id bigint, p_expected_generation bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_run exchange_assessment_runs%ROWTYPE; v_registry jsonb; v_projection jsonb; v_digest text; v_row exchange_assessment_claim_snapshots%ROWTYPE; v_support_stale boolean;
BEGIN
  SELECT r.* INTO v_run FROM exchange_assessment_runs r
  JOIN exchange_assessment_projects p ON p.id=r.project_id
  WHERE r.id=p_run_id AND exchange_assessment_domain_authorized(p_actor_id,p.domain_id,'exchange.assessment.audit')
  FOR UPDATE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'Exchange assessment run not found' USING ERRCODE='BZ317'; END IF;
  IF v_run.generation<>p_expected_generation THEN RAISE EXCEPTION 'Exchange assessment generation is stale' USING ERRCODE='BZ318'; END IF;
  SELECT s.projection,(s.source_digest<>v_run.registry_digest) INTO v_registry,v_support_stale
  FROM exchange_registry_snapshots s WHERE s.registry_version=v_run.registry_version;
  v_support_stale:=COALESCE(v_support_stale,true) OR v_registry IS NULL OR NOT EXISTS(
    SELECT 1 FROM jsonb_array_elements(COALESCE(v_registry->'supportCells','[]'::jsonb)) cell
    WHERE cell->>'id'=v_run.support_cell_id AND cell->>'digest'=v_run.support_cell_digest);
  IF v_support_stale THEN
    UPDATE exchange_assessment_evidence SET invalidated_at=COALESCE(invalidated_at,statement_timestamp()),
      invalidation_reason=COALESCE(invalidation_reason,'registry_or_support_cell_drift')
      WHERE run_id=v_run.id AND invalidated_at IS NULL;
    UPDATE exchange_assessment_claim_snapshots SET invalidated_at=COALESCE(invalidated_at,statement_timestamp()),
      invalidation_reason=COALESCE(invalidation_reason,'registry_or_support_cell_drift')
      WHERE run_id=v_run.id AND invalidated_at IS NULL;
  END IF;

  SELECT jsonb_build_object(
    'schemaVersion','setjoin.exchange.claim-snapshot/v1','phase','V1A',
    'replacementReady',false,'runId',v_run.id,'runGeneration',v_run.generation,
    'registryDigest',v_run.registry_digest,'supportCellDigest',v_run.support_cell_digest,
    'supportCellStale',v_support_stale,
    'rows',COALESCE(jsonb_agg(jsonb_build_object(
      'capabilityId',c->>'id','mapping',COALESCE(d.outcome_mapping,'none'),
      'decision',COALESCE(d.decision,'pending'),
      'assessmentState',CASE WHEN probe.total=0 THEN 'unassessed'
        WHEN probe.failures>0 THEN 'failed'
        WHEN probe.terminals=probe.total THEN 'complete' ELSE 'partial' END,
      'evidenceTier',COALESCE(e.tier,'unassessed'),
      'claimState',CASE
        WHEN v_support_stale THEN 'stale'
        WHEN COALESCE(d.decision,'pending') NOT IN ('accepted','waived') THEN 'unassessed'
        WHEN e.id IS NULL THEN CASE WHEN stale.has_stale THEN 'stale' ELSE 'unassessed' END
        WHEN d.decision='waived' THEN 'experimental'
        WHEN c->>'claimMaximum' IN ('excluded','unsupported','unassessed') THEN c->>'claimMaximum'
        WHEN e.tier='T0' OR c->>'claimMaximum'='experimental' THEN 'experimental'
        WHEN e.tier='T1' OR c->>'claimMaximum'='provisional' THEN 'provisional'
        ELSE 'supported' END
    ) ORDER BY c->>'id'),'[]'::jsonb))
  INTO v_projection
  FROM exchange_registry_snapshots s CROSS JOIN LATERAL jsonb_array_elements(s.projection->'capabilities') c
  LEFT JOIN exchange_assessment_decisions d ON d.run_id=v_run.id AND d.capability_id=c->>'id'
  LEFT JOIN LATERAL (SELECT count(*)::integer total,
      count(*) FILTER (WHERE pr.terminal_state IN ('collected','not_applicable'))::integer terminals,
      count(*) FILTER (WHERE pr.terminal_state='collection_failed')::integer failures
    FROM exchange_assessment_probe_results pr WHERE pr.run_id=v_run.id AND pr.capability_id=c->>'id') probe ON true
  LEFT JOIN LATERAL (SELECT ev.* FROM exchange_assessment_evidence ev
    WHERE ev.run_id=v_run.id AND ev.capability_id=c->>'id'
      AND ev.support_cell_digest=v_run.support_cell_digest AND ev.invalidated_at IS NULL
      AND ev.expires_at>statement_timestamp()
    ORDER BY ev.tier DESC,ev.captured_at DESC,ev.id DESC LIMIT 1) e ON true
  LEFT JOIN LATERAL (SELECT EXISTS(SELECT 1 FROM exchange_assessment_evidence ev
    WHERE ev.run_id=v_run.id AND ev.capability_id=c->>'id') has_stale) stale ON true
  WHERE s.registry_version=v_run.registry_version;
  v_digest:=encode(digest(convert_to(v_projection::text,'UTF8'),'sha256'),'hex');
  INSERT INTO exchange_assessment_claim_snapshots(run_id,run_generation,registry_digest,support_cell_digest,projection,projection_digest,resolved_by)
  VALUES(v_run.id,v_run.generation,v_run.registry_digest,v_run.support_cell_digest,v_projection,v_digest,p_actor_id)
  ON CONFLICT(run_id,run_generation,projection_digest) DO UPDATE SET projection=excluded.projection RETURNING * INTO v_row;
  PERFORM audit_write(p_actor_id,'exchange.assessment.claim.resolve','exchange_assessment_run',p_run_id,NULL,jsonb_build_object('projectionDigest',v_digest),NULL,NULL,'core');
  RETURN to_jsonb(v_row);
END;
$$;
SELECT apply_worker_ownership('exchange_assessment_claim_resolve(bigint,bigint,bigint)'::regprocedure);
