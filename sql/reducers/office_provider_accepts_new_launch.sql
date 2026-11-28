CREATE OR REPLACE FUNCTION office_provider_accepts_new_launch(
  p_provider_id text,p_platform text,p_family text,p_classification text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.office_provider_policies p
      JOIN public.office_provider_qualifications q
        ON q.id=p.active_qualification_id
       AND q.provider_id=p.provider_id
       AND q.provider_generation=p.generation-1
       AND q.config_sha256=p.config_sha256
       AND q.status='passed' AND q.expires_at>statement_timestamp()
     WHERE p.provider_id=p_provider_id
       AND p.removed_at IS NULL AND p.enabled AND NOT p.draining
       AND p.route_state='active_for_scope'
       AND p.entitlement_state IN ('evaluation','valid','expiring')
       AND p_platform=ANY(p.allowed_platforms)
       AND p_family=ANY(p.allowed_file_families)
       AND p_classification=ANY(p.allowed_classifications)
       AND EXISTS (
         SELECT 1 FROM public.office_provider_health_observations h
          WHERE h.provider_id=p.provider_id
            AND h.provider_generation=p.generation
            AND h.state='healthy' AND h.capacity_state='available'
            AND h.expires_at>statement_timestamp()
          ORDER BY h.observed_at DESC,h.id DESC LIMIT 1)
       AND (q.profile='existing-provider' OR EXISTS (
         SELECT 1 FROM public.office_app_revisions r
          WHERE r.id=q.app_revision_id AND r.provider_id=p.provider_id
            AND r.image_digest=q.build_digest
            AND r.state IN ('qualified','active')))
  )
$$;
SELECT apply_worker_ownership('office_provider_accepts_new_launch(text,text,text,text)'::regprocedure);
