CREATE OR REPLACE FUNCTION office_wopi_callback_allowed(
  p_launch_id uuid,p_token_hash text,p_required_capability text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.office_editor_launches l
      JOIN public.office_editor_sessions s ON s.id=l.session_id
      JOIN public.office_provider_policies p ON p.provider_id=s.provider_id
      JOIN public.drive_nodes n ON n.id=s.file_node_id
     WHERE l.id=p_launch_id AND l.token_hash=p_token_hash
       AND l.revoked_at IS NULL AND l.expires_at>statement_timestamp()
       AND l.fence_generation=s.fence_generation
       AND s.status IN ('active','saving','draining')
       AND s.lease_expires_at>statement_timestamp()
       AND n.deleted_at IS NULL AND n.purged_at IS NULL
       AND p.removed_at IS NULL
       AND p.route_state IN ('active_for_scope','draining')
       AND p.entitlement_state IN ('evaluation','valid','expiring')
       AND p_required_capability IN ('download','modify_content')
       AND public.drive_runtime_has_node_capability(
             l.actor_user_id,s.file_node_id,p_required_capability)
  )
$$;
SELECT apply_worker_ownership('office_wopi_callback_allowed(uuid,text,text)'::regprocedure);
