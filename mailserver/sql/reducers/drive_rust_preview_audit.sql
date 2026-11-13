-- Frozen Go auditDedup transaction; preserve its fifteen-minute read window.
CREATE OR REPLACE FUNCTION drive_rust_preview_audit(
  p_user_id BIGINT, p_space_id BIGINT, p_version_id BIGINT,
  p_admitted BOOLEAN DEFAULT FALSE
) RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  -- Only the adapter sets p_admitted, after verified metadata admission.
  -- Go audits that admitted read even when authority is revoked afterwards.
  IF (coalesce(p_admitted,false) OR EXISTS(SELECT 1 FROM drive_file_versions v
      WHERE v.id=p_version_id AND v.space_id=p_space_id
        AND drive_runtime_has_node_capability(p_user_id,v.file_node_id,'preview')))
    AND NOT EXISTS(SELECT 1 FROM drive_audit_log
      WHERE space_id=p_space_id AND user_id=p_user_id AND action='preview'
        AND target_id=p_version_id AND occurred_at>now()-interval '15 minutes') THEN
    PERFORM drive_access_audit(p_user_id,p_space_id,'preview','version',p_version_id,NULL,NULL,NULL,NULL);
  END IF;
END;
$$;
