-- mailserver/sql/reducers/drive_activity_feed.sql
-- §5.6 activity feed over the actor-bearing audit chain (LR-2: drive_changes
-- has no actor column; drive_audit_log is the superset — it records every
-- journal-worthy event plus branch/lock/label events the journal never
-- sees). Read-only; invoker-rights (membership check here is primary, the
-- drive_audit_log_read RLS policy is the backstop, same posture as
-- drive_changes_since). Rows are returned per-access; session grouping is
-- the client's job (§9.3).
CREATE OR REPLACE FUNCTION drive_activity_feed(
  p_user_id BIGINT, p_space_id BIGINT, p_node_id BIGINT DEFAULT NULL,
  p_max INT DEFAULT 50, p_before_id BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE v_lim INT;
BEGIN
  IF (p_node_id IS NOT NULL AND NOT public.drive_runtime_has_node_capability(
        p_user_id,p_node_id,'read_metadata'))
     OR (p_node_id IS NULL AND NOT EXISTS(
       SELECT 1 FROM public.drive_nodes n
        WHERE n.space_id=p_space_id
          AND public.drive_runtime_has_node_capability(p_user_id,n.id,'view_audit')
     )) THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  v_lim := LEAST(GREATEST(COALESCE(p_max, 50), 1), 200);

  RETURN jsonb_build_object('items', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
             'id', a.id, 'action', a.action, 'actorId', a.user_id, 'actorName', m.display_name,
             'targetType', a.target_type, 'targetId', a.target_id,
             'at', a.occurred_at, 'notes', a.notes) ORDER BY a.id DESC)
      FROM (
        SELECT * FROM drive_audit_log
         WHERE space_id = p_space_id
           AND (p_before_id IS NULL OR id < p_before_id)
           AND (p_node_id IS NULL
                OR (target_type = 'node' AND target_id = p_node_id)
                OR (target_type = 'version' AND target_id IN
                      (SELECT id FROM drive_file_versions WHERE file_node_id = p_node_id))
                OR (target_type = 'branch' AND target_id IN
                      (SELECT id FROM drive_file_branches WHERE file_node_id = p_node_id)))
         ORDER BY id DESC
         LIMIT v_lim
      ) a
      LEFT JOIN mailboxes m ON m.user_id = a.user_id AND m.is_primary
  ), '[]'::jsonb));
END;
$$ LANGUAGE plpgsql STABLE;
