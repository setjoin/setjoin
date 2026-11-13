-- mailserver/sql/reducers/drive_changes_since.sql
-- Read reducer (the task_list_tasks wrapped-read pattern): JMAP Email/changes
-- semantics over drive_changes (§4.2). BZ139 = not a member (no oracle).
CREATE OR REPLACE FUNCTION drive_changes_since(
  p_user_id BIGINT, p_space_id BIGINT, p_since BIGINT, p_max INT DEFAULT 500
) RETURNS JSONB AS $$
DECLARE v_head BIGINT; v_floor BIGINT; v_rows JSONB; v_n BIGINT;
BEGIN
  SELECT s.change_seq INTO v_head FROM drive_spaces s
   WHERE s.id=p_space_id
     AND public.drive_user_has_space_access(p_user_id,s.id);
  IF v_head IS NULL THEN
    RAISE EXCEPTION 'drive space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  -- floor: the oldest seq still answerable from the journal (MIN(seq)-1); an
  -- empty journal can only answer p_since = head.
  SELECT COALESCE(MIN(seq) - 1, v_head) INTO v_floor FROM drive_changes WHERE space_id = p_space_id;
  IF p_since < v_floor THEN
    RETURN jsonb_build_object('cannotCalculateChanges', true);
  END IF;
  WITH scanned AS MATERIALIZED (
    SELECT node_id,op,seq FROM drive_changes
     WHERE space_id=p_space_id AND seq>p_since
     ORDER BY seq LIMIT LEAST(GREATEST(p_max,1),1000)
  ), visible AS (
    SELECT s.* FROM scanned s
     WHERE s.node_id=0
        OR public.drive_runtime_has_node_capability(
             p_user_id,s.node_id,'read_metadata')
        OR (NOT EXISTS(SELECT 1 FROM public.drive_nodes n WHERE n.id=s.node_id)
            AND public.drive_runtime_has_space_root_capability(
              p_user_id,p_space_id,'read_metadata'))
        OR (s.op IN ('trash','destroy') AND EXISTS(
          SELECT 1 FROM public.drive_access_invalidations i
           WHERE i.space_id=p_space_id AND i.anchor_node_id=s.node_id
             AND (i.principal_kind='all'
                  OR (i.principal_kind='user' AND i.principal_id=p_user_id))
        ))
  )
  SELECT COALESCE((SELECT jsonb_agg(jsonb_build_object(
           'nodeId',node_id::text,'op',op,'seq',seq::text) ORDER BY seq)
         FROM visible),'[]'::jsonb),
         COALESCE((SELECT max(seq) FROM scanned),p_since)
    INTO v_rows,v_n;
  RETURN jsonb_build_object(
    'newState', v_n::text,
    'changed',  v_rows,
    'hasMore',  (SELECT EXISTS (SELECT 1 FROM drive_changes
                  WHERE space_id = p_space_id
                    AND seq > v_n)));
END;
$$ LANGUAGE plpgsql STABLE;
