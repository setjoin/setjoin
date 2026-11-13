-- Frozen-Go executeSearch completion: count, persisted binding, status atomically.
-- p_predicate is generated only from fixed SQL templates and allowlisted AST
-- operators/columns by the family; every query value is in bound p_values.
-- Invoker privileges remain the explicit worker credential; no extra grants.
CREATE OR REPLACE FUNCTION rust_compliance_search_complete(
 p_actor bigint,p_search_id bigint,p_predicate text,p_values text[]
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_count bigint;
BEGIN
 EXECUTE 'SELECT count(*) FROM messages m WHERE ('||p_predicate||') AND $2::bigint>0'
  INTO v_count USING p_values,p_actor;
 DELETE FROM ediscovery_search_results r WHERE r.search_id=p_search_id
  AND EXISTS(SELECT 1 FROM ediscovery_searches s WHERE s.id=r.search_id AND s.created_by=p_actor);
 EXECUTE 'INSERT INTO ediscovery_search_results(search_id,message_id) '
  ||'SELECT $2,m.id FROM messages m WHERE ('||p_predicate||') '
  ||'AND EXISTS(SELECT 1 FROM ediscovery_searches s WHERE s.id=$2 AND s.created_by=$3) '
  ||'ORDER BY m.received_at DESC LIMIT 500 ON CONFLICT DO NOTHING'
  USING p_values,p_search_id,p_actor;
 UPDATE ediscovery_searches SET status='complete',result_count=v_count,completed_at=now()
  WHERE id=p_search_id AND created_by=p_actor;
END;
$$;
