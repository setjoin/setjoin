-- Organization-wide verified mail.export admission precedes this worker call.
-- Gate and mandatory audit share one transaction; never stream before commit.
CREATE OR REPLACE FUNCTION rust_compliance_export_authorize(
 p_actor bigint,p_case bigint,p_ids bigint[],p_original jsonb,p_ip text
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_status text; v_complete boolean; v_count bigint;
BEGIN
 IF p_actor<=0 THEN RETURN '403:Forbidden'; END IF;
 SELECT c.status,EXISTS(SELECT 1 FROM ediscovery_searches s WHERE s.case_id=c.id AND s.status='complete')
 INTO v_status,v_complete FROM ediscovery_cases c WHERE c.id=p_case AND p_actor>0;
 IF NOT FOUND THEN RETURN '404:case not found'; END IF;
 IF v_status<>'active' THEN RETURN '403:case is closed'; END IF;
 IF NOT v_complete THEN RETURN '403:no completed eDiscovery search authorizes this case'; END IF;
 BEGIN
  SELECT count(DISTINCT r.message_id) INTO v_count FROM ediscovery_search_results r
   JOIN ediscovery_searches s ON s.id=r.search_id
   WHERE s.case_id=p_case AND s.status='complete' AND r.message_id=ANY(p_ids) AND p_actor>0;
 EXCEPTION WHEN OTHERS THEN RETURN '500:export binding check failed'; END;
 IF v_count<cardinality(p_ids) THEN RETURN '403:message ids are not bound to this case''s completed search results'; END IF;
 BEGIN
  PERFORM audit_write(p_actor,'ediscovery_export','ediscovery_case',p_case,p_original,NULL,NULLIF(p_ip,'')::inet,'','core');
 EXCEPTION WHEN OTHERS THEN RETURN '500:export audit could not be persisted'; END;
 RETURN '';
END;
$$;
