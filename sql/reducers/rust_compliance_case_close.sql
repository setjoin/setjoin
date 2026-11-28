-- Frozen-Go CloseCase: update active case and best-effort audit in one call.
-- Organization-wide grant admission is enforced by the gateway before entry;
-- p_actor is the verified actor, never request-supplied case ownership.
CREATE OR REPLACE FUNCTION rust_compliance_case_close(
 p_actor bigint,p_case_id bigint,p_reason text,p_ip text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 UPDATE ediscovery_cases
 SET status='closed',closed_at=now(),closed_by=p_actor,updated_at=now()
 WHERE id=p_case_id AND status='active' AND p_actor>0;
 IF NOT FOUND THEN RETURN false; END IF;
 BEGIN
  PERFORM audit_write(p_actor,'ediscovery_case_close','ediscovery_case',p_case_id,
   jsonb_build_object('reason',p_reason),NULL,NULLIF(p_ip,'')::inet,'','core');
 EXCEPTION WHEN OTHERS THEN
  -- Go ignores audit.Write errors; preserve its successful close in that case.
  NULL;
 END;
 RETURN true;
END;
$$;
