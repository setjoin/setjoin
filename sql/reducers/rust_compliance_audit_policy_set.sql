-- Frozen-Go AuditPolicy.Put: verified actor, policy update and audit row.
-- Owner-approved security fix 2026-11-05 (#437): the audit row is part of the same transaction; an
-- audit failure aborts the change (frozen Go swallowed it and left the policy changed unaudited).
CREATE OR REPLACE FUNCTION rust_compliance_audit_policy_set(
 p_actor bigint,p_level text,p_areas text[],p_reason text,p_ip text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_before jsonb;
BEGIN
 SELECT jsonb_build_object('level',level,'reasonRequiredAreas',COALESCE(reason_required_areas,'{}'::text[]))
 INTO v_before FROM audit_policy WHERE id=1 AND p_actor>0;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE audit_policy SET level=p_level,reason_required_areas=p_areas,updated_at=now(),updated_by=p_actor
 WHERE id=1 AND p_actor>0;
 PERFORM audit_write(p_actor,'audit_policy_change','',NULL,v_before,
  jsonb_build_object('level',p_level,'reasonRequiredAreas',p_areas),NULLIF(p_ip,'')::inet,p_reason,'core');
 RETURN true;
END;
$$;
