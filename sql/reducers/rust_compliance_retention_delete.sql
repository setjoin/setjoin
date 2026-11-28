-- Frozen-Go DeletePolicy: scoped DELETE and mandatory returning-row audit.
CREATE OR REPLACE FUNCTION rust_compliance_retention_delete(
 p_actor bigint,p_scope bigint,p_id bigint,p_ip text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_name text;v_domain bigint;
BEGIN
 DELETE FROM retention_policies WHERE id=p_id AND p_actor>0
 AND (p_scope<=0 OR domain_id=p_scope) RETURNING name,domain_id INTO v_name,v_domain;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM audit_write(p_actor,'retention_policy_delete','retention_policy',p_id,
 jsonb_build_object('name',v_name,'domainId',v_domain),NULL,NULLIF(p_ip,'')::inet,'','core');
 RETURN true;
END;
$$;
