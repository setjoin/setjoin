-- Frozen-Go CreatePolicy: policy and mandatory after-image audit commit together.
-- p_scope and p_actor come exclusively from verified request authority.
CREATE OR REPLACE FUNCTION rust_compliance_retention_create(
 p_actor bigint,p_scope bigint,p_patch jsonb,p_ip text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_row retention_policies%ROWTYPE;
BEGIN
 INSERT INTO retention_policies(name,description,retain_days,action,is_default,domain_id)
 SELECT p_patch->>'name',p_patch->>'description',(p_patch->>'retainDays')::integer,
 p_patch->>'action',(p_patch->>'isDefault')::boolean,
 CASE WHEN p_scope>0 THEN p_scope ELSE (p_patch->>'domainId')::bigint END
 WHERE p_actor>0 AND (p_scope<=0 OR p_patch->>'domainId' IS NULL OR (p_patch->>'domainId')::bigint=p_scope)
 RETURNING * INTO v_row;
 IF NOT FOUND THEN RETURN NULL; END IF;
 PERFORM audit_write(p_actor,'retention_policy_create','retention_policy',v_row.id,NULL,
 jsonb_build_object('id',v_row.id,'name',v_row.name,'description',v_row.description,
 'retainDays',v_row.retain_days,'action',v_row.action,'isDefault',v_row.is_default,'domainId',v_row.domain_id),
 NULLIF(p_ip,'')::inet,'','core');
 RETURN v_row.id;
END;
$$;
