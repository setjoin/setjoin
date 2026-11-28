-- Frozen-Go UpdatePolicy: lock the scoped pre-image, patch and mandatory audit.
CREATE OR REPLACE FUNCTION rust_compliance_retention_update(
 p_actor bigint,p_scope bigint,p_id bigint,p_patch jsonb,p_ip text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_pre retention_policies%ROWTYPE; v_post retention_policies%ROWTYPE;
BEGIN
 SELECT * INTO v_pre FROM retention_policies WHERE id=p_id AND p_actor>0
 AND (p_scope<=0 OR domain_id=p_scope) FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE retention_policies SET
 name=COALESCE(p_patch->>'name',name),description=COALESCE(p_patch->>'description',description),
 retain_days=COALESCE((p_patch->>'retainDays')::integer,retain_days),
 action=COALESCE(p_patch->>'action',action),is_default=COALESCE((p_patch->>'isDefault')::boolean,is_default),
 domain_id=CASE WHEN p_patch ? 'domainId' THEN CASE WHEN p_scope>0 THEN p_scope ELSE (p_patch->>'domainId')::bigint END ELSE domain_id END
 WHERE id=p_id AND p_actor>0 AND (p_scope<=0 OR domain_id=p_scope)
 AND (p_scope<=0 OR p_patch->>'domainId' IS NULL OR (p_patch->>'domainId')::bigint=p_scope)
 RETURNING * INTO v_post;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM audit_write(p_actor,'retention_policy_update','retention_policy',p_id,
 jsonb_build_object('id',v_pre.id,'name',v_pre.name,'description',v_pre.description,'retainDays',v_pre.retain_days,'action',v_pre.action,'isDefault',v_pre.is_default,'domainId',v_pre.domain_id),
 jsonb_build_object('id',v_post.id,'name',v_post.name,'description',v_post.description,'retainDays',v_post.retain_days,'action',v_post.action,'isDefault',v_post.is_default,'domainId',v_post.domain_id),
 NULLIF(p_ip,'')::inet,'','core');
 RETURN true;
END;
$$;
