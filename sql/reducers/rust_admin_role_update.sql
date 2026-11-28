-- Frozen Go's UpdateRole transaction: V172 authority fence, role row lock,
-- scope confinement, built-in refusal, edge-validated body problem, the 等保三级
-- SoD checks (dengbao.sod_mode), the patch UPDATE and the role_update audit.
-- Returns {status,detail}; any status other than 204 is Go's problem response
-- and the caller rolls back. p_problem_* carries Go's body validation result,
-- which Go evaluates only after the lock, scope and built-in checks.
CREATE OR REPLACE FUNCTION rust_admin_role_update(
 p_actor bigint,p_scope bigint,p_id bigint,p_name text,p_description text,
 p_permissions text[],p_domain_scope bigint,p_sod_class text,
 p_problem_status integer,p_problem_detail text,p_classes jsonb,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_builtin boolean; v_scope bigint; v_class text; v_perms text[];
 v_sod boolean; v_eff_class text; v_eff_perms text[]; v_bad text[];
 v_rows bigint; v_after jsonb;
BEGIN
 PERFORM admin_authority_fence();
 v_sod := COALESCE((SELECT enabled FROM feature_toggles WHERE key='dengbao.sod_mode'),false);
 SELECT is_builtin,domain_scope,sod_class,permissions INTO v_builtin,v_scope,v_class,v_perms
  FROM admin_role_groups WHERE id=p_id FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','role not found'); END IF;
 IF p_scope>0 AND (v_scope IS NULL OR v_scope<>p_scope) THEN
  RETURN jsonb_build_object('status',404,'detail','role not found');
 END IF;
 IF v_builtin THEN
  RETURN jsonb_build_object('status',409,'detail','cannot modify a built-in role');
 END IF;
 IF p_problem_status<>0 THEN
  RETURN jsonb_build_object('status',p_problem_status,'detail',p_problem_detail);
 END IF;
 IF v_sod THEN
  v_eff_class := COALESCE(p_sod_class,v_class);
  v_eff_perms := COALESCE(p_permissions,v_perms);
  IF v_eff_class IS NOT NULL AND v_eff_class<>'' AND cardinality(v_eff_perms)>0 THEN
   SELECT array_agg(p ORDER BY o) INTO v_bad FROM unnest(v_eff_perms) WITH ORDINALITY u(p,o)
    WHERE NOT (COALESCE(p_classes->p,'[]'::jsonb) ? v_eff_class);
   IF v_bad IS NOT NULL THEN
    RETURN jsonb_build_object('status',409,'detail',
     'SoD class violation: permissions not allowed in class '''||v_eff_class||''': '||array_to_string(v_bad,', '));
   END IF;
  END IF;
  IF v_eff_class IS NOT NULL AND v_eff_class<>''
     AND (v_class IS NULL OR v_class<>v_eff_class) THEN
   IF EXISTS (SELECT 1 FROM admin_role_assignments ara_this
    WHERE ara_this.role_group_id=p_id AND (ara_this.expires_at IS NULL OR ara_this.expires_at>now())
    AND EXISTS (SELECT 1 FROM admin_role_assignments ara_other
     JOIN admin_role_groups rg_other ON rg_other.id=ara_other.role_group_id
     WHERE ara_other.user_id=ara_this.user_id AND ara_other.role_group_id<>p_id
     AND (ara_other.expires_at IS NULL OR ara_other.expires_at>now())
     AND rg_other.sod_class IS NOT NULL AND rg_other.sod_class<>v_eff_class)) THEN
    RETURN jsonb_build_object('status',409,'detail',
     'SoD class conflict: changing this role''s class would cause existing assignees to span multiple 等保 classes');
   END IF;
  END IF;
 END IF;
 IF p_name IS NULL AND p_description IS NULL AND p_permissions IS NULL
    AND p_domain_scope IS NULL AND p_sod_class IS NULL THEN
  RETURN jsonb_build_object('status',400,'detail','no fields to update');
 END IF;
 UPDATE admin_role_groups SET
  name=COALESCE(p_name,name),
  description=COALESCE(p_description,description),
  permissions=COALESCE(p_permissions,permissions),
  domain_scope=CASE WHEN p_domain_scope IS NULL THEN domain_scope WHEN p_domain_scope<=0 THEN NULL ELSE p_domain_scope END,
  sod_class=CASE WHEN p_sod_class IS NULL THEN sod_class WHEN p_sod_class='' THEN NULL ELSE p_sod_class END,
  updated_at=now()
  WHERE id=p_id AND (p_scope<=0 OR domain_scope=p_scope);
 GET DIAGNOSTICS v_rows=ROW_COUNT;
 IF v_rows=0 THEN RETURN jsonb_build_object('status',404,'detail','role not found'); END IF;
 v_after := '{}'::jsonb;
 IF p_name IS NOT NULL THEN v_after := v_after||jsonb_build_object('name',p_name); END IF;
 IF p_permissions IS NOT NULL THEN v_after := v_after||jsonb_build_object('permissions',to_jsonb(p_permissions)); END IF;
 IF p_sod_class IS NOT NULL THEN v_after := v_after||jsonb_build_object('sodClass',p_sod_class); END IF;
 PERFORM audit_write(p_actor,'role_update','role_group',p_id,NULL,v_after,NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',204);
END;
$$;
