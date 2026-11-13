-- Frozen Go's AssignMember transaction, in Go's check order: authority fence,
-- role row lock, Rule A (against the actor's live permissions), edge-validated
-- body problem, Rule B domain/OU reach, 等保三级 SoD pre-check, scope-set lock,
-- scope-containment, admin_protection_check, expiry, upsert and role_assign audit.
-- Returns {status,detail,id}; any status other than 201 means roll back.
-- admin_protection_check raises BZ064/BZ065/BZ066, which the caller maps (and
-- audits separately, as Go does after the rollback).
CREATE OR REPLACE FUNCTION rust_admin_role_assign(
 p_actor bigint,p_scope bigint,p_actor_perms text[],p_role bigint,p_user bigint,
 p_domain_override bigint,p_expires_at text,p_expires_bad boolean,
 p_scope_type text,p_scope_id bigint,p_eligible boolean,
 p_problem_status integer,p_problem_detail text,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_perms text[]; v_role_scope bigint; v_class text; v_sod boolean; v_missing text;
 v_effective bigint; v_in_scope boolean; v_dummy bigint; v_id bigint;
BEGIN
 PERFORM admin_authority_fence();
 v_sod := COALESCE((SELECT enabled FROM feature_toggles WHERE key='dengbao.sod_mode'),false);
 SELECT permissions,domain_scope,sod_class INTO v_perms,v_role_scope,v_class
  FROM admin_role_groups WHERE id=p_role FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','role not found'); END IF;
 SELECT p INTO v_missing FROM unnest(v_perms) WITH ORDINALITY u(p,o)
  WHERE NOT (p = ANY(p_actor_perms)) ORDER BY o LIMIT 1;
 IF v_missing IS NOT NULL THEN
  RETURN jsonb_build_object('status',403,'detail',
   'cannot assign a role granting a permission you do not hold: '||v_missing);
 END IF;
 IF p_problem_status<>0 THEN
  RETURN jsonb_build_object('status',p_problem_status,'detail',p_problem_detail);
 END IF;
 IF p_scope>0 THEN
  v_in_scope := EXISTS(SELECT 1 FROM users WHERE id=p_user AND domain_id=p_scope);
  IF NOT v_in_scope THEN RETURN jsonb_build_object('status',404,'detail','user not found'); END IF;
  IF p_domain_override IS NOT NULL AND p_domain_override<>p_scope THEN
   RETURN jsonb_build_object('status',403,'detail','cannot assign a role outside your domain');
  END IF;
  v_effective := COALESCE(p_domain_override,v_role_scope);
  IF v_effective IS NULL OR v_effective<>p_scope THEN
   RETURN jsonb_build_object('status',403,'detail','cannot assign a role outside your domain');
  END IF;
 END IF;
 IF NOT admin_can_manage(p_actor,p_user) THEN
  RETURN jsonb_build_object('status',404,'detail','user not found');
 END IF;
 IF v_sod AND v_class IS NOT NULL AND v_class<>'' THEN
  PERFORM 1 FROM users WHERE id=p_user FOR UPDATE;
  IF EXISTS (SELECT 1 FROM admin_role_assignments ara
   JOIN admin_role_groups rg ON rg.id=ara.role_group_id
   WHERE ara.user_id=p_user AND ara.role_group_id<>p_role
   AND (ara.expires_at IS NULL OR ara.expires_at>now())
   AND rg.sod_class IS NOT NULL AND rg.sod_class<>'' AND rg.sod_class<>v_class) THEN
   RETURN jsonb_build_object('status',409,'detail',
    'SoD class conflict: this assignment would give the principal roles spanning multiple 等保 classes');
  END IF;
 END IF;
 IF p_scope_type='set' THEN
  SELECT id INTO v_dummy FROM admin_scope_sets WHERE id=p_scope_id FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',400,'detail','scope-set not found'); END IF;
 END IF;
 IF NOT admin_scope_within(p_actor,p_scope_type,p_scope_id,NULL) THEN
  RETURN jsonb_build_object('status',403,'detail','cannot grant a scope broader than your own reach');
 END IF;
 PERFORM admin_protection_check(p_actor,p_user,'assign_role',p_role);
 IF p_expires_bad THEN
  RETURN jsonb_build_object('status',400,'detail','invalid expiresAt: must be RFC3339');
 END IF;
 INSERT INTO admin_role_assignments(user_id,role_group_id,domain_override,granted_by,expires_at,scope_type,scope_id,eligible)
  SELECT p_user,p_role,p_domain_override,p_actor,NULLIF(p_expires_at,'')::timestamptz,p_scope_type,p_scope_id,COALESCE(p_eligible,false)
   WHERE p_scope<=0 OR EXISTS(SELECT 1 FROM users WHERE id=p_user AND domain_id=p_scope)
  ON CONFLICT (user_id,role_group_id) DO UPDATE SET
   domain_override=EXCLUDED.domain_override,expires_at=EXCLUDED.expires_at,
   granted_by=EXCLUDED.granted_by,granted_at=now(),scope_type=EXCLUDED.scope_type,
   scope_id=EXCLUDED.scope_id,eligible=EXCLUDED.eligible
  RETURNING id INTO v_id;
 IF v_id IS NULL THEN RETURN jsonb_build_object('status',404,'detail','user not found'); END IF;
 PERFORM audit_write(p_actor,'role_assign','role_assignment',v_id,NULL,
  jsonb_build_object('targetUserId',p_user,'roleId',p_role,'scopeType',p_scope_type,'scopeId',p_scope_id),
  NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',201,'id',v_id);
END;
$$;
