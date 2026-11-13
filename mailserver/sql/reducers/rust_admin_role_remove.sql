-- Frozen Go's RemoveMember: Rule B reach checks, admin_protection_check, the
-- assignment DELETE and the role_revoke audit, as one transaction (Go has no
-- authority fence here). Returns {status,detail,id}; any status other than 204
-- means roll back. admin_protection_check raises BZ064/BZ065/BZ066.
CREATE OR REPLACE FUNCTION rust_admin_role_remove(
 p_actor bigint,p_scope bigint,p_role bigint,p_user bigint,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_id bigint;
BEGIN
 IF p_scope>0 AND NOT EXISTS(SELECT 1 FROM users WHERE id=p_user AND domain_id=p_scope) THEN
  RETURN jsonb_build_object('status',404,'detail','assignment not found');
 END IF;
 IF NOT admin_can_manage(p_actor,p_user) THEN
  RETURN jsonb_build_object('status',404,'detail','assignment not found');
 END IF;
 PERFORM admin_protection_check(p_actor,p_user,'remove_role',p_role);
 DELETE FROM admin_role_assignments WHERE role_group_id=p_role AND user_id=p_user
  AND (p_scope<=0 OR EXISTS(SELECT 1 FROM users WHERE id=p_user AND domain_id=p_scope))
  RETURNING id INTO v_id;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','assignment not found'); END IF;
 PERFORM audit_write(p_actor,'role_revoke','role_assignment',v_id,
  jsonb_build_object('targetUserId',p_user,'roleId',p_role),NULL,NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',204,'id',v_id);
END;
$$;
