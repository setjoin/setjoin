-- Frozen Go's DeleteRole transaction: authority fence, role row lock, scope
-- confinement, built-in refusal, assignment and role DELETEs, role_delete audit.
-- Returns {status,detail}; any status other than 204 means roll back.
CREATE OR REPLACE FUNCTION rust_admin_role_delete(
 p_actor bigint,p_scope bigint,p_id bigint,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_builtin boolean; v_name text; v_perms text[]; v_scope bigint;
BEGIN
 PERFORM admin_authority_fence();
 SELECT is_builtin,name,permissions,domain_scope INTO v_builtin,v_name,v_perms,v_scope
  FROM admin_role_groups WHERE id=p_id FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','role not found'); END IF;
 IF p_scope>0 AND (v_scope IS NULL OR v_scope<>p_scope) THEN
  RETURN jsonb_build_object('status',404,'detail','role not found');
 END IF;
 IF v_builtin THEN
  RETURN jsonb_build_object('status',409,'detail','cannot delete a built-in role');
 END IF;
 -- Ownership repeats in each DELETE's own WHERE (the row lock above is held).
 DELETE FROM admin_role_assignments WHERE role_group_id=p_id AND EXISTS
  (SELECT 1 FROM admin_role_groups g WHERE g.id=p_id AND (p_scope<=0 OR g.domain_scope=p_scope));
 DELETE FROM admin_role_groups WHERE id=p_id AND (p_scope<=0 OR domain_scope=p_scope);
 PERFORM audit_write(p_actor,'role_delete','role_group',p_id,
  jsonb_build_object('name',v_name,'permissions',to_jsonb(v_perms)),NULL,NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',204);
END;
$$;
