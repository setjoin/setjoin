-- Frozen Go's DeleteScopeSet: the DELETE (the in-use RESTRICT trigger raises
-- P0001), the grant count for the 409 message, and the scope_set_delete audit,
-- as one transaction. Returns {status,detail}: 204, 404 (no set) or 409.
--
-- Owner-approved security fix 2026-11-05 (#384, #510): the actor is restricted to sets owned
-- by its domain, derived here from its live scope_sets.manage grants (0 = org-wide grant,
-- -1 = none); others answer 404, scope in the DELETE's own WHERE (R3).
DROP FUNCTION IF EXISTS rust_admin_scope_set_delete(bigint,bigint,text);
DROP FUNCTION IF EXISTS rust_admin_scope_set_delete(bigint,bigint,text,bigint);
CREATE OR REPLACE FUNCTION rust_admin_scope_set_delete(
 p_actor bigint,p_id bigint,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_n bigint; v_scope bigint := admin_domain_restriction(p_actor,ARRAY['scope_sets.manage']);
BEGIN
 BEGIN
  DELETE FROM admin_scope_sets WHERE id=p_id AND (v_scope=0 OR domain_id=v_scope);
 EXCEPTION WHEN SQLSTATE 'P0001' THEN
  SELECT count(*) INTO v_n FROM admin_role_assignments WHERE scope_type='set' AND scope_id=p_id;
  RETURN jsonb_build_object('status',409,
   'detail',v_n||' admin grant(s) are scoped to this set; reassign them first');
 END;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','scope set not found'); END IF;
 PERFORM audit_write(p_actor,'scope_set_delete','admin_scope_set',p_id,NULL,NULL,
  NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',204);
END;
$$;
