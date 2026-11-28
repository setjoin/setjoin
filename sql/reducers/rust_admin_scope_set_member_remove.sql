-- Frozen Go's RemoveMember DELETE plus its scope_set_member_remove audit, as one
-- transaction. Returns {status,detail}: 204 or 404 (no such member, no audit).
--
-- Owner-approved security fix 2026-11-05 (#384, #510): the actor is restricted to sets owned
-- by its domain, derived here from its live scope_sets.manage grants (0 = org-wide grant,
-- -1 = none); the check is in the DELETE's own WHERE (R3) and a foreign set answers 404.
DROP FUNCTION IF EXISTS rust_admin_scope_set_member_remove(bigint,bigint,text,bigint,text);
DROP FUNCTION IF EXISTS rust_admin_scope_set_member_remove(bigint,bigint,text,bigint,text,bigint);
CREATE OR REPLACE FUNCTION rust_admin_scope_set_member_remove(
 p_actor bigint,p_set bigint,p_type text,p_member bigint,p_ip text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_scope bigint := admin_domain_restriction(p_actor,ARRAY['scope_sets.manage']);
BEGIN
 DELETE FROM admin_scope_set_members WHERE set_id=p_set AND member_type=p_type AND member_id=p_member
  AND (v_scope=0 OR EXISTS(SELECT 1 FROM admin_scope_sets s WHERE s.id=p_set AND s.domain_id=v_scope));
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','member not found'); END IF;
 PERFORM audit_write(p_actor,'scope_set_member_remove','admin_scope_set',p_set,NULL,
  jsonb_build_object('setId',p_set,'memberType',p_type,'memberId',p_member),
  NULLIF(p_ip,'')::inet,'','core');
 RETURN jsonb_build_object('status',204);
END;
$$;
