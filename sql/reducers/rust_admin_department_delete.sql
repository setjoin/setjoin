-- Frozen Go's DepartmentsHandler.Delete after the edge id parse: scope check, the
-- child and user counts and the DELETE, as one transaction (no audit row, as in Go).
-- Returns {status,detail}: 204 (also for a missing id), 403 or 409.
CREATE OR REPLACE FUNCTION rust_admin_department_delete(
 p_actor bigint,p_id bigint,p_grant_domain bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_ok boolean; v_children bigint; v_users bigint;
BEGIN
 SELECT admin_scope_within(p_actor,'ou',p_id,p_grant_domain) INTO v_ok;
 IF v_ok IS NOT TRUE THEN
  RETURN jsonb_build_object('status',403,'detail','department not within your administrative scope');
 END IF;
 -- Owner-approved security fix 2026-11-05 (#402, #510): departments carry no domain, so the
 -- tree is an organization-wide object. An actor whose users.create grants reach a whole domain
 -- (a grant with no OU/set narrowing) may not create, rename, move or delete departments unless
 -- one of them is organization-wide; OU/set-confined actors stay inside their subtree through
 -- admin_scope_within. Derived from grants that carry users.create only; same transaction.
 IF NOT admin_org_wide_grant(p_actor,ARRAY['users.create'])
    AND admin_perm_unconfined(p_actor,ARRAY['users.create']) THEN
  RETURN jsonb_build_object('status',403,'detail','department not within your administrative scope');
 END IF;
 SELECT COUNT(*) INTO v_children FROM departments WHERE parent_id = p_id;
 SELECT COUNT(*) INTO v_users FROM users WHERE department_id = p_id;
 IF v_children > 0 THEN
  RETURN jsonb_build_object('status',409,'detail','cannot delete department with sub-departments');
 END IF;
 IF v_users > 0 THEN
  RETURN jsonb_build_object('status',409,'detail','cannot delete department with assigned users');
 END IF;
 DELETE FROM departments WHERE id = p_id;
 RETURN jsonb_build_object('status',204);
END;
$$;
