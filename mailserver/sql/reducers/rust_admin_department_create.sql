-- Frozen Go's DepartmentsHandler.Create after the edge validation: the OU scope
-- check, the parent path lookup and the INSERT, as one transaction (Go runs them as
-- separate autocommit statements; no audit row, as in Go). Returns {status,detail,id}:
-- 200, 403 (outside the actor's scope) or 400 (parent not found). A non-positive
-- parent is not a parent for the scope check but IS bound to the INSERT, where the
-- foreign key refuses it (SQLSTATE 23505/23503 propagate for the adapter's 500).
CREATE OR REPLACE FUNCTION rust_admin_department_create(
 p_actor bigint,p_name text,p_parent bigint,p_ldap_ou text,p_grant_domain bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_eff bigint; v_ok boolean; v_path text; v_parent_path text; v_id bigint;
BEGIN
 IF p_parent IS NOT NULL AND p_parent > 0 THEN v_eff := p_parent; END IF;
 SELECT admin_scope_within(p_actor,CASE WHEN v_eff IS NULL THEN NULL ELSE 'ou' END,v_eff,p_grant_domain) INTO v_ok;
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
 IF p_parent IS NOT NULL AND p_parent > 0 THEN
  SELECT path INTO v_parent_path FROM departments WHERE id=p_parent;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',400,'detail','parent not found'); END IF;
  v_path := v_parent_path || '/' || p_name;
 ELSE
  v_path := p_name;
 END IF;
 INSERT INTO departments(name,parent_id,path,ldap_ou,sort_order)
  VALUES(p_name,p_parent,v_path,p_ldap_ou,
   (SELECT COALESCE(MAX(sort_order),0)+1 FROM departments WHERE parent_id IS NOT DISTINCT FROM p_parent))
  RETURNING id INTO v_id;
 RETURN jsonb_build_object('status',200,'id',v_id);
END;
$$;
