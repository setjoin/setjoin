-- Frozen Go's DepartmentsHandler.Update after the edge decode: scope checks on the
-- department and the destination parent, the path lookups, the recursive subtree path
-- rewrite and the dynamic field UPDATE, in Go's order, as one transaction. Returns
-- {status,detail}: 204, 403, 404 (department not found), 400 (parent not found) or 500.
-- Go commits the path rewrite before the field UPDATE, so a failing field UPDATE (a
-- non-positive parentId violates the foreign key) or an empty field set answers 500
-- with the path rewrite kept: the 500 verdict COMMITS (it is the only committed
-- non-success status). Failures of the rewrite itself propagate as SQLSTATE errors.
-- p_name/p_ldap_ou '' and p_parent/p_sort NULL mean "absent", as Go's pointer fields.
CREATE OR REPLACE FUNCTION rust_admin_department_update(
 p_actor bigint,p_id bigint,p_name text,p_parent bigint,p_ldap_ou text,p_sort bigint,p_grant_domain bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_ok boolean; v_old text; v_parent_path text := ''; v_name text; v_new text;
 v_sets text[] := ARRAY[]::text[]; v_args text[] := ARRAY[]::text[]; v_sql text;
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
 IF p_parent IS NOT NULL AND p_parent > 0 THEN
  SELECT admin_scope_within(p_actor,'ou',p_parent,p_grant_domain) INTO v_ok;
  IF v_ok IS NOT TRUE THEN
   RETURN jsonb_build_object('status',403,'detail','department not within your administrative scope');
  END IF;
 END IF;
 IF p_name <> '' OR p_parent IS NOT NULL THEN
  SELECT path INTO v_old FROM departments WHERE id=p_id;
  IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'detail','department not found'); END IF;
  v_name := p_name;
  IF v_name = '' THEN v_name := (string_to_array(v_old,'/'))[cardinality(string_to_array(v_old,'/'))]; END IF;
  IF p_parent IS NOT NULL AND p_parent > 0 THEN
   SELECT path INTO v_parent_path FROM departments WHERE id=p_parent;
   IF NOT FOUND THEN RETURN jsonb_build_object('status',400,'detail','parent not found'); END IF;
  END IF;
  v_new := v_name;
  IF v_parent_path <> '' THEN v_new := v_parent_path || '/' || v_name; END IF;
  WITH RECURSIVE subtree AS (
   SELECT id, path FROM departments WHERE id = p_id
   UNION ALL
   SELECT d.id, d.path FROM departments d JOIN subtree s ON d.parent_id = s.id
  )
  UPDATE departments d SET path = v_new || SUBSTRING(s.path FROM LENGTH(v_old)+1)
  FROM subtree s WHERE d.id = s.id;
 END IF;
 IF p_name <> '' THEN v_sets := v_sets || ('name = $' || (cardinality(v_sets)+1)); v_args := v_args || p_name; END IF;
 IF p_ldap_ou <> '' THEN v_sets := v_sets || ('ldap_ou = $' || (cardinality(v_sets)+1)); v_args := v_args || p_ldap_ou; END IF;
 IF p_parent IS NOT NULL THEN v_sets := v_sets || ('parent_id = $' || (cardinality(v_sets)+1) || '::bigint'); v_args := v_args || p_parent::text; END IF;
 IF p_sort IS NOT NULL THEN v_sets := v_sets || ('sort_order = $' || (cardinality(v_sets)+1) || '::bigint::integer'); v_args := v_args || p_sort::text; END IF;
 IF cardinality(v_sets) = 0 THEN
  RETURN jsonb_build_object('status',500,'detail','database error');
 END IF;
 v_sql := 'UPDATE departments SET ' || array_to_string(v_sets,', ') || ' WHERE id = $' || (cardinality(v_sets)+1) || '::bigint';
 BEGIN
  CASE cardinality(v_sets)
   WHEN 1 THEN EXECUTE v_sql USING v_args[1], p_id;
   WHEN 2 THEN EXECUTE v_sql USING v_args[1], v_args[2], p_id;
   WHEN 3 THEN EXECUTE v_sql USING v_args[1], v_args[2], v_args[3], p_id;
   ELSE EXECUTE v_sql USING v_args[1], v_args[2], v_args[3], v_args[4], p_id;
  END CASE;
 EXCEPTION WHEN OTHERS THEN
  RETURN jsonb_build_object('status',500,'detail','database error');
 END;
 RETURN jsonb_build_object('status',204);
END;
$$;
