-- Frozen Go's UpdateScopeSet UPDATE (COALESCE patch of name/description) plus its
-- scope_set_update audit row, as one transaction. Returns false when no set has
-- the id (Go answers 404 and writes no audit). A duplicate name raises 23505.
--
-- Owner-approved security fix 2026-11-05 (#384, #510): the actor is restricted to sets owned
-- by its domain, derived here from its live scope_sets.manage grants (0 = org-wide grant,
-- -1 = none); a foreign or domain-less set is as if missing. The scope is in the UPDATE's
-- own WHERE (R3).
DROP FUNCTION IF EXISTS rust_admin_scope_set_update(bigint,bigint,text,text,text);
DROP FUNCTION IF EXISTS rust_admin_scope_set_update(bigint,bigint,text,text,text,bigint);
CREATE OR REPLACE FUNCTION rust_admin_scope_set_update(
 p_actor bigint,p_id bigint,p_name text,p_description text,p_ip text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_scope bigint := admin_domain_restriction(p_actor,ARRAY['scope_sets.manage']);
BEGIN
 UPDATE admin_scope_sets SET name=COALESCE(p_name,name),
  description=COALESCE(p_description,description),updated_at=now() WHERE id=p_id AND (v_scope=0 OR domain_id=v_scope);
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM audit_write(p_actor,'scope_set_update','admin_scope_set',p_id,NULL,
  jsonb_build_object('id',p_id,'name',p_name,'description',p_description),
  NULLIF(p_ip,'')::inet,'','core');
 RETURN true;
END;
$$;
