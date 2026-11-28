-- Frozen Go's CreateScopeSet INSERT plus its scope_set_create audit row, as one
-- transaction (Go commits the INSERT and then audits in a separate autocommit).
-- Name validation happens at the edge, as in Go. A duplicate (domain, name)
-- raises 23505 for the adapter to answer Go's 409.
--
-- Owner-approved security fix 2026-11-05 (#384, #510): the actor's restriction is derived
-- here from its live scope_sets.manage grants (admin_domain_restriction: 0 = org-wide grant,
-- a domain id, or -1 = none). Any other actor may only create a set owned by its own domain;
-- the domain-less (organization-wide) set needs the org-wide grant. Returns NULL when refused.
DROP FUNCTION IF EXISTS rust_admin_scope_set_create(bigint,text,bigint,text,text);
DROP FUNCTION IF EXISTS rust_admin_scope_set_create(bigint,text,bigint,text,text,bigint);
CREATE OR REPLACE FUNCTION rust_admin_scope_set_create(
 p_actor bigint,p_name text,p_domain bigint,p_description text,p_ip text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_id bigint; v_scope bigint := admin_domain_restriction(p_actor,ARRAY['scope_sets.manage']);
BEGIN
 IF v_scope <> 0 AND p_domain IS DISTINCT FROM v_scope THEN RETURN NULL; END IF;
 INSERT INTO admin_scope_sets(name,domain_id,description,created_by)
  VALUES(p_name,p_domain,p_description,p_actor) RETURNING id INTO v_id;
 PERFORM audit_write(p_actor,'scope_set_create','admin_scope_set',v_id,NULL,
  jsonb_build_object('name',p_name,'domainId',p_domain),NULLIF(p_ip,'')::inet,'','core');
 RETURN v_id;
END;
$$;
