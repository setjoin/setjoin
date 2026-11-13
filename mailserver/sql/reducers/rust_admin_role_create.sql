-- Frozen Go's role INSERT plus its role_create audit row, as one transaction.
-- Go commits the INSERT and then writes the audit in a separate autocommit;
-- the Rust port commits both together (same rows on success, none on failure).
-- Name, permission and Rule A/B validation happen at the edge, as in Go.
CREATE OR REPLACE FUNCTION rust_admin_role_create(
 p_actor bigint,p_name text,p_description text,p_permissions text[],p_domain_scope bigint,p_ip text
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_id bigint;
BEGIN
 INSERT INTO admin_role_groups(name,description,permissions,domain_scope)
  VALUES(p_name,p_description,p_permissions,p_domain_scope) RETURNING id INTO v_id;
 PERFORM audit_write(p_actor,'role_create','role_group',v_id,NULL,
  jsonb_build_object('name',p_name,'permissions',to_jsonb(p_permissions)),
  NULLIF(p_ip,'')::inet,'','core');
 RETURN v_id;
END;
$$;
