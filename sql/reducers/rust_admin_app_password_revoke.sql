-- Frozen Go's admin app-password revocation (admin_app_passwords.go): the UPDATE
-- (ownership and the domain scope in its WHERE) followed by the app_password_revoke
-- audit row. Go audits in a second autocommit; here both commit together.
-- Returns true when a row was revoked; false rolls back with no audit.
CREATE OR REPLACE FUNCTION rust_admin_app_password_revoke(
 p_actor bigint,p_user bigint,p_ap bigint,p_domain_scope bigint,p_ip text,p_email text
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 UPDATE app_passwords SET revoked_at=now()
  WHERE id=p_ap AND user_id=p_user AND revoked_at IS NULL
    AND (p_domain_scope<=0 OR user_id IN (SELECT id FROM users WHERE id=p_user AND domain_id=p_domain_scope));
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM audit_write(p_actor,'app_password_revoke','app_password',p_ap,
  jsonb_build_object('revoked_by',p_email,'user_id',p_user),NULL,NULLIF(p_ip,'')::inet,'','core');
 RETURN true;
END;
$$;
