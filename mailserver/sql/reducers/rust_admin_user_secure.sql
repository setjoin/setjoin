-- Frozen Go's admin secure-account transaction (admin_signin.go): revoke the
-- target's OAuth families and web sessions, then secure_account (flag, audit,
-- admin:alert notify). The client IP binds as inet exactly as Go's `$3::inet`
-- (an unparsable value is an error, hence Go's 500). Go gates the target's domain in
-- an earlier statement; the same containment is repeated here (R3) so a domain move
-- between the two cannot widen the actor's reach: out of scope raises BZ084.
CREATE OR REPLACE FUNCTION rust_admin_user_secure(
 p_actor bigint,p_target bigint,p_ip text,p_domain_scope bigint
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 IF p_domain_scope>0 AND NOT EXISTS (SELECT 1 FROM users WHERE id=p_target AND domain_id=p_domain_scope) THEN
  RAISE EXCEPTION 'secure_account: user % not found',p_target USING ERRCODE='BZ084';
 END IF;
 UPDATE oauth_tokens SET revoked_at=now(),revoked_by=p_actor
  WHERE user_id=p_target AND revoked_at IS NULL;
 DELETE FROM sessions WHERE user_id=p_target;
 PERFORM secure_account(p_target,p_actor,p_ip::inet,'admin_secure');
END;
$$;
