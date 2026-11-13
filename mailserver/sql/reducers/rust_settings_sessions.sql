-- Frozen Go's self-service session and account-security writes (user.SessionsHandler.Revoke /
-- RevokeAll and user.SecureAccountHandler.Secure), each as one transaction keyed by the verified
-- token's user. p_user sits in every predicate (R3). They compose the existing
-- revoke_user_sessions / secure_account reducers exactly as Go does, so the denylist rows, audit
-- entries and the single 'session_revoke' / 'admin:alert' notifications are Go's.

-- DELETE /user/sessions/{id}: the web session (jti arm) wins, then the caller's oauth token
-- (family arm, or the single-token fallback for a token without a family). Returns 'revoked' or
-- 'not_found' (Go's 404); a failure raises, as Go's 500 does.
CREATE OR REPLACE FUNCTION rust_session_revoke_one(p_user bigint, p_id text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
 v_web boolean;
 v_family text;
 v_rows bigint;
BEGIN
 SELECT EXISTS(SELECT 1 FROM sessions WHERE id = p_id AND user_id = p_user) INTO v_web;
 IF v_web THEN
  PERFORM revoke_user_sessions(p_user, 'jti', 'user_revoke_one', p_user, p_id, NULL);
  RETURN 'revoked';
 END IF;
 SELECT family_id::text INTO v_family FROM oauth_tokens
  WHERE id::text = p_id AND user_id = p_user LIMIT 1;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF v_family IS NOT NULL AND v_family <> '' THEN
  PERFORM revoke_user_sessions(p_user, 'family', 'user_revoke_one', p_user, NULL, v_family);
 ELSE
  UPDATE oauth_tokens SET revoked_at = now(), revoked_by = p_user
   WHERE user_id = p_user AND revoked_at IS NULL AND id::text = p_id;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows = 0 THEN RETURN 'not_found'; END IF;
 END IF;
 RETURN 'revoked';
END;
$$;

-- POST /user/sessions/revoke-all.
CREATE OR REPLACE FUNCTION rust_sessions_revoke_all(p_user bigint)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 UPDATE oauth_tokens SET revoked_at = now(), revoked_by = p_user
  WHERE user_id = p_user AND revoked_at IS NULL;
 DELETE FROM sessions WHERE user_id = p_user;
 RETURN revoke_user_sessions(p_user, 'all', 'user_revoke_all', p_user, NULL, NULL);
END;
$$;

-- POST /user/sign-ins/secure-account ("This wasn't me"): revoke the caller's oauth tokens and
-- sessions, then secure_account(user, user, ip, 'user_self_report'). p_ip is the resolved client
-- address as text; an unparsable one fails the transaction, as Go's `$2::inet` does.
CREATE OR REPLACE FUNCTION rust_secure_account_self(p_user bigint, p_ip text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
BEGIN
 UPDATE oauth_tokens SET revoked_at = now(), revoked_by = p_user
  WHERE user_id = p_user AND revoked_at IS NULL;
 DELETE FROM sessions WHERE user_id = p_user;
 RETURN secure_account(p_user, p_user, p_ip::inet, 'user_self_report');
END;
$$;
