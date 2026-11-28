-- revoke_user_sessions.sql — CA-3a Task 2: session-revocation denylist + notify.
-- Inserts a session_revocations row (scope: all|family|jti) and fires the single
-- fixed 'session_revoke' app_notify so the gateway denylist + open WS tabs cut the
-- session in near-real-time. Writes an admin_audit_log entry in the same txn
-- (CA-0b: sensitive write must be audited). For scope='all', this reducer is
-- also the single transaction boundary for OAuth-token revocation and runtime
-- session cleanup. Callers must not reimplement only part of that boundary.
--
-- First-factor possession gate (v7 §2.5, V273): the same boundary deletes the
-- gate's artifacts — scope all deletes every mfa_reauth_step_ups and
-- webauthn_ceremonies row for the user; scope family/jti delete the rows
-- whose refresh_family_id / session_jti match. The canonical source here and
-- the V273 migration must stay byte-equivalent in behavior.
--
-- BZ097: illegal scope.
CREATE OR REPLACE FUNCTION revoke_user_sessions(
  p_user_id    BIGINT,
  p_scope      TEXT,
  p_reason     TEXT,
  p_created_by BIGINT,
  p_jti        TEXT,
  p_family_id  TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_id      BIGINT;
  v_payload JSONB;
  v_expires_at TIMESTAMPTZ := statement_timestamp() + interval '31 days';
BEGIN
  IF p_scope NOT IN ('all', 'family', 'jti') THEN
    RAISE EXCEPTION 'illegal revocation scope %', p_scope
      USING ERRCODE = 'BZ097',
            HINT = jsonb_build_object('type', 'bad_scope', 'scope', p_scope)::TEXT;
  END IF;
  IF (p_scope = 'jti' AND NULLIF(trim(p_jti), '') IS NULL)
     OR (p_scope = 'family' AND NULLIF(trim(p_family_id), '') IS NULL) THEN
    RAISE EXCEPTION 'revocation scope % requires its exact token identifier', p_scope
      USING ERRCODE = 'BZ097',
            HINT = jsonb_build_object('type', 'missing_scope_identifier', 'scope', p_scope)::TEXT;
  END IF;

  -- Serialize every revocation against privileged identity-link completion.
  -- Whichever transaction obtains this person fence first defines the outcome:
  -- a committed revocation deletes all pending elevations before a callback can
  -- bind a durable provider subject. The first-factor possession gate (v7 §2.2)
  -- makes this the SAME fence every grant issuance/consumption transaction
  -- takes first, so a committed revocation is always visible to a later
  -- issuance/consumption and an in-flight one always finishes before a
  -- revocation proceeds.
  PERFORM identity_auth_person_fence(p_user_id);
  DELETE FROM identity_auth_link_elevations
   WHERE user_id=p_user_id AND consumed_at IS NULL;

  -- A global credential/session revocation is complete only when the durable
  -- OAuth anchors and both runtime-session stores are closed under the same
  -- person fence. Narrow family/jti denylist events intentionally do not widen
  -- into an all-session revocation.
  IF p_scope = 'all' THEN
    UPDATE oauth_tokens
       SET revoked_at=COALESCE(revoked_at,statement_timestamp()),
           revoked_by=COALESCE(revoked_by,p_created_by)
     WHERE user_id=p_user_id
       AND revoked_at IS NULL;
    -- oidc_tokens is the OIDC PROVIDER's own token store for federated
    -- relying-party clients (authserver internal/federation/oidc_op_token_store.go)
    -- — a DISTINCT table from first-party oauth_tokens. A global revocation
    -- (disable, admin reset, suspected compromise) that spared it would leave
    -- the disabled user's OP sessions indefinitely renewable: the OP refresh
    -- grant only checks revoked_at/refresh_expires_at, so the surviving rows
    -- would mint fresh access tokens forever. Narrow family/jti events below
    -- intentionally do not widen into the OP store (no family concept there).
    UPDATE oidc_tokens
       SET revoked_at=COALESCE(revoked_at,statement_timestamp())
     WHERE user_id=p_user_id
       AND revoked_at IS NULL;
    DELETE FROM ws_subscriptions WHERE user_id=p_user_id;
    DELETE FROM sessions WHERE user_id=p_user_id;
    -- Possession-gate artifacts (v7 §2.5): scope 'all' deletes EVERY proof
    -- grant and ceremony for the user — artifact deletion kills
    -- pre-revocation grants outright; the §2.2 durable in-tx recheck is the
    -- belt-and-braces for requests already admitted.
    DELETE FROM mfa_reauth_step_ups WHERE user_id=p_user_id;
    DELETE FROM webauthn_ceremonies WHERE user_id=p_user_id;
    -- One greatest watermark per user is sufficient; audit_write below keeps
    -- the immutable historical evidence separately from this enforcement set.
    DELETE FROM session_revocations
     WHERE user_id=p_user_id AND scope='all';
  ELSIF p_scope = 'family' THEN
    -- A family revocation must close both refresh capability and currently
    -- issued access tokens. The family anchor rows supply the exact durable
    -- lifetime; 31 days is the access-token compatibility floor.
    SELECT GREATEST(
             COALESCE(MAX(expires_at), statement_timestamp()),
             statement_timestamp() + interval '31 days'
           )
      INTO v_expires_at
      FROM oauth_tokens
     WHERE user_id=p_user_id
       AND family_id::text=p_family_id;
    UPDATE oauth_tokens
       SET revoked_at=COALESCE(revoked_at,statement_timestamp()),
           revoked_by=COALESCE(revoked_by,p_created_by)
     WHERE user_id=p_user_id
       AND family_id::text=p_family_id
       AND revoked_at IS NULL;
    -- Narrow predicate (v7 §2.5): only the revoked family's grants and
    -- ceremonies die; another family's legal artifacts survive and complete.
    DELETE FROM mfa_reauth_step_ups
     WHERE user_id=p_user_id AND refresh_family_id=p_family_id;
    DELETE FROM webauthn_ceremonies
     WHERE user_id=p_user_id AND refresh_family_id=p_family_id;
    DELETE FROM session_revocations
     WHERE user_id=p_user_id AND scope='family' AND family_id=p_family_id;
  ELSE
    -- Access JWTs are capped at 30 days by authserver config validation. When
    -- a best-effort web-session row exists, retain the exact later expiry.
    SELECT GREATEST(
             COALESCE(MAX(expires_at), statement_timestamp()),
             statement_timestamp() + interval '31 days'
           )
      INTO v_expires_at
      FROM sessions
     WHERE user_id=p_user_id AND id=p_jti;
    DELETE FROM sessions WHERE user_id=p_user_id AND id=p_jti;
    DELETE FROM mfa_reauth_step_ups
     WHERE user_id=p_user_id AND session_jti=p_jti;
    DELETE FROM webauthn_ceremonies
     WHERE user_id=p_user_id AND session_jti=p_jti;
    DELETE FROM session_revocations
     WHERE user_id=p_user_id AND scope='jti' AND jti=p_jti;
  END IF;

  INSERT INTO session_revocations(
    user_id, scope, jti, family_id, reason, created_by, expires_at
  )
  VALUES (
    p_user_id, p_scope, p_jti, p_family_id, p_reason, p_created_by, v_expires_at
  )
  RETURNING id, jsonb_build_object(
    'user_id',    user_id,
    'scope',      scope,
    'not_before', not_before,
    'jti',        jti,
    'family_id',  family_id,
    'expires_at', expires_at
  ) INTO v_id, v_payload;

  -- CA-0b: audit every sensitive revocation write in-txn.
  PERFORM audit_write(p_created_by, 'revoke_user_sessions', 'user', p_user_id, NULL, v_payload, NULL, NULL, 'core');

  PERFORM app_notify('session_revoke', v_payload::TEXT);
  RETURN v_id;
END;
$$ LANGUAGE plpgsql VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public;
SELECT apply_worker_ownership(
  'revoke_user_sessions(bigint,text,text,bigint,text,text)'::regprocedure
);
