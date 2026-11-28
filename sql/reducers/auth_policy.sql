-- auth_policy.sql — shared authentication policy functions for all services.
-- Both authserver and mailserver gateway call these for password validation
-- and MFA policy enforcement. Policy is configured via system_config.

-- validate_password: checks password against configured complexity requirements.
-- Returns JSONB: {"valid": true} or {"valid": false, "error": "reason"}
CREATE OR REPLACE FUNCTION validate_password(
  p_password     TEXT,
  p_is_admin     BOOL DEFAULT FALSE
) RETURNS JSONB AS $$
DECLARE
  v_min_len      INT;
  v_require_up   BOOL;
  v_require_low  BOOL;
  v_require_dig  BOOL;
  v_require_spec BOOL;
BEGIN
  IF p_password IS NOT NULL AND octet_length(p_password) > 72 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Password exceeds the 72-byte limit');
  END IF;

  -- Load all password policy config in a single round-trip
  SELECT
    COALESCE(MAX(CASE WHEN key = 'password_min_length'        THEN (value->>0)::INT  END), 8),
    -- bool_or, not MAX: PostgreSQL has no MAX(boolean) aggregate. Each key matches
    -- at most one row, so bool_or returns that row's value (ignoring the NULLs from
    -- non-matching CASE branches) — equivalent to "the configured value".
    COALESCE(bool_or(CASE WHEN key = 'password_require_uppercase' THEN (value->>0)::BOOL END), TRUE),
    COALESCE(bool_or(CASE WHEN key = 'password_require_lowercase' THEN (value->>0)::BOOL END), TRUE),
    COALESCE(bool_or(CASE WHEN key = 'password_require_digit'     THEN (value->>0)::BOOL END), TRUE),
    COALESCE(bool_or(CASE WHEN key = 'password_require_special'   THEN (value->>0)::BOOL END), TRUE)
  INTO v_min_len, v_require_up, v_require_low, v_require_dig, v_require_spec
  FROM system_config
  WHERE key IN ('password_min_length', 'password_require_uppercase', 'password_require_lowercase',
                'password_require_digit', 'password_require_special');

  IF p_password IS NULL OR length(p_password) < v_min_len THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Password must be at least ' || v_min_len || ' characters');
  END IF;

  IF v_require_up AND p_password !~ '[A-Z]' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Password must contain at least one uppercase letter');
  END IF;

  IF v_require_low AND p_password !~ '[a-z]' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Password must contain at least one lowercase letter');
  END IF;

  IF v_require_dig AND p_password !~ '[0-9]' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Password must contain at least one digit');
  END IF;

  IF v_require_spec AND p_password !~ '[!@#$%^&*()_+\-=\[\]{};'':"\\|,.<>/?~`]' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Password must contain at least one special character');
  END IF;

  RETURN jsonb_build_object('valid', true);
END;
$$ LANGUAGE plpgsql STABLE;

-- mfa_status: checks MFA enforcement policy for a given user.
-- Returns JSONB with enforcement status, user's MFA methods, and required action.
CREATE OR REPLACE FUNCTION mfa_status(
  p_user_id BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_totp_enabled     BOOL;
  v_push_enabled     BOOL;
  v_webauthn_count   INT;
  v_mfa_exempt       BOOL;
  v_enforcement_mode TEXT;
  v_feature_enabled  BOOL;
BEGIN
  SELECT u.totp_enabled,
         u.push_mfa_enabled,
         COALESCE((
           SELECT count(*)::INT
             FROM passkey_credentials p
            WHERE p.user_id=u.id
              AND p.revoked_at IS NULL
         ),0),
         COALESCE(u.mfa_exempt, FALSE)
  INTO v_totp_enabled, v_push_enabled, v_webauthn_count, v_mfa_exempt
  FROM users u WHERE u.id = p_user_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'user not found');
  END IF;

  -- Read enforcement policy
  v_enforcement_mode := COALESCE((SELECT value->>0 FROM system_config WHERE key = 'mfa_enforcement_mode'), 'required');
  v_feature_enabled  := COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.require_mfa'), true);

  -- User is exempt or already has MFA
  IF v_mfa_exempt THEN
    RETURN jsonb_build_object('status', 'exempt');
  END IF;

  -- Password-first login can challenge only TOTP or push. Passkeys are a
  -- separate passwordless login entry point, never a password step-up method;
  -- the legacy users.webauthn_credentials JSON must therefore not satisfy this
  -- admission gate either.
  IF v_totp_enabled OR v_push_enabled THEN
    RETURN jsonb_build_object('status', 'enrolled',
      'totp', v_totp_enabled,
      'push', v_push_enabled,
      'webauthn_count', v_webauthn_count);
  END IF;

  -- Check if MFA is required
  IF v_feature_enabled AND v_enforcement_mode = 'required' THEN
    RETURN jsonb_build_object('status', 'enrollment_required',
      'totp', v_totp_enabled,
      'push', v_push_enabled,
      'webauthn_count', v_webauthn_count,
      'message', 'Multi-factor authentication is required. Please set up MFA in Settings.');
  END IF;

  RETURN jsonb_build_object('status', 'optional',
    'totp', v_totp_enabled,
    'push', v_push_enabled,
    'webauthn_count', v_webauthn_count);
END;
$$ LANGUAGE plpgsql STABLE;
