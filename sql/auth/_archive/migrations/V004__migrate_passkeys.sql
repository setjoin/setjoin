-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V004: Migrate WebAuthn credentials from users.webauthn_credentials JSONB
-- to the normalized passkey_credentials table.
DO $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN
        SELECT id, webauthn_credentials, webauthn_user_handle
        FROM users WHERE webauthn_credentials IS NOT NULL
          AND webauthn_credentials != '[]'::JSONB
          AND webauthn_credentials != 'null'::JSONB
    LOOP
        -- Only migrate if passkey_credentials is empty for this user
        IF NOT EXISTS (SELECT 1 FROM passkey_credentials WHERE user_id = rec.id) THEN
            WITH creds AS (
                SELECT jsonb_array_elements(rec.webauthn_credentials) AS cred
            )
            INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count, created_at)
            SELECT
                decode(c.cred->>'ID', 'base64')::BYTEA,
                rec.id,
                decode(c.cred->>'PublicKey', 'base64')::BYTEA,
                COALESCE(c.cred->>'AttestationType', 'none'),
                COALESCE((c.cred->'Authenticator'->>'SignCount')::INT, 0),
                now()
            FROM creds c
            WHERE c.cred->>'ID' IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM passkey_credentials
                  WHERE id = decode(c.cred->>'ID', 'base64')::BYTEA
              );
        END IF;
    END LOOP;
END;
$$;
