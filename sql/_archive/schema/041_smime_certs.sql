-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 041_smime_certs.sql — S/MIME certificate storage for per-user encrypt/sign
-- Depends on: 003_users.sql, 006_messages.sql

-- user_smime_certs: per-user X.509 certificates for S/MIME signing/encryption.
-- cert_pem is stored unencrypted (public info).
-- private_key_enc is AES-256-GCM encrypted via pgp_sym_encrypt() using app.encryption_key.
CREATE TABLE IF NOT EXISTS user_smime_certs (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL DEFAULT '',
    cert_pem        TEXT NOT NULL,
    private_key_enc TEXT,
    issued_at       TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    is_default      BOOL NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, label)
);

-- crypto_type on messages: detected S/MIME or PGP type for inbound messages.
-- NULL = no crypto detected; 'smime-signed', 'smime-encrypted', 'pgp-signed', 'pgp-encrypted'.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS crypto_type TEXT;

-- smime_encrypt flag: set when compose requests S/MIME encryption for outbound.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS smime_encrypt BOOL NOT NULL DEFAULT FALSE;
