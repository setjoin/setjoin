-- V177: bind the OIDC Provider's generated authorization code to its completed
-- request instead of assuming the code equals oidc_auth_requests.id.
--
-- The zitadel OP library generates a distinct high-entropy bearer code and
-- calls SaveAuthCode(request_id, code). Only a SHA-256 digest is persisted;
-- token exchange looks up that digest under FOR UPDATE and deletes the request
-- in the same transaction, preserving one-time use without retaining the
-- bearer credential in recoverable form.

ALTER TABLE oidc_auth_requests
    ADD COLUMN IF NOT EXISTS code_hash BYTEA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_auth_requests_code_hash
    ON oidc_auth_requests (code_hash)
    WHERE code_hash IS NOT NULL;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (177, now())
ON CONFLICT (version) DO NOTHING;
