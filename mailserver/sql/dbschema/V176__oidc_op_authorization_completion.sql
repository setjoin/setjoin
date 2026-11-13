-- V176: make the OIDC Provider authorization-code login hand-off durable.
--
-- The OP library creates a short-lived request before redirecting to Setjoin's
-- login/session completion route. These columns record the authenticated
-- subject and exact authentication context that completed that request. The
-- callback and code exchange accept only completed, unexpired rows.

ALTER TABLE oidc_auth_requests
    ADD COLUMN IF NOT EXISTS done BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS acr TEXT,
    ADD COLUMN IF NOT EXISTS amr TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_oidc_auth_requests_pending_expiry
    ON oidc_auth_requests (expires_at)
    WHERE done = FALSE;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (176, now())
ON CONFLICT (version) DO NOTHING;
