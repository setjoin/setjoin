-- #547 owner-approved security fix 2026-11-05: OIDC link completion, same-site.
-- The IdP's redirect back to /auth/oidc/callback is a cross-site navigation, so the
-- SameSite=Strict `access_token` cookie never reaches it (the SAML ACS has the same shape,
-- V281). A verified link-purpose OIDC assertion waits here for the same session's same-site
-- completion request. One row per link flow, single use, two minutes; reducers only
-- (FORCE RLS, policy for setjoin_worker alone), so frozen Go (setjoin_app) sees no row.
-- Idempotent: `mailctl schema apply` re-runs the newest migration in its rollback oracle (#472).
CREATE TABLE IF NOT EXISTS public.oidc_link_completions (
    token_hash   bytea  PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    provider_key text   NOT NULL CHECK (octet_length(provider_key) BETWEEN 1 AND 2048),
    flow_id      uuid   NOT NULL,
    issuer       text   NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    subject      text   NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 2048),
    groups       jsonb,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS oidc_link_completions_expiry_idx ON public.oidc_link_completions (expires_at);
ALTER TABLE public.oidc_link_completions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oidc_link_completions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oidc_link_completions_worker ON public.oidc_link_completions;
CREATE POLICY oidc_link_completions_worker ON public.oidc_link_completions
    USING (current_user = 'setjoin_worker')
    WITH CHECK (current_user = 'setjoin_worker');
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
        ALTER TABLE public.oidc_link_completions OWNER TO setjoin_owner;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
        REVOKE ALL ON public.oidc_link_completions FROM setjoin_app;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
        REVOKE ALL ON public.oidc_link_completions FROM setjoin_worker;
        GRANT SELECT,INSERT,DELETE ON public.oidc_link_completions TO setjoin_worker;
    END IF;
END $$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (282, now())
    ON CONFLICT (version) DO NOTHING;
