-- #546 owner-approved feature 2026-11-08 (#534): the verified SAML ACS.
-- (1) Per-registration IdP-initiated SSO switch, default OFF. A column with a
--     default: frozen Go lists columns explicitly everywhere and never reads it.
-- (2) The assertion/request replay cache. Only the Rust ACS touches it, and only
--     through rust_identity_saml_consume (SECURITY DEFINER, worker-owned): FORCE RLS
--     with a policy for setjoin_worker alone, so frozen Go (setjoin_app, NOBYPASSRLS)
--     sees no row and cannot write one even where provision-roles.sql re-grants table
--     privileges. It holds no user data: IDs are stored as SHA-256 digests with the
--     time they stop mattering.
ALTER TABLE public.saml_sp_registrations
    ADD COLUMN allow_idp_initiated boolean NOT NULL DEFAULT false;

CREATE TABLE public.saml_assertion_replay (
    registration_id bigint NOT NULL
        REFERENCES public.saml_sp_registrations(id) ON DELETE CASCADE,
    kind            text   NOT NULL CHECK (kind IN ('assertion','request')),
    token_hash      bytea  NOT NULL CHECK (octet_length(token_hash) = 32),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (registration_id, kind, token_hash)
);
CREATE INDEX saml_assertion_replay_expiry_idx
    ON public.saml_assertion_replay (expires_at);

-- (3) A verified link-purpose assertion waits here for the same session's same-site
--     completion request (the IdP's cross-site POST carries no SameSite=Strict cookie).
--     One row per link flow, single use, two minutes; reducers only, like the replay cache.
CREATE TABLE public.saml_link_completions (
    token_hash      bytea  PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    registration_id bigint NOT NULL
        REFERENCES public.saml_sp_registrations(id) ON DELETE CASCADE,
    flow_id         uuid   NOT NULL,
    subject         text   NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 2048),
    groups          jsonb,
    expires_at      timestamptz NOT NULL
);
CREATE INDEX saml_link_completions_expiry_idx ON public.saml_link_completions (expires_at);
ALTER TABLE public.saml_link_completions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.saml_link_completions FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_link_completions_worker ON public.saml_link_completions
    USING (current_user = 'setjoin_worker')
    WITH CHECK (current_user = 'setjoin_worker');

ALTER TABLE public.saml_assertion_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.saml_assertion_replay FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_assertion_replay_worker ON public.saml_assertion_replay
    USING (current_user = 'setjoin_worker')
    WITH CHECK (current_user = 'setjoin_worker');
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
        ALTER TABLE public.saml_assertion_replay OWNER TO setjoin_owner;
        ALTER TABLE public.saml_link_completions OWNER TO setjoin_owner;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
        REVOKE ALL ON public.saml_assertion_replay FROM setjoin_app;
        REVOKE ALL ON public.saml_link_completions FROM setjoin_app;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
        REVOKE ALL ON public.saml_assertion_replay FROM setjoin_worker;
        GRANT SELECT,INSERT,DELETE ON public.saml_assertion_replay TO setjoin_worker;
        REVOKE ALL ON public.saml_link_completions FROM setjoin_worker;
        GRANT SELECT,INSERT,DELETE ON public.saml_link_completions TO setjoin_worker;
    END IF;
END $$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (281, now())
    ON CONFLICT (version) DO NOTHING;
