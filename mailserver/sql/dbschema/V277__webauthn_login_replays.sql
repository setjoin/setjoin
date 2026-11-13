-- #336: owner-approved security fix 2026-11-05. Legacy Go login cookies
-- have no expiry, so accepted challenge hashes must not expire either.
-- New authentication still requires a verified signature before this write.
CREATE TABLE public.webauthn_login_replays (
    user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash)=32),
    PRIMARY KEY(user_id,challenge_hash)
);
ALTER TABLE public.webauthn_login_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webauthn_login_replays FORCE ROW LEVEL SECURITY;
CREATE POLICY webauthn_login_replays_self ON public.webauthn_login_replays
    USING (user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint))
    WITH CHECK (user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint));
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
        ALTER TABLE public.webauthn_login_replays OWNER TO setjoin_owner;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
        GRANT SELECT,INSERT ON public.webauthn_login_replays TO setjoin_app;
    END IF;
END $$;
INSERT INTO public.schema_migrations (version, applied_at) VALUES (277, now())
    ON CONFLICT(version) DO NOTHING;
