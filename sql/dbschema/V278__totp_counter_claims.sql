-- #336 owner-approved security fix 2026-11-05: elapsed wall time alone
-- cannot make an accepted TOTP counter reusable inside the drift window.
CREATE TABLE public.totp_counter_claims (
    user_id bigint PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash)=32),
    last_counter bigint NOT NULL CHECK (last_counter>=0)
);
ALTER TABLE public.totp_counter_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.totp_counter_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY totp_counter_claims_self ON public.totp_counter_claims
    USING (user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint))
    WITH CHECK (user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint));
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
        ALTER TABLE public.totp_counter_claims OWNER TO setjoin_owner;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
        GRANT SELECT,INSERT,UPDATE ON public.totp_counter_claims TO setjoin_app;
    END IF;
END $$;
INSERT INTO public.schema_migrations (version, applied_at) VALUES (278, now())
    ON CONFLICT(version) DO NOTHING;
