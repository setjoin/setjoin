-- STAGED, NOT LOADED (not under dbschema/): #525 FORCE RLS on oidc_tokens.
-- Applied by the Go-deletion ticket (DELETE), as the next free Vnnn migration, once
-- authserverd is gone. Why not now: the default install runs authserverd as setjoin_app
-- (NOBYPASSRLS, not the owner; install.sh, config.env.sample, NATIVE_RLS_FLIP_RUNBOOK:
-- fresh installs are already flipped). Frozen Go's OP token store (oidc_op_token_store.go)
-- uses that request pool and never sets app.current_user_id, so under this policy its
-- token INSERT fails with 42501, refresh/revoke/introspect lookups find no rows and the
-- OIDC token GC deletes nothing. The credential-keyed lookups already go through the
-- worker-owned reducers of reducers/rust_identity_oidc_lookup.sql, so Rust is ready.
-- DELETE must also: seed foreign-user oidc_tokens fixtures as the owner in
-- tests/rust_identity_oidc.pg, move staged/oidc_tokens_rls.pg into tests/, and re-add the
-- sql:oidc-tokens-no-rls mutant plus the request-role test to oidc_secfix10.rs.
-- Rust OP looked tokens up by credential with no user scope. Reads and writes
ALTER TABLE public.oidc_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oidc_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oidc_tokens_self ON public.oidc_tokens;
CREATE POLICY oidc_tokens_self ON public.oidc_tokens
    USING (user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint))
    WITH CHECK (user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint));
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
        ALTER TABLE public.oidc_tokens OWNER TO setjoin_owner;
    END IF;
END $$;
INSERT INTO public.schema_migrations (version, applied_at) VALUES (280, now())
    ON CONFLICT (version) DO NOTHING;
