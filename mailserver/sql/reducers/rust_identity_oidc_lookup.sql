-- #525 owner-approved security fix 2026-11-05: the credential-keyed reads of oidc_tokens.
-- Each worker-owned DEFINER lookup takes the PRESENTED credential (SHA-256 refresh hash, or
-- an access-token id taken from a verified token) and derives the owning user from the
-- stored row; the caller then repeats that user as its transaction scope for every follow-up
-- read or write, as with rust_identity_oidc_consume. They never take a user id. FORCE RLS on
-- oidc_tokens is staged (sql/staged/oidc_tokens_force_rls.sql) for the Go-deletion ticket:
-- frozen authserverd runs as setjoin_app and never sets the user GUC.

-- Refresh grant anchor: the row a presented refresh hash names, with its spent
-- and live flags (family lifetime included, #523).
CREATE OR REPLACE FUNCTION rust_identity_oidc_refresh_anchor(p_hash text)
RETURNS TABLE(id text,client_id text,user_id bigint,scopes text[],spent boolean,live boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT t.id,t.client_id,t.user_id,t.scopes,t.revoked_at IS NOT NULL,
           t.refresh_expires_at>now()
           AND COALESCE(t.refresh_family_expires_at,t.created_at+interval '90 days')>now()
      FROM public.oidc_tokens t WHERE t.refresh_token_hash=p_hash LIMIT 1;
$$;
SELECT apply_worker_ownership('rust_identity_oidc_refresh_anchor(text)'::regprocedure);

-- Owner of an access-token row (UserInfo, introspection). The row's user is the
-- authority; the caller still verifies the credential's subject equals it.
CREATE OR REPLACE FUNCTION rust_identity_oidc_token_owner(p_id text)
RETURNS TABLE(user_id bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT t.user_id FROM public.oidc_tokens t WHERE t.id=p_id LIMIT 1;
$$;
SELECT apply_worker_ownership('rust_identity_oidc_token_owner(text)'::regprocedure);

-- Unrevoked token (refresh hash or access id) of the authenticated client: the
-- owner whose scope the revocation UPDATE then runs under.
CREATE OR REPLACE FUNCTION rust_identity_oidc_revoke_target(p_hash text,p_id text,p_client_id text)
RETURNS TABLE(user_id bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT t.user_id FROM public.oidc_tokens t
     WHERE (t.refresh_token_hash=p_hash OR t.id=p_id) AND t.client_id=p_client_id
       AND t.revoked_at IS NULL LIMIT 1;
$$;
SELECT apply_worker_ownership('rust_identity_oidc_revoke_target(text,text,text)'::regprocedure);
