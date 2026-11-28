-- #523 owner-approved security fix 2026-11-05: OIDC refresh-token families.
-- Every refresh grant names a family (its first token row) and a hard absolute
-- lifetime; rotation inherits both, so reuse of a rotated token can revoke the
-- whole family and rotation can no longer slide the window forever. Rows
-- issued before this migration have NULL family columns and are treated as a
-- family of one whose lifetime is created_at + 90 days.
ALTER TABLE public.oidc_tokens
    ADD COLUMN refresh_family text,
    ADD COLUMN refresh_family_expires_at timestamptz;
CREATE INDEX oidc_tokens_refresh_family_idx
    ON public.oidc_tokens (refresh_family) WHERE refresh_family IS NOT NULL;
-- The consume reducer gained a client predicate (new signature); drop the old overload.
DROP FUNCTION IF EXISTS public.rust_identity_oidc_consume(bigint, bytea);
INSERT INTO public.schema_migrations (version, applied_at) VALUES (279, now())
    ON CONFLICT (version) DO NOTHING;
