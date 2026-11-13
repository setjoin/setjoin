-- V121__oidc_op_refresh_expiry.sql — authserver OIDC-OP refresh tokens never
-- expire (codebase review 2026-07-11 A5).
--
-- oidc_tokens.expires_at is the ACCESS token's own short TTL (5 minutes,
-- internal/federation/oidc_op_token_store.go createAccessToken) — it is
-- reused verbatim for every row, including the ones that go on to carry a
-- refresh_token_hash. Checking expires_at in the refresh-token lookup would
-- make a refresh token usable for the same 5 minutes as the access token it
-- was issued with, defeating the point of refresh tokens. The refresh token
-- needs its OWN expiry column, set only on rows that actually carry one.
ALTER TABLE public.oidc_tokens
  ADD COLUMN refresh_expires_at TIMESTAMPTZ;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (121, now())
ON CONFLICT (version) DO NOTHING;
