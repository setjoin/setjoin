-- V238: SCIM bearer-token indexed lookup column.
--
-- Security remediation (D-MAILSERVER-INTERNAL-SCIM-001, CWE-307 amplification
-- surface): SCIM bearer auth verified every request by bcrypt-scanning ALL
-- active tokens (scim_list_active_tokens() + per-row bcrypt in
-- internal/scim/server.go). With SCIM_ENABLED=on that is an unauthenticated
-- remote CPU amplifier: one request costs O(active tokens) bcrypt compares.
--
-- Fix (paired with the Go/reducer changes in the same change-set): minted
-- tokens now also store a non-secret lookup key — the lowercase hex SHA-256 of
-- the raw bearer token — so auth resolves the single candidate row by an
-- indexed equality lookup (scim_token_lookup), then runs ONE bcrypt compare as
-- the actual verifier. The DB never sees the plaintext; the lookup hash alone
-- cannot authenticate (bcrypt remains mandatory) and is not recoverable back
-- into the high-entropy 256-bit token.
--
-- Rotation story: pre-existing provisioned tokens cannot be converted (bcrypt
-- is one-way and the plaintext is gone), so the column is NULL for them and
-- they keep authenticating through the legacy bcrypt-scan fallback, which
-- (from this migration on) surfaces ONLY NULL-lookup-hash rows
-- (scim_list_active_tokens gains `AND token_lookup_hash IS NULL`). The scan
-- shrinks to zero rows as legacy tokens are rotated via `mailctl scim
-- create-token`; no provisioned token breaks.
--
-- Layer 1 (this migration): column + partial UNIQUE index (NULLs excluded, so
-- any number of legacy rows coexist) + drop of the superseded 6-argument
-- scim_token_create signature (the reducer reload replaces it with the
-- 7-argument form that takes the lookup hash; old callers fail loudly instead
-- of silently minting un-indexable tokens).

ALTER TABLE public.scim_tokens
  ADD COLUMN token_lookup_hash text;

CREATE UNIQUE INDEX scim_tokens_token_lookup_hash_key
  ON public.scim_tokens (token_lookup_hash)
  WHERE token_lookup_hash IS NOT NULL;

DROP FUNCTION IF EXISTS
  scim_token_create(text, text, text, timestamptz, text, text);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (238, now())
ON CONFLICT (version) DO NOTHING;
