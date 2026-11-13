-- ════════════════════════════════════════════════════════════════════════
-- V271__mfa_reauth_step_ups.sql — single-use re-authentication step-up
-- tokens for FIRST-factor MFA enrollment and recovery-code regeneration
-- (ER5 s07 named residual: stolen-bearer step-up).
--
-- The residual: a stolen bearer (valid access token on someone else's
-- session) could enroll a FIRST authenticator via /auth/totp/setup +
-- /auth/totp/confirm, or replace every recovery code via
-- /auth/backup-codes/generate, with no proof the session holder is the
-- account owner. Possession checks cannot exist on the first-factor arm
-- (there is no existing verified factor to prove possession against), so
-- the contract is a fresh re-authentication: the account password,
-- presented now, at the challenge path POST /auth/mfa/reauth.
--
-- The lifecycle mirrors the V250 de-enrollment step-up exactly:
--
--   1. POST /auth/mfa/reauth (requireAuth + CSRF): verifies the session
--      holder's current password through the same pwhash seam as login and
--      the V250 removal begin. On success an opaque re-auth token is
--      issued whose SHA-256 hash is stored HERE, bound to the user and the
--      access session (users JWT jti), with a short expiry.
--   2. The gated arms consume it:
--        - GET  /auth/totp/setup   (no verified factor on the account):
--          validates WITHOUT consuming — the same single token must still
--          authorize the follow-up /auth/totp/confirm;
--        - POST /auth/totp/confirm (no verified factor): consumption is
--          the DELETE below — atomic and single-use, so a replayed token,
--          a foreign-session token, or a concurrent double-submission is
--          refused (zero rows) before the factor activates;
--        - POST /auth/backup-codes/generate (every account — recovery
--          regeneration replaces every recovery code regardless of factor
--          state): consumed the same way, before any code is minted.
--      Accounts that ALREADY have a verified factor keep their existing
--      posture on the setup/confirm arms (current_totp_code possession
--      check, V250 removal step-up); this table never gates them there.
--
-- The table stores only the token HASH (never the raw token), mirroring
-- totp_removal_step_ups. Rows are deleted on consumption; a stale tail
-- (issued but never consumed) is bounded by (a) deleting the user's prior
-- rows on every new issuance and (b) the expires_at guard, so no
-- background pruner is required for correctness.
--
-- No RLS policy is added here: the native-RLS flip and its per-table
-- policies are owned by the dbschema-rls package (same posture as the
-- sibling totp_removal_step_ups / push_mfa_challenges tables).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.mfa_reauth_step_ups (
    token_hash text NOT NULL PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
    session_jti text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE INDEX mfa_reauth_step_ups_user_id_idx
    ON public.mfa_reauth_step_ups USING btree (user_id);

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (271, now())
    ON CONFLICT (version) DO NOTHING;
