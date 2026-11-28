-- ════════════════════════════════════════════════════════════════════════
-- V250__totp_removal_step_ups.sql — single-use step-up tokens for TOTP
-- de-enrollment (med-webmail-mfa-lifecycle-001 /
-- D-MAILSERVER-WEBMAIL-SRC-ROUTES-SETTINGS-001).
--
-- The webmail settings surfaces advertised MFA de-enrollment by POSTing
-- /auth/totp/remove, but authserverd registered no such route: the control
-- was dead and users with a lost authenticator could not remove the factor
-- at all. The new secure lifecycle is a two-call transaction:
--
--   1. POST /auth/totp/remove/begin (requireAuth + CSRF): password plus a
--      current TOTP code — or, when the authenticator is lost and recovery
--      codes remain, a valid recovery code — per the factor/recovery
--      decision table. On success authserverd issues an opaque step-up
--      token whose SHA-256 hash is stored HERE, bound to the user and the
--      access session (users JWT jti), with a short expiry.
--   2. POST /auth/totp/remove (requireAuth + CSRF): carries the step-up
--      token and a typed confirmation. Consumption is the DELETE below —
--      atomic and single-use, so a replayed token or a concurrent
--      double-submission is refused (zero rows) with the factor intact.
--      The factor row and the recovery codes are then removed in ONE
--      serialized transaction (SELECT ... FOR UPDATE on the users row) so
--      no replay or concurrent change can leave a half-removed factor.
--
-- The table stores only the token HASH (never the raw token), mirroring
-- used_password_reset_tokens. Rows are deleted on consumption; a stale
-- tail (issued but never consumed) is bounded by (a) deleting the user's
-- prior rows on every new issuance and (b) the expires_at guard, so no
-- background pruner is required for correctness.
--
-- No RLS policy is added here: the native-RLS flip and its per-table
-- policies are owned by the dbschema-rls package (same posture as the
-- sibling push_mfa_challenges / used_password_reset_tokens tables).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.totp_removal_step_ups (
    token_hash text NOT NULL PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
    session_jti text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE INDEX totp_removal_step_ups_user_id_idx
    ON public.totp_removal_step_ups USING btree (user_id);

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (250, now())
    ON CONFLICT (version) DO NOTHING;
