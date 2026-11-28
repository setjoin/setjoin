-- ════════════════════════════════════════════════════════════════════════
-- V272__possession_first_factor_gate.sql — first-factor possession gate
-- (docs/verification/2026-09-23-possession-scheme-v7.md §2.1, items 1–5).
--
-- Owner decision (a): every factor-set mutation requires a fresh possession
-- proof of an already-enrolled factor; bearer identity alone never extends a
-- factor set. This migration carries the storage authority:
--
--   1. mfa_reauth_step_ups (the V271 transport table) gains the proof-grant
--      tuple: operation, target_ref, proof_method, proving_factor_id,
--      bound_factor_generation, token_scope, refresh_family_id. Existing
--      unconsumed password-only rows are DELETED at migration time (owner
--      clean cut, v2 §7; pre-GA) — they carry no operation binding and the
--      new consumption contract re-validates the FULL tuple, so a row that
--      predates the gate is unattributable and must not survive it.
--   2. totp_pending_enrollments — staged TOTP enrollment secrets with UUID
--      identity, staged_by_jti provenance and their own expiry, so
--      replacement setup no longer overwrites the ACTIVE factor (§1.6).
--   3. passkey_credentials.uv_capable — cohort classification input (§1.2);
--      all pre-existing rows are false (the clean cut: unknown = non-UV).
--   4. webauthn_ceremonies — the dedicated server-side challenge store for
--      management-assertion and registration ceremonies (§1.4), bound to
--      {user, kind, operation, target_ref, real JTI, token scope, family}.
--   5. users gains factor_generation (§1.8, the mutation-only grant
--      invalidation counter) plus the possession failure-budget counter
--      pairs for the `password` and `webauthn_uv` proof methods (§2.3).
--      The existing totp_failed_attempts / totp_locked_until pair remains
--      the `totp` proof-method counter.
--
-- No RLS policy is added here: the native-RLS flip and its per-table
-- policies are owned by the dbschema-rls package (same posture as the
-- V271 parent table).
-- ════════════════════════════════════════════════════════════════════════

-- ── 1. Proof-grant tuple on the V271 transport table ────────────────────────
-- Clean cut first: unconsumed legacy rows cannot satisfy the full-tuple
-- consumption contract (no operation, no generation binding), so the
-- migration invalidates them by deleting them.
DELETE FROM public.mfa_reauth_step_ups;

ALTER TABLE public.mfa_reauth_step_ups
    ADD COLUMN operation text NOT NULL,
    ADD COLUMN target_ref text,
    ADD COLUMN proof_method text NOT NULL,
    ADD COLUMN proving_factor_id bytea,
    ADD COLUMN bound_factor_generation bigint NOT NULL,
    ADD COLUMN token_scope text NOT NULL DEFAULT 'session',
    ADD COLUMN refresh_family_id text;

-- ── 2. Staged TOTP pending enrollments (§1.6) ───────────────────────────────
CREATE TABLE public.totp_pending_enrollments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id bigint NOT NULL UNIQUE REFERENCES public.users (id) ON DELETE CASCADE,
    secret_enc bytea NOT NULL,
    staged_by_jti text NOT NULL,
    staged_via text NOT NULL DEFAULT 'unknown',
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

-- ── 3. UV capability on normalized passkey credentials (§1.2) ───────────────
ALTER TABLE public.passkey_credentials
    ADD COLUMN uv_capable boolean NOT NULL DEFAULT false;

-- ── 4. Dedicated WebAuthn ceremony store (§1.4) ─────────────────────────────
CREATE TABLE public.webauthn_ceremonies (
    challenge_hash text NOT NULL PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
    kind text NOT NULL,
    operation text NOT NULL,
    target_ref text,
    session_jti text NOT NULL,
    token_scope text NOT NULL DEFAULT 'session',
    refresh_family_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT webauthn_ceremonies_kind_check
        CHECK (kind IN ('registration', 'management_assertion')),
    CONSTRAINT webauthn_ceremonies_token_scope_check
        CHECK (token_scope IN ('session', 'mfa_pending'))
);

CREATE INDEX webauthn_ceremonies_user_kind_idx
    ON public.webauthn_ceremonies USING btree (user_id, kind);

-- ── 5. users: factor generation + possession failure budgets (§1.8, §2.3) ──
ALTER TABLE public.users
    ADD COLUMN factor_generation bigint NOT NULL DEFAULT 0,
    ADD COLUMN possession_password_failed_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN possession_password_locked_until timestamp with time zone,
    ADD COLUMN possession_webauthn_failed_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN possession_webauthn_locked_until timestamp with time zone;

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (272, now())
    ON CONFLICT (version) DO NOTHING;
