-- ════════════════════════════════════════════════════════════════════════
-- V066__sessions_auth_method_certificate.sql — CA-3b Task 7 LOCKSTEP:
-- extend the sessions.auth_method CHECK to accept 'certificate'.
--
-- The certAuthMethod in the auth chain (priority 5) is the per-request mTLS
-- path; when it writes login_events / future session rows the CHECK must allow
-- 'certificate'. PostgreSQL CHECK constraints require DROP + re-ADD to extend;
-- UNLOGGED table so the ALTER does not generate WAL.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.sessions
    DROP CONSTRAINT IF EXISTS sessions_auth_method_check;

ALTER TABLE public.sessions
    ADD CONSTRAINT sessions_auth_method_check
    CHECK (auth_method = ANY (ARRAY[
        'password'::text,
        'webauthn'::text,
        'kerberos'::text,
        'saml'::text,
        'oidc'::text,
        'totp'::text,
        'certificate'::text
    ]));

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (66, now())
    ON CONFLICT (version) DO NOTHING;
