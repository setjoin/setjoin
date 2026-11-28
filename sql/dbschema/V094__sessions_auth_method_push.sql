-- ════════════════════════════════════════════════════════════════════════
-- V094__sessions_auth_method_push.sql — Queue B #1 (web-session-revoke Tier 1).
--
-- Web logins now INSERT a `sessions` row on every issueTokensWithFactors call
-- (authserver), using the same auth_method vocabulary as login_events
-- (authMethodFromFactors). One reachable value — 'push' (native push-MFA
-- approve, device.go MFAApprove) — was never added to sessions_auth_method_check
-- (V066 added 'certificate' only), so a push-MFA web login's session INSERT
-- would violate the CHECK and drop the row. Widen the constraint the same way
-- V066 did (DROP + re-ADD; UNLOGGED table, no WAL from the ALTER).
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
        'certificate'::text,
        'push'::text
    ]));

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (94, now())
    ON CONFLICT (version) DO NOTHING;
