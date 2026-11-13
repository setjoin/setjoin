-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 019: Forgot-password self-service reset infrastructure.
-- Single-use token tracking prevents replay — same pattern as used_saml_assertions (016).

CREATE TABLE used_password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Auto-prune rows older than 10 minutes (tokens expire at 5 min).
-- Runs every 5 minutes via the Go cron worker (pg_cron is optional).
-- TRIAGE FENCE (D-AUTHSERVER-SQL--ARCHIVE-009, 2026-09): the prune documented
-- below NEVER SHIPPED — no live code implements this schedule (the archived
-- pg_cron block is inert and no Go cron task replaced it), so the replay
-- table grows unboundedly. Single-use safety comes from the token_hash PK and
-- only hashes are stored, so this is retention debt, not replay exposure —
-- but do NOT cite this block as an implemented retention control. Wiring a
-- real prune (Go cron registry, like prune_old_lockouts) is the closing fix.
-- [pg_cron→Go cron worker] SELECT cron.schedule(
--     'forgot-password-prune',
--     '*/5 * * * *',
--     $$DELETE FROM used_password_reset_tokens WHERE created_at < now() - interval '10 minutes'$$
-- );

-- Feature toggles: admin can disable self-service or restrict to TOTP-only.
INSERT INTO feature_toggles (key, enabled, description) VALUES
    ('feature.forgot_password',      TRUE, 'Allow users to reset forgotten passwords via MFA'),
    ('feature.forgot_password_push', TRUE, 'Allow push MFA as forgot-password verification method')
ON CONFLICT (key) DO NOTHING;
