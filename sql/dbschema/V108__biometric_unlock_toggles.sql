-- ════════════════════════════════════════════════════════════════════════
-- V108__biometric_unlock_toggles.sql — biometric unlock admin toggles
-- (biometric-unlock program, P1-T: backend toggle wiring, server-side only).
--
-- Seeds the two admin gates the client reads to learn whether the biometric
-- app-lock tier and the Windows domain-SSO unlock tier are org-enabled (spec
-- docs/superpowers/specs/2026-07-08-biometric-unlock-spec.md §8, Model M).
-- Both seeded OFF: off = offline mail opens automatically whenever the
-- device is unlocked (today's behavior, unchanged) until an admin opts in.
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.biometric_unlock', false, 'Let users lock offline mail behind Face ID/Touch ID/Windows Hello (hardware-bound key, never leaves the device). Seeded OFF; off = offline mail opens automatically whenever the device is unlocked.'),
  ('feature.windows_sso_unlock', false, 'On domain-joined Windows PCs, gate offline mail on the user being signed in to their company account (no extra prompt). Seeded OFF; off = the standard device-unlock default, not tied to domain sign-in.')
ON CONFLICT (key) DO NOTHING;

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (108, now())
    ON CONFLICT (version) DO NOTHING;
