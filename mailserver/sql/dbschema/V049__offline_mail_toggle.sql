-- ════════════════════════════════════════════════════════════════════════
-- V049__offline_mail_toggle.sql — seed feature.offline_mail (DEFAULT OFF).
--
-- Offline mail #1a (NATIVE encrypted on-device SQLCipher cache + windowed
-- sync). Gated OFF until #2a governance ships caps.offline.allowed. The CODE
-- default is the real net: shared/toggle.IsEnabledDefault('feature.offline_mail',
-- false) is false when the row is absent, so a fresh deploy is inert regardless
-- of this row. (New seed data belongs in a forward migration, not a hand-edit
-- of V001.)
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO public.feature_toggles (key, enabled, description)
VALUES ('feature.offline_mail', false,
        'Native encrypted offline mail cache (SQLCipher) + windowed sync. DEFAULT OFF — enable/Work-Offline UI also gates on caps.offline.allowed (owned by #2a) AND a native shell (isOfflineAvailable), inert until then. Browser is online-only.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (49, now())
    ON CONFLICT (version) DO NOTHING;
