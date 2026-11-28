-- ════════════════════════════════════════════════════════════════════════
-- V007__device_trust_toggle.sql — forward migration (device-trust enforcement).
--
-- Seeds the feature.device_trust_enforcement toggle (DEFAULT OFF) so it is
-- visible + flippable in the admin console. The CODE default is the real safety
-- net: shared/toggle.IsEnabledDefault(key, false) returns false when the row is
-- absent (unlike IsEnabled, which defaults unknown keys to TRUE) — so an
-- unseeded/fresh deployment is inert regardless of this row. Off => login embeds
-- no device claim and the gateway gate is a pure pass-through no-op. Flip
-- deliberately, staged, after verifying enrolled-compliant devices pass and a
-- test-quarantined device is blocked.
--
-- (New seed data belongs in a forward migration, NOT a hand-edit of the FROZEN
-- V001 collapse snapshot.)
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO public.feature_toggles (key, enabled, description)
VALUES ('feature.device_trust_enforcement', false,
        'Block quarantined/non-compliant managed devices from the gateway API (login embeds a managed_devices-derived device claim; gateway gates on it). DEFAULT OFF — inert until deliberately flipped.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (7, now())
    ON CONFLICT (version) DO NOTHING;
