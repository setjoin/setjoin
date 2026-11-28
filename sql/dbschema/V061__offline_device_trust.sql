-- ════════════════════════════════════════════════════════════════════════
-- V061__offline_device_trust.sql — Offline mail #2b (NATIVE-OFFLINE PIVOT):
-- device-trust completion.
--
-- Adds the best-effort remote-wipe ACK column to user_devices (mirrors
-- mdm_device_state.wipe_acked_at). Written opportunistically by the NATIVE
-- client on its next online session after an offline.wipe push: it confirms
-- it dropped the offline-core 'mail' store + destroyed its key (held via
-- guard-core) (offline_device_wipe_ack reducer, Task 3).
--
-- The DURABLE revocation guarantee is #2a's seed-withholding (F4); this
-- column is only the best-effort "the native client confirmed it cleared"
-- signal. NULL = unacknowledged.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS wipe_acked_at TIMESTAMPTZ;

COMMENT ON COLUMN public.user_devices.wipe_acked_at IS
    'Best-effort timestamp the NATIVE client confirmed it dropped its offline-core ''mail'' store + destroyed its key (held via guard-core) after an offline.wipe push (#2b). NULL = unacknowledged. Not load-bearing for security; the durable deny is #2a seed-withholding.';

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (61, now())
    ON CONFLICT (version) DO NOTHING;
