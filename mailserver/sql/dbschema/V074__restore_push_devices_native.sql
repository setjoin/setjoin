-- V074: restore the native push-device schema lost in the ARCH-007 baseline collapse.
--
-- authserver live code requires both pieces but the collapsed V001 has neither,
-- so HarmonyOS / native push-device registration is broken in production:
--   • internal/handlers/device.go INSERTs device_public_key and accepts provider
--     'hms' (case "apns","fcm","hms"); internal/authn/push.go SELECTs
--     device_public_key WHERE push_provider IN ('apns','fcm','hms').
--   • the baseline push_devices has no device_public_key column and its CHECK
--     constraint allows only ('webpush','apns','fcm') — an 'hms' INSERT is rejected
--     and the device_public_key INSERT errors "column does not exist".
--
-- Re-applies authserver/sql/_archive/schema/023_push_devices_native.sql, which the
-- collapse dropped. Caught by authserver/sql/tests/023_push_devices_native_test.pg.

ALTER TABLE push_devices DROP CONSTRAINT push_devices_push_provider_check;

ALTER TABLE push_devices
    ADD CONSTRAINT push_devices_push_provider_check
    CHECK (push_provider IN ('webpush', 'apns', 'fcm', 'hms'));

ALTER TABLE push_devices ADD COLUMN IF NOT EXISTS device_public_key BYTEA;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (74, now())
  ON CONFLICT (version) DO NOTHING;
