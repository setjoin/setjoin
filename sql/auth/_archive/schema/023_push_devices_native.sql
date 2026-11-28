-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 023: Extend push_devices for native APNs/FCM/HMS push and ECDH device registration.

-- Drop the old CHECK and re-create with hms included.
ALTER TABLE push_devices
    DROP CONSTRAINT push_devices_push_provider_check;

ALTER TABLE push_devices
    ADD CONSTRAINT push_devices_push_provider_check
    CHECK (push_provider IN ('webpush', 'apns', 'fcm', 'hms'));

-- DER-encoded P-256 public key submitted by the device at registration.
-- NULL for webpush devices (they don't use ECIES).
ALTER TABLE push_devices
    ADD COLUMN device_public_key BYTEA;
