-- ════════════════════════════════════════════════════════════════════════
-- V247__device_hmac_secret_enc.sql — devices.hmac_secret at-rest encryption
-- (med-auth-baseline-secrets-001 / D-AUTHSERVER-SQL--ARCHIVE-003).
--
-- devices.hmac_secret — the attestation key for device check-in and
-- policy-read HMAC — was plaintext TEXT in the live baseline (installed
-- verbatim from archived authserver V008__unified_devices.sql:23) while
-- sibling secrets in the same family are AES-256-GCM _enc columns
-- (signing_keys.private_key_enc via the cryptokey EK01 envelope). With
-- V060's devices_admin_read USING(true) policy the app pool could SELECT
-- every plaintext key, so a single read-path leak forges every device's
-- HMACs (CWE-312).
--
-- This migration moves the stored secret to the family's AES-256-GCM _enc
-- format with key-id handling:
--
--   hmac_secret_enc    BYTEA — cryptokey EK01 column envelope (AES-256-GCM
--                             under the standard profile), sealed by the app
--                             via cryptokey.EncryptColumn from the RAW master
--                             secret (DeriveDBEncryptionKey inside the seam —
--                             the exact signing_keys.private_key_enc contract;
--                             never pre-derive, never pass keys into SQL).
--   hmac_secret_key_id TEXT — non-secret master-key version stamped beside
--                             new envelopes ("v1"), the same key-version
--                             convention as the system_config secret codec.
--                             Readers fail closed on an unknown/unstamped id.
--                             Rotation/rollback semantics for already-issued
--                             keys (in-place re-encrypt with key-id dual-verify
--                             versus forced re-attestation) remain an OPEN
--                             decision; this column carries the id so that
--                             decision needs no further migration.
--
-- Compatibility leg (this package's only claim — no RLS claims closed here):
-- existing rows keep their working trust channel. SQL cannot seal the
-- envelope (the master key never enters the database), so:
--   - hmac_secret drops NOT NULL and remains the legacy representation for
--     pre-existing rows;
--   - the Go reader (shared/device GetDeviceSecret) lazily re-seals a legacy
--     row on first verification — one atomic UPDATE that stores the envelope
--     + key id and NULLs the plaintext, after which the row stores only _enc
--     ciphertext (including rows migrated from plaintext);
--   - new registrations write _enc + key_id only and never persist plaintext.
-- Dropping the legacy column is the backfill-completion gate and is
-- deliberately NOT part of this migration.
--
-- OWNERSHIP NOTE: V060's devices_admin_read USING(true) read-policy
-- tightening is owned exclusively by med-dbschema-rls-001; this migration
-- changes NO RLS policies. App-pool read-scope assertions for hmac_secret are
-- med-dbschema-rls-001's acceptance evidence, not this package's.
--
-- Interaction with the device_enroll_transition revoke rotation
-- (med-shard2-006, out of scope here): the reducer replaces the revoked row's
-- trust value with a fresh random in the legacy column. For a row already in
-- the ciphertext form this leaves the stale envelope tombstoned — acceptable
-- because revocation is terminal and every verify path refuses revoked rows
-- BEFORE consulting any stored secret.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS hmac_secret_enc bytea;
ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS hmac_secret_key_id text;

-- Ciphertext-only writes (registration, lazy migration) leave hmac_secret NULL.
ALTER TABLE public.devices ALTER COLUMN hmac_secret DROP NOT NULL;

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (247, now())
    ON CONFLICT (version) DO NOTHING;
