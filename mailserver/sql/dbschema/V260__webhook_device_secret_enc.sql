-- ════════════════════════════════════════════════════════════════════════
-- V260__webhook_device_secret_enc.sql — remaining RECOVERABLE secrets move to
-- the family's AES-256-GCM _enc envelope (D6 / DBSCHEMA-005, V247 pattern).
--
-- D6 scope (Astra AGREE with the scope correction): envelope-encrypt
-- RECOVERABLE secrets ONLY. oidc_clients.secret is deliberately EXCLUDED —
-- it stores bcrypt HASHES (non-recoverable by design; the hash is the
-- verifier, not a secret that can be re-emitted), and envelope-encrypting a
-- verifier would add key dependency without removing anything readable.
-- devices.hmac_secret is already covered by V247; this migration completes
-- the family with the remaining plaintext recoverable-secret columns:
--
--   webhook_subscriptions.secret       TEXT NOT NULL — the per-subscription
--                             HMAC signing secret (shared/webhook.Sign);
--                             recoverable by definition (the server must
--                             re-derive signatures per delivery).
--   webhook_subscriptions.prev_secret  TEXT — the rotation-grace copy of the
--                             previous signing secret (kept so in-flight
--                             deliveries do not break across rotation).
--   device_registry.device_secret      TEXT — legacy MAM check-in HMAC key
--                             (archived V060); NO live writer or reader
--                             exists today (check-in authenticates through
--                             devices.hmac_secret via shared/device, and
--                             shared/threat inserts rows without it), so
--                             this migration envelopes the at-rest form and
--                             retires the plaintext default. Because no
--                             live reader exists, the loader-driven lazy
--                             migration can never fire for this column: the
--                             migration path is the one-shot startup
--                             backfill (mailserver/internal/mdm
--                             BackfillRegistryDeviceSecrets), which seals
--                             every legacy plaintext value into the
--                             envelope and NULLs the plaintext (Astra D6
--                             impl-r2 finding 2).
--
-- Each column gains the V247 column pair:
--
--   <col>_enc     BYTEA — cryptokey EK01 column envelope (AES-256-GCM under
--                       the standard profile), sealed by the app via
--                       cryptokey.EncryptColumn from the RAW master secret
--                       (DeriveDBEncryptionKey inside the seam — the exact
--                       devices.hmac_secret_enc / signing_keys.private_key_enc
--                       contract; never pre-derive, never pass keys into SQL).
--   <col>_key_id  TEXT — non-secret master-key version stamped beside new
--                       envelopes ("v1"), the system_config secret-codec
--                       convention. Readers fail closed on an unknown or
--                       unstamped id.
--
-- Compatibility leg (this package's only claim — no RLS claims closed here):
-- existing rows keep their working trust channel. SQL cannot seal the
-- envelope (the master key never enters the database), so:
--   - webhook_subscriptions.secret drops NOT NULL and remains the legacy
--     representation for pre-existing rows;
--   - the Go reader (shared/webhook LoadSubscriptionSecret) requires the
--     process codec on every read — legacy rows included (delivery never
--     depends on encryption being unavailable; the V247 fail-closed
--     contract) — and lazily re-seals a legacy row on first delivery: one
--     atomic UPDATE that stores both envelopes + key ids and NULLs BOTH
--     plaintext cells (secret AND prev_secret), so a rotated legacy row ends
--     ciphertext-only in all four columns (Astra D6 impl-r2 findings 1+3);
--   - new registrations write _enc + key_id only and never persist plaintext;
--   - rotation re-seals the previous value into the prev_* columns and NULLs
--     every plaintext cell, so a rotated row ends ciphertext-only in all four
--     columns (legacy rows drain on first rotation or first delivery).
-- Dropping the legacy columns is the backfill-completion gate and is
-- deliberately NOT part of this migration.
-- ════════════════════════════════════════════════════════════════════════

-- ── Webhook signing secrets (recoverable; delivered per-event) ───────────────
ALTER TABLE public.webhook_subscriptions ADD COLUMN IF NOT EXISTS secret_enc bytea;
ALTER TABLE public.webhook_subscriptions ADD COLUMN IF NOT EXISTS secret_key_id text;
ALTER TABLE public.webhook_subscriptions ADD COLUMN IF NOT EXISTS prev_secret_enc bytea;
ALTER TABLE public.webhook_subscriptions ADD COLUMN IF NOT EXISTS prev_secret_key_id text;

-- Ciphertext-only writes (registration, rotation, lazy migration) leave the
-- plaintext cells NULL.
ALTER TABLE public.webhook_subscriptions ALTER COLUMN secret DROP NOT NULL;

-- ── Legacy device check-in secret (no live writer/reader; at-rest posture) ──
ALTER TABLE public.device_registry ADD COLUMN IF NOT EXISTS device_secret_enc bytea;
ALTER TABLE public.device_registry ADD COLUMN IF NOT EXISTS device_secret_key_id text;

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (260, now())
    ON CONFLICT (version) DO NOTHING;
