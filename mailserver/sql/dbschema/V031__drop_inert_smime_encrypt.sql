-- ════════════════════════════════════════════════════════════════════════
-- V031__drop_inert_smime_encrypt.sql — drop the dead messages.smime_encrypt column.
--
-- The boolean `messages.smime_encrypt` was the OLD outbound-worker encrypt gate.
-- V011/D3 removed the worker signing path, and SP1 Phase 3 re-homed ENCRYPTION to
-- the EmailSubmission/set Go handler (jmap/mail_encrypt.go) — encryption intent is
-- now per-submission (`encryptSMIME` in the create map), never a stored column. No
-- reducer reads/writes it and no INSERT lists it (it rode the DEFAULT false);
-- internal/smtp/smime_encrypt_gate_test.go already guards that the worker source
-- never references it. The column has been inert since SP1 — drop it.
--
-- Drop from the partitioned PARENT (public.messages); PostgreSQL cascades the drop
-- to every existing partition, and future partitions (startup.EnsureMessagePartitions
-- → CREATE TABLE … PARTITION OF messages) inherit the post-drop column set. IF EXISTS
-- keeps it idempotent / a no-op on a tree where it was already removed.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.messages DROP COLUMN IF EXISTS smime_encrypt;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (31, now())
    ON CONFLICT (version) DO NOTHING;
