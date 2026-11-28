-- ════════════════════════════════════════════════════════════════════════
-- V014__outbound_sign_smime.sql — forward migration (outbound S/MIME intent).
--
-- Carries the user's "Sign (S/MIME)" choice from the submission to the outbound
-- worker, mirroring the existing dkim_signed column. APPENDED to BOTH outbound
-- queue tables so drain_outbound_hot()'s positional `INSERT ... SELECT *` stays
-- column-aligned. Drops the prior 16-arg send() overload so the reducer reload
-- recreates send() with the new trailing DEFAULT param without an ambiguous
-- overload on a live upgrade (no-op on a fresh load).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.outbound_queue     ADD COLUMN IF NOT EXISTS sign_smime boolean DEFAULT false NOT NULL;
ALTER TABLE public.outbound_queue_hot ADD COLUMN IF NOT EXISTS sign_smime boolean DEFAULT false NOT NULL;

DROP FUNCTION IF EXISTS public.send(
  bigint, bigint, text, text, text, jsonb, jsonb, jsonb, text, text, text, text, text,
  bigint, boolean, timestamptz);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (14, now())
    ON CONFLICT (version) DO NOTHING;
