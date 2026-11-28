-- ════════════════════════════════════════════════════════════════════════
-- V030__recipient_smime_certs_label.sql — addendum migration (SP1 Phase 6).
--
-- Adds the optional user-facing label to recipient_smime_certs so that
-- manually-imported certs can be annotated. NULL for harvested rows; the
-- import handler sets it via COALESCE(NULLIF($label,''), existing.label).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.recipient_smime_certs
    ADD COLUMN IF NOT EXISTS label TEXT;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (30, now())
    ON CONFLICT (version) DO NOTHING;
