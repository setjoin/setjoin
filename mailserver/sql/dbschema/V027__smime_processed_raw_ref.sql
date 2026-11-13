-- ════════════════════════════════════════════════════════════════════════
-- V027__smime_processed_raw_ref.sql — forward migration (SP1 Phase 3 Task 3.2).
--
-- Renames the EmailSubmission/set swap seam: p_signed_raw_ref → p_processed_raw_ref
-- (the blob may now be signed AND/OR encrypted) and adds p_is_encrypted JSONB
-- (creationId → bool) which 3.3 uses to null body columns for encrypted-at-rest.
--
-- The reducer's CREATE OR REPLACE recreates it at the new 5-arg arity. A live
-- upgrade would LEAVE the prior 4-arg (p_signed_raw_ref) overload behind →
-- ambiguous overload. Drop it here (mirrors V016's overload-drop discipline).
-- No-op on a fresh load.
-- ════════════════════════════════════════════════════════════════════════

DROP FUNCTION IF EXISTS public.jmap_email_submission_set(bigint, bigint, jsonb, jsonb);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (27, now())
    ON CONFLICT (version) DO NOTHING;
