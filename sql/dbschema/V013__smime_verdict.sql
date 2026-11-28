-- ════════════════════════════════════════════════════════════════════════
-- V013__smime_verdict.sql — forward migration (S/MIME inbound verification).
--
-- Adds the graded inbound S/MIME signature verdict + signer identity to
-- messages (computed in Go at delivery, like dkim_result; stored here, read by
-- jmap_email_get). Seeds feature.smime_verify DEFAULT OFF (inert until flipped;
-- the code gate is shared/toggle.IsEnabledDefault("feature.smime_verify",false)).
-- Drops the prior 28-arg deliver() overload so the reducer reload recreates
-- deliver() with the new trailing DEFAULT params without an ambiguous overload
-- on a live upgrade (no-op on a fresh load — the baseline carries no reducer).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.messages ADD COLUMN IF NOT EXISTS smime_status       text;
ALTER TABLE public.messages ADD COLUMN IF NOT EXISTS smime_signer_email text;
ALTER TABLE public.messages ADD COLUMN IF NOT EXISTS smime_signer_cn    text;
ALTER TABLE public.messages ADD COLUMN IF NOT EXISTS smime_issuer_cn    text;

DO $$
BEGIN
  ALTER TABLE public.messages DROP CONSTRAINT IF EXISTS messages_smime_status_check;
  ALTER TABLE public.messages ADD CONSTRAINT messages_smime_status_check
    CHECK (smime_status = ANY (ARRAY['valid'::text, 'invalid'::text, 'untrusted'::text]));
END $$;

DROP FUNCTION IF EXISTS public.deliver(
  text, text, text, text, text, jsonb, jsonb, jsonb, text, text, text, text, text,
  bigint, boolean, timestamptz, text, text, text, real, jsonb, text, text, boolean,
  text, boolean, integer, text);

INSERT INTO public.feature_toggles (key, enabled, description)
VALUES ('feature.smime_verify', false,
        'Verify inbound S/MIME signatures at delivery and store a graded verdict (green verified shield in the list). DEFAULT OFF — inert until deliberately flipped.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (13, now())
    ON CONFLICT (version) DO NOTHING;
