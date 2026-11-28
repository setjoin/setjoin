-- ════════════════════════════════════════════════════════════════════════
-- V016__remove_outbound_sign_smime.sql — forward migration (Phase D3).
--
-- Removes the now-dormant worker-side S/MIME signing plumbing. Phase D re-homed
-- S/MIME signing from the SMTP outbound worker into the EmailSubmission/set Go
-- handler (jmap/mail_smime.go), which signs at submission and strips signSMIME
-- before the reducer — so nothing sets sign_smime=true anymore and the worker's
-- signSMIME pass early-returns. This drops the dead column + stale overloads.
--
-- Drops sign_smime from BOTH outbound queue tables IN MATCHED ORDER so
-- drain_outbound_hot()'s positional `INSERT ... SELECT *` stays column-aligned
-- (the V014 alignment invariant; dropping from only one table would silently
-- corrupt the drain).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.outbound_queue     DROP COLUMN IF EXISTS sign_smime;
ALTER TABLE public.outbound_queue_hot DROP COLUMN IF EXISTS sign_smime;

-- Drop the 17-arg send() overload (the one with trailing p_sign_smime BOOLEAN) so
-- the reducer reload recreates the slimmed 16-arg send() with no ambiguous overload
-- on a live upgrade (mirrors V014’s drop of the prior 16-arg signature).
DROP FUNCTION IF EXISTS public.send(
  bigint, bigint, text, text, text, jsonb, jsonb, jsonb, text, text, text, text, text,
  bigint, boolean, timestamptz, boolean);

-- Drop the OLD 3-arg jmap_email_submission_set overload. D1 added a 4th param
-- (p_signed_raw_ref); a CREATE OR REPLACE with a new arity LEAVES the 3-arg version
-- behind on a live upgrade -> ambiguous overload. (No-op on a fresh load.)
DROP FUNCTION IF EXISTS public.jmap_email_submission_set(bigint, bigint, jsonb);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (16, now())
    ON CONFLICT (version) DO NOTHING;
