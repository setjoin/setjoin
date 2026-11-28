-- ════════════════════════════════════════════════════════════════════════
-- V028__smime_send_deliver_encrypted.sql — forward migration (SP1 Phase 3 3.3).
--
-- Encrypted-at-rest: send() and deliver() each gain a trailing
-- p_is_encrypted BOOLEAN DEFAULT FALSE that nulls the stored body_text/body_html
-- (the FTS trigger then blanks body_tsv) so an encrypted copy persists ONLY the
-- ciphertext in raw_ref; subject is retained.
--
-- The reducer CREATE OR REPLACE recreates each at the new trailing-param arity.
-- A live upgrade would LEAVE the prior overloads behind → ambiguous overload.
-- Drop the EXACT prior signatures here (type lists copied from \df+; an arity
-- mismatch makes the DROP a silent no-op — V016 matched-drop discipline).
-- No-op on a fresh load.
-- ════════════════════════════════════════════════════════════════════════

-- Prior send(): 16 args ending p_send_at timestamptz.
DROP FUNCTION IF EXISTS public.send(
  bigint, bigint, text, text, text, jsonb, jsonb, jsonb, text, text, text, text, text,
  bigint, boolean, timestamptz);

-- Prior deliver(): 32 args ending p_smime_issuer_cn text.
DROP FUNCTION IF EXISTS public.deliver(
  text, text, text, text, text, jsonb, jsonb, jsonb, text, text, text, text, text,
  bigint, boolean, timestamptz, text, text, text, real, jsonb, text, text, boolean,
  text, boolean, integer, text, text, text, text, text);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (28, now())
    ON CONFLICT (version) DO NOTHING;
