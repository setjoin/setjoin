-- ════════════════════════════════════════════════════════════════════════
-- V029__smime_encrypted_no_fts.sql — forward migration (SP1 Phase 5 5.7).
--
-- Encrypted mail must NEVER be full-text indexed. V028 nulls body_text/body_html
-- for an encrypted copy, but the BEFORE-INSERT FTS trigger trg_messages_tsv()
-- still ran to_tsvector('simple', coalesce(body_text,'')) → an EMPTY tsvector
-- (not NULL) on the encrypted row. Empty indexes nothing, but it is a footgun:
-- a later edit that fed ciphertext through coalesce would silently start indexing
-- it. Make the invariant explicit at the data layer — for a row whose
-- crypto_type = 'smime-encrypted', body_tsv is set to NULL (genuinely no body
-- index). subject_tsv / from_tsv are KEPT: subject + From stay cleartext headers
-- and remain searchable (the read-side preview/body are nulled in jmap_email_get).
--
-- CREATE OR REPLACE keeps the trigger binding intact (only the function body
-- changes). No-op-safe to re-run on a fresh load.
-- ════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION public.trg_messages_tsv() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF current_setting('app.skip_fts', true) = 'true' THEN
    RETURN NEW;
  END IF;
  -- C7: an S/MIME-encrypted copy stores only ciphertext; its body is NEVER
  -- indexed. body_tsv stays NULL so no plaintext can leak via full-text search.
  IF NEW.crypto_type = 'smime-encrypted' THEN
    NEW.body_tsv := NULL;
  ELSE
    NEW.body_tsv := to_tsvector('simple', coalesce(NEW.body_text, ''));
  END IF;
  NEW.subject_tsv := to_tsvector('simple', coalesce(NEW.subject, ''));
  NEW.from_tsv    := to_tsvector('simple',
                       coalesce(NEW.from_addr, '') || ' ' || coalesce(NEW.from_name, ''));
  RETURN NEW;
END;
$$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (29, now())
    ON CONFLICT (version) DO NOTHING;
