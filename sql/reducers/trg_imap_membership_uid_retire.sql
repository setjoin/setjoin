-- Preserve an immutable retirement record when a folder membership disappears,
-- stamping retired_modseq from the single mailboxes.jmap_email_state currency
-- (#554) so QRESYNC VANISHED queries filter deterministically by MODSEQ without
-- wall-clock timestamp races.
CREATE OR REPLACE FUNCTION trg_imap_membership_uid_retire()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_modseq bigint;
BEGIN
  -- Post-bump draft deletion paths (jmap_email_submission, mail_draft_replace)
  -- set app.imap_retire_modseq = (committed_state + 1) so retired_modseq matches
  -- the exact committed MODSEQ cursor without an off-by-one (#554).
  v_modseq := NULLIF(current_setting('app.imap_retire_modseq', TRUE), '')::bigint;
  IF v_modseq IS NULL THEN
    SELECT COALESCE(mb.jmap_email_state, 0) + 2
      INTO v_modseq
      FROM public.tags t
      JOIN public.mailboxes mb ON mb.id = t.mailbox_id
     WHERE t.id = OLD.tag_id;
  END IF;

  UPDATE public.imap_membership_uid_ledger
     SET active = false,
         retired_at = now(),
         retired_modseq = COALESCE(v_modseq, 1)
   WHERE tag_id = OLD.tag_id
     AND imap_uid = OLD.imap_uid
     AND message_id = OLD.message_id
     AND received_at = OLD.received_at
     AND active;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS message_tags_imap_uid_retire ON public.message_tags;
CREATE TRIGGER message_tags_imap_uid_retire
AFTER DELETE ON public.message_tags FOR EACH ROW
EXECUTE FUNCTION public.trg_imap_membership_uid_retire();

SELECT public.apply_worker_ownership('trg_imap_membership_uid_retire()'::regprocedure);
