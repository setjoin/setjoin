-- Preserve an immutable retirement record when a folder membership disappears.
CREATE OR REPLACE FUNCTION trg_imap_membership_uid_retire()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  UPDATE public.imap_membership_uid_ledger SET active=false,retired_at=now()
   WHERE tag_id=OLD.tag_id AND imap_uid=OLD.imap_uid
     AND message_id=OLD.message_id AND received_at=OLD.received_at AND active;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS message_tags_imap_uid_retire ON public.message_tags;
CREATE TRIGGER message_tags_imap_uid_retire
AFTER DELETE ON public.message_tags FOR EACH ROW
EXECUTE FUNCTION public.trg_imap_membership_uid_retire();

SELECT public.apply_worker_ownership('trg_imap_membership_uid_retire()'::regprocedure);
