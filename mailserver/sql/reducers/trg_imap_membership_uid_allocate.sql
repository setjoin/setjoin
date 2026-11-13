-- Allocate and ledger every newly inserted folder membership.
CREATE OR REPLACE FUNCTION trg_imap_membership_uid_allocate()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF NEW.imap_uid IS NULL OR NEW.imap_uid <= 0 THEN
    NEW.imap_uid := public.imap_membership_uid_allocate(NEW.tag_id);
  ELSE
    PERFORM 1 FROM public.tags WHERE id=NEW.tag_id FOR UPDATE;
    UPDATE public.tags SET imap_uid_next=GREATEST(imap_uid_next,NEW.imap_uid+1),
      imap_modseq=imap_modseq+1,updated_at=now() WHERE id=NEW.tag_id;
  END IF;
  INSERT INTO public.imap_membership_uid_ledger
    (tag_id,imap_uid,message_id,received_at,active)
  VALUES (NEW.tag_id,NEW.imap_uid,NEW.message_id,NEW.received_at,true);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS message_tags_imap_uid_allocate ON public.message_tags;
CREATE TRIGGER message_tags_imap_uid_allocate
BEFORE INSERT ON public.message_tags FOR EACH ROW
EXECUTE FUNCTION public.trg_imap_membership_uid_allocate();

SELECT public.apply_worker_ownership('trg_imap_membership_uid_allocate()'::regprocedure);
