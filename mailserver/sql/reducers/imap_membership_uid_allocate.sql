-- Allocate the next UID in one tag-local namespace.
CREATE OR REPLACE FUNCTION imap_membership_uid_allocate(p_tag_id bigint)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_uid bigint;
BEGIN
  SELECT GREATEST(t.imap_uid_next,
         COALESCE((SELECT max(l.imap_uid)+1 FROM public.imap_membership_uid_ledger l
                   WHERE l.tag_id=t.id),1))
    INTO v_uid FROM public.tags t WHERE t.id=p_tag_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'IMAP tag not found' USING ERRCODE='BZ268';
  END IF;
  UPDATE public.tags SET imap_uid_next=v_uid+1, imap_modseq=imap_modseq+1,
    updated_at=now() WHERE id=p_tag_id;
  RETURN v_uid;
END;
$$;

SELECT public.apply_worker_ownership('imap_membership_uid_allocate(bigint)'::regprocedure);
