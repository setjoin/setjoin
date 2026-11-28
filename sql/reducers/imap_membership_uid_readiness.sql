-- Validate one tag before a selected IMAP session may use membership UIDs.
CREATE OR REPLACE FUNCTION imap_membership_uid_readiness(p_tag_id bigint)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_missing bigint;
  v_nonpositive bigint;
  v_duplicates bigint;
  v_orphans bigint;
  v_max_uid bigint;
  v_uid_next bigint;
BEGIN
  SELECT count(*) FILTER (WHERE mt.imap_uid IS NULL),
         count(*) FILTER (WHERE mt.imap_uid <= 0),
         COALESCE(max(mt.imap_uid),0)
    INTO v_missing,v_nonpositive,v_max_uid
    FROM public.message_tags mt WHERE mt.tag_id=p_tag_id;

  SELECT count(*) INTO v_duplicates FROM (
    SELECT mt.imap_uid FROM public.message_tags mt
     WHERE mt.tag_id=p_tag_id AND mt.imap_uid IS NOT NULL
     GROUP BY mt.imap_uid HAVING count(*)>1
  ) duplicate_uids;

  SELECT count(*) INTO v_orphans
    FROM public.imap_membership_uid_ledger l
   WHERE l.tag_id=p_tag_id AND l.active
     AND NOT EXISTS (
       SELECT 1 FROM public.message_tags mt
        WHERE mt.tag_id=l.tag_id AND mt.imap_uid=l.imap_uid
          AND mt.message_id=l.message_id AND mt.received_at=l.received_at);

  SELECT imap_uid_next INTO v_uid_next FROM public.tags WHERE id=p_tag_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'IMAP tag not found' USING ERRCODE='BZ268';
  END IF;

  RETURN jsonb_build_object(
    'ready',v_missing=0 AND v_nonpositive=0 AND v_duplicates=0 AND v_orphans=0
      AND v_uid_next>v_max_uid,
    'missing',v_missing,'nonpositive',v_nonpositive,'duplicates',v_duplicates,
    'orphanLedger',v_orphans,'maxUid',v_max_uid,'uidNext',v_uid_next);
END;
$$;

SELECT public.apply_worker_ownership('imap_membership_uid_readiness(bigint)'::regprocedure);
