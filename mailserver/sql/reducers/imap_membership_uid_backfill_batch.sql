-- Repair at most 10,000 legacy memberships per transaction.
CREATE OR REPLACE FUNCTION imap_membership_uid_backfill_batch(p_limit integer DEFAULT 10000)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
  v_row record;
  v_uid bigint;
  v_processed integer := 0;
  v_repaired integer := 0;
  v_candidate_ok boolean;
BEGIN
  IF p_limit < 1 OR p_limit > 10000 THEN
    RAISE EXCEPTION 'IMAP UID backfill limit must be 1..10000' USING ERRCODE='BZ269';
  END IF;
  FOR v_row IN
    SELECT mt.tableoid,mt.ctid,mt.tag_id,mt.message_id,mt.received_at,m.imap_uid AS legacy_uid
      FROM public.message_tags mt
      JOIN public.messages m ON m.id=mt.message_id AND m.received_at=mt.received_at
     WHERE mt.imap_uid IS NULL
     ORDER BY mt.tag_id,mt.received_at,mt.message_id
     LIMIT p_limit FOR UPDATE OF mt SKIP LOCKED
  LOOP
    v_candidate_ok := v_row.legacy_uid IS NOT NULL AND v_row.legacy_uid > 0
      AND NOT EXISTS (SELECT 1 FROM public.imap_membership_uid_ledger
                       WHERE tag_id=v_row.tag_id AND imap_uid=v_row.legacy_uid);
    IF v_candidate_ok THEN
      v_uid := v_row.legacy_uid;
      PERFORM 1 FROM public.tags WHERE id=v_row.tag_id FOR UPDATE;
      UPDATE public.tags SET imap_uid_next=GREATEST(imap_uid_next,v_uid+1)
       WHERE id=v_row.tag_id;
    ELSE
      v_uid := public.imap_membership_uid_allocate(v_row.tag_id);
      v_repaired := v_repaired+1;
      INSERT INTO public.imap_membership_uid_backfill(tag_id,repaired,uid_validity_bumped)
      VALUES(v_row.tag_id,1,true)
      ON CONFLICT(tag_id) DO UPDATE SET repaired=public.imap_membership_uid_backfill.repaired+1,
        uid_validity_bumped=true,updated_at=now();
      UPDATE public.tags SET imap_uid_validity=GREATEST(imap_uid_validity+1,
        extract(epoch from clock_timestamp())::bigint),updated_at=now()
       WHERE id=v_row.tag_id
         AND NOT EXISTS (SELECT 1 FROM public.imap_membership_uid_backfill b
                          WHERE b.tag_id=v_row.tag_id AND b.repaired>1);
    END IF;
    EXECUTE format('UPDATE %s SET imap_uid=$1 WHERE ctid=$2',v_row.tableoid::regclass)
      USING v_uid,v_row.ctid;
    INSERT INTO public.imap_membership_uid_ledger
      (tag_id,imap_uid,message_id,received_at,active)
    VALUES(v_row.tag_id,v_uid,v_row.message_id,v_row.received_at,true);
    INSERT INTO public.imap_membership_uid_backfill(tag_id,processed)
    VALUES(v_row.tag_id,1)
    ON CONFLICT(tag_id) DO UPDATE SET processed=public.imap_membership_uid_backfill.processed+1,
      updated_at=now();
    v_processed := v_processed+1;
  END LOOP;

  IF v_processed=0 THEN
    UPDATE public.imap_membership_uid_backfill b SET completed_at=COALESCE(completed_at,now()),updated_at=now()
     WHERE NOT EXISTS (SELECT 1 FROM public.message_tags mt WHERE mt.tag_id=b.tag_id AND mt.imap_uid IS NULL);
  END IF;
  RETURN jsonb_build_object('processed',v_processed,'repaired',v_repaired,
    'remaining',(SELECT count(*) FROM public.message_tags WHERE imap_uid IS NULL));
END;
$$;

SELECT public.apply_worker_ownership('imap_membership_uid_backfill_batch(integer)'::regprocedure);
