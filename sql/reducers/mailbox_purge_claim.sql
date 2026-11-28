-- Claim one independently approved, eligible purge for bounded worker execution.

CREATE OR REPLACE FUNCTION mailbox_purge_claim(p_worker_id text,p_lease_seconds integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_p mailbox_purge_requests%ROWTYPE; v_blockers jsonb;
BEGIN
  IF NULLIF(trim(p_worker_id),'') IS NULL OR p_lease_seconds NOT BETWEEN 10 AND 600 THEN
    RAISE EXCEPTION 'invalid mailbox purge claim' USING ERRCODE='22023';
  END IF;
  SELECT * INTO v_p FROM mailbox_purge_requests
   WHERE eligible_at<=statement_timestamp() AND attempts<20 AND (
     state='approved' OR (state IN ('claimed','failed') AND lease_until<=statement_timestamp()))
   ORDER BY eligible_at,id FOR UPDATE SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN NULL; END IF;
  v_blockers:=mailbox_purge_blockers(v_p.mailbox_id);
  IF jsonb_array_length(v_blockers)>0 THEN
    UPDATE mailbox_purge_requests SET state='blocked',claimed_by=NULL,lease_until=NULL,
      blocker_snapshot=v_blockers,attempts=attempts+1 WHERE id=v_p.id;
    RETURN jsonb_build_object('purgeRequestId',v_p.id,'mailboxId',v_p.mailbox_id::text,
      'blocked',true,'blockers',v_blockers);
  END IF;
  UPDATE mailbox_purge_requests SET state='claimed',claimed_by=p_worker_id,
    lease_until=statement_timestamp()+make_interval(secs=>p_lease_seconds),attempts=attempts+1,
    blocker_snapshot='[]'::jsonb WHERE id=v_p.id RETURNING * INTO v_p;
  RETURN jsonb_build_object('purgeRequestId',v_p.id,'mailboxId',v_p.mailbox_id::text,
    'actorUserId',v_p.requested_by::text,'operationId',v_p.execute_operation_id::text,
    'requestDigest',encode(digest('mailbox-purge-execute:'||v_p.id::text,'sha256'),'hex'),
    'attempt',v_p.attempts,'blocked',false);
END $$;

ALTER FUNCTION mailbox_purge_claim(text,integer) OWNER TO setjoin_worker;
