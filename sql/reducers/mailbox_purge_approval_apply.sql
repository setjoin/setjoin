-- Mailbox Lifecycle & Retention authority: mailbox_purge_approval_apply.

CREATE OR REPLACE FUNCTION mailbox_purge_approval_apply(p_request_id bigint,p_actor bigint,p_decision text,p_comment text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_status text; v_p mailbox_purge_requests%ROWTYPE;
BEGIN
  SELECT p.* INTO v_p FROM mailbox_purge_requests p JOIN approval_requests a ON a.id=p.approval_request_id
   WHERE a.id=p_request_id AND a.consumer_type='mailbox.purge' FOR UPDATE OF p;
  IF NOT FOUND THEN RAISE EXCEPTION 'purge approval not found' USING ERRCODE='BZ310'; END IF;
  v_status:=approval_decide(p_request_id,p_actor,p_decision,p_comment);
  UPDATE mailbox_purge_requests SET state=CASE WHEN v_status='approved' THEN 'approved' ELSE 'cancelled' END,
    approved_by=CASE WHEN v_status='approved' THEN p_actor ELSE NULL END,
    approved_at=CASE WHEN v_status='approved' THEN statement_timestamp() ELSE NULL END WHERE id=v_p.id RETURNING * INTO v_p;
  RETURN jsonb_build_object('purgeRequestId',v_p.id,'state',v_p.state);
END $$;

ALTER FUNCTION mailbox_purge_approval_apply(bigint,bigint,text,text) OWNER TO setjoin_worker;
