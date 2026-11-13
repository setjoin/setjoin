-- Competitive Productivity retention-domain contribution. Mailbox purge fails
-- closed while collaboration authority or delivery receipts still exist.

CREATE OR REPLACE FUNCTION mail_work_retention_blockers(p_mailbox_id bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_result jsonb:='[]'::jsonb; v_count bigint;
BEGIN
  SELECT count(*) INTO v_count FROM mail_thread_work WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v_result:=v_result||jsonb_build_array(jsonb_build_object('kind','thread_work','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_thread_comments WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v_result:=v_result||jsonb_build_array(jsonb_build_object('kind','private_comments','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_thread_work_events WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v_result:=v_result||jsonb_build_array(jsonb_build_object('kind','work_events','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_draft_collaboration WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v_result:=v_result||jsonb_build_array(jsonb_build_object('kind','collaborative_drafts','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_work_outbox o
    JOIN mail_thread_work_events e ON e.id=o.event_id WHERE e.mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v_result:=v_result||jsonb_build_array(jsonb_build_object('kind','work_delivery_receipts','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_work_action_links WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v_result:=v_result||jsonb_build_array(jsonb_build_object('kind','internal_action_links','count',v_count)); END IF;
  RETURN v_result;
END $$;

ALTER FUNCTION mail_work_retention_blockers(bigint) OWNER TO setjoin_worker;
