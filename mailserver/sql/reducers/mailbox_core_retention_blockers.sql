-- Mailbox Lifecycle & Retention authority: mailbox_core_retention_blockers.

CREATE OR REPLACE FUNCTION mailbox_core_retention_blockers(p_mailbox_id bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v jsonb:='[]'::jsonb; v_count bigint; v_until timestamptz;
BEGIN
  SELECT count(*) FILTER(WHERE litigation_hold),max(hold_since)
    INTO v_count,v_until FROM mailboxes WHERE id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object(
    'kind','legal_hold','count',v_count,'until',NULL)); END IF;

  SELECT count(*),max(mrt.expires_at) INTO v_count,v_until
    FROM message_retention_tags mrt JOIN messages m
      ON m.id=mrt.message_id AND m.received_at=mrt.received_at
   WHERE m.mailbox_id=p_mailbox_id
     AND (mrt.expires_at IS NULL OR mrt.expires_at>statement_timestamp());
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object(
    'kind','message_retention','count',v_count,'until',v_until)); END IF;

  SELECT count(*) INTO v_count FROM distribution_groups WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','distribution_group_authority','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM dlp_violations WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','dlp_evidence','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM journal_queue WHERE journal_mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','journal_queue','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM journaling_policies WHERE journal_mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','journaling_policy','count',v_count)); END IF;

  SELECT count(*) INTO v_count FROM mail_recovery_incident_accounts WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','mail_recovery_incident','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_recovery_upload_sessions WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','mail_recovery_upload','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_recovery_quarantine_artifacts WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','mail_recovery_quarantine','count',v_count)); END IF;
  SELECT count(*) INTO v_count FROM mail_recovery_ledger WHERE mailbox_id=p_mailbox_id;
  IF v_count>0 THEN v:=v||jsonb_build_array(jsonb_build_object('kind','mail_recovery_ledger','count',v_count)); END IF;
  RETURN v;
END $$;

ALTER FUNCTION mailbox_core_retention_blockers(bigint) OWNER TO setjoin_worker;
