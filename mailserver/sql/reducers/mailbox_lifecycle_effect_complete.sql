-- Complete an externally executed lifecycle effect under its active lease.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_effect_complete(p_worker_id text,p_effect_id bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_e mailbox_lifecycle_effects%ROWTYPE;
BEGIN
  SELECT * INTO v_e FROM mailbox_lifecycle_effects WHERE id=p_effect_id FOR UPDATE;
  IF NOT FOUND OR v_e.state<>'claimed' OR v_e.claimed_by<>p_worker_id OR v_e.lease_until<=statement_timestamp() THEN
    RAISE EXCEPTION 'mailbox lifecycle effect lease lost' USING ERRCODE='55000';
  END IF;
  IF v_e.effect_kind='evict_media' AND EXISTS(
    SELECT 1 FROM mailbox_lifecycle_effect_targets WHERE operation_id=v_e.operation_id
      AND effect_kind='evict_media' AND completed_at IS NULL) THEN
    RAISE EXCEPTION 'mailbox lifecycle media targets remain' USING ERRCODE='55000';
  END IF;
  UPDATE mailbox_lifecycle_effects SET state='completed',completed_at=statement_timestamp(),
    lease_until=NULL,claimed_by=NULL,last_error=NULL WHERE id=v_e.id;
  IF v_e.effect_kind='lifecycle_webhook' THEN
    UPDATE mailbox_lifecycle_outbox SET state='completed',completed_at=statement_timestamp(),
      lease_until=NULL,claimed_by=NULL,last_error=NULL WHERE operation_id=v_e.operation_id;
  END IF;
END $$;

ALTER FUNCTION mailbox_lifecycle_effect_complete(text,bigint) OWNER TO setjoin_worker;
