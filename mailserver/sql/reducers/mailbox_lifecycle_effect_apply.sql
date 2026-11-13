-- Apply database-local mailbox lifecycle effects; external effects are completed by the Go worker.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_effect_apply(p_worker_id text,p_effect_id bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_e mailbox_lifecycle_effects%ROWTYPE; v_o mailbox_lifecycle_operations%ROWTYPE; v_user_id bigint;
BEGIN
  SELECT * INTO v_e FROM mailbox_lifecycle_effects WHERE id=p_effect_id FOR UPDATE;
  IF NOT FOUND OR v_e.state<>'claimed' OR v_e.claimed_by<>p_worker_id OR v_e.lease_until<=statement_timestamp() THEN
    RAISE EXCEPTION 'mailbox lifecycle effect lease lost' USING ERRCODE='55000';
  END IF;
  SELECT * INTO STRICT v_o FROM mailbox_lifecycle_operations WHERE operation_id=v_e.operation_id;
  SELECT COALESCE(
    (SELECT h.from_user_id FROM mailbox_binding_history h WHERE h.operation_id=v_e.operation_id),
    (SELECT m.user_id FROM mailboxes m WHERE m.id=v_e.mailbox_id)
  ) INTO v_user_id;
  IF v_e.effect_kind='revoke_sessions' THEN
    IF v_user_id IS NOT NULL THEN
      PERFORM revoke_user_sessions(v_user_id,'all','mailbox_lifecycle.'||v_o.action,v_o.actor_user_id,NULL,NULL);
    END IF;
  ELSIF v_e.effect_kind='revoke_delegates' THEN
    DELETE FROM mailbox_delegates WHERE mailbox_id=v_e.mailbox_id;
  ELSIF v_e.effect_kind='notify_clients' THEN
    PERFORM app_notify('mailbox_lifecycle',jsonb_build_object('mailbox_id',v_e.mailbox_id,
      'operation_id',v_e.operation_id,'action',v_o.action)::text);
  ELSE
    RAISE EXCEPTION 'mailbox lifecycle effect requires external executor' USING ERRCODE='55000';
  END IF;
  UPDATE mailbox_lifecycle_effects SET state='completed',completed_at=statement_timestamp(),
    lease_until=NULL,claimed_by=NULL,last_error=NULL WHERE id=v_e.id;
END $$;

ALTER FUNCTION mailbox_lifecycle_effect_apply(text,bigint) OWNER TO setjoin_worker;
