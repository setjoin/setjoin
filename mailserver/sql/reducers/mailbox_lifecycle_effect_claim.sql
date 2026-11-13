-- Claim one committed mailbox-lifecycle effect with crash-recoverable leasing.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_effect_claim(p_worker_id text,p_lease_seconds integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_e mailbox_lifecycle_effects%ROWTYPE; v_o mailbox_lifecycle_operations%ROWTYPE;
  v_user_id bigint; v_targets jsonb; v_outbox jsonb;
BEGIN
  IF NULLIF(trim(p_worker_id),'') IS NULL OR p_lease_seconds NOT BETWEEN 10 AND 600 THEN
    RAISE EXCEPTION 'invalid lifecycle effect claim' USING ERRCODE='22023';
  END IF;
  SELECT * INTO v_e FROM mailbox_lifecycle_effects
   WHERE attempts<20 AND (
     state='pending' OR (state IN ('claimed','failed') AND lease_until<=statement_timestamp()))
   ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN NULL; END IF;
  UPDATE mailbox_lifecycle_effects SET state='claimed',claimed_by=p_worker_id,
    attempts=attempts+1,lease_until=statement_timestamp()+make_interval(secs=>p_lease_seconds),last_error=NULL
   WHERE id=v_e.id RETURNING * INTO v_e;
  SELECT * INTO STRICT v_o FROM mailbox_lifecycle_operations WHERE operation_id=v_e.operation_id;
  SELECT COALESCE(
    (SELECT h.from_user_id FROM mailbox_binding_history h WHERE h.operation_id=v_e.operation_id),
    (SELECT m.user_id FROM mailboxes m WHERE m.id=v_e.mailbox_id)
  ) INTO v_user_id;
  SELECT COALESCE(jsonb_agg(jsonb_build_object('room',t.room_name,'identity',t.identity,
      'evictUntil',t.evict_until) ORDER BY t.room_name,t.identity),'[]'::jsonb)
    INTO v_targets FROM mailbox_lifecycle_effect_targets t
   WHERE t.operation_id=v_e.operation_id AND t.effect_kind=v_e.effect_kind AND t.completed_at IS NULL;
  SELECT CASE WHEN o.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',o.operation_id::text,'type',o.event_kind,'time',o.created_at,'data',o.payload) END
    INTO v_outbox FROM mailbox_lifecycle_outbox o WHERE o.operation_id=v_e.operation_id;
  IF v_e.effect_kind='lifecycle_webhook' THEN
    UPDATE mailbox_lifecycle_outbox SET state='claimed',claimed_by=p_worker_id,
      attempts=attempts+1,lease_until=v_e.lease_until,last_error=NULL
     WHERE operation_id=v_e.operation_id AND state<>'completed';
  END IF;
  RETURN jsonb_build_object('effectId',v_e.id::text,'operationId',v_e.operation_id::text,
    'mailboxId',v_e.mailbox_id::text,'kind',v_e.effect_kind,'action',v_o.action,
    'actorUserId',v_o.actor_user_id::text,'targetUserId',CASE WHEN v_user_id IS NULL THEN NULL ELSE v_user_id::text END,
    'attempt',v_e.attempts,'targets',v_targets,'event',v_outbox);
END $$;

ALTER FUNCTION mailbox_lifecycle_effect_claim(text,integer) OWNER TO setjoin_worker;
