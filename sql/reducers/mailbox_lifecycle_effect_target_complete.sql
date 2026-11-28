-- Record one successfully evicted media target under the owning effect lease.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_effect_target_complete(
  p_worker_id text,p_effect_id bigint,p_room_name text,p_identity text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_e mailbox_lifecycle_effects%ROWTYPE;
BEGIN
  SELECT * INTO v_e FROM mailbox_lifecycle_effects WHERE id=p_effect_id FOR UPDATE;
  IF NOT FOUND OR v_e.effect_kind<>'evict_media' OR v_e.state<>'claimed'
     OR v_e.claimed_by<>p_worker_id OR v_e.lease_until<=statement_timestamp() THEN
    RAISE EXCEPTION 'mailbox lifecycle effect lease lost' USING ERRCODE='55000';
  END IF;
  UPDATE mailbox_lifecycle_effect_targets SET completed_at=statement_timestamp(),last_error=NULL
   WHERE operation_id=v_e.operation_id AND effect_kind='evict_media'
     AND room_name=p_room_name AND identity=p_identity;
  IF NOT FOUND THEN RAISE EXCEPTION 'mailbox lifecycle media target not found' USING ERRCODE='55000'; END IF;
END $$;

ALTER FUNCTION mailbox_lifecycle_effect_target_complete(text,bigint,text,text) OWNER TO setjoin_worker;
