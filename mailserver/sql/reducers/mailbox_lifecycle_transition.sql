-- Mailbox Lifecycle & Retention authority: mailbox_lifecycle_transition.

CREATE OR REPLACE FUNCTION mailbox_lifecycle_transition(
  p_actor bigint,p_mailbox_id bigint,p_operation_id uuid,p_action text,
  p_expected_generation bigint,p_request_digest text,p_reason text,
  p_target_user_id bigint DEFAULT NULL,p_evidence_kind text DEFAULT NULL,
  p_identity_link_id bigint DEFAULT NULL,p_link_generation bigint DEFAULT NULL,
  p_source_key_digest text DEFAULT NULL,p_actor_auth_time timestamptz DEFAULT NULL,
  p_delivery_state text DEFAULT NULL,p_redirect_address text DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_l mailbox_lifecycle%ROWTYPE; v_m mailboxes%ROWTYPE; v_existing mailbox_lifecycle_operations%ROWTYPE;
  v_before jsonb; v_after jsonb; v_before_digest text; v_after_digest text; v_result jsonb;
  v_policy mailbox_lifecycle_policies%ROWTYPE; v_old_user bigint; v_event text;
BEGIN
  IF NOT mailbox_lifecycle_enabled() THEN RAISE EXCEPTION 'mailbox lifecycle is disabled' USING ERRCODE='BZ300'; END IF;
  IF p_operation_id IS NULL OR p_expected_generation<1 OR p_request_digest !~ '^[0-9a-f]{64}$'
     OR p_action NOT IN ('suspend','resume','detach_retain','reconnect')
     OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024 OR p_reason~'[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid mailbox lifecycle command' USING ERRCODE='BZ301';
  END IF;
  SELECT * INTO v_existing FROM mailbox_lifecycle_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.mailbox_id=p_mailbox_id AND v_existing.action=p_action
       AND v_existing.expected_generation=p_expected_generation AND v_existing.request_digest=p_request_digest THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'mailbox lifecycle idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  SELECT * INTO v_l FROM mailbox_lifecycle WHERE mailbox_id=p_mailbox_id FOR UPDATE;
  SELECT * INTO v_m FROM mailboxes WHERE id=p_mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_l.mailbox_id IS NULL OR v_m.type<>'personal' OR v_l.binding_state='shared' THEN
    RAISE EXCEPTION 'personal mailbox not found' USING ERRCODE='BZ302';
  END IF;
  IF v_l.generation<>p_expected_generation THEN RAISE EXCEPTION 'mailbox lifecycle generation is stale' USING ERRCODE='BZ304'; END IF;
  IF v_m.user_id IS NOT NULL
     AND NOT admin_can_manage_with_permission(p_actor,v_m.user_id,'users.delete') THEN
    RAISE EXCEPTION 'personal mailbox not found' USING ERRCODE='BZ302';
  END IF;
  v_before:=to_jsonb(v_l); v_before_digest:=encode(digest(v_before::text,'sha256'),'hex'); v_old_user:=v_m.user_id;

  IF p_action='suspend' THEN
    IF v_l.binding_state<>'bound' THEN RAISE EXCEPTION 'only bound mailboxes can be suspended' USING ERRCODE='BZ305'; END IF;
    UPDATE mailbox_lifecycle SET access_state='suspended',generation=generation+1,reason=p_reason,
      updated_by=p_actor,updated_at=statement_timestamp(),last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailboxes SET enabled=false,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    v_event:='mailbox.suspended';
  ELSIF p_action='resume' THEN
    IF v_l.binding_state<>'bound' THEN RAISE EXCEPTION 'retained mailbox must be reconnected, not resumed' USING ERRCODE='BZ305'; END IF;
    UPDATE mailbox_lifecycle SET access_state='active',generation=generation+1,reason=p_reason,
      updated_by=p_actor,updated_at=statement_timestamp(),last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailboxes SET enabled=true,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    v_event:='mailbox.resumed';
  ELSIF p_action='detach_retain' THEN
    IF v_l.binding_state<>'bound' OR v_m.user_id IS NULL THEN RAISE EXCEPTION 'mailbox is not actively bound' USING ERRCODE='BZ305'; END IF;
    SELECT p.* INTO v_policy FROM mailbox_lifecycle_policies p
      WHERE (p.domain_id=v_m.domain_id OR p.domain_id IS NULL) AND p.effective_at<=statement_timestamp()
      ORDER BY (p.domain_id IS NOT NULL) DESC,p.effective_at DESC LIMIT 1;
    UPDATE mailbox_lifecycle SET was_primary=v_m.is_primary WHERE mailbox_id=p_mailbox_id;
    UPDATE mailboxes SET user_id=NULL,is_primary=false,enabled=false,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    UPDATE mailbox_lifecycle SET access_state='detached',binding_state='retained',bound_user_id=NULL,
      delivery_state=COALESCE(p_delivery_state,'accepting'),redirect_address=p_redirect_address,
      retained_at=statement_timestamp(),retention_until=statement_timestamp()+make_interval(days=>v_policy.retention_days),
      policy_generation=v_policy.generation,generation=generation+1,reason=p_reason,updated_by=p_actor,
      updated_at=statement_timestamp(),last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailbox_address_claims SET claim_state='retained',generation=generation+1,released_at=NULL WHERE mailbox_id=p_mailbox_id;
    INSERT INTO mailbox_binding_history(mailbox_id,from_user_id,to_user_id,operation_id,evidence_kind,actor_user_id,actor_auth_time,reason)
      VALUES(p_mailbox_id,v_old_user,NULL,p_operation_id,'initial',p_actor,COALESCE(p_actor_auth_time,statement_timestamp()),p_reason);
    v_event:='mailbox.detached';
  ELSE
    IF v_l.binding_state<>'retained' OR v_m.user_id IS NOT NULL OR p_target_user_id IS NULL THEN
      RAISE EXCEPTION 'mailbox is not retained or target is missing' USING ERRCODE='BZ305';
    END IF;
    IF EXISTS(SELECT 1 FROM mailboxes WHERE user_id=p_target_user_id AND is_primary AND id<>p_mailbox_id) THEN
      RAISE EXCEPTION 'target already has a primary mailbox' USING ERRCODE='BZ306';
    END IF;
    IF p_evidence_kind='identity_link' THEN
      IF NOT EXISTS(SELECT 1 FROM user_identity_links WHERE id=p_identity_link_id AND user_id=p_target_user_id
                    AND state='active' AND generation=p_link_generation) THEN
        RAISE EXCEPTION 'reconnect identity evidence is stale' USING ERRCODE='BZ307'; END IF;
    ELSIF p_evidence_kind='local_user' THEN
      IF NOT EXISTS(SELECT 1 FROM user_lifecycle_authorities WHERE user_id=p_target_user_id AND authority_kind='local') THEN
        RAISE EXCEPTION 'target is not a stable local identity' USING ERRCODE='BZ307'; END IF;
    ELSE RAISE EXCEPTION 'verified reconnect evidence is required' USING ERRCODE='BZ307'; END IF;
    IF NOT admin_can_manage_with_permission(p_actor,p_target_user_id,'users.delete') THEN
      RAISE EXCEPTION 'target user not found' USING ERRCODE='BZ302';
    END IF;
    UPDATE mailboxes SET user_id=p_target_user_id,is_primary=v_l.was_primary,enabled=true,updated_at=statement_timestamp() WHERE id=p_mailbox_id;
    UPDATE mailbox_lifecycle SET access_state='active',binding_state='bound',bound_user_id=p_target_user_id,
      retained_at=NULL,retention_until=NULL,delivery_state='accepting',redirect_address=NULL,
      generation=generation+1,reason=p_reason,updated_by=p_actor,updated_at=statement_timestamp(),
      last_operation_id=p_operation_id WHERE mailbox_id=p_mailbox_id RETURNING * INTO v_l;
    UPDATE mailbox_address_claims SET claim_state='active',generation=generation+1,released_at=NULL WHERE mailbox_id=p_mailbox_id;
    INSERT INTO mailbox_binding_history(mailbox_id,from_user_id,to_user_id,operation_id,evidence_kind,identity_link_id,
      link_generation,source_key_digest,actor_user_id,actor_auth_time,reason)
      VALUES(p_mailbox_id,NULL,p_target_user_id,p_operation_id,p_evidence_kind,p_identity_link_id,p_link_generation,
        p_source_key_digest,p_actor,COALESCE(p_actor_auth_time,statement_timestamp()),p_reason);
    v_event:='mailbox.reconnected';
  END IF;
  v_after:=to_jsonb(v_l); v_after_digest:=encode(digest(v_after::text,'sha256'),'hex');
  v_result:=mailbox_lifecycle_read(p_mailbox_id)||jsonb_build_object('operationId',p_operation_id,'replayed',false);
  INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,
    request_digest,before_digest,after_digest,result) VALUES(p_operation_id,p_mailbox_id,p_action,p_actor,
    p_expected_generation,p_request_digest,v_before_digest,v_after_digest,v_result);
  INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind)
    SELECT p_operation_id,p_mailbox_id,x
      FROM unnest(CASE
        WHEN p_action='detach_retain' THEN ARRAY['revoke_sessions','evict_media','revoke_delegates','notify_clients','lifecycle_webhook']
        WHEN p_action='suspend' THEN ARRAY['revoke_sessions','evict_media','notify_clients','lifecycle_webhook']
        ELSE ARRAY['notify_clients','lifecycle_webhook']
      END) x;
  IF p_action IN ('suspend','detach_retain') AND v_old_user IS NOT NULL THEN
    INSERT INTO mailbox_lifecycle_effect_targets(operation_id,room_name,identity)
    SELECT p_operation_id,t.room_name,t.identity
      FROM (
        SELECT m.room_name,p.identity
          FROM meeting_participants p JOIN meetings m ON m.id=p.meeting_id
         WHERE p.user_id=v_old_user AND m.state<>'ended'
        UNION
        SELECT b.room_name,p.identity
          FROM meeting_participants p
          JOIN meetings m ON m.id=p.meeting_id
          JOIN meeting_breakouts b ON b.meeting_id=m.id
         WHERE p.user_id=v_old_user AND m.state<>'ended'
      ) t
    ON CONFLICT DO NOTHING;
    INSERT INTO mailbox_lifecycle_effect_targets(operation_id,room_name,identity,evict_until)
    SELECT p_operation_id,a.room_name,a.identity,a.expires_at
      FROM identity_media_admissions a
     WHERE a.user_id=v_old_user AND a.expires_at>statement_timestamp()
    ON CONFLICT(operation_id,effect_kind,room_name,identity) DO UPDATE
      SET evict_until=GREATEST(mailbox_lifecycle_effect_targets.evict_until,EXCLUDED.evict_until);
  END IF;
  INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload)
    VALUES(p_operation_id,v_event,'mailbox-lifecycle:'||p_operation_id::text,
      jsonb_build_object('mailboxId',p_mailbox_id::text,'generation',v_l.generation::text,'event',v_event));
  PERFORM audit_write(p_actor,replace(v_event,'.','_'),'mailbox',p_mailbox_id,v_before,v_after,NULL,p_reason,'core');
  PERFORM app_notify('mailbox_lifecycle',json_build_object('mailbox_id',p_mailbox_id,'generation',v_l.generation)::text);
  RETURN v_result;
END $$;

ALTER FUNCTION mailbox_lifecycle_transition(bigint,bigint,uuid,text,bigint,text,text,bigint,text,bigint,bigint,text,timestamptz,text,text) OWNER TO setjoin_worker;
