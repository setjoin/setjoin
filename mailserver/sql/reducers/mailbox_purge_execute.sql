-- Mailbox Lifecycle & Retention authority: mailbox_purge_execute.

CREATE OR REPLACE FUNCTION mailbox_purge_execute(p_actor bigint,p_purge_request_id uuid,p_operation_id uuid,p_request_digest text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_p mailbox_purge_requests%ROWTYPE; v_l mailbox_lifecycle%ROWTYPE; v_blockers jsonb;
  v_addresses jsonb; v_messages bigint; v_blobs bigint; v_result jsonb; v_before text; v_tomb_digest text;
  v_existing mailbox_lifecycle_operations%ROWTYPE; v_found boolean;
BEGIN
  SELECT * INTO v_p FROM mailbox_purge_requests WHERE id=p_purge_request_id FOR UPDATE;
  v_found:=FOUND;
  -- #424 (owner-approved security fix 2026-11-05): execution needs the same reach as cancel -- the
  -- requester, an admin holding users.delete over the requester, or the superadmin role -- so a
  -- users.delete admin scoped to another domain cannot execute (or replay) a foreign purge; a foreign
  -- request answers exactly like a missing one (BZ311).
  IF v_found AND NOT (p_actor=v_p.requested_by
     OR admin_can_manage_with_permission(p_actor,v_p.requested_by,'users.delete')
     OR EXISTS(SELECT 1 FROM admin_role_assignments
                WHERE user_id=p_actor AND role_group_id=1
                  AND (expires_at IS NULL OR expires_at>statement_timestamp())
                  AND admin_assignment_active(eligible,activated_until))) THEN
    RAISE EXCEPTION 'purge is not independently approved and eligible' USING ERRCODE='BZ311';
  END IF;
  SELECT * INTO v_existing FROM mailbox_lifecycle_operations WHERE operation_id=p_operation_id;
  IF FOUND THEN
    IF v_existing.action='purge_execute' AND v_existing.request_digest=p_request_digest
       AND v_existing.result->>'purgeRequestId'=p_purge_request_id::text THEN
      RETURN v_existing.result||'{"replayed":true}'::jsonb;
    END IF;
    RAISE EXCEPTION 'mailbox lifecycle idempotency conflict' USING ERRCODE='BZ303';
  END IF;
  IF NOT v_found OR v_p.state NOT IN ('approved','claimed') OR v_p.approved_by=p_actor OR v_p.eligible_at>statement_timestamp() THEN
    RAISE EXCEPTION 'purge is not independently approved and eligible' USING ERRCODE='BZ311'; END IF;
  SELECT * INTO v_l FROM mailbox_lifecycle WHERE mailbox_id=v_p.mailbox_id FOR UPDATE;
  IF NOT FOUND OR v_l.binding_state<>'retained' OR v_l.generation<>v_p.lifecycle_generation+1 THEN
    RAISE EXCEPTION 'purge lifecycle generation is stale' USING ERRCODE='BZ304'; END IF;
  v_blockers:=mailbox_purge_blockers(v_p.mailbox_id);
  IF jsonb_array_length(v_blockers)>0 THEN
    UPDATE mailbox_purge_requests SET state='blocked',blocker_snapshot=v_blockers,attempts=attempts+1 WHERE id=v_p.id;
    RAISE EXCEPTION 'purge is blocked by retention authority' USING ERRCODE='BZ312',HINT=v_blockers::text;
  END IF;
  SELECT COALESCE(jsonb_agg(encode(digest(normalized_address,'sha256'),'hex') ORDER BY normalized_address),'[]'::jsonb)
    INTO v_addresses FROM mailbox_address_claims WHERE mailbox_id=v_p.mailbox_id AND claim_state<>'released';
  SELECT count(*) INTO v_messages FROM messages WHERE mailbox_id=v_p.mailbox_id;
  SELECT count(DISTINCT ma.blob_sha256) INTO v_blobs FROM message_attachments ma JOIN messages m
    ON m.id=ma.message_id AND m.received_at=ma.received_at WHERE m.mailbox_id=v_p.mailbox_id;
  v_tomb_digest:=encode(digest(jsonb_build_object('mailboxId',v_p.mailbox_id::text,'addresses',v_addresses,
    'messageCount',v_messages,'blobCount',v_blobs,'requestId',v_p.id)::text,'sha256'),'hex');
  v_before:=encode(digest(to_jsonb(v_l)::text,'sha256'),'hex');
  INSERT INTO mailbox_tombstones(mailbox_id,purge_request_id,address_digests,message_count,blob_count,evidence_digest,reason,purged_by)
    VALUES(v_p.mailbox_id,v_p.id,v_addresses,v_messages,v_blobs,v_tomb_digest,v_p.reason,p_actor);
  DELETE FROM mailbox_address_claims WHERE mailbox_id=v_p.mailbox_id;
  DELETE FROM mailbox_lifecycle WHERE mailbox_id=v_p.mailbox_id;
  DELETE FROM message_attachments WHERE (message_id,received_at) IN
    (SELECT id,received_at FROM messages WHERE mailbox_id=v_p.mailbox_id);
  DELETE FROM messages WHERE mailbox_id=v_p.mailbox_id;
  DELETE FROM mailboxes WHERE id=v_p.mailbox_id;
  UPDATE mailbox_purge_requests SET state='completed',attempts=attempts+1,claimed_by=NULL,lease_until=NULL WHERE id=v_p.id;
  v_result:=jsonb_build_object('purgeRequestId',v_p.id,'mailboxId',v_p.mailbox_id::text,
    'state','completed','messageCount',v_messages,'blobCount',v_blobs,'evidenceDigest',v_tomb_digest,'replayed',false);
  INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,
    request_digest,before_digest,after_digest,result) VALUES(p_operation_id,v_p.mailbox_id,'purge_execute',p_actor,
    v_l.generation,p_request_digest,v_before,v_tomb_digest,v_result);
  INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload) VALUES(
    p_operation_id,'mailbox.purged','mailbox-lifecycle:'||p_operation_id::text,v_result-'replayed');
  INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind)
    VALUES(p_operation_id,v_p.mailbox_id,'lifecycle_webhook');
  PERFORM audit_write(p_actor,'mailbox_purged','mailbox',v_p.mailbox_id,NULL,v_result,NULL,v_p.reason,'core');
  RETURN v_result;
END $$;

ALTER FUNCTION mailbox_purge_execute(bigint,uuid,uuid,text) OWNER TO setjoin_worker;
