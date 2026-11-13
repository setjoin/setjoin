CREATE OR REPLACE FUNCTION mail_recovery_artifact_ingest(
    p_actor_user_id bigint,
    p_quarantine_id uuid,
    p_resolution text,
    p_reason text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_artifact mail_recovery_quarantine_artifacts%ROWTYPE;
    v_incident mail_recovery_incidents%ROWTYPE;
    v_existing mail_recovery_ledger%ROWTYPE;
    v_inbox_id bigint;
    v_recovered_tag_id bigint;
    v_message_id bigint;
    v_received_at timestamptz;
    v_message_header text;
    v_from_addr text;
    v_thread_id text;
    v_blob jsonb;
    v_blob_count integer:=0;
    v_total_size bigint;
BEGIN
    IF NOT mail_recovery_feature_enabled() OR NOT mail_recovery_has_global_permission(p_actor_user_id) THEN
        RAISE EXCEPTION 'global system.recovery permission and enabled intake are required'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_quarantine_id IS NULL OR p_resolution NOT IN ('accept','accept_fork') OR
       length(btrim(COALESCE(p_reason,''))) NOT BETWEEN 8 AND 1024 OR p_reason~'[\r\n]' THEN
        RAISE EXCEPTION 'invalid recovery ingestion request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_artifact FROM mail_recovery_quarantine_artifacts
     WHERE id=p_quarantine_id FOR UPDATE;
    SELECT * INTO STRICT v_incident FROM mail_recovery_incidents
     WHERE id=v_artifact.incident_id FOR SHARE;
    SELECT * INTO v_existing FROM mail_recovery_ledger
     WHERE artifact_identity=v_artifact.artifact_identity;
    IF FOUND THEN
        RETURN jsonb_build_object('id',p_quarantine_id,'status',v_existing.outcome,
                                  'messageId',CASE WHEN v_existing.recovered_message_id IS NULL THEN NULL
                                                   ELSE v_existing.recovered_message_id::text END,'replayed',true);
    END IF;
    IF v_incident.status<>'open' OR v_incident.expires_at<=statement_timestamp() OR
       (v_incident.approval_required AND v_incident.approved_by IS NULL) OR
       v_artifact.malware_status<>'clean' OR
       v_artifact.status NOT IN ('quarantined','fork_conflict') OR
       NOT EXISTS(SELECT 1 FROM mail_recovery_incident_accounts account
                   WHERE account.incident_id=v_incident.id AND account.mailbox_id=v_artifact.mailbox_id) OR
       NOT EXISTS(SELECT 1 FROM mailboxes mailbox JOIN users affected ON affected.id=mailbox.user_id
                   WHERE mailbox.id=v_artifact.mailbox_id AND mailbox.enabled AND affected.enabled) THEN
        RAISE EXCEPTION 'recovery artifact is not eligible for ingestion'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    IF v_artifact.status='fork_conflict' AND
       (p_resolution<>'accept_fork' OR v_artifact.fork_consented_by IS NULL OR v_artifact.fork_consented_at IS NULL) THEN
        RAISE EXCEPTION 'fork recovery requires explicit affected-user consent and admin resolution'
            USING ERRCODE='BZ003',HINT='{"type":"fork_consent_required"}';
    END IF;

    v_message_header:=COALESCE(NULLIF(v_artifact.parsed_headers->>'messageId',''),
                               '<recovered-'||encode(v_artifact.artifact_identity,'hex')||'@setjoin.invalid>');
    v_from_addr:=NULLIF(v_artifact.parsed_headers->>'fromAddr','');
    IF v_from_addr IS NULL OR octet_length(v_from_addr)>320 OR
       octet_length(v_message_header)>998 OR
       jsonb_typeof(COALESCE(v_artifact.parsed_headers->'toAddrs','[]'::jsonb))<>'array' OR
       jsonb_typeof(COALESCE(v_artifact.parsed_headers->'ccAddrs','[]'::jsonb))<>'array' OR
       jsonb_typeof(COALESCE(v_artifact.parsed_headers->'bccAddrs','[]'::jsonb))<>'array' THEN
        RAISE EXCEPTION 'recovery MIME metadata is invalid'
            USING ERRCODE='BZ251',HINT='{"type":"malformed_message"}';
    END IF;
    BEGIN
        v_received_at:=COALESCE((v_artifact.parsed_headers->>'receivedAt')::timestamptz,statement_timestamp());
    EXCEPTION WHEN OTHERS THEN
        v_received_at:=statement_timestamp();
    END;
    IF v_received_at>statement_timestamp()+interval '5 minutes' OR
       v_received_at<statement_timestamp()-interval '20 years' THEN
        v_received_at:=statement_timestamp();
    END IF;
    v_total_size:=v_artifact.raw_mime_size+
        COALESCE((SELECT sum((blob->>'size')::bigint)
                   FROM jsonb_array_elements(v_artifact.blob_inventory) blob),0);
    IF NOT check_quota(v_artifact.mailbox_id,v_total_size) THEN
        RAISE EXCEPTION 'mailbox over quota'
            USING ERRCODE='BZ001',HINT='{"type":"over_quota"}';
    END IF;
    v_inbox_id:=get_tag_id('Inbox',v_artifact.mailbox_id);
    IF v_inbox_id IS NULL THEN
        RAISE EXCEPTION 'recovery mailbox has no Inbox tag'
            USING ERRCODE='BZ008',HINT='{"type":"missing_inbox"}';
    END IF;
    INSERT INTO tags(mailbox_id,name,color,icon,sort_order,tag_type,is_default,imap_expose,imap_name)
    VALUES(v_artifact.mailbox_id,'Recovered from device','#b45309','history',900,'user',false,true,'Recovered from device')
    ON CONFLICT(mailbox_id,name) DO NOTHING;
    SELECT id INTO STRICT v_recovered_tag_id FROM tags
     WHERE mailbox_id=v_artifact.mailbox_id AND name='Recovered from device';
    v_thread_id:=compute_thread_id(v_message_header,v_artifact.parsed_headers->>'inReplyTo',
                                   v_artifact.parsed_headers->>'references',v_artifact.mailbox_id);

    INSERT INTO messages(
        mailbox_id,folder_id,message_id,subject,from_addr,from_name,to_addrs,cc_addrs,bcc_addrs,
        in_reply_to,references_hdr,body_text,body_html,size_bytes,has_attachments,is_read,is_flagged,
        is_draft,raw_ref,thread_id,imap_uid,received_at,sent_at,spf_result,dkim_result,dmarc_result,
        spam_headers,is_external
    ) VALUES(
        v_artifact.mailbox_id,v_inbox_id,v_message_header,v_artifact.parsed_headers->>'subject',v_from_addr,
        v_artifact.parsed_headers->>'fromName',COALESCE(v_artifact.parsed_headers->'toAddrs','[]'::jsonb),
        COALESCE(v_artifact.parsed_headers->'ccAddrs','[]'::jsonb),COALESCE(v_artifact.parsed_headers->'bccAddrs','[]'::jsonb),
        v_artifact.parsed_headers->>'inReplyTo',v_artifact.parsed_headers->>'references',
        left(COALESCE(v_artifact.parsed_headers->>'bodyText',''),65536),
        left(COALESCE(v_artifact.parsed_headers->>'bodyHtml',''),65536),v_artifact.raw_mime_size,
        jsonb_array_length(v_artifact.blob_inventory)>0,false,false,false,v_artifact.raw_ref,v_thread_id,
        next_imap_uid_for_tag(v_inbox_id),v_received_at,
        CASE WHEN v_artifact.parsed_headers->>'eligibility'='sent-terminal' THEN v_received_at ELSE NULL END,
        NULL,NULL,NULL,jsonb_build_object('recoveryProvenance',jsonb_build_object(
            'incidentId',v_artifact.incident_id,'artifactIdentity',encode(v_artifact.artifact_identity,'hex'),
            'sourceTimeline',v_artifact.signed_timeline::text,'sourceBootEpoch',v_artifact.signed_boot_epoch,
            'deviceId',v_artifact.device_id,'authenticationResultsPreserved',false)),false
    ) RETURNING id INTO v_message_id;
    PERFORM tag_message(v_message_id,v_received_at,'Inbox',v_artifact.mailbox_id,'recovery',true);
    PERFORM tag_message(v_message_id,v_received_at,'Recovered from device',v_artifact.mailbox_id,'recovery',false);

    FOR v_blob IN SELECT blob FROM jsonb_array_elements(v_artifact.blob_inventory) blob LOOP
        IF v_blob->>'sha256'!~'^[0-9a-f]{64}$' OR v_blob->>'objectRef'<>v_blob->>'sha256' OR
           v_blob->>'role' NOT IN ('attachment','inline') OR v_blob->>'size'!~'^[1-9][0-9]{0,18}$' THEN
            RAISE EXCEPTION 'recovery blob inventory is invalid'
                USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
        END IF;
        INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count)
        VALUES(v_blob->>'sha256',v_blob->>'objectRef',(v_blob->>'size')::bigint,'application/octet-stream',0)
        ON CONFLICT(sha256) DO NOTHING;
        IF NOT EXISTS(
            SELECT 1 FROM blobs
             WHERE sha256=v_blob->>'sha256'
               AND minio_ref=v_blob->>'objectRef'
               AND size_bytes=(v_blob->>'size')::bigint
        ) THEN
            RAISE EXCEPTION 'recovery blob conflicts with existing content address'
                USING ERRCODE='BZ251',HINT='{"type":"continuity_blob_conflict"}';
        END IF;
        INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,disposition,size_bytes)
        VALUES(v_message_id,v_received_at,v_blob->>'sha256',left(v_blob->>'blobId',255),'application/octet-stream',
               v_blob->>'role',(v_blob->>'size')::bigint);
        v_blob_count:=v_blob_count+1;
    END LOOP;

    INSERT INTO mail_recovery_ledger(
        artifact_identity,incident_id,mailbox_id,quarantine_id,outcome,recovered_message_id,recovered_received_at
    ) VALUES(v_artifact.artifact_identity,v_artifact.incident_id,v_artifact.mailbox_id,v_artifact.id,
             'accepted',v_message_id,v_received_at);
    UPDATE mail_recovery_quarantine_artifacts
       SET status='accepted',terminal_at=statement_timestamp(),rejection_reason=NULL
     WHERE id=v_artifact.id;
    PERFORM notify_state_change(v_artifact.mailbox_id,v_inbox_id,v_message_id,'created');
    PERFORM audit_write(p_actor_user_id,'mail_recovery_artifact_accept','mail_recovery_artifact',v_message_id,NULL,
        jsonb_build_object('incidentId',v_artifact.incident_id,'quarantineId',v_artifact.id,
                           'mailboxId',v_artifact.mailbox_id::text,
                           'artifactIdentity',encode(v_artifact.artifact_identity,'hex'),
                           'blobCount',v_blob_count,'resolution',p_resolution,'reason',btrim(p_reason)),
        NULL,NULL,'core');
    PERFORM app_notify('mail_recovery_incident_changed',jsonb_build_object(
        'incident_id',v_artifact.incident_id,'status','accepted','message_id',v_message_id)::text);
    RETURN jsonb_build_object('id',v_artifact.id,'status','accepted','messageId',v_message_id::text,
                              'receivedAt',v_received_at,'replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_artifact_ingest(bigint,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_artifact_ingest(bigint,uuid,text,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_artifact_ingest(bigint,uuid,text,text)'::regprocedure);
