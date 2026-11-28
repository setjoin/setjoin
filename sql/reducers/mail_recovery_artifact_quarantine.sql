CREATE OR REPLACE FUNCTION mail_recovery_artifact_quarantine(
    p_user_id bigint,
    p_session_id uuid,
    p_quarantine_id uuid,
    p_parsed_headers jsonb,
    p_malware_status text,
    p_rejection_reason text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_session mail_recovery_upload_sessions%ROWTYPE;
    v_existing mail_recovery_quarantine_artifacts%ROWTYPE;
    v_timeline bigint;
    v_boot uuid;
    v_raw_ref text;
    v_inventory jsonb;
    v_status text;
    v_ledger mail_recovery_ledger%ROWTYPE;
BEGIN
    IF p_user_id IS NULL OR p_session_id IS NULL OR p_quarantine_id IS NULL OR
       jsonb_typeof(p_parsed_headers)<>'object' OR octet_length(p_parsed_headers::text)>262144 OR
       p_malware_status NOT IN ('clean','infected') OR
       (p_rejection_reason IS NOT NULL AND octet_length(p_rejection_reason)>256) THEN
        RAISE EXCEPTION 'invalid recovery quarantine request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_session FROM mail_recovery_upload_sessions
     WHERE id=p_session_id AND uploading_user_id=p_user_id FOR UPDATE;
    IF v_session.status IN ('quarantined','deduplicated','rejected') THEN
        SELECT * INTO v_existing FROM mail_recovery_quarantine_artifacts WHERE session_id=p_session_id;
        RETURN jsonb_build_object('id',v_existing.id,'status',v_session.status,'replayed',true);
    END IF;
    IF v_session.status<>'uploading' OR v_session.expires_at<=statement_timestamp() OR
       p_parsed_headers->>'eligibility' IS DISTINCT FROM v_session.eligibility OR
       EXISTS(SELECT 1 FROM mail_recovery_upload_items item
               WHERE item.session_id=p_session_id AND item.status<>'verified') THEN
        RAISE EXCEPTION 'recovery upload is not completely verified'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    BEGIN
        v_timeline:=(v_session.receipt->'claims'->>'timelineGeneration')::bigint;
        v_boot:=(v_session.receipt->'claims'->>'bootEpoch')::uuid;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'stored recovery receipt is invalid'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
    END;
    SELECT object_ref INTO STRICT v_raw_ref FROM mail_recovery_upload_items
     WHERE session_id=p_session_id AND role='raw';
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'blobId',item_id,'role',role,'sha256',encode(sha256,'hex'),
        'size',declared_size::text,'objectRef',object_ref
    ) ORDER BY item_id),'[]'::jsonb) INTO v_inventory
      FROM mail_recovery_upload_items WHERE session_id=p_session_id AND role<>'raw';

    SELECT * INTO v_ledger FROM mail_recovery_ledger
     WHERE artifact_identity=v_session.artifact_identity;
    IF FOUND THEN
        UPDATE mail_recovery_upload_sessions SET status='deduplicated',terminal_reason='artifact_replay',
               updated_at=statement_timestamp() WHERE id=p_session_id;
        RETURN jsonb_build_object('id',v_ledger.quarantine_id,'status','deduplicated',
                                  'outcome',v_ledger.outcome,'replayed',true);
    END IF;
    SELECT * INTO v_existing FROM mail_recovery_quarantine_artifacts
     WHERE artifact_identity=v_session.artifact_identity ORDER BY created_at LIMIT 1;
    IF FOUND THEN
        UPDATE mail_recovery_upload_sessions SET status='deduplicated',terminal_reason='artifact_replay',
               updated_at=statement_timestamp() WHERE id=p_session_id;
        RETURN jsonb_build_object('id',v_existing.id,'status','deduplicated',
                                  'outcome',v_existing.status,'replayed',true);
    END IF;

    v_status:=CASE WHEN p_malware_status='infected' OR NULLIF(p_rejection_reason,'') IS NOT NULL
                   THEN 'rejected' ELSE 'quarantined' END;
    IF p_malware_status='clean' AND EXISTS(
        SELECT 1 FROM mail_recovery_quarantine_artifacts existing
         WHERE existing.lineage_sha256=v_session.lineage_sha256
           AND existing.raw_mime_sha256<>v_session.raw_mime_sha256
    ) THEN
        IF EXISTS(
            SELECT 1 FROM mail_recovery_quarantine_artifacts existing
             WHERE existing.lineage_sha256=v_session.lineage_sha256
               AND existing.raw_mime_sha256<>v_session.raw_mime_sha256
               AND existing.signed_timeline=v_timeline
        ) THEN
            v_status:='tampered';
            UPDATE mail_recovery_quarantine_artifacts
               SET status='tampered',rejection_reason='same_lineage_timeline_different_hash',terminal_at=statement_timestamp()
             WHERE lineage_sha256=v_session.lineage_sha256 AND raw_mime_sha256<>v_session.raw_mime_sha256;
        ELSE
            v_status:='fork_conflict';
            UPDATE mail_recovery_quarantine_artifacts
               SET status='fork_conflict',rejection_reason='different_verified_timeline_branch'
             WHERE lineage_sha256=v_session.lineage_sha256 AND status='quarantined';
        END IF;
    END IF;

    INSERT INTO mail_recovery_quarantine_artifacts(
        id,session_id,incident_id,mailbox_id,uploading_user_id,device_id,
        artifact_identity,lineage_sha256,raw_mime_sha256,raw_mime_size,raw_ref,receipt,
        signed_timeline,signed_boot_epoch,parsed_headers,blob_inventory,malware_status,status,
        rejection_reason,terminal_at
    ) VALUES(
        p_quarantine_id,p_session_id,v_session.incident_id,v_session.mailbox_id,p_user_id,v_session.device_id,
        v_session.artifact_identity,v_session.lineage_sha256,v_session.raw_mime_sha256,v_session.declared_size,
        v_raw_ref,v_session.receipt,v_timeline,v_boot,p_parsed_headers,v_inventory,p_malware_status,v_status,
        CASE WHEN v_status='rejected' THEN COALESCE(NULLIF(p_rejection_reason,''),'malware_detected')
             WHEN v_status='tampered' THEN 'same_lineage_timeline_different_hash'
             WHEN v_status='fork_conflict' THEN 'different_verified_timeline_branch' ELSE NULL END,
        CASE WHEN v_status IN ('rejected','tampered') THEN statement_timestamp() ELSE NULL END
    );
    UPDATE mail_recovery_upload_sessions
       SET status=CASE WHEN v_status IN ('rejected','tampered') THEN 'rejected' ELSE 'quarantined' END,
           terminal_reason=CASE WHEN v_status IN ('rejected','tampered') THEN v_status ELSE NULL END,
           updated_at=statement_timestamp()
     WHERE id=p_session_id;
    IF v_status IN ('rejected','tampered') THEN
        INSERT INTO mail_recovery_ledger(artifact_identity,incident_id,mailbox_id,quarantine_id,outcome)
        VALUES(v_session.artifact_identity,v_session.incident_id,v_session.mailbox_id,p_quarantine_id,v_status)
        ON CONFLICT(artifact_identity) DO NOTHING;
    END IF;
    PERFORM audit_write(p_user_id,'mail_recovery_artifact_offer','mail_recovery_incident',NULL,NULL,
        jsonb_build_object('incidentId',v_session.incident_id,'mailboxId',v_session.mailbox_id::text,
                           'artifactIdentity',encode(v_session.artifact_identity,'hex'),'status',v_status),
        NULL,NULL,'core');
    PERFORM app_notify('mail_recovery_incident_changed',jsonb_build_object('incident_id',v_session.incident_id,'status',v_status)::text);
    RETURN jsonb_build_object('id',p_quarantine_id,'status',v_status,'replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_artifact_quarantine(bigint,uuid,uuid,jsonb,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_artifact_quarantine(bigint,uuid,uuid,jsonb,text,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_artifact_quarantine(bigint,uuid,uuid,jsonb,text,text)'::regprocedure);
