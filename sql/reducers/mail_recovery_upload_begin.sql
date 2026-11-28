CREATE OR REPLACE FUNCTION mail_recovery_upload_begin(
    p_user_id bigint,
    p_session_id uuid,
    p_incident_id uuid,
    p_mailbox_id bigint,
    p_device_id uuid,
    p_artifact_identity text,
    p_eligibility text,
    p_receipt jsonb,
    p_inventory jsonb,
    p_consented_at timestamptz,
    p_idempotency_key uuid
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_incident mail_recovery_incidents%ROWTYPE;
    v_existing mail_recovery_upload_sessions%ROWTYPE;
    v_claims jsonb;
    v_installation text;
    v_account text;
    v_original text;
    v_raw_sha text;
    v_raw_size bigint;
    v_timeline bigint;
    v_boot uuid;
    v_expected_identity bytea;
    v_lineage bytea;
    v_total bigint;
    v_items jsonb;
    v_reserved_sessions bigint;
    v_reserved_bytes bigint;
BEGIN
    IF NOT mail_recovery_feature_enabled() THEN
        RAISE EXCEPTION 'client recovery intake is disabled'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_user_id IS NULL OR p_session_id IS NULL OR p_incident_id IS NULL OR p_mailbox_id IS NULL OR
       p_device_id IS NULL OR p_idempotency_key IS NULL OR p_artifact_identity!~'^[0-9a-f]{64}$' OR
       p_eligibility NOT IN ('received','sent-terminal') OR
       jsonb_typeof(p_receipt)<>'object' OR octet_length(p_receipt::text)>1048576 OR
       jsonb_typeof(p_inventory)<>'array' OR jsonb_array_length(p_inventory) NOT BETWEEN 1 AND 4097 OR
       p_consented_at IS NULL OR p_consented_at>statement_timestamp()+interval '5 minutes' OR
       p_consented_at<statement_timestamp()-interval '15 minutes' THEN
        RAISE EXCEPTION 'invalid recovery upload request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    IF NOT mail_recovery_user_can_upload(p_user_id,p_mailbox_id) THEN
        RAISE EXCEPTION 'recovery mailbox upload is not authorized'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;

    SELECT * INTO v_existing FROM mail_recovery_upload_sessions
     WHERE uploading_user_id=p_user_id AND idempotency_key=p_idempotency_key;
    IF FOUND THEN
        SELECT COALESCE(jsonb_agg(jsonb_build_object('itemId',item_id,'nextOffset',next_offset::text,
                                                     'size',declared_size::text,'status',status)
                                  ORDER BY CASE role WHEN 'raw' THEN 0 ELSE 1 END,item_id),'[]'::jsonb)
          INTO v_items FROM mail_recovery_upload_items WHERE session_id=v_existing.id;
        RETURN jsonb_build_object('sessionId',v_existing.id,'status',v_existing.status,
                                  'expiresAt',v_existing.expires_at,'items',v_items,'replayed',true);
    END IF;

    SELECT * INTO STRICT v_incident FROM mail_recovery_incidents WHERE id=p_incident_id FOR SHARE;
    IF v_incident.status<>'open' OR v_incident.expires_at<=statement_timestamp() OR
       (v_incident.approval_required AND v_incident.approved_by IS NULL) OR
       NOT EXISTS(SELECT 1 FROM mail_recovery_incident_accounts account
                   WHERE account.incident_id=p_incident_id AND account.mailbox_id=p_mailbox_id) THEN
        RAISE EXCEPTION 'recovery incident is unavailable for this mailbox'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;

    v_claims:=p_receipt->'claims';
    v_installation:=v_claims->>'installationId';
    v_account:=v_claims->>'accountId';
    v_original:=v_claims->>'originalMessageId';
    v_raw_sha:=v_claims->>'rawMimeSha256';
    BEGIN
        v_raw_size:=(v_claims->>'rawMimeSize')::bigint;
        v_timeline:=(v_claims->>'timelineGeneration')::bigint;
        v_boot:=(v_claims->>'bootEpoch')::uuid;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid signed recovery receipt claims'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
    END;
    IF v_claims->>'eligibility' NOT IN ('received','sent-terminal') OR
       v_claims->>'eligibility'<>p_eligibility THEN
        RAISE EXCEPTION 'recovery eligibility does not match signed receipt'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
    END IF;
    IF v_installation<>v_incident.installation_id::text OR v_account<>p_mailbox_id::text OR
       v_original IS NULL OR octet_length(v_original) NOT BETWEEN 1 AND 256 OR
       v_raw_sha!~'^[0-9a-f]{64}$' OR v_raw_size NOT BETWEEN 1 AND 52428800 OR
       v_timeline NOT BETWEEN v_incident.minimum_timeline AND v_incident.maximum_timeline OR v_boot IS NULL THEN
        RAISE EXCEPTION 'recovery receipt is outside incident scope'
            USING ERRCODE='BZ245',HINT='{"type":"continuity_scope_mismatch"}';
    END IF;
    v_expected_identity:=digest(
        convert_to('v1','UTF8')||decode('00','hex')||convert_to(v_installation,'UTF8')||decode('00','hex')||
        convert_to(v_account,'UTF8')||decode('00','hex')||convert_to(v_original,'UTF8')||decode('00','hex')||
        convert_to(v_raw_sha,'UTF8'),'sha256');
    v_lineage:=digest(
        convert_to('lineage-v1','UTF8')||decode('00','hex')||convert_to(v_installation,'UTF8')||decode('00','hex')||
        convert_to(v_account,'UTF8')||decode('00','hex')||convert_to(v_original,'UTF8'),'sha256');
    IF decode(p_artifact_identity,'hex')<>v_expected_identity THEN
        RAISE EXCEPTION 'recovery artifact identity mismatch'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
    END IF;

    -- Inventory must contain exactly one raw item and exactly the signed blob set.
    IF (SELECT count(*) FROM jsonb_array_elements(p_inventory) item WHERE item->>'role'='raw')<>1 OR
       NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_inventory) item
                   WHERE item->>'role'='raw' AND item->>'itemId'='raw' AND item->>'sha256'=v_raw_sha
                     AND item->>'size'=v_raw_size::text) OR
       (SELECT count(*) FROM jsonb_array_elements(p_inventory) item WHERE item->>'role'<>'raw')<>
       jsonb_array_length(COALESCE(v_claims->'blobs','[]'::jsonb)) OR
       EXISTS(
          SELECT 1 FROM jsonb_array_elements(COALESCE(v_claims->'blobs','[]'::jsonb)) signed_blob
           WHERE NOT EXISTS(
             SELECT 1 FROM jsonb_array_elements(p_inventory) item
              WHERE item->>'role' IN ('attachment','inline')
                AND item->>'itemId'=signed_blob->>'blobId'
                AND item->>'sha256'=signed_blob->>'sha256'
                AND item->>'size'=signed_blob->>'size')) OR
       EXISTS(
          SELECT 1 FROM jsonb_array_elements(p_inventory) item
           WHERE item->>'itemId' IS NULL OR octet_length(item->>'itemId') NOT BETWEEN 1 AND 256 OR
                 item->>'itemId'~'[[:cntrl:]/]' OR item->>'role' NOT IN ('raw','attachment','inline') OR
                 item->>'sha256'!~'^[0-9a-f]{64}$' OR octet_length(item->>'size') NOT BETWEEN 1 AND 19 OR
                 item->>'size'!~'^(0|[1-9][0-9]*)$' OR
                 (item->>'size')::numeric NOT BETWEEN 1 AND 8589934592) THEN
        RAISE EXCEPTION 'recovery upload inventory does not match signed receipt'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
    END IF;
    SELECT sum((item->>'size')::bigint) INTO v_total FROM jsonb_array_elements(p_inventory) item;
    IF v_total>8589934592 THEN
        RAISE EXCEPTION 'recovery artifact exceeds bounded upload size'
            USING ERRCODE='BZ251',HINT='{"type":"too_large"}';
    END IF;

    -- Recovery is normally OFF and rare when enabled, so serialize admission
    -- per installation. The lock closes the count/sum-to-INSERT race across
    -- devices, mailboxes, and incidents without holding a long-lived row lock.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('mail-recovery-upload-budget-v1:'||v_installation,0)
    );

    SELECT count(*),COALESCE(sum(session.total_declared_size),0)
      INTO v_reserved_sessions,v_reserved_bytes
      FROM mail_recovery_upload_sessions session
      JOIN mail_recovery_incidents incident ON incident.id=session.incident_id
     WHERE incident.installation_id=v_incident.installation_id
       AND session.device_id=p_device_id
       AND (session.status IN ('uploading','committing') OR EXISTS(
             SELECT 1 FROM mail_recovery_upload_chunks chunk WHERE chunk.session_id=session.id));
    IF v_reserved_sessions>=8 OR v_reserved_bytes>17179869184-v_total THEN
        RAISE EXCEPTION 'recovery upload budget exhausted'
            USING ERRCODE='BZ001',HINT='{"type":"over_quota"}';
    END IF;

    SELECT count(*),COALESCE(sum(session.total_declared_size),0)
      INTO v_reserved_sessions,v_reserved_bytes
      FROM mail_recovery_upload_sessions session
      JOIN mail_recovery_incidents incident ON incident.id=session.incident_id
     WHERE incident.installation_id=v_incident.installation_id
       AND session.mailbox_id=p_mailbox_id
       AND (session.status IN ('uploading','committing') OR EXISTS(
             SELECT 1 FROM mail_recovery_upload_chunks chunk WHERE chunk.session_id=session.id));
    IF v_reserved_sessions>=16 OR v_reserved_bytes>34359738368-v_total THEN
        RAISE EXCEPTION 'recovery upload budget exhausted'
            USING ERRCODE='BZ001',HINT='{"type":"over_quota"}';
    END IF;

    SELECT count(*),COALESCE(sum(session.total_declared_size),0)
      INTO v_reserved_sessions,v_reserved_bytes
      FROM mail_recovery_upload_sessions session
     WHERE session.incident_id=p_incident_id
       AND (session.status IN ('uploading','committing') OR EXISTS(
             SELECT 1 FROM mail_recovery_upload_chunks chunk WHERE chunk.session_id=session.id));
    IF v_reserved_sessions>=256 OR v_reserved_bytes>274877906944-v_total THEN
        RAISE EXCEPTION 'recovery upload budget exhausted'
            USING ERRCODE='BZ001',HINT='{"type":"over_quota"}';
    END IF;

    SELECT count(*),COALESCE(sum(session.total_declared_size),0)
      INTO v_reserved_sessions,v_reserved_bytes
      FROM mail_recovery_upload_sessions session
      JOIN mail_recovery_incidents incident ON incident.id=session.incident_id
     WHERE incident.installation_id=v_incident.installation_id
       AND (session.status IN ('uploading','committing') OR EXISTS(
             SELECT 1 FROM mail_recovery_upload_chunks chunk WHERE chunk.session_id=session.id));
    IF v_reserved_sessions>=4096 OR v_reserved_bytes>1099511627776-v_total THEN
        RAISE EXCEPTION 'recovery upload budget exhausted'
            USING ERRCODE='BZ001',HINT='{"type":"over_quota"}';
    END IF;

    INSERT INTO mail_recovery_upload_sessions(
        id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,
        raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key
    ) VALUES(
        p_session_id,p_incident_id,p_mailbox_id,p_user_id,p_device_id,v_expected_identity,v_lineage,
        decode(v_raw_sha,'hex'),p_eligibility,v_raw_size,v_total,p_receipt,p_consented_at,
        LEAST(v_incident.expires_at,statement_timestamp()+interval '24 hours'),p_idempotency_key
    );
    INSERT INTO mail_recovery_upload_items(session_id,item_id,role,sha256,declared_size)
    SELECT p_session_id,item->>'itemId',item->>'role',decode(item->>'sha256','hex'),(item->>'size')::bigint
      FROM jsonb_array_elements(p_inventory) item;
    PERFORM audit_write(p_user_id,'mail_recovery_upload_consent','mail_recovery_incident',NULL,NULL,
        jsonb_build_object('incidentId',p_incident_id,'mailboxId',p_mailbox_id::text,
                           'deviceId',p_device_id,'artifactIdentity',p_artifact_identity,
                           'declaredBytes',v_total::text),NULL,NULL,'core');
    SELECT jsonb_agg(jsonb_build_object('itemId',item_id,'nextOffset','0','size',declared_size::text,'status','uploading')
                     ORDER BY CASE role WHEN 'raw' THEN 0 ELSE 1 END,item_id)
      INTO v_items FROM mail_recovery_upload_items WHERE session_id=p_session_id;
    RETURN jsonb_build_object('sessionId',p_session_id,'status','uploading',
                              'expiresAt',LEAST(v_incident.expires_at,statement_timestamp()+interval '24 hours'),
                              'items',v_items,'replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_upload_begin(bigint,uuid,uuid,bigint,uuid,text,text,jsonb,jsonb,timestamptz,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_upload_begin(bigint,uuid,uuid,bigint,uuid,text,text,jsonb,jsonb,timestamptz,uuid) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_upload_begin(bigint,uuid,uuid,bigint,uuid,text,text,jsonb,jsonb,timestamptz,uuid)'::regprocedure);
