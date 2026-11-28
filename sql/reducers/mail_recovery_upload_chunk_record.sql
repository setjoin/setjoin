CREATE OR REPLACE FUNCTION mail_recovery_upload_chunk_record(
    p_user_id bigint,
    p_session_id uuid,
    p_item_id text,
    p_start_offset bigint,
    p_size_bytes integer,
    p_sha256 text,
    p_object_key text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_session mail_recovery_upload_sessions%ROWTYPE;
    v_item mail_recovery_upload_items%ROWTYPE;
    v_existing mail_recovery_upload_chunks%ROWTYPE;
BEGIN
    IF p_user_id IS NULL OR p_session_id IS NULL OR p_item_id IS NULL OR
       octet_length(p_item_id) NOT BETWEEN 1 AND 256 OR p_item_id~'[[:cntrl:]/]' OR
       p_start_offset IS NULL OR p_start_offset<0 OR p_size_bytes IS NULL OR p_size_bytes NOT BETWEEN 1 AND 262144 OR
       p_sha256!~'^[0-9a-f]{64}$' OR
       p_object_key!~'^recovery-quarantine/[0-9a-f-]{36}/[0-9a-f-]{36}/[0-9a-f]{64}/[0-9]+-[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid recovery upload chunk'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_session FROM mail_recovery_upload_sessions
     WHERE id=p_session_id AND uploading_user_id=p_user_id FOR UPDATE;
    IF v_session.status<>'uploading' OR v_session.expires_at<=statement_timestamp() OR
       NOT EXISTS(SELECT 1 FROM mail_recovery_incidents incident
                   WHERE incident.id=v_session.incident_id AND incident.status='open'
                     AND incident.expires_at>statement_timestamp()) THEN
        RAISE EXCEPTION 'recovery upload session is unavailable'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    SELECT * INTO STRICT v_item FROM mail_recovery_upload_items
     WHERE session_id=p_session_id AND item_id=p_item_id FOR UPDATE;
    SELECT * INTO v_existing FROM mail_recovery_upload_chunks
     WHERE session_id=p_session_id AND item_id=p_item_id AND start_offset=p_start_offset;
    IF FOUND THEN
        IF v_existing.size_bytes=p_size_bytes AND v_existing.sha256=decode(p_sha256,'hex') AND
           v_existing.object_key=p_object_key THEN
            RETURN jsonb_build_object('nextOffset',v_item.next_offset::text,'replayed',true);
        END IF;
        RAISE EXCEPTION 'recovery chunk replay differs'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_chunk_mismatch"}';
    END IF;
    IF v_item.status<>'uploading' OR p_start_offset<>v_item.next_offset OR
       p_start_offset+p_size_bytes>v_item.declared_size THEN
        RAISE EXCEPTION 'recovery chunk offset is not the acknowledged offset'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    INSERT INTO mail_recovery_upload_chunks(session_id,item_id,start_offset,size_bytes,sha256,object_key)
    VALUES(p_session_id,p_item_id,p_start_offset,p_size_bytes,decode(p_sha256,'hex'),p_object_key);
    UPDATE mail_recovery_upload_items SET next_offset=next_offset+p_size_bytes
     WHERE session_id=p_session_id AND item_id=p_item_id;
    UPDATE mail_recovery_upload_sessions
       SET next_offset=next_offset+CASE WHEN v_item.role='raw' THEN p_size_bytes ELSE 0 END,
           updated_at=statement_timestamp()
     WHERE id=p_session_id;
    RETURN jsonb_build_object('nextOffset',(p_start_offset+p_size_bytes)::text,'replayed',false,
                              'complete',p_start_offset+p_size_bytes=v_item.declared_size);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_upload_chunk_record(bigint,uuid,text,bigint,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_upload_chunk_record(bigint,uuid,text,bigint,integer,text,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_upload_chunk_record(bigint,uuid,text,bigint,integer,text,text)'::regprocedure);
