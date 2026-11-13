CREATE OR REPLACE FUNCTION mail_recovery_upload_item_verify(
    p_user_id bigint,
    p_session_id uuid,
    p_item_id text,
    p_object_ref text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_item mail_recovery_upload_items%ROWTYPE;
BEGIN
    IF p_user_id IS NULL OR p_session_id IS NULL OR p_item_id IS NULL OR p_object_ref!~'^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid recovery item verification'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM mail_recovery_upload_sessions session
                   WHERE session.id=p_session_id AND session.uploading_user_id=p_user_id
                     AND session.status='uploading' AND session.expires_at>statement_timestamp()) THEN
        RAISE EXCEPTION 'recovery upload session is unavailable'
            USING ERRCODE='BZ002',HINT='{"type":"state_mismatch"}';
    END IF;
    SELECT * INTO STRICT v_item FROM mail_recovery_upload_items
     WHERE session_id=p_session_id AND item_id=p_item_id FOR UPDATE;
    IF v_item.status='verified' THEN
        IF v_item.object_ref=p_object_ref THEN
            RETURN jsonb_build_object('itemId',p_item_id,'status','verified','replayed',true);
        END IF;
        RAISE EXCEPTION 'verified recovery item differs'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_chunk_mismatch"}';
    END IF;
    IF v_item.next_offset<>v_item.declared_size OR encode(v_item.sha256,'hex')<>p_object_ref THEN
        RAISE EXCEPTION 'recovery item is incomplete or digest differs'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_chunk_mismatch"}';
    END IF;
    UPDATE mail_recovery_upload_items SET status='verified',object_ref=p_object_ref
     WHERE session_id=p_session_id AND item_id=p_item_id;
    RETURN jsonb_build_object('itemId',p_item_id,'status','verified','replayed',false);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_upload_item_verify(bigint,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_upload_item_verify(bigint,uuid,text,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_upload_item_verify(bigint,uuid,text,text)'::regprocedure);
