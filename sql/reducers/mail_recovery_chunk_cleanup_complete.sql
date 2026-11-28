CREATE OR REPLACE FUNCTION mail_recovery_chunk_cleanup_complete(
    p_session_id uuid,
    p_item_id text,
    p_start_offset bigint,
    p_object_key text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_deleted integer;
BEGIN
    IF p_session_id IS NULL OR p_item_id IS NULL OR p_start_offset IS NULL OR p_object_key IS NULL THEN
        RAISE EXCEPTION 'invalid recovery chunk cleanup record'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    DELETE FROM mail_recovery_upload_chunks chunk
     USING mail_recovery_upload_sessions session
     WHERE chunk.session_id=p_session_id AND chunk.item_id=p_item_id
       AND chunk.start_offset=p_start_offset AND chunk.object_key=p_object_key
       AND session.id=chunk.session_id
       AND session.status IN ('quarantined','deduplicated','rejected','aborted','expired');
    GET DIAGNOSTICS v_deleted=ROW_COUNT;
    RETURN v_deleted=1;
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_chunk_cleanup_complete(uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_chunk_cleanup_complete(uuid,text,bigint,text) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_chunk_cleanup_complete(uuid,text,bigint,text)'::regprocedure);
