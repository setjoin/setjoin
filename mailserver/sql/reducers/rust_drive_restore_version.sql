-- Frozen restoreVersion's reducer call followed by its fresh source-manifest
-- SELECT, in the same transaction (including rollback if that read fails).
CREATE OR REPLACE FUNCTION rust_drive_restore_version(p_actor BIGINT,p_node_id BIGINT,p_body JSONB)
RETURNS JSONB LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
  v_result JSONB;
  v_manifest JSONB;
BEGIN
  IF p_actor IS DISTINCT FROM NULLIF(current_setting('app.current_user_id',true),'')::bigint THEN
    RAISE EXCEPTION 'actor does not match authenticated context' USING ERRCODE='42501';
  END IF;
  v_result:=drive_file_restore_version(p_actor,p_node_id,(p_body->>'sourceVersionId')::bigint,
    (p_body->>'baseVersionId')::bigint,p_body->>'note',p_body->>'deviceLabel',(p_body->>'branchId')::bigint);
  SELECT coalesce(jsonb_agg(jsonb_build_object('sha256',vc.chunk_sha256,'size',c.size_bytes)
      ORDER BY vc.ordinal),'[]'::jsonb) INTO v_manifest
    FROM drive_version_chunks vc JOIN drive_chunks c
      ON c.scope_key=vc.scope_key AND c.sha256=vc.chunk_sha256
   WHERE vc.version_id=(p_body->>'sourceVersionId')::bigint AND vc.stream='content'
     AND p_actor=NULLIF(current_setting('app.current_user_id',true),'')::bigint;
  RETURN jsonb_build_object('_result',v_result,'_manifest',v_manifest);
END;
$$;
