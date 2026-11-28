-- Frozen content.go versionMetaAndManifest: two SELECT snapshots in one
-- user-scoped transaction. VOLATILE is intentional: a revocation committed
-- after metadata admission must affect the subsequent manifest RLS read.
CREATE OR REPLACE FUNCTION rust_drive_content_meta(p_actor BIGINT,p_version_id BIGINT)
RETURNS JSONB LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE
  v_meta JSONB;
  v_manifest JSONB;
BEGIN
  IF p_actor IS DISTINCT FROM NULLIF(current_setting('app.current_user_id',true),'')::bigint THEN
    RAISE EXCEPTION 'actor does not match authenticated context' USING ERRCODE='42501';
  END IF;
  SELECT jsonb_build_object('spaceId',v.space_id,'classification',s.classification,
      'size',v.size_bytes,'contentType',v.content_type,
      'auditReads',coalesce((drive_policy_resolve(v.space_id)->>'audit_reads')::boolean,false))
    INTO v_meta
    FROM drive_file_versions v JOIN drive_spaces s ON s.id=v.space_id
   WHERE v.id=p_version_id AND drive_runtime_has_node_capability(p_actor,v.file_node_id,'download')
     AND (s.chat_channel_id IS NULL OR EXISTS(
       SELECT 1 FROM chat_message_attachments ca JOIN chat_messages msg ON msg.id=ca.message_id
       JOIN chat_channel_members cm ON cm.channel_id=msg.channel_id AND cm.user_id=p_actor
        WHERE ca.version_id=v.id AND msg.deleted_at IS NULL AND msg.seq>coalesce(cm.history_floor_seq,0)
          AND (cm.history_floor_seq IS NULL OR msg.created_at>=cm.joined_at)));
  IF NOT FOUND THEN RETURN NULL; END IF;
  -- Admission is above; this fresh statement retains Go's RLS visibility
  -- rather than introducing another download decision or an old CTE snapshot.
  SELECT coalesce(jsonb_agg(jsonb_build_object('key',c.storage_ref,'size',c.size_bytes)
      ORDER BY vc.ordinal),'[]'::jsonb) INTO v_manifest
    FROM drive_version_chunks vc JOIN drive_chunks c
      ON c.scope_key=vc.scope_key AND c.sha256=vc.chunk_sha256
   WHERE vc.version_id=p_version_id AND vc.stream='content'
     AND p_actor=NULLIF(current_setting('app.current_user_id',true),'')::bigint;
  RETURN v_meta||jsonb_build_object('manifest',v_manifest);
END;
$$;
