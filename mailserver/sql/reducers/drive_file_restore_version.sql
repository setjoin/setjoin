-- Restore an existing version as a new version without exposing original
-- bytes or a chunk manifest to the browser.  The source must belong to the
-- same file and remain downloadable by the caller; the target must pass the
-- canonical modify-content gate inside drive_file_put_version.  A trashed
-- file is restored in the same transaction before the new version is made,
-- so any lock/quota/policy failure rolls the tree restore back as well.
CREATE OR REPLACE FUNCTION drive_file_restore_version(
  p_user_id          BIGINT,
  p_file_node_id     BIGINT,
  p_source_version_id BIGINT,
  p_base_version_id  BIGINT DEFAULT NULL,
  p_note             TEXT DEFAULT NULL,
  p_device_label     TEXT DEFAULT NULL,
  p_branch_id        BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_content_sha256 TEXT;
  v_size           BIGINT;
  v_content_type   TEXT;
  v_deleted_at     TIMESTAMPTZ;
  v_purged_at      TIMESTAMPTZ;
  v_manifest       JSONB;
  v_base            BIGINT := p_base_version_id;
BEGIN
  -- Same-file binding prevents this endpoint becoming a cross-file content
  -- oracle.  Exact download authority is required even though no bytes leave
  -- the server; callers with metadata/modify-only grants cannot republish
  -- content they are not allowed to obtain.
  SELECT v.content_sha256, v.size_bytes, v.content_type,
         n.deleted_at, n.purged_at
    INTO v_content_sha256, v_size, v_content_type,
         v_deleted_at, v_purged_at
    FROM drive_file_versions v
    JOIN drive_nodes n ON n.id = v.file_node_id
   WHERE v.id = p_source_version_id
     AND v.file_node_id = p_file_node_id
     AND public.drive_runtime_has_node_capability(
           p_user_id, v.file_node_id, 'download');
  IF NOT FOUND OR v_purged_at IS NOT NULL THEN
    RAISE EXCEPTION 'source version not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"source version not found"}';
  END IF;

  -- Time-point restore may target a tier-1 trashed file.  Reuse the canonical
  -- collision, delete/create-child capability, audit, and journal authority.
  IF v_deleted_at IS NOT NULL THEN
    PERFORM drive_node_restore(p_user_id, p_file_node_id);
  END IF;

  -- A time-point restore intentionally means "make this the latest content".
  -- Snapshot the current ref head when the caller did not supply one; the
  -- downstream reducer locks and compares it, preserving its conflict rules
  -- if another writer advances the ref before this transaction reaches it.
  IF v_base IS NULL THEN
    IF p_branch_id IS NULL THEN
      SELECT head_version_id INTO v_base
        FROM drive_files WHERE node_id = p_file_node_id;
    ELSE
      SELECT head_version_id INTO v_base
        FROM drive_file_branches
       WHERE id = p_branch_id AND file_node_id = p_file_node_id;
    END IF;
  END IF;

  SELECT COALESCE(jsonb_agg(
           jsonb_build_object('sha256', vc.chunk_sha256, 'size', c.size_bytes)
           ORDER BY vc.ordinal), '[]'::jsonb)
    INTO v_manifest
    FROM drive_version_chunks vc
    JOIN drive_chunks c
      ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
   WHERE vc.version_id = p_source_version_id
     AND vc.stream = 'content';

  RETURN drive_file_put_version(
    p_user_id, p_file_node_id, v_content_sha256, v_size, v_content_type,
    v_base, v_manifest, p_note, p_device_label, p_branch_id);
END;
$$ LANGUAGE plpgsql;
