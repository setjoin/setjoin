-- mailserver/sql/reducers/drive_preview_attach.sql
-- setjoin_worker connection, so invoker rights are sufficient — unlike
-- drive_access_audit's DEFINER (needed because it may run under an
-- OWNER/app-role caller too), this function is ONLY ever called from the
-- preview worker's own BYPASSRLS pool, matching drive_maintenance_sweep's
-- plain-invoker genre. No p_user_id: the rendition is server-triggered, not
-- attributable to a caller.
--
-- Success path (p_status = 'ready', the default): registers the rendition's
-- chunks DIRECTLY (the worker generated these bytes server-side — there is no
-- client upload-claim/anti-oracle step to satisfy here, unlike
-- drive_file_put_version's manifest, which only REFERENCES chunks a client
-- already proved possession of via drive_chunk_register). Replaces any prior
-- 'preview' manifest rows (DELETE-then-INSERT, not ON CONFLICT DO UPDATE —
-- V114 only wires refcount triggers on INSERT/DELETE of drive_version_chunks,
-- not UPDATE, so a delete-then-insert is what keeps ref_count correct;
-- "last attach wins" for a benign duplicate-render race, ponytail-flagged in
-- preview.go — a per-row advisory claim is the upgrade if that race ever
-- matters in practice). Failure path (p_status IN ('failed','unsupported'))
-- only flips preview_status — no chunk I/O. The WORM trigger's rendition
-- carve-out (trg_drive_version_worm_fn, V114 §D) already allows this UPDATE on
-- a gxp version inside retention because it touches only
-- preview_sha256/preview_status; a genuine content-field UPDATE on the same
-- row still raises BZ145 — proven in drive_preview.pg, not re-implemented here.
CREATE OR REPLACE FUNCTION drive_preview_attach(
  p_version_id     BIGINT,
  p_preview_sha256 TEXT,
  p_manifest       JSONB,
  p_status         TEXT DEFAULT 'ready'
) RETURNS VOID AS $$
DECLARE
  v_space BIGINT; v_class TEXT; v_scope TEXT;
BEGIN
  IF p_status NOT IN ('ready','failed','unsupported') THEN
    RAISE EXCEPTION 'invalid preview status' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"status must be ready, failed, or unsupported"}';
  END IF;

  SELECT v.space_id, s.classification INTO v_space, v_class
    FROM drive_file_versions v JOIN drive_spaces s ON s.id = v.space_id
   WHERE v.id = p_version_id;
  IF v_space IS NULL THEN
    RAISE EXCEPTION 'version not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"version not found"}';
  END IF;

  IF p_status <> 'ready' THEN
    UPDATE drive_file_versions SET preview_status = p_status WHERE id = p_version_id;
    RETURN;
  END IF;

  -- Manifest shape (BZ141): array of {sha256,size}, every chunk 1..4 MiB
  -- (follows drive_file_put_version's validation shape; a rendition has no
  -- "last chunk may be short only" asymmetry to check since there is no
  -- separate p_size to reconcile against — the whole-rendition hash is
  -- p_preview_sha256, computed by the worker over the produced PDF bytes).
  IF p_preview_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid preview sha256' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"preview_sha256 must be 64 hex chars"}';
  END IF;
  IF p_manifest IS NULL OR jsonb_typeof(p_manifest) <> 'array' OR jsonb_array_length(p_manifest) = 0 THEN
    RAISE EXCEPTION 'preview manifest must be a non-empty array' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"manifest must be a non-empty array"}';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_manifest) c
              WHERE (c->>'sha256') !~ '^[0-9a-f]{64}$'
                 OR (c->>'size')::bigint NOT BETWEEN 1 AND 4194304) THEN
    RAISE EXCEPTION 'bad preview manifest chunk' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"every preview chunk must be 1..4194304 bytes"}';
  END IF;

  v_scope := CASE WHEN v_class = 'regular' THEN 'g' ELSE 's' || v_space END;

  INSERT INTO drive_chunks (scope_key, sha256, size_bytes, storage_ref)
  SELECT v_scope, c->>'sha256', (c->>'size')::integer,
         'drive/' || v_scope || '/' || (c->>'sha256')
    FROM jsonb_array_elements(p_manifest) c
  ON CONFLICT (scope_key, sha256) DO NOTHING;

  DELETE FROM drive_version_chunks WHERE version_id = p_version_id AND stream = 'preview';
  INSERT INTO drive_version_chunks (version_id, stream, ordinal, scope_key, chunk_sha256)
  SELECT p_version_id, 'preview', (ord - 1)::int, v_scope, c->>'sha256'
    FROM jsonb_array_elements(p_manifest) WITH ORDINALITY AS m(c, ord);

  UPDATE drive_file_versions
     SET preview_sha256 = p_preview_sha256, preview_status = 'ready'
   WHERE id = p_version_id;
END;
$$ LANGUAGE plpgsql;
