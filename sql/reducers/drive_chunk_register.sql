-- mailserver/sql/reducers/drive_chunk_register.sql
-- Called by the chunk PUT handler AFTER the tmp→verify→promote (§3.3). Content
-- plane only: NOT a notify/journal/audit site. ref_count is untouched (G7
-- triggers own it); the claim is this user's proof-of-possession (I-4).
--
-- SECURITY DEFINER + worker-owned (apply_worker_ownership): this reducer FULLY
-- authorizes on its own through drive_chunk_upload_require, which is also the
-- HTTP handler's pre-storage authorization choke. It gates BZ139 (no
-- membership) / BZ140 (guest account or not manager/editor) before any write. It
-- must run as setjoin_worker so its drive_chunks INSERT does not trip
-- drive_chunks_insert's WITH CHECK under FORCE-RLS. The 2026-07-16 fresh-VM
-- gate found chat/drive attachment upload 500ing here for DERIVED members
-- (chat/meeting-bound spaces carry no drive_space_members row, and the
-- policy's own drive_spaces enumeration is RLS-filtered): the two call sites
-- had DIVERGED — the meet recording ingest (worker_recordings.go) already
-- runs this on the BYPASSRLS worker pool and worked, while the putChunk
-- handler ran it as the constrained setjoin_app and hit the wall. DEFINER
-- unifies them (the chat_space_ensure pattern, plan Decision Audit #6). The
-- drive_chunks RLS INSERT policy remains as pure defense-in-depth.
CREATE OR REPLACE FUNCTION drive_chunk_upload_require(
  p_user_id BIGINT, p_space_id BIGINT
) RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_role TEXT; v_classification TEXT; v_acl_mode TEXT;
BEGIN
  SELECT s.classification,s.acl_mode,public.drive_member_role(s.id,p_user_id)
    INTO v_classification,v_acl_mode,v_role
    FROM public.drive_spaces s
   WHERE s.id = p_space_id
     FOR SHARE;
  IF NOT FOUND OR v_role IS NULL THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  IF v_acl_mode='acl' THEN
    RAISE EXCEPTION 'ACL-mode upload requires target and epoch binding'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"uploadBinding"}';
  END IF;
  -- Guestgate must allow the chunk PUT shape because attachment reads use the
  -- same content-addressed rail, but Guest G4 grants no mutation authority.
  -- Keep this independent of the derived role: a guest meeting host retains
  -- the locked host→manager read/governance mapping without gaining a route to
  -- manufacture upload claims or orphan canonical objects.
  IF public.is_guest_account(p_user_id) OR v_role NOT IN ('manager','editor') THEN
    RAISE EXCEPTION 'editor role required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"editor role required"}';
  END IF;
  RETURN CASE WHEN v_classification = 'regular' THEN 'g' ELSE 's' || p_space_id END;
END;
$$;
SELECT apply_worker_ownership('drive_chunk_upload_require(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_chunk_register(
  p_user_id BIGINT, p_space_id BIGINT, p_sha256 TEXT, p_size INT
) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_scope TEXT;
BEGIN
  v_scope := public.drive_chunk_upload_require(p_user_id, p_space_id);
  IF p_sha256 !~ '^[0-9a-f]{64}$' OR p_size IS NULL OR p_size < 1 OR p_size > 4194304 THEN
    RAISE EXCEPTION 'invalid chunk' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"sha256 must be 64 hex chars, size 1..4194304"}';
  END IF;
  -- Re-entrant when CommitStagedChunk already holds it; load-bearing for any
  -- direct reducer caller so GC cannot consume a stale queue verdict while a
  -- new claim is being written.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'drive-chunk:' || v_scope || ':' || p_sha256, 0));
  INSERT INTO drive_chunks (scope_key, sha256, size_bytes, ref_count, storage_ref)
  VALUES (v_scope, p_sha256, p_size, 0, 'drive/' || v_scope || '/' || p_sha256)
  ON CONFLICT (scope_key, sha256) DO NOTHING;
  INSERT INTO drive_upload_claims (scope_key, sha256, user_id)
  VALUES (v_scope, p_sha256, p_user_id)
  ON CONFLICT (scope_key, sha256, user_id) DO UPDATE SET claimed_at = now();
  -- A prior version deletion may already have queued this zero-ref row. A
  -- fresh claim makes that queued verdict stale; the maintenance sweep will
  -- enqueue it again after the seven-day claim window if no version consumes
  -- the upload. This delete runs under the same per-chunk advisory lock as the
  -- canonical promote in Go, so GC cannot erase a just-accepted retry.
  DELETE FROM drive_chunk_gc_queue
   WHERE scope_key = v_scope AND sha256 = p_sha256;
END;
$$;
SELECT apply_worker_ownership('drive_chunk_register(bigint,bigint,text,integer)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_chunk_register_bound(
  p_user_id bigint,p_space_id bigint,p_target_node_id bigint,
  p_expected_epoch bigint,p_sha256 text,p_size integer
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_scope text; v_kind text; v_classification text; v_epoch bigint;
  v_created timestamptz;
BEGIN
  SELECT n.kind,s.classification,g.epoch
    INTO v_kind,v_classification,v_epoch
    FROM public.drive_nodes n
    JOIN public.drive_spaces s ON s.id=n.space_id
    JOIN public.drive_acl_generations g ON g.space_id=s.id
   WHERE n.id=p_target_node_id AND n.space_id=p_space_id
     AND n.deleted_at IS NULL AND n.purged_at IS NULL AND s.acl_mode='acl'
   FOR SHARE OF n,s,g;
  IF NOT FOUND OR v_epoch<>p_expected_epoch
     OR public.is_guest_account(p_user_id)
     OR NOT public.drive_runtime_has_node_capability(
       p_user_id,p_target_node_id,
       CASE WHEN v_kind='folder' THEN 'create_child' ELSE 'modify_content' END) THEN
    RAISE EXCEPTION 'ACL upload binding is stale or forbidden'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"uploadBinding"}';
  END IF;
  IF p_sha256!~'^[0-9a-f]{64}$' OR p_size NOT BETWEEN 1 AND 4194304 THEN
    RAISE EXCEPTION 'invalid chunk' USING ERRCODE='BZ252',
      HINT='{"type":"drive_acl_invalid","field":"chunk"}';
  END IF;
  v_scope:=CASE WHEN v_classification='regular' THEN 'g' ELSE 's'||p_space_id END;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'drive-chunk:'||v_scope||':'||p_sha256,0));
  INSERT INTO public.drive_chunks(scope_key,sha256,size_bytes,ref_count,storage_ref)
  VALUES(v_scope,p_sha256,p_size,0,'drive/'||v_scope||'/'||p_sha256)
  ON CONFLICT(scope_key,sha256) DO NOTHING;
  INSERT INTO public.drive_upload_claims(scope_key,sha256,user_id)
  VALUES(v_scope,p_sha256,p_user_id)
  ON CONFLICT(scope_key,sha256,user_id) DO UPDATE SET claimed_at=now();
  v_created:=clock_timestamp();
  INSERT INTO public.drive_upload_authorizations(
    scope_key,sha256,user_id,space_id,target_node_id,acl_epoch,created_at,expires_at
  ) VALUES(v_scope,p_sha256,p_user_id,p_space_id,p_target_node_id,v_epoch,
    v_created,v_created+interval '24 hours')
  ON CONFLICT(scope_key,sha256,user_id,target_node_id) DO UPDATE SET
    acl_epoch=EXCLUDED.acl_epoch,created_at=EXCLUDED.created_at,
    expires_at=EXCLUDED.expires_at;
  DELETE FROM public.drive_chunk_gc_queue
   WHERE scope_key=v_scope AND sha256=p_sha256;
  RETURN v_scope;
END;
$$;
SELECT apply_worker_ownership(
  'drive_chunk_register_bound(bigint,bigint,bigint,bigint,text,integer)'::regprocedure);
