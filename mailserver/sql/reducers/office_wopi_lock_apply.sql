-- Apply WOPI's opaque cohort lock. WOPI requires the current raw value on a
-- conflict; the FORCE-RLS table is reducer-only and never exposed to app reads.
CREATE OR REPLACE FUNCTION office_wopi_lock_apply(
  p_launch_id uuid,p_token_hash text,p_operation text,p_lock_value text,
  p_old_lock_value text DEFAULT NULL,p_ttl_seconds integer DEFAULT 1800
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
  v_launch public.office_editor_launches%ROWTYPE;
  v_session public.office_editor_sessions%ROWTYPE;
  v_lock public.office_wopi_locks%ROWTYPE;
  v_lock_hash text;
  v_old_lock_hash text;
BEGIN
  IF p_operation NOT IN ('LOCK','REFRESH_LOCK','UNLOCK','UNLOCK_AND_RELOCK')
     OR p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_lock_value IS NULL OR length(p_lock_value) NOT BETWEEN 1 AND 4096
     OR (p_old_lock_value IS NOT NULL AND length(p_old_lock_value) NOT BETWEEN 1 AND 4096)
     OR p_ttl_seconds NOT BETWEEN 60 AND 3600 THEN
    RAISE EXCEPTION 'invalid WOPI lock request' USING ERRCODE='BZ322',
      HINT='{"type":"invalidArguments","detail":"invalid WOPI lock request"}';
  END IF;
  v_lock_hash := encode(digest(p_lock_value,'sha256'),'hex');
  v_old_lock_hash := CASE WHEN p_old_lock_value IS NULL THEN NULL
    ELSE encode(digest(p_old_lock_value,'sha256'),'hex') END;
  SELECT * INTO v_launch FROM public.office_editor_launches
   WHERE id=p_launch_id AND token_hash=p_token_hash AND revoked_at IS NULL AND expires_at>now()
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Office launch unavailable' USING ERRCODE='BZ321',
      HINT='{"type":"notFound","detail":"Office launch unavailable"}';
  END IF;
  SELECT * INTO v_session FROM public.office_editor_sessions
   WHERE id=v_launch.session_id FOR UPDATE;
  IF v_session.status NOT IN ('active','saving','draining')
     OR v_session.lease_expires_at<=now()
     OR v_launch.fence_generation<>v_session.fence_generation THEN
    RAISE EXCEPTION 'Office session fenced' USING ERRCODE='BZ324',
      HINT='{"type":"stateMismatch","detail":"Office session is no longer current"}';
  END IF;
  IF NOT public.office_wopi_callback_allowed(p_launch_id,p_token_hash,'modify_content') THEN
    RAISE EXCEPTION 'WOPI lock forbidden' USING ERRCODE='BZ323',
      HINT='{"type":"forbidden","detail":"Office write authority is no longer current"}';
  END IF;
  SELECT * INTO v_lock FROM public.office_wopi_locks WHERE session_id=v_session.id FOR UPDATE;
  IF FOUND AND v_lock.expires_at<=now() THEN
    DELETE FROM public.office_wopi_locks WHERE session_id=v_session.id;
    v_lock := NULL;
  END IF;

  IF p_operation='LOCK' THEN
    IF v_lock.session_id IS NOT NULL AND v_lock.opaque_lock_hash<>v_lock_hash THEN
      RETURN jsonb_build_object('ok',false,'conflict',true,
        'currentLock',v_lock.opaque_lock_value);
    END IF;
    INSERT INTO public.office_wopi_locks(session_id,space_id,file_node_id,opaque_lock_hash,opaque_lock_value,
      fence_generation,lock_epoch,expires_at)
    VALUES(v_session.id,v_session.space_id,v_session.file_node_id,v_lock_hash,p_lock_value,
      v_session.fence_generation,v_session.lock_epoch,now()+make_interval(secs=>p_ttl_seconds))
    ON CONFLICT(session_id) DO UPDATE SET opaque_lock_hash=EXCLUDED.opaque_lock_hash,
      opaque_lock_value=EXCLUDED.opaque_lock_value,
      fence_generation=EXCLUDED.fence_generation,lock_epoch=EXCLUDED.lock_epoch,
      expires_at=EXCLUDED.expires_at,updated_at=now();
  ELSIF p_operation='REFRESH_LOCK' THEN
    IF v_lock.session_id IS NULL OR v_lock.opaque_lock_hash<>v_lock_hash THEN
      RETURN jsonb_build_object('ok',false,'conflict',true,
        'currentLock',COALESCE(v_lock.opaque_lock_value,''));
    END IF;
    UPDATE public.office_wopi_locks SET expires_at=now()+make_interval(secs=>p_ttl_seconds),updated_at=now()
     WHERE session_id=v_session.id;
  ELSIF p_operation='UNLOCK' THEN
    IF v_lock.session_id IS NULL OR v_lock.opaque_lock_hash<>v_lock_hash THEN
      RETURN jsonb_build_object('ok',false,'conflict',true,
        'currentLock',COALESCE(v_lock.opaque_lock_value,''));
    END IF;
    DELETE FROM public.office_wopi_locks WHERE session_id=v_session.id;
  ELSE
    IF v_lock.session_id IS NULL OR v_old_lock_hash IS NULL OR v_lock.opaque_lock_hash<>v_old_lock_hash THEN
      RETURN jsonb_build_object('ok',false,'conflict',true,
        'currentLock',COALESCE(v_lock.opaque_lock_value,''));
    END IF;
    UPDATE public.office_wopi_locks SET opaque_lock_hash=v_lock_hash,opaque_lock_value=p_lock_value,
      lock_epoch=lock_epoch+1,expires_at=now()+make_interval(secs=>p_ttl_seconds),updated_at=now()
     WHERE session_id=v_session.id;
    UPDATE public.office_editor_sessions SET lock_epoch=lock_epoch+1,updated_at=now() WHERE id=v_session.id;
  END IF;
  RETURN jsonb_build_object('ok',true,'sessionId',v_session.id);
END;
$$;
SELECT apply_worker_ownership('office_wopi_lock_apply(uuid,text,text,text,text,integer)'::regprocedure);
