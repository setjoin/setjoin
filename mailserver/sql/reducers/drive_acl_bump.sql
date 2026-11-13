-- The epoch and targeted invalidation cursor are distinct currencies. This is
-- the single mutation seam that commits both and emits the push in one txn.
CREATE OR REPLACE FUNCTION drive_acl_bump(
  p_space_id BIGINT,
  p_principal_kind TEXT,
  p_principal_id BIGINT,
  p_anchor_node_id BIGINT,
  p_reason TEXT
) RETURNS TABLE(epoch BIGINT, invalidation_cursor BIGINT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_epoch BIGINT;
  v_cursor BIGINT;
BEGIN
  IF p_principal_kind NOT IN ('user', 'all')
     OR ((p_principal_kind = 'user') <> (p_principal_id IS NOT NULL)) THEN
    RAISE EXCEPTION 'invalid invalidation principal' USING ERRCODE='BZ252',
      HINT='{"type":"driveAclInvalid","field":"principal"}';
  END IF;

  INSERT INTO public.drive_acl_generations (space_id, epoch, updated_at)
  VALUES (p_space_id, 1, now())
  ON CONFLICT (space_id) DO UPDATE
    SET epoch = public.drive_acl_generations.epoch + 1,
        updated_at = now()
  RETURNING public.drive_acl_generations.epoch INTO v_epoch;

  INSERT INTO public.drive_access_invalidations
    (space_id, principal_kind, principal_id, anchor_node_id,
     resulting_epoch, reason)
  VALUES (p_space_id, p_principal_kind, p_principal_id, p_anchor_node_id,
          v_epoch, p_reason)
  RETURNING cursor INTO v_cursor;

  PERFORM public.drive_acl_revoke_bound_artifacts(
    p_space_id,p_principal_kind,p_principal_id,NULL,p_anchor_node_id,p_reason);

  PERFORM public.app_notify('drive_access', json_build_object(
    'spaceId', p_space_id::text,
    'epoch', v_epoch::text,
    'cursor', v_cursor::text,
    'principalKind', p_principal_kind
  )::text);

  RETURN QUERY SELECT v_epoch, v_cursor;
END;
$$;
SELECT apply_worker_ownership('drive_acl_bump(BIGINT, TEXT, BIGINT, BIGINT, TEXT)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_bump_group(
  p_space_id BIGINT,
  p_group_id BIGINT,
  p_anchor_node_id BIGINT,
  p_reason TEXT
) RETURNS TABLE(epoch BIGINT, invalidation_cursor BIGINT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_epoch BIGINT; v_cursor BIGINT;
BEGIN
  IF p_group_id IS NULL OR NOT EXISTS(
    SELECT 1 FROM public.directory_groups WHERE id=p_group_id
  ) THEN
    RAISE EXCEPTION 'invalid invalidation group' USING ERRCODE='BZ252',
      HINT='{"type":"drive_acl_invalid","field":"groupId"}';
  END IF;
  UPDATE public.drive_acl_generations AS g
     SET epoch=g.epoch+1,updated_at=clock_timestamp()
   WHERE g.space_id=p_space_id RETURNING g.epoch INTO v_epoch;
  IF v_epoch IS NULL THEN
    RAISE EXCEPTION 'Drive ACL generation not found' USING ERRCODE='BZ254',
      HINT='{"type":"drive_acl_conflict","field":"spaceId"}';
  END IF;
  INSERT INTO public.drive_access_invalidations(
    space_id,principal_kind,principal_group_id,anchor_node_id,resulting_epoch,reason
  ) VALUES(p_space_id,'group',p_group_id,p_anchor_node_id,v_epoch,p_reason)
  RETURNING cursor INTO v_cursor;
  PERFORM public.drive_acl_revoke_bound_artifacts(
    p_space_id,'group',NULL,p_group_id,p_anchor_node_id,p_reason);
  PERFORM public.app_notify('drive_access',json_build_object(
    'spaceId',p_space_id::text,'epoch',v_epoch::text,'cursor',v_cursor::text,
    'principalKind','group'
  )::text);
  RETURN QUERY SELECT v_epoch,v_cursor;
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_bump_group(bigint,bigint,bigint,text)'::regprocedure);
