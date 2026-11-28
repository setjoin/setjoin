-- Serialize an ACL-mode mutation's terminal authorization check against any
-- generation-changing revoke/downgrade.  The shared generation row is locked
-- before capabilities are evaluated: a revoke that committed first is seen by
-- the check, while a revoke that starts later waits for this transaction.
CREATE OR REPLACE FUNCTION drive_require_node_mutation_capability(
  p_user_id bigint,p_node_id bigint,p_capability text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_space_id bigint; v_acl_mode text;
BEGIN
  SELECT n.space_id,s.acl_mode INTO v_space_id,v_acl_mode
    FROM public.drive_nodes n
    JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_node_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Drive node not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"node not found"}';
  END IF;
  IF v_acl_mode='acl' THEN
    PERFORM 1 FROM public.drive_acl_generations
     WHERE space_id=v_space_id FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Drive ACL generation not found'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"spaceId"}';
    END IF;
  END IF;
  PERFORM public.drive_require_node_capability(
    p_user_id,p_node_id,p_capability);
END;
$$;
SELECT apply_worker_ownership(
  'drive_require_node_mutation_capability(bigint,bigint,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_require_space_root_mutation_capability(
  p_user_id bigint,p_space_id bigint,p_capability text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_acl_mode text;
BEGIN
  SELECT acl_mode INTO v_acl_mode FROM public.drive_spaces
   WHERE id=p_space_id;
  IF NOT FOUND THEN
    PERFORM public.drive_require_space_root_capability(
      p_user_id,p_space_id,p_capability);
    RETURN;
  END IF;
  IF v_acl_mode='acl' THEN
    PERFORM 1 FROM public.drive_acl_generations
     WHERE space_id=p_space_id FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Drive ACL generation not found'
        USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"spaceId"}';
    END IF;
  END IF;
  PERFORM public.drive_require_space_root_capability(
    p_user_id,p_space_id,p_capability);
END;
$$;
SELECT apply_worker_ownership(
  'drive_require_space_root_mutation_capability(bigint,bigint,text)'::regprocedure);
