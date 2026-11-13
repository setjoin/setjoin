-- mailserver/sql/reducers/drive_notify_change.sql
-- THE per-space state choke point (spec §6.2) — Drive's jmap_*_state analog:
-- change_seq bump + journal row + app_notify, one txn. SECURITY DEFINER owned
-- by setjoin_worker (Locked resolution R2): an *editor* must bump change_seq
-- while the spaces-UPDATE policy is manager-only under FORCE.
-- ponytail: row-lock serializes writers per space; per-space advisory striping
-- is the upgrade if contention shows (spec §6.2 accepted ceiling).
CREATE OR REPLACE FUNCTION drive_notify_change(
  p_space_id BIGINT, p_node_id BIGINT, p_op TEXT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_seq BIGINT;
BEGIN
  UPDATE drive_spaces SET change_seq = change_seq + 1
   WHERE id = p_space_id RETURNING change_seq INTO v_seq;
  IF v_seq IS NULL THEN
    RAISE EXCEPTION 'drive space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;
  INSERT INTO drive_changes (space_id, seq, node_id, op) VALUES (p_space_id, v_seq, p_node_id, p_op);
  PERFORM app_notify('drive', json_build_object('spaceId', p_space_id, 'seq', v_seq)::text);
  RETURN v_seq;
END;
$$;
SELECT apply_worker_ownership('drive_notify_change(BIGINT, BIGINT, TEXT)'::regprocedure);
