-- notify_task_list_state.sql — the single owner of "a shared list changed".
-- Bumps task_lists.state_seq in-txn (the per-list sync token) and fans a
-- 'tasklist_changed' event out on each member's EXISTING 'task:{mailbox_id}'
-- channel (owner included via their member row) — zero new subscription
-- plumbing; the webmail's task push handler just refetches the active list.
CREATE OR REPLACE FUNCTION notify_task_list_state(
  p_list_id BIGINT,
  p_event   TEXT,
  p_task_id BIGINT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
  v_mb    BIGINT;
BEGIN
  IF p_list_id IS NULL THEN
    RAISE EXCEPTION 'notify_task_list_state requires a list'
      USING ERRCODE = 'BZ034', HINT = '{"type":"missing_list"}';
  END IF;

  UPDATE task_lists SET state_seq = state_seq + 1, updated_at = now()
  WHERE id = p_list_id
  RETURNING state_seq INTO v_state;
  IF v_state IS NULL THEN RETURN 0; END IF;  -- list vanished mid-txn: nothing to push

  FOR v_mb IN
    SELECT mb.id FROM task_list_members m
    JOIN mailboxes mb ON mb.user_id = m.user_id AND mb.is_primary
    WHERE m.list_id = p_list_id
  LOOP
    PERFORM app_notify('task:' || v_mb,
      jsonb_build_object('event', 'tasklist_changed', 'list_id', p_list_id,
                         'task_id', p_task_id, 'list_state', v_state::TEXT)::TEXT);
  END LOOP;
  RETURN v_state;
END;
$$ LANGUAGE plpgsql;
