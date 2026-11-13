-- tasks_assigned.sql — "Assigned to me": a cross-mailbox read + status-only
-- mutation for tasks assigned to the caller (plan 2026-07-08-shared-team-
-- task-lists.md, Phase 1). Scope note: this INCLUDES self-assigned own-mailbox
-- tasks — the view is "everything assigned to me"; the webmail may visually
-- dedupe the personal-view overlap (`listId == null && ownerEmail == me`) but
-- the reducer does not special-case it.
--
-- Error codes: BZ132 = task not assigned to caller / caller no longer a list
-- member (404-indistinguishable, no oracle — the task_list_tasks.sql band);
-- BZ133 = invalid arguments (bad status value).

-- tasks_assigned_to_me: THE cross-mailbox read. R1 = assignee_user_id =
-- p_user_id in the one statement; for list tasks the assignee must STILL be a
-- member (removal from a list revokes visibility even of your own
-- assignments — the membership predicate is the visibility authority,
-- assignment alone is not). Runs on workerPool (BYPASS posture) like every
-- sharing read; the projection is the full task shape + provenance
-- (owner/list) — the assignee may read, and may mutate ONLY status
-- (task_assignee_set_status below).
CREATE OR REPLACE FUNCTION tasks_assigned_to_me(p_user_id BIGINT)
RETURNS JSONB AS $$
DECLARE
  v_out JSONB := '[]'::JSONB;
  v_row RECORD;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'tasks_assigned_to_me requires a user'
      USING ERRCODE = 'BZ034', HINT = '{"type":"missing_user"}';
  END IF;
  FOR v_row IN
    SELECT t.*, tl.name AS list_name,
           mb.email AS owner_email, mb.display_name AS owner_name
    FROM tasks t
    LEFT JOIN task_lists tl ON tl.id = t.list_id
    JOIN mailboxes mb ON mb.id = t.mailbox_id
    WHERE t.assignee_user_id = p_user_id
      AND (t.list_id IS NULL OR task_list_role(t.list_id, p_user_id) IS NOT NULL)
    ORDER BY (t.status IN ('completed','cancelled')), t.due_at NULLS LAST, t.priority DESC, t.created_at DESC
  LOOP
    v_out := v_out || jsonb_build_object(
      'id', v_row.id::TEXT, 'title', v_row.title, 'description', v_row.description,
      'status', v_row.status, 'priority', v_row.priority,
      'startAt', v_row.start_at, 'dueAt', v_row.due_at, 'completedAt', v_row.completed_at,
      'checklist', COALESCE(v_row.checklist, '[]'::JSONB),
      'listId', v_row.list_id::TEXT, 'listName', v_row.list_name,
      'ownerEmail', v_row.owner_email, 'ownerName', v_row.owner_name,
      'updatedAt', v_row.updated_at);
  END LOOP;
  RETURN v_out;
END;
$$ LANGUAGE plpgsql;

-- task_assignee_set_status: the assignee's ONE legal mutation — status.
-- Single R3 statement carries the ownership/membership predicate in the same
-- WHERE as the UPDATE (no TOCTOU); 0 rows → BZ132 (no oracle). No recurring-
-- spawn here (ponytail: the spawn belongs to the owner/list edit paths — an
-- assignee completing a recurring personal task pings the owner, who owns
-- the series; add assignee-side spawning if a future request asks for it).
CREATE OR REPLACE FUNCTION task_assignee_set_status(
  p_user_id BIGINT,
  p_task_id BIGINT,
  p_status  TEXT
) RETURNS JSONB AS $$
DECLARE
  v_row tasks%ROWTYPE;
BEGIN
  IF p_status IS NULL OR p_status NOT IN ('needs-action', 'in-progress', 'completed', 'cancelled') THEN
    RAISE EXCEPTION 'invalid task status %', p_status
      USING ERRCODE = 'BZ133', HINT = '{"type":"invalidArguments","detail":"invalid status"}';
  END IF;

  UPDATE tasks SET
    status = p_status,
    completed_at = CASE
      WHEN p_status = 'completed' AND status != 'completed' THEN now()
      WHEN p_status != 'completed' AND status = 'completed' THEN NULL
      ELSE completed_at
    END,
    updated_at = now(),
    jmap_state = jmap_state + 1
  WHERE id = p_task_id
    AND assignee_user_id = p_user_id
    AND (list_id IS NULL OR task_list_role(list_id, p_user_id) IS NOT NULL)
  RETURNING * INTO v_row;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'task not found or not assigned to caller'
      USING ERRCODE = 'BZ132', HINT = '{"type":"notFound"}';
  END IF;

  INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, meta)
  VALUES (p_task_id, v_row.mailbox_id, p_user_id, 'status_change',
          jsonb_build_object('old', NULL, 'new', v_row.status));

  -- The OWNER's personal view syncs via the task secondary seam (their own
  -- mailbox channel); a list task ALSO gets the list seam so every member's
  -- board re-fetches.
  PERFORM notify_task_state(v_row.mailbox_id, 'task_updated', p_task_id);
  IF v_row.list_id IS NOT NULL THEN
    PERFORM notify_task_list_state(v_row.list_id, 'task_updated', p_task_id);
  END IF;

  RETURN jsonb_build_object('id', v_row.id::TEXT, 'status', v_row.status);
END;
$$ LANGUAGE plpgsql;
