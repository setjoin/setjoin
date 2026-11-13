-- task_list_tasks.sql — member-scoped read/write over shared-list tasks
-- (plan 2026-07-08-shared-team-task-lists.md, Phase 1). THE cross-mailbox
-- surface: any list member may read/create/edit/destroy any task in a list
-- they belong to (Planner semantics — roles beyond owner/member are Phase 2).
-- Every reducer takes p_user_id + p_list_id and gates on task_list_role
-- (R1); mutations carry `AND list_id = p_list_id` in the same WHERE as the
-- write (R3 — a foreign/personal task id is unreachable through this path).
--
-- Error codes: BZ132 = caller is not a list member (404-indistinguishable, no
-- membership oracle); BZ133 = invalid arguments (assignee not a list member,
-- bad status, caller has no primary mailbox to create into).

-- task_list_tasks: the member-scoped read — same JSONB shape as jmap_task_get
-- (the webmail Task type is reused verbatim) plus listId/creatorEmail/
-- creatorName so members can see whose task it is. Wrapped with the list's
-- OWN sync token (task_lists.state_seq), not the creator's per-mailbox one.
CREATE OR REPLACE FUNCTION task_list_tasks(
  p_user_id BIGINT,
  p_list_id BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_state  BIGINT;
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  IF task_list_role(p_list_id, p_user_id) IS NULL THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ132', HINT = '{"type":"notFound"}';
  END IF;

  SELECT state_seq INTO v_state FROM task_lists WHERE id = p_list_id;

  FOR v_row IN
    SELECT t.*,
      au.email AS assignee_email, au.display_name AS assignee_name,
      mb.email AS creator_email, mb.display_name AS creator_name
    FROM tasks t
    LEFT JOIN users au ON au.id = t.assignee_user_id
    JOIN mailboxes mb ON mb.id = t.mailbox_id
    WHERE t.list_id = p_list_id
    ORDER BY t.sort_order ASC, t.priority DESC, t.due_at NULLS LAST, t.created_at DESC
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'title', v_row.title,
      'description', v_row.description,
      'status', v_row.status,
      'priority', v_row.priority,
      'startAt', v_row.start_at,
      'dueAt', v_row.due_at,
      'reminderAt', v_row.reminder_at,
      'completedAt', v_row.completed_at,
      'assigneeUserId', v_row.assignee_user_id::TEXT,
      'assigneeEmail', v_row.assignee_email,
      'assigneeName', v_row.assignee_name,
      'parentId', v_row.parent_id::TEXT,
      'linkedMessageId', v_row.linked_message_id::TEXT,
      'linkedEventId', v_row.linked_event_id::TEXT,
      'categories', v_row.categories,
      'recurrenceRule', v_row.rrule,
      'sortOrder', v_row.sort_order,
      'checklist', COALESCE(v_row.checklist, '[]'::JSONB),
      'listId', v_row.list_id::TEXT,
      'creatorEmail', v_row.creator_email,
      'creatorName', v_row.creator_name,
      'createdAt', v_row.created_at,
      'updatedAt', v_row.updated_at
    );
  END LOOP;

  RETURN jsonb_build_object('listId', p_list_id::TEXT, 'state', v_state::TEXT, 'list', v_result);
END;
$$ LANGUAGE plpgsql;

-- task_list_task_set: the member-scoped mirror of jmap_task_set_{create,
-- update,destroy} collapsed into one call (a user-scoped surface has no
-- CallScopedBatch to fan out over) — one shared membership gate up front,
-- then per-key create/update/destroy phases, each in its own exception block
-- (a single bad key never aborts its siblings). Returns the RFC 8620 Set
-- shape with oldState/newState from task_lists.state_seq (the list's own
-- sync token — distinct from any member's personal Task/changes cursor).
CREATE OR REPLACE FUNCTION task_list_task_set(
  p_user_id  BIGINT,
  p_list_id  BIGINT,
  p_creates  JSONB DEFAULT NULL,
  p_updates  JSONB DEFAULT NULL,
  p_destroys JSONB DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_mailbox_id    BIGINT;
  v_old_state     BIGINT;
  v_new_state     BIGINT;
  v_created       JSONB := '{}'::JSONB;
  v_notCreated    JSONB := '{}'::JSONB;
  v_updated       JSONB := '[]'::JSONB;
  v_notUpdated    JSONB := '{}'::JSONB;
  v_destroyed     JSONB := '[]'::JSONB;
  v_notDestroyed  JSONB := '{}'::JSONB;
  v_client_key    TEXT;
  v_obj           JSONB;
  v_patch         JSONB;
  v_id            BIGINT;
  v_email         TEXT;
  v_assignee_id   BIGINT;
  v_assignee_set  BOOLEAN;
  v_row           tasks%ROWTYPE;
  v_prev_status   TEXT;
  v_prev_assignee BIGINT;
  v_prev_due      TIMESTAMPTZ;
  v_new_id        BIGINT;
  v_anchor        TIMESTAMPTZ;
  v_next          TIMESTAMPTZ;
  v_delta         INTERVAL;
  v_rr_count      INT;
  v_new_rrule     TEXT;
BEGIN
  IF task_list_role(p_list_id, p_user_id) IS NULL THEN
    RAISE EXCEPTION 'task list not found'
      USING ERRCODE = 'BZ132', HINT = '{"type":"notFound"}';
  END IF;

  SELECT state_seq INTO v_old_state FROM task_lists WHERE id = p_list_id;

  -- ── create ────────────────────────────────────────────────────────────
  IF p_creates IS NOT NULL THEN
    SELECT id INTO v_mailbox_id FROM mailboxes WHERE user_id = p_user_id AND is_primary;

    FOR v_client_key, v_obj IN SELECT * FROM jsonb_each(p_creates)
    LOOP
      BEGIN
        IF v_mailbox_id IS NULL THEN
          RAISE EXCEPTION 'caller has no primary mailbox'
            USING ERRCODE = 'BZ133', HINT = '{"type":"invalidArguments","detail":"no primary mailbox"}';
        END IF;

        v_email := NULLIF(btrim(v_obj->>'assigneeEmail'), '');
        v_assignee_id := NULL;
        IF v_email IS NOT NULL THEN
          SELECT user_id INTO v_assignee_id FROM resolve_identity(v_email);
          IF v_assignee_id IS NULL OR task_list_role(p_list_id, v_assignee_id) IS NULL THEN
            RAISE EXCEPTION 'assigneeEmail % is not a member of this list', v_email
              USING ERRCODE = 'BZ133', HINT = '{"type":"invalidArguments","detail":"assignee is not a list member"}';
          END IF;
        END IF;

        INSERT INTO tasks (
          mailbox_id, list_id, parent_id, title, description, status, priority,
          start_at, due_at, reminder_at, assignee_user_id,
          linked_message_id, linked_message_received_at, linked_event_id,
          categories, rrule, sort_order, checklist, jmap_state
        ) VALUES (
          v_mailbox_id, p_list_id,
          (SELECT id FROM tasks WHERE id = (v_obj->>'parentId')::BIGINT AND list_id = p_list_id),
          COALESCE(v_obj->>'title', 'Untitled Task'),
          v_obj->>'description',
          COALESCE(v_obj->>'status', 'needs-action'),
          COALESCE((v_obj->>'priority')::INT, 0),
          (v_obj->>'startAt')::TIMESTAMPTZ,
          (v_obj->>'dueAt')::TIMESTAMPTZ,
          (v_obj->>'reminderAt')::TIMESTAMPTZ,
          v_assignee_id,
          (SELECT id FROM messages WHERE id = (v_obj->>'linkedMessageId')::BIGINT AND mailbox_id = v_mailbox_id),
          (v_obj->>'linkedMessageReceivedAt')::TIMESTAMPTZ,
          (SELECT ce.id FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id
            WHERE ce.id = (v_obj->>'linkedEventId')::BIGINT AND c.mailbox_id = v_mailbox_id),
          COALESCE(array(SELECT jsonb_array_elements_text(v_obj->'categories')), '{}'),
          v_obj->>'recurrenceRule',
          -- Board order is PER-LIST (the plan's "board order is per-list" call).
          COALESCE((v_obj->>'sortOrder')::DOUBLE PRECISION,
                   (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM tasks WHERE list_id = p_list_id)),
          task_checklist_normalize(v_obj->'checklist'),
          -- Per-row jmap_state stays scoped to the creator's MAILBOX (not the
          -- list) — trg_journal_task (V095) journals this write under
          -- v_mailbox_id automatically, keeping the creator's own personal
          -- Task/changes cursor truthful even though the row is list-owned.
          (SELECT COALESCE(MAX(jmap_state), 0) + 1 FROM tasks WHERE mailbox_id = v_mailbox_id)
        )
        RETURNING id INTO v_id;

        PERFORM notify_task_list_state(p_list_id, 'task_created', v_id);

        IF v_assignee_id IS NOT NULL AND v_assignee_id IS DISTINCT FROM p_user_id THEN
          BEGIN
            PERFORM notify_task_assignee(v_mailbox_id, v_id, v_assignee_id, v_obj->>'title');
          EXCEPTION WHEN OTHERS THEN
            NULL; -- ponytail: best-effort notification, not load-bearing for the create
          END;
        END IF;

        v_created := v_created || jsonb_build_object(v_client_key, jsonb_build_object('id', v_id::TEXT));
      EXCEPTION WHEN OTHERS THEN
        v_notCreated := v_notCreated || jsonb_build_object(
          v_client_key, jsonb_build_object('type', 'invalidArguments', 'description', 'creation failed'));
      END;
    END LOOP;
  END IF;

  -- ── update ────────────────────────────────────────────────────────────
  IF p_updates IS NOT NULL THEN
    FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
    LOOP
      BEGIN
        v_assignee_set := v_patch ? 'assigneeEmail';
        v_assignee_id  := NULL;
        IF v_assignee_set THEN
          v_email := NULLIF(btrim(v_patch->>'assigneeEmail'), '');
          IF v_email IS NOT NULL THEN
            SELECT user_id INTO v_assignee_id FROM resolve_identity(v_email);
            IF v_assignee_id IS NULL OR task_list_role(p_list_id, v_assignee_id) IS NULL THEN
              RAISE EXCEPTION 'assigneeEmail % is not a member of this list', v_email
                USING ERRCODE = 'BZ133', HINT = '{"type":"invalidArguments","detail":"assignee is not a list member"}';
            END IF;
          END IF;
        END IF;

        SELECT status, assignee_user_id, due_at INTO v_prev_status, v_prev_assignee, v_prev_due
        FROM tasks WHERE id = v_id AND list_id = p_list_id;

        UPDATE tasks SET
          title = COALESCE(v_patch->>'title', title),
          description = COALESCE(v_patch->>'description', description),
          status = COALESCE(v_patch->>'status', status),
          priority = COALESCE((v_patch->>'priority')::INT, priority),
          start_at = COALESCE((v_patch->>'startAt')::TIMESTAMPTZ, start_at),
          due_at = COALESCE((v_patch->>'dueAt')::TIMESTAMPTZ, due_at),
          reminder_at = COALESCE((v_patch->>'reminderAt')::TIMESTAMPTZ, reminder_at),
          completed_at = CASE
            WHEN v_patch->>'status' = 'completed' AND status != 'completed' AND NOT v_patch ? 'completedAt' THEN now()
            WHEN v_patch ? 'completedAt' THEN (v_patch->>'completedAt')::TIMESTAMPTZ
            WHEN v_patch ? 'status' AND v_patch->>'status' != 'completed' AND status = 'completed' THEN NULL
            ELSE completed_at
          END,
          assignee_user_id = CASE WHEN v_assignee_set THEN v_assignee_id ELSE assignee_user_id END,
          parent_id = CASE
            WHEN v_patch ? 'parentId' THEN
              (SELECT id FROM tasks WHERE id = NULLIF(v_patch->>'parentId', '')::BIGINT
                 AND list_id = p_list_id AND id <> v_id)
            ELSE parent_id
          END,
          categories = COALESCE(array(SELECT jsonb_array_elements_text(v_patch->'categories')), categories),
          rrule = COALESCE(v_patch->>'recurrenceRule', rrule),
          sort_order = COALESCE((v_patch->>'sortOrder')::DOUBLE PRECISION, sort_order),
          checklist = CASE WHEN v_patch ? 'checklist'
            THEN task_checklist_normalize(v_patch->'checklist') ELSE checklist END,
          updated_at = now(),
          jmap_state = jmap_state + 1
        WHERE id = v_id AND list_id = p_list_id
        RETURNING * INTO v_row;

        IF FOUND THEN
          v_updated := v_updated || to_jsonb(v_id);
          PERFORM notify_task_list_state(p_list_id, 'task_updated', v_id);

          IF v_row.status IS DISTINCT FROM v_prev_status THEN
            INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, meta)
            VALUES (v_id, v_row.mailbox_id, p_user_id, 'status_change',
                    jsonb_build_object('old', v_prev_status, 'new', v_row.status));
          END IF;
          IF v_row.assignee_user_id IS DISTINCT FROM v_prev_assignee THEN
            INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, meta)
            VALUES (v_id, v_row.mailbox_id, p_user_id, 'assignee_change',
                    jsonb_build_object('old', v_prev_assignee, 'new', v_row.assignee_user_id));
          END IF;
          IF v_row.due_at IS DISTINCT FROM v_prev_due THEN
            INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, meta)
            VALUES (v_id, v_row.mailbox_id, p_user_id, 'due_change',
                    jsonb_build_object('old', v_prev_due, 'new', v_row.due_at));
          END IF;

          IF v_assignee_set AND v_assignee_id IS NOT NULL
             AND v_assignee_id IS DISTINCT FROM v_prev_assignee THEN
            BEGIN
              PERFORM notify_task_assignee(v_row.mailbox_id, v_id, v_assignee_id, v_row.title);
            EXCEPTION WHEN OTHERS THEN
              NULL; -- ponytail: best-effort notification, not load-bearing for the update
            END;
          END IF;

          -- Recurring regeneration (mirrors jmap_task_set_update): the
          -- spawned successor carries list_id forward so the series stays
          -- in the same shared list.
          IF v_patch->>'status' = 'completed'
             AND COALESCE(v_prev_status, '') <> 'completed'
             AND v_row.rrule IS NOT NULL AND v_row.rrule <> '' THEN

            v_rr_count := substring(v_row.rrule FROM 'COUNT=(\d+)')::INT;
            v_anchor   := COALESCE(v_row.due_at, v_row.start_at);

            IF v_anchor IS NOT NULL AND (v_rr_count IS NULL OR v_rr_count > 1) THEN
              SELECT MIN(occ_start) INTO v_next
              FROM expand_recurrence(v_anchor, v_anchor, v_row.rrule,
                                     v_anchor + INTERVAL '1 microsecond',
                                     'infinity'::TIMESTAMPTZ)
              WHERE occ_start > v_anchor;

              IF v_next IS NOT NULL THEN
                v_delta := v_next - v_anchor;
                v_new_rrule := CASE WHEN v_rr_count IS NOT NULL
                  THEN regexp_replace(v_row.rrule, 'COUNT=\d+', 'COUNT=' || (v_rr_count - 1))
                  ELSE v_row.rrule END;

                INSERT INTO tasks (
                  mailbox_id, list_id, parent_id, title, description, status, priority,
                  start_at, due_at, reminder_at, assignee_user_id,
                  linked_message_id, linked_message_received_at, linked_event_id,
                  categories, rrule, sort_order, jmap_state
                ) VALUES (
                  v_row.mailbox_id, p_list_id, v_row.parent_id, v_row.title, v_row.description,
                  'needs-action', v_row.priority,
                  CASE WHEN v_row.start_at    IS NOT NULL THEN v_row.start_at    + v_delta END,
                  CASE WHEN v_row.due_at      IS NOT NULL THEN v_row.due_at      + v_delta END,
                  CASE WHEN v_row.reminder_at IS NOT NULL THEN v_row.reminder_at + v_delta END,
                  v_row.assignee_user_id,
                  v_row.linked_message_id, v_row.linked_message_received_at, v_row.linked_event_id,
                  v_row.categories, v_new_rrule,
                  (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM tasks WHERE list_id = p_list_id),
                  (SELECT COALESCE(MAX(jmap_state), 0) + 1 FROM tasks WHERE mailbox_id = v_row.mailbox_id)
                )
                RETURNING id INTO v_new_id;

                PERFORM notify_task_list_state(p_list_id, 'task_created', v_new_id);
              END IF;
            END IF;
          END IF;
        ELSE
          v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
            jsonb_build_object('type', 'notFound', 'description', 'task not found'));
        END IF;
      EXCEPTION WHEN OTHERS THEN
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'invalidArguments', 'description', 'update failed'));
      END;
    END LOOP;
  END IF;

  -- ── destroy ───────────────────────────────────────────────────────────
  IF p_destroys IS NOT NULL THEN
    FOR v_id IN SELECT jsonb_array_elements_text(p_destroys)::BIGINT
    LOOP
      BEGIN
        DELETE FROM tasks WHERE id = v_id AND list_id = p_list_id;
        IF FOUND THEN
          v_destroyed := v_destroyed || to_jsonb(v_id);
          PERFORM notify_task_list_state(p_list_id, 'task_destroyed', v_id);
        ELSE
          v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
            jsonb_build_object('type', 'notFound', 'description', 'task not found'));
        END IF;
      EXCEPTION WHEN OTHERS THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'serverFail', 'description', 'destroy failed'));
      END;
    END LOOP;
  END IF;

  SELECT state_seq INTO v_new_state FROM task_lists WHERE id = p_list_id;

  RETURN jsonb_build_object(
    'listId', p_list_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created, 'notCreated', v_notCreated,
    'updated', v_updated, 'notUpdated', v_notUpdated,
    'destroyed', v_destroyed, 'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;
