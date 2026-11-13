-- JMAP Task/* reducers (JMAP Tasks draft)
--
-- Task reactivity is wired end-to-end (D2): Task/set create/update/destroy bump the
-- per-row tasks.jmap_state (the Task/changes token) on the row itself, then PERFORM
-- notify_task_state(p_mailbox_id, 'task_*', v_id) to push on 'task:{mailbox_id}'. The
-- seam is PUSH-ONLY (it does not re-bump — the per-row bump above already advanced the
-- token); routing the push through notify_task_state keeps the pg_notify out of this
-- file (app_notify capture seam + check-account-scope Check E).

CREATE OR REPLACE FUNCTION jmap_task_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_row       RECORD;
  v_state     BIGINT;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  v_state := entity_state(p_mailbox_id, 'Task');

  FOR v_row IN
    SELECT t.*,
      u.email AS assignee_email,
      u.display_name AS assignee_name
    FROM tasks t
    LEFT JOIN users u ON u.id = t.assignee_user_id
    WHERE t.mailbox_id = p_mailbox_id
      AND (p_ids IS NULL OR t.id = ANY(p_ids))
      -- Personal/shared split (shared task lists Phase 1): the unfiltered
      -- personal view excludes tasks that live in a shared list (they surface
      -- via TaskList/tasks + the assigned-to-me view instead) — a task moved
      -- into a list must leave the owner's personal Task list, not appear
      -- twice. An EXPLICIT id lookup (p_ids given — deep links) still resolves
      -- a list task as long as it's on the caller's own mailbox (ownership
      -- unchanged; list tasks keep mailbox_id = the creating member).
      AND (p_ids IS NOT NULL OR t.list_id IS NULL)
    -- Manual sort_order (QoL #20) leads: the client renders tasks in the order
    -- Task/get returns them (it re-sorts, ignoring the Task/query id order), so
    -- the persisted drag order MUST win here too — the old derived keys only
    -- break ties.
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
      'createdAt', v_row.created_at,
      'updatedAt', v_row.updated_at
    );
    v_found := v_found || v_row.id::TEXT;
  END LOOP;

  RETURN build_jmap_get_response(
    p_mailbox_id, v_state, v_result, v_found,
    CASE WHEN p_ids IS NOT NULL
      THEN ARRAY(SELECT x::TEXT FROM unnest(p_ids) AS x) END
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_task_query(
  p_mailbox_id  BIGINT,
  p_filter      JSONB DEFAULT NULL,
  p_sort        JSONB DEFAULT NULL,
  p_position    INT   DEFAULT 0,
  p_limit       INT   DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_state       BIGINT;
  v_ids         TEXT[];  -- JMAP Id[] is strings; BIGINT[] here fed numeric ids to Task/get ([]string) and 400'd every load
  v_total       INT;
  -- Personal/shared split (shared task lists Phase 1): Task/query is always
  -- the personal-view listing (no explicit-id deep-link concept here, unlike
  -- Task/get) — a list task never appears in it, full stop.
  v_where       TEXT := 'mailbox_id = $1 AND list_id IS NULL';
  v_order       TEXT := 'sort_order ASC, priority DESC, due_at NULLS LAST, created_at DESC';
  v_pat         TEXT;
BEGIN
  v_state := entity_state(p_mailbox_id, 'Task');

  IF p_filter IS NOT NULL THEN
    IF p_filter ? 'status' THEN
      v_where := v_where || format(' AND status = %L', p_filter->>'status');
    END IF;
    IF p_filter ? 'assignee' THEN
      v_where := v_where || format(' AND assignee_user_id = %s', (p_filter->>'assignee')::BIGINT);
    END IF;
    IF p_filter ? 'beforeDue' THEN
      v_where := v_where || format(' AND due_at < %L', p_filter->>'beforeDue');
    END IF;
    IF p_filter ? 'afterDue' THEN
      v_where := v_where || format(' AND due_at > %L', p_filter->>'afterDue');
    END IF;
    IF p_filter ? 'text' THEN
      v_pat := '%' || (p_filter->>'text') || '%';
      v_where := v_where || format(' AND (title ILIKE %L OR description ILIKE %L)',
        v_pat, v_pat);
    END IF;
    IF p_filter ? 'hasParent' THEN
      IF (p_filter->>'hasParent')::BOOL THEN
        v_where := v_where || ' AND parent_id IS NOT NULL';
      ELSE
        v_where := v_where || ' AND parent_id IS NULL';
      END IF;
    END IF;
  END IF;

  EXECUTE format('SELECT COUNT(*) FROM tasks WHERE %s', v_where)
    INTO v_total USING p_mailbox_id;

  EXECUTE format(
    'SELECT array_agg(id::TEXT) FROM (
      SELECT id FROM tasks WHERE %s ORDER BY %s LIMIT %s OFFSET %s
    ) sub',
    v_where, v_order, p_limit, p_position
  ) INTO v_ids USING p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state', v_state::TEXT,
    'canCalculateChanges', false,
    'position', p_position,
    'total', v_total,
    'ids', COALESCE(to_jsonb(v_ids), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;

-- Real Task/changes deltas (A4). The trg_journal_task trigger (V095) records
-- created/updated/destroyed rows in jmap_changes_journal at each bump of the
-- 'Task' entity_state counter; this delegates to the shared reader. Cascade
-- deletes (parent-task → subtasks) are journaled per-child by the row trigger,
-- so a subtask delete surfaces precisely instead of ghosting.
CREATE OR REPLACE FUNCTION jmap_task_changes(
  p_mailbox_id   BIGINT,
  p_since_state  TEXT
) RETURNS JSONB AS $$
  SELECT jmap_entity_changes(p_mailbox_id, 'Task', p_since_state, NULL);
$$ LANGUAGE sql;

-- notify_task_assignee: assigning a task to someone other than the task's OWNER
-- was a silent no-op (no email/push/visibility for the assignee) — this closes it
-- with the same "system message landed in the recipient's own mailbox" pattern
-- used elsewhere (mail_external_ndr, scheduled_action_dsn): deliver() inserts a
-- one-off notification into the assignee's own mailbox, so their normal unread
-- count / IMAP IDLE / JMAP push (all mailbox-keyed) picks it up for free — no new
-- cross-mailbox "assigned to me" view needed (that's a deferred L item).
-- Best-effort: called from inside a create/update's per-row exception block, so a
-- delivery failure (e.g. assignee over quota) must NOT unwind the task write —
-- callers wrap this in their own BEGIN/EXCEPTION and swallow.
CREATE OR REPLACE FUNCTION notify_task_assignee(
  p_owner_mailbox_id BIGINT,
  p_task_id          BIGINT,
  p_assignee_id      BIGINT,
  p_title            TEXT
) RETURNS VOID AS $$
DECLARE
  v_owner_email    TEXT;
  v_owner_name     TEXT;
  v_assignee_email TEXT;
  v_body           TEXT;
BEGIN
  SELECT email, display_name INTO v_owner_email, v_owner_name
  FROM mailboxes WHERE id = p_owner_mailbox_id;

  SELECT email INTO v_assignee_email
  FROM mailboxes WHERE user_id = p_assignee_id AND is_primary;

  IF v_assignee_email IS NULL THEN
    RETURN; -- no primary mailbox to deliver into (defensive; nothing to notify)
  END IF;

  v_body := COALESCE(v_owner_name, v_owner_email, 'Someone') ||
    ' assigned you a task: ' || COALESCE(p_title, 'Untitled Task');

  PERFORM deliver(
    'task-assign/' || p_task_id::TEXT || '/' || extract(epoch FROM clock_timestamp())::BIGINT,
    '<task-assign-' || p_task_id::TEXT || '-' || extract(epoch FROM clock_timestamp())::BIGINT || '@mailserver.local>',
    COALESCE(v_owner_email, 'tasks@mailserver.local'),
    COALESCE(v_owner_name, 'Tasks'),
    v_assignee_email,
    jsonb_build_array(jsonb_build_object('email', v_assignee_email)),
    '[]'::JSONB, '[]'::JSONB,
    'Task assigned to you: ' || COALESCE(p_title, 'Untitled Task'),
    NULL, NULL,
    v_body, NULL,
    octet_length(v_body)::BIGINT, FALSE, now(),
    'pass', NULL, NULL, 0.0, NULL
  );
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;

-- task_checklist_normalize (QoL #21): validate + normalize a client-supplied
-- checklist array — each item needs a non-empty `text` and (optional) boolean
-- `done`; a server-side `id` (gen_random_uuid) is assigned when absent so items
-- are stably addressable. Reused by create + update (whole-array replace). A
-- NULL/absent input normalizes to '[]'; a non-array or a bad item RAISEs BZ040.
CREATE OR REPLACE FUNCTION task_checklist_normalize(p_checklist JSONB)
RETURNS JSONB AS $$
DECLARE
  v_item JSONB;
  v_text TEXT;
  v_id   TEXT;
  v_out  JSONB := '[]'::JSONB;
BEGIN
  IF p_checklist IS NULL THEN RETURN '[]'::JSONB; END IF;
  IF jsonb_typeof(p_checklist) <> 'array' THEN
    RAISE EXCEPTION 'checklist must be an array'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","detail":"checklist must be an array"}';
  END IF;
  FOR v_item IN SELECT jsonb_array_elements(p_checklist)
  LOOP
    v_text := NULLIF(btrim(COALESCE(v_item->>'text', '')), '');
    IF v_text IS NULL THEN
      RAISE EXCEPTION 'checklist item text is required'
        USING ERRCODE = 'BZ040',
              HINT = '{"type":"invalidArguments","detail":"checklist item text is required"}';
    END IF;
    IF v_item ? 'done' AND jsonb_typeof(v_item->'done') <> 'boolean' THEN
      RAISE EXCEPTION 'checklist item done must be boolean'
        USING ERRCODE = 'BZ040',
              HINT = '{"type":"invalidArguments","detail":"checklist item done must be boolean"}';
    END IF;
    v_id := NULLIF(btrim(COALESCE(v_item->>'id', '')), '');
    IF v_id IS NULL THEN v_id := gen_random_uuid()::TEXT; END IF;
    v_out := v_out || jsonb_build_object(
      'id',   v_id,
      'text', v_text,
      'done', COALESCE((v_item->>'done')::BOOLEAN, FALSE)
    );
  END LOOP;
  RETURN v_out;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_task_set_create(
  p_mailbox_id BIGINT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_client_key    TEXT;
  v_obj           JSONB;
  v_id            BIGINT;
  v_created       JSONB := '{}'::JSONB;
  v_notCreated    JSONB := '{}'::JSONB;
  v_old_state     BIGINT;
  v_new_state     BIGINT;
  v_email         TEXT;
  v_assignee_id   BIGINT;
  v_owner_user_id BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'Task');

  SELECT user_id INTO v_owner_user_id FROM mailboxes WHERE id = p_mailbox_id;

  FOR v_client_key, v_obj IN SELECT * FROM jsonb_each(p_creates)
  LOOP
    BEGIN
      -- Assignment authz: resolve the client-supplied assigneeEmail to an INTERNAL
      -- users.id IN THE REDUCER (address-aware, enabled users only) via the shared
      -- resolve_identity seam. The raw client 'assigneeUserId' is NO LONGER honored
      -- — trusting it let a crafted id read back a foreign user's email/name through
      -- jmap_task_get (a cross-tenant PII enumeration oracle). An explicitly-provided
      -- but unresolvable email fails LOUD (BZ040 → this create lands in notCreated);
      -- an absent/blank email = unassigned (NULL), no error.
      v_email := NULLIF(btrim(v_obj->>'assigneeEmail'), '');
      v_assignee_id := NULL;
      IF v_email IS NOT NULL THEN
        SELECT user_id INTO v_assignee_id FROM resolve_identity(v_email);
        IF v_assignee_id IS NULL THEN
          RAISE EXCEPTION 'assigneeEmail % does not resolve to an internal user', v_email
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"invalidArguments","detail":"assigneeEmail is not an internal user"}';
        END IF;
      END IF;

      INSERT INTO tasks (
        mailbox_id, parent_id, title, description, status, priority,
        start_at, due_at, reminder_at, assignee_user_id,
        linked_message_id, linked_message_received_at, linked_event_id,
        categories, rrule, sort_order, checklist, jmap_state
      ) VALUES (
        p_mailbox_id,
        -- Reference ids come from client JSON; null any that don't belong to this
        -- mailbox so a task can't carry a dangling cross-tenant parent/link.
        (SELECT id FROM tasks WHERE id = (v_obj->>'parentId')::BIGINT AND mailbox_id = p_mailbox_id),
        COALESCE(v_obj->>'title', 'Untitled Task'),
        v_obj->>'description',
        COALESCE(v_obj->>'status', 'needs-action'),
        COALESCE((v_obj->>'priority')::INT, 0),
        (v_obj->>'startAt')::TIMESTAMPTZ,
        (v_obj->>'dueAt')::TIMESTAMPTZ,
        (v_obj->>'reminderAt')::TIMESTAMPTZ,
        v_assignee_id,
        (SELECT id FROM messages WHERE id = (v_obj->>'linkedMessageId')::BIGINT AND mailbox_id = p_mailbox_id),
        (v_obj->>'linkedMessageReceivedAt')::TIMESTAMPTZ,
        (SELECT ce.id FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id
          WHERE ce.id = (v_obj->>'linkedEventId')::BIGINT AND c.mailbox_id = p_mailbox_id),
        COALESCE(array(SELECT jsonb_array_elements_text(v_obj->'categories')), '{}'),
        v_obj->>'recurrenceRule',
        -- QoL #20: a brand-new task lands at the END of the manual order. A client
        -- sortOrder is honoured if sent, else MAX+1 for this mailbox.
        COALESCE((v_obj->>'sortOrder')::DOUBLE PRECISION,
                 (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM tasks WHERE mailbox_id = p_mailbox_id)),
        -- QoL #21: validate + assign item ids (defaults to '[]' when absent).
        task_checklist_normalize(v_obj->'checklist'),
        -- The Task/changes token is MAX(tasks.jmap_state). A literal 1 would not
        -- advance the cursor when the mailbox already has tasks past state 1, so a
        -- state-polling client would miss the create. Stamp MAX+1 (monotonic).
        (SELECT COALESCE(MAX(jmap_state), 0) + 1 FROM tasks WHERE mailbox_id = p_mailbox_id)
      )
      RETURNING id INTO v_id;

      -- Push on 'task:{mailbox_id}' through the task seam (the per-row jmap_state
      -- bump above already advanced the Task/changes token; the seam is push-only).
      PERFORM notify_task_state(p_mailbox_id, 'task_created', v_id);

      -- Assigned to someone other than the owner → notify them (closes the silent
      -- no-op). Nested BEGIN/EXCEPTION: a notify failure must not undo the create.
      IF v_assignee_id IS NOT NULL AND v_assignee_id IS DISTINCT FROM v_owner_user_id THEN
        BEGIN
          PERFORM notify_task_assignee(p_mailbox_id, v_id, v_assignee_id, v_obj->>'title');
        EXCEPTION WHEN OTHERS THEN
          NULL; -- ponytail: best-effort notification, not load-bearing for the create
        END;
      END IF;

      v_created := v_created || jsonb_build_object(
        v_client_key, jsonb_build_object('id', v_id::TEXT)
      );
    EXCEPTION WHEN OTHERS THEN
      v_notCreated := v_notCreated || jsonb_build_object(
        v_client_key, jsonb_build_object('type', 'invalidArguments', 'description', 'creation failed')
      );
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'Task');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_task_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id           BIGINT;
  v_patch        JSONB;
  v_updated      JSONB := '[]'::JSONB;
  v_notUpdated   JSONB := '{}'::JSONB;
  v_new_state    BIGINT;
  v_email        TEXT;
  v_assignee_id  BIGINT;
  v_assignee_set BOOLEAN;
  v_prev_status  TEXT;
  v_prev_assignee BIGINT;
  v_prev_due     TIMESTAMPTZ;
  v_row          tasks%ROWTYPE;
  v_anchor       TIMESTAMPTZ;
  v_next         TIMESTAMPTZ;
  v_delta        INTERVAL;
  v_rr_count     INT;
  v_new_rrule    TEXT;
  v_new_id       BIGINT;
  v_owner_user_id BIGINT;
BEGIN
  SELECT user_id INTO v_owner_user_id FROM mailboxes WHERE id = p_mailbox_id;

  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      -- Assignment authz (mirrors set_create): a PRESENT 'assigneeEmail' is resolved
      -- to an INTERNAL users.id in-reducer; empty/absent value = explicit unassign
      -- (NULL). The raw client 'assigneeUserId' is IGNORED — closing the enumeration
      -- oracle. An unresolvable-but-present email fails LOUD (BZ040 → notUpdated).
      v_assignee_set := v_patch ? 'assigneeEmail';
      v_assignee_id  := NULL;
      IF v_assignee_set THEN
        v_email := NULLIF(btrim(v_patch->>'assigneeEmail'), '');
        IF v_email IS NOT NULL THEN
          SELECT user_id INTO v_assignee_id FROM resolve_identity(v_email);
          IF v_assignee_id IS NULL THEN
            RAISE EXCEPTION 'assigneeEmail % does not resolve to an internal user', v_email
              USING ERRCODE = 'BZ040',
                    HINT = '{"type":"invalidArguments","detail":"assigneeEmail is not an internal user"}';
          END IF;
        END IF;
      END IF;

      -- Prior status (recurring-completion transition) + prior assignee (so we can
      -- tell an ACTUAL reassignment from a re-save of the same assignee) — SET refs
      -- see OLD values but the decisions below run after the UPDATE, so capture here.
      SELECT status, assignee_user_id, due_at INTO v_prev_status, v_prev_assignee, v_prev_due
      FROM tasks WHERE id = v_id AND mailbox_id = p_mailbox_id;

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
          -- Un-complete: the patch explicitly moves status off 'completed' → clear the
          -- stale stamp (guard on `? 'status'` so a plain edit to a completed task keeps it).
          WHEN v_patch ? 'status' AND v_patch->>'status' != 'completed' AND status = 'completed' THEN NULL
          ELSE completed_at
        END,
        assignee_user_id = CASE WHEN v_assignee_set THEN v_assignee_id ELSE assignee_user_id END,
        -- Only accept a linked id that belongs to this mailbox; a foreign/absent id
        -- resolves to NULL → COALESCE keeps the existing value (no dangling ref written).
        linked_message_id = COALESCE(
          (SELECT id FROM messages WHERE id = (v_patch->>'linkedMessageId')::BIGINT AND mailbox_id = p_mailbox_id),
          linked_message_id),
        linked_message_received_at = COALESCE((v_patch->>'linkedMessageReceivedAt')::TIMESTAMPTZ, linked_message_received_at),
        linked_event_id = COALESCE(
          (SELECT ce.id FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id
            WHERE ce.id = (v_patch->>'linkedEventId')::BIGINT AND c.mailbox_id = p_mailbox_id),
          linked_event_id),
        -- Subtask parent (guard on `? 'parentId'` so a plain edit leaves it alone):
        -- accept only a parent task IN THIS mailbox and never self (a foreign/dangling/
        -- self id resolves to NULL → the task becomes top-level rather than carrying a
        -- cross-tenant or self-cyclic parent). An explicit null/'' clears the parent.
        parent_id = CASE
          WHEN v_patch ? 'parentId' THEN
            (SELECT id FROM tasks WHERE id = NULLIF(v_patch->>'parentId', '')::BIGINT
               AND mailbox_id = p_mailbox_id AND id <> v_id)
          ELSE parent_id
        END,
        categories = COALESCE(array(SELECT jsonb_array_elements_text(v_patch->'categories')), categories),
        rrule = COALESCE(v_patch->>'recurrenceRule', rrule),
        -- QoL #20: drag/reorder rides the same Task/set path as every other field.
        sort_order = COALESCE((v_patch->>'sortOrder')::DOUBLE PRECISION, sort_order),
        -- QoL #21: whole-array replace ONLY when the key is present (an absent key
        -- on an unrelated edit must not wipe the checklist — task_checklist_normalize
        -- returns '[]' for a NULL input, so a plain COALESCE would clobber it).
        checklist = CASE WHEN v_patch ? 'checklist'
          THEN task_checklist_normalize(v_patch->'checklist') ELSE checklist END,
        updated_at = now(),
        jmap_state = jmap_state + 1
      WHERE id = v_id AND mailbox_id = p_mailbox_id
      RETURNING * INTO v_row;

      IF FOUND THEN
        v_updated := v_updated || to_jsonb(v_id);
        PERFORM notify_task_state(p_mailbox_id, 'task_updated', v_id);

        -- C1 fix: a shared-list task (v_row.list_id NOT NULL) still carries the
        -- CREATOR's mailbox_id, so it is reachable through this personal Task/set
        -- surface too (not just task_list_task_set). Without this, editing/
        -- destroying it here silently skipped task_lists.state_seq — other
        -- members' task_list_tasks poll never saw the change (state token frozen).
        IF v_row.list_id IS NOT NULL THEN
          PERFORM notify_task_list_state(v_row.list_id, 'task_updated', v_id);
        END IF;

        -- Change history (QoL #17): record a task_activity row whenever status,
        -- assignee, or due_at ACTUALLY changed — the system-entry half of the
        -- unified feed, written alongside the notify_task_assignee call below (not
        -- a new mechanism). author = the mailbox owner; meta carries old→new.
        IF v_row.status IS DISTINCT FROM v_prev_status THEN
          INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, meta)
          VALUES (v_id, p_mailbox_id, v_owner_user_id, 'status_change',
                  jsonb_build_object('old', v_prev_status, 'new', v_row.status));
        END IF;
        IF v_row.assignee_user_id IS DISTINCT FROM v_prev_assignee THEN
          INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, meta)
          VALUES (v_id, p_mailbox_id, v_owner_user_id, 'assignee_change',
                  jsonb_build_object('old', v_prev_assignee, 'new', v_row.assignee_user_id));
        END IF;
        IF v_row.due_at IS DISTINCT FROM v_prev_due THEN
          INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, meta)
          VALUES (v_id, p_mailbox_id, v_owner_user_id, 'due_change',
                  jsonb_build_object('old', v_prev_due, 'new', v_row.due_at));
        END IF;

        -- Reassigned to someone other than the owner → notify them, but only on an
        -- ACTUAL change of assignee (one-time notification, not a repeat on every
        -- unrelated edit that happens to re-send the same assigneeEmail).
        IF v_assignee_set AND v_assignee_id IS NOT NULL
           AND v_assignee_id IS DISTINCT FROM v_owner_user_id
           AND v_assignee_id IS DISTINCT FROM v_prev_assignee THEN
          BEGIN
            PERFORM notify_task_assignee(p_mailbox_id, v_id, v_assignee_id, v_row.title);
          EXCEPTION WHEN OTHERS THEN
            NULL; -- ponytail: best-effort notification, not load-bearing for the update
          END;
        END IF;

        -- Recurring regeneration: on the fresh transition into 'completed' of a task
        -- that carries an rrule, spawn the NEXT occurrence as a new needs-action task
        -- scoped to this mailbox. Bounds (data-bloat / infinite-chain guard): COUNT is
        -- decremented per spawn so a COUNT-bounded series stops at its last occurrence,
        -- and UNTIL is honoured by expand_recurrence (no occurrence strictly after the
        -- anchor ⇒ no spawn). The anchor is strictly-after the current due_at (or
        -- start_at) so the same date is never re-spawned.
        IF v_patch->>'status' = 'completed'
           AND COALESCE(v_prev_status, '') <> 'completed'
           AND v_row.rrule IS NOT NULL AND v_row.rrule <> '' THEN

          v_rr_count := substring(v_row.rrule FROM 'COUNT=(\d+)')::INT;
          v_anchor   := COALESCE(v_row.due_at, v_row.start_at);

          -- COUNT<=1 ⇒ this WAS the final occurrence; a NULL anchor ⇒ no date to shift.
          IF v_anchor IS NOT NULL AND (v_rr_count IS NULL OR v_rr_count > 1) THEN
            -- Re-anchor the expansion at the current occurrence (itself a valid series
            -- point, so the forward sequence/phase is preserved) and take the first
            -- occurrence strictly after it. UNTIL (absolute) still bounds the walk.
            SELECT MIN(occ_start) INTO v_next
            FROM expand_recurrence(v_anchor, v_anchor, v_row.rrule,
                                   v_anchor + INTERVAL '1 microsecond',
                                   'infinity'::TIMESTAMPTZ)
            WHERE occ_start > v_anchor;

            IF v_next IS NOT NULL THEN
              v_delta := v_next - v_anchor;
              -- Decrement COUNT on the copy so the regeneration chain stays bounded.
              v_new_rrule := CASE WHEN v_rr_count IS NOT NULL
                THEN regexp_replace(v_row.rrule, 'COUNT=\d+', 'COUNT=' || (v_rr_count - 1))
                ELSE v_row.rrule END;

              INSERT INTO tasks (
                mailbox_id, parent_id, title, description, status, priority,
                start_at, due_at, reminder_at, assignee_user_id,
                linked_message_id, linked_message_received_at, linked_event_id,
                categories, rrule, sort_order, jmap_state
              ) VALUES (
                p_mailbox_id, v_row.parent_id, v_row.title, v_row.description,
                'needs-action', v_row.priority,
                CASE WHEN v_row.start_at    IS NOT NULL THEN v_row.start_at    + v_delta END,
                CASE WHEN v_row.due_at      IS NOT NULL THEN v_row.due_at      + v_delta END,
                CASE WHEN v_row.reminder_at IS NOT NULL THEN v_row.reminder_at + v_delta END,
                v_row.assignee_user_id,
                v_row.linked_message_id, v_row.linked_message_received_at, v_row.linked_event_id,
                v_row.categories, v_new_rrule,
                -- QoL #20: the spawned successor appends at the end of the manual order.
                (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM tasks WHERE mailbox_id = p_mailbox_id),
                (SELECT COALESCE(MAX(jmap_state), 0) + 1 FROM tasks WHERE mailbox_id = p_mailbox_id)
              )
              RETURNING id INTO v_new_id;

              PERFORM notify_task_state(p_mailbox_id, 'task_created', v_new_id);
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

  v_new_state := entity_state(p_mailbox_id, 'Task');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', (v_new_state - 1)::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_task_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_id           BIGINT;
  v_list_id      BIGINT;
  v_destroyed    JSONB := '[]'::JSONB;
  v_notDestroyed JSONB := '{}'::JSONB;
  v_new_state    BIGINT;
BEGIN
  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      DELETE FROM tasks
      WHERE id = v_id AND mailbox_id = p_mailbox_id
      RETURNING list_id INTO v_list_id;

      IF FOUND THEN
        v_destroyed := v_destroyed || to_jsonb(v_id);
        PERFORM notify_task_state(p_mailbox_id, 'task_destroyed', v_id);
        -- C1 fix: same shared-list reachability gap as jmap_task_set_update.
        IF v_list_id IS NOT NULL THEN
          PERFORM notify_task_list_state(v_list_id, 'task_destroyed', v_id);
        END IF;
      ELSE
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'task not found'));
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'serverFail', 'description', 'destroy failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'Task');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', (v_new_state - 1)::TEXT,
    'newState', v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;
