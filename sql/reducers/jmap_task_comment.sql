-- Task comments + activity feed (QoL #17). The change-history half (status/
-- assignee/due change rows) is written inline by jmap_task_set_update in
-- jmap_task.sql; this file owns the user-authored comment path + the reader +
-- the @mention notification.
--
-- Shared task lists (Phase 1): task_comment_create/task_activity_list are
-- still called from the mailbox-scoped Task/TaskComment surface (CallScoped,
-- p_mailbox_id), so a shared task's feed must ALSO open for every list
-- member, not just the mailbox that owns the row's provenance. Their
-- ownership predicate gains an OR arm: the task is in a list AND the caller's
-- mailbox's user is a member of that list (task_list_role translates
-- mailbox→user once, the same address-aware posture as every other
-- cross-mailbox read here).

-- notify_task_mention: someone @mentioned in a task comment gets the same
-- "system message landed in the recipient's own mailbox" treatment as
-- notify_task_assignee — deliver() into the mentioned user's own primary
-- mailbox, so their normal unread count / IMAP IDLE / JMAP push picks it up.
-- Best-effort: called from inside task_comment_create's per-mention exception
-- block, so a delivery failure never unwinds the comment insert.
CREATE OR REPLACE FUNCTION notify_task_mention(
  p_author_mailbox_id BIGINT,
  p_task_id           BIGINT,
  p_mentioned_id      BIGINT,
  p_title             TEXT
) RETURNS VOID AS $$
DECLARE
  v_author_email    TEXT;
  v_author_name     TEXT;
  v_mentioned_email TEXT;
  v_body            TEXT;
BEGIN
  SELECT email, display_name INTO v_author_email, v_author_name
  FROM mailboxes WHERE id = p_author_mailbox_id;

  SELECT email INTO v_mentioned_email
  FROM mailboxes WHERE user_id = p_mentioned_id AND is_primary;

  IF v_mentioned_email IS NULL THEN
    RETURN; -- no primary mailbox to deliver into (defensive; nothing to notify)
  END IF;

  v_body := COALESCE(v_author_name, v_author_email, 'Someone') ||
    ' mentioned you in a task comment: ' || COALESCE(p_title, 'Untitled Task');

  PERFORM deliver(
    'task-mention/' || p_task_id::TEXT || '/' || extract(epoch FROM clock_timestamp())::BIGINT,
    '<task-mention-' || p_task_id::TEXT || '-' || extract(epoch FROM clock_timestamp())::BIGINT || '@mailserver.local>',
    COALESCE(v_author_email, 'tasks@mailserver.local'),
    COALESCE(v_author_name, 'Tasks'),
    v_mentioned_email,
    jsonb_build_array(jsonb_build_object('email', v_mentioned_email)),
    '[]'::JSONB, '[]'::JSONB,
    'You were mentioned in a task: ' || COALESCE(p_title, 'Untitled Task'),
    NULL, NULL,
    v_body, NULL,
    octet_length(v_body)::BIGINT, FALSE, now(),
    'pass', NULL, NULL, 0.0, NULL
  );
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;

-- task_comment_create: append a user comment to a task's activity feed, resolve
-- each @mention email to an internal user (BZ040 on unresolvable — mirrors
-- jmap_task's assigneeEmail path), then push on the existing task:{mailbox}
-- channel and best-effort notify each mentioned user (distinct from the author).
CREATE OR REPLACE FUNCTION task_comment_create(
  p_mailbox_id       BIGINT,
  p_task_id          BIGINT,
  p_body             TEXT,
  p_mentioned_emails JSONB DEFAULT '[]'::JSONB
) RETURNS JSONB AS $$
DECLARE
  v_author_user_id BIGINT;
  v_title          TEXT;
  v_email          TEXT;
  v_uid            BIGINT;
  v_mentioned      BIGINT[] := '{}';
  v_activity_id    BIGINT;
BEGIN
  -- R1 ownership: the task must belong to the caller's mailbox, OR (shared
  -- task lists Phase 1) live in a list the caller's mailbox-owning user is a
  -- member of. Also resolves the author + title in one shot.
  SELECT t.title INTO v_title
  FROM tasks t WHERE t.id = p_task_id
    AND (t.mailbox_id = p_mailbox_id
         OR (t.list_id IS NOT NULL AND task_list_role(
               t.list_id, (SELECT user_id FROM mailboxes WHERE id = p_mailbox_id)) IS NOT NULL));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'task % not found in mailbox', p_task_id
      USING ERRCODE = 'BZ041',
            HINT = '{"type":"notFound","detail":"task not in this mailbox"}';
  END IF;

  IF NULLIF(btrim(COALESCE(p_body, '')), '') IS NULL THEN
    RAISE EXCEPTION 'comment body is required'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","detail":"body is required"}';
  END IF;
  IF length(p_body) > 5000 THEN
    RAISE EXCEPTION 'comment body too long'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalidArguments","detail":"body exceeds 5000 chars"}';
  END IF;

  SELECT user_id INTO v_author_user_id FROM mailboxes WHERE id = p_mailbox_id;

  -- Resolve each @mention email to an internal users.id (address-aware, enabled
  -- users only) via the shared seam — same as jmap_task's assigneeEmail. An
  -- explicitly-provided but unresolvable email fails LOUD (BZ040), consistent
  -- with the assignment path; blanks are skipped.
  FOR v_email IN SELECT jsonb_array_elements_text(COALESCE(p_mentioned_emails, '[]'::JSONB))
  LOOP
    v_email := NULLIF(btrim(v_email), '');
    CONTINUE WHEN v_email IS NULL;
    SELECT user_id INTO v_uid FROM resolve_identity(v_email);
    IF v_uid IS NULL THEN
      RAISE EXCEPTION 'mention % does not resolve to an internal user', v_email
        USING ERRCODE = 'BZ040',
              HINT = '{"type":"invalidArguments","detail":"mention is not an internal user"}';
    END IF;
    IF NOT (v_uid = ANY(v_mentioned)) THEN
      v_mentioned := v_mentioned || v_uid;
    END IF;
  END LOOP;

  INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, body, mentioned_user_ids)
  VALUES (p_task_id, p_mailbox_id, v_author_user_id, 'comment', p_body, v_mentioned)
  RETURNING id INTO v_activity_id;

  -- Reuse the existing task push (no new channel). The comment isn't a Task/set,
  -- so there's no per-row jmap_state bump — this is a pure push to nudge any open
  -- activity view to re-read task_activity_list.
  PERFORM notify_task_state(p_mailbox_id, 'task_commented', p_task_id);

  -- Best-effort notify each mentioned user other than the author (mirrors the
  -- notify_task_assignee block: a delivery failure must NOT unwind the comment).
  FOREACH v_uid IN ARRAY v_mentioned
  LOOP
    IF v_uid IS DISTINCT FROM v_author_user_id THEN
      BEGIN
        PERFORM notify_task_mention(p_mailbox_id, p_task_id, v_uid, v_title);
      EXCEPTION WHEN OTHERS THEN
        NULL; -- ponytail: best-effort notification, not load-bearing for the comment
      END;
    END IF;
  END LOOP;

  RETURN jsonb_build_object('id', v_activity_id::TEXT);
END;
$$ LANGUAGE plpgsql;

-- task_activity_list: the ownership-checked feed reader — every activity row for
-- a task (comments + system change entries), author display resolved, oldest
-- first (a feed reads top-to-bottom chronologically).
CREATE OR REPLACE FUNCTION task_activity_list(
  p_mailbox_id BIGINT,
  p_task_id    BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB;
BEGIN
  -- R1 ownership check up front (no existence oracle on a foreign task), OR
  -- (shared task lists Phase 1) the caller's mailbox-owning user is a member
  -- of the task's list.
  PERFORM 1 FROM tasks WHERE id = p_task_id
    AND (mailbox_id = p_mailbox_id
         OR (list_id IS NOT NULL AND task_list_role(
               list_id, (SELECT user_id FROM mailboxes WHERE id = p_mailbox_id)) IS NOT NULL));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'task % not found in mailbox', p_task_id
      USING ERRCODE = 'BZ041',
            HINT = '{"type":"notFound","detail":"task not in this mailbox"}';
  END IF;

  -- The feed is scoped by task_id ALONE (ownership already proved above) —
  -- NOT also by a.mailbox_id: a shared task's activity rows carry whichever
  -- MEMBER authored each one (task_comment_create stamps the commenter's own
  -- mailbox_id), so re-filtering by the READER's mailbox_id would hide every
  -- other member's comments/system entries. For a personal (non-shared) task
  -- every row already carries the single owning mailbox_id, so this is a
  -- no-op there — byte-identical behavior, just no longer redundant.
  SELECT COALESCE(jsonb_agg(row ORDER BY row_created_at), '[]'::JSONB)
  INTO v_result
  FROM (
    SELECT
      a.created_at AS row_created_at,
      jsonb_build_object(
        'id', a.id::TEXT,
        'kind', a.kind,
        'body', a.body,
        'meta', a.meta,
        'authorName', COALESCE(u.display_name, u.email),
        'authorEmail', u.email,
        'mentionedUserIds', to_jsonb(a.mentioned_user_ids),
        'createdAt', a.created_at
      ) AS row
    FROM task_activity a
    JOIN users u ON u.id = a.author_user_id
    WHERE a.task_id = p_task_id
  ) sub;

  RETURN jsonb_build_object('accountId', p_mailbox_id::TEXT, 'list', v_result);
END;
$$ LANGUAGE plpgsql;
