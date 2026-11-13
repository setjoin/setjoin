-- notify_task_state.sql: the single owner of "a task changed → push on
-- task:{mailbox_id}". The task secondary seam (mirrors notify_contact_state /
-- notify_calendar_state): static SQL, one channel + one payload.
--
-- Contract — PUSH-ONLY (B1a):
--   * Tasks carry a PER-ROW tasks.jmap_state (the Task/changes token), bumped by
--     jmap_task_set_{create,update,destroy} on the row itself. Unlike calendars/
--     contacts — where the seam owns the domain bump — this seam DOES NOT bump:
--     the per-row bump already advanced the token in jmap_task.sql, and bumping
--     again here would double-count. The seam's job is ONLY the push + the channel.
--   * Reads (does not advance) the new MAX(tasks.jmap_state) for the mailbox so the
--     return value is the current Task/changes sync cursor, and pushes on the
--     canonical 'task:{mailbox_id}' channel with {event,task_id}.
--   * Returns the current MAX(tasks.jmap_state) for the mailbox (0 if the mailbox
--     has no tasks — e.g. immediately after a destroy that emptied the mailbox).
--
-- Routing ALL task pushes through this seam (never an inline pg_notify in
-- jmap_task.sql) keeps app_notify the single capturable choke point
-- (check-app-notify.sh) AND keeps the per-row bump in jmap_task.sql free of an
-- adjacent pg_notify, so check-account-scope.sh Check E never fires on
-- jmap_task.sql (this file is allowlisted for E alongside the other seam owners).
--
-- p_mailbox_id — the owning mailbox id (required; BZ034 if NULL).
-- p_event      — the event name ('task_created' | 'task_updated' |
--   'task_destroyed'), preserved verbatim.
-- p_task_id    — the changed task id, or NULL.
CREATE OR REPLACE FUNCTION notify_task_state(
  p_mailbox_id BIGINT,
  p_event      TEXT,
  p_task_id    BIGINT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_task_state requires a mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  SELECT COALESCE(MAX(jmap_state), 0) INTO v_state
  FROM tasks WHERE mailbox_id = p_mailbox_id;

  PERFORM app_notify(
    'task:' || p_mailbox_id,
    jsonb_build_object(
      'event',   p_event,
      'task_id', p_task_id
    )::TEXT
  );

  RETURN v_state;
END;
$$ LANGUAGE plpgsql;
