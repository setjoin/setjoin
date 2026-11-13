-- notify_state_change.sql: the single owner of "a thing changed → bump the
-- right JMAP state channels → push". Every mutating path that changes message
-- or tag visibility calls this instead of open-coding bump_email_state /
-- bump_tag_mailbox_state / pg_notify.
--
-- Contract:
--   * Always bumps mailboxes.jmap_email_state (returns the new value).
--   * Bumps mailboxes.jmap_tag_state ONLY when p_tag_id is non-NULL (a specific
--     tag's membership changed). The per-tag tags.jmap_state is owned by the
--     message_tags counter trigger (030_message_tags.sql) and is NOT touched
--     here — that prevents the per-tag double-bump.
--   * Pushes on the canonical 'tag:{mailbox_id}' channel with a uniform payload.
--   * When p_message_id + p_op are both non-NULL, appends a PRECISE journal row
--     to jmap_changes_journal in the SAME txn as the state bump (offline #3).
--     When either is NULL (legacy 2-arg callers, pure-tag ops), appends a 'resync'
--     sentinel so every state bump has a journal record. Task 4 upgrades each
--     site to pass message_id, converting sentinels to precise rows.
--
-- p_mailbox_id — owning mailbox (required; BZ034 if NULL).
-- p_tag_id     — changed tag, or NULL for a mailbox-wide change (no tag bump).
-- p_message_id — message that changed (DEFAULT NULL → no journal row written here).
-- p_op         — 'created'|'updated'|'destroyed' (DEFAULT NULL; ignored if message_id NULL).
CREATE OR REPLACE FUNCTION notify_state_change(
  p_mailbox_id BIGINT,
  p_tag_id     BIGINT,
  p_message_id BIGINT DEFAULT NULL,
  p_op         TEXT   DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
  v_email_state BIGINT;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RAISE EXCEPTION 'notify_state_change requires a mailbox'
      USING ERRCODE = 'BZ034',
            HINT = jsonb_build_object('type', 'missing_mailbox')::TEXT;
  END IF;

  v_email_state := bump_email_state(p_mailbox_id);

  -- Offline #3: id-bearing callers thread (message_id, op) → precise journal row
  -- in the SAME txn as the bump. NULL callers (transition_message_location et al.)
  -- fall to the ELSE and emit a resync sentinel so every state bump has a record.
  -- Task 4 upgrades these sites to precise rows.
  -- ponytail: resync on null-caller path forces BZ011 cannotCalculateChanges for
  -- any spanning delta until Task 4 threads message_id; conservative but correct.
  -- Guard on v_email_state IS NOT NULL: a foreign / non-existent mailbox_id yields
  -- NULL from bump_email_state → skip the append (no-op, not a crash).
  IF v_email_state IS NOT NULL THEN
    IF p_message_id IS NOT NULL AND p_op IS NOT NULL THEN
      PERFORM append_email_change(p_mailbox_id, v_email_state, p_message_id, p_op);
    ELSE
      PERFORM append_email_change(p_mailbox_id, v_email_state, NULL, 'resync');
    END IF;
  END IF;

  IF p_tag_id IS NOT NULL THEN
    PERFORM bump_tag_mailbox_state(p_mailbox_id);
  END IF;

  PERFORM app_notify(
    'tag:' || p_mailbox_id,
    json_build_object(
      'event',  'state_change',
      'tag_id', p_tag_id,
      'state',  v_email_state
    )::TEXT
  );

  RETURN v_email_state;
END;
$$ LANGUAGE plpgsql;
