-- quick_steps.sql — Quick Steps (Track A2): user-defined one-click action macros.
--
-- A Quick Step is a named, ordered array of actions reusing a SUBSET of the
-- rule-engine action vocabulary so rules and macros share one execution path
-- (apply_action). Allowed action types: move_to, categorize, flag, mark_read,
-- forward_to. Privileged rule actions (add_header, discard, delete) are NOT
-- exposed and are rejected at both set and apply time — the enforcement invariant:
-- every action type the schema/UI accepts is enforced in the use path, never
-- silently passed through to a more-permissive rule behaviour.
--
-- R4 / DATABASE_SECURITY: every statement filters by p_mailbox_id from the auth
-- context (R1/R3); inserts set mailbox_id from the parameter, never req.* (R2).

-- The single source of truth for which action types a Quick Step may contain.
-- IMMUTABLE so it can be inlined in CHECK-style guards.
CREATE OR REPLACE FUNCTION quick_step_action_allowed(p_type TEXT) RETURNS BOOLEAN AS $$
  SELECT p_type IN ('move_to', 'categorize', 'flag', 'mark_read', 'forward_to');
$$ LANGUAGE sql IMMUTABLE;

CREATE OR REPLACE FUNCTION quick_step_list(p_mailbox_id BIGINT) RETURNS JSONB AS $$
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'id', id::TEXT, 'name', name, 'icon', icon,
    'position', position, 'actions', actions) ORDER BY position, id), '[]'::JSONB)
  FROM quick_steps WHERE mailbox_id = p_mailbox_id;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION quick_step_set(
  p_mailbox_id BIGINT, p_id BIGINT, p_name TEXT, p_icon TEXT, p_actions JSONB
) RETURNS BIGINT AS $$
DECLARE
  v_id     BIGINT;
  v_action JSONB;
  v_type   TEXT;
BEGIN
  IF p_name IS NULL OR length(trim(p_name)) = 0 THEN
    RAISE EXCEPTION 'quick step name required'
      USING ERRCODE = 'BZ040', HINT = '{"type":"invalidArguments"}';
  END IF;
  IF p_actions IS NULL OR jsonb_typeof(p_actions) <> 'array' OR jsonb_array_length(p_actions) = 0 THEN
    RAISE EXCEPTION 'quick step needs at least one action'
      USING ERRCODE = 'BZ041', HINT = '{"type":"invalidArguments"}';
  END IF;

  -- Enforce the action allowlist at write time (the enforcement invariant): a
  -- macro can never persist a privileged rule action that apply_action would run.
  FOR v_action IN SELECT * FROM jsonb_array_elements(p_actions) LOOP
    v_type := v_action->>'type';
    IF NOT quick_step_action_allowed(v_type) THEN
      RAISE EXCEPTION 'quick step action type not allowed: %', COALESCE(v_type, '(null)')
        USING ERRCODE = 'BZ043',
              HINT = '{"type":"forbiddenAction"}';
    END IF;
  END LOOP;

  IF p_id IS NULL THEN
    INSERT INTO quick_steps (mailbox_id, name, icon, actions, position)
    VALUES (p_mailbox_id, p_name, COALESCE(NULLIF(p_icon, ''), 'Zap'), p_actions,
            COALESCE((SELECT max(position) + 1 FROM quick_steps WHERE mailbox_id = p_mailbox_id), 0))
    RETURNING id INTO v_id;
  ELSE
    UPDATE quick_steps SET name = p_name, icon = COALESCE(NULLIF(p_icon, ''), icon),
           actions = p_actions, updated_at = now()
    WHERE id = p_id AND mailbox_id = p_mailbox_id          -- R3: ownership in WHERE
    RETURNING id INTO v_id;
    IF v_id IS NULL THEN
      RAISE EXCEPTION 'quick step not found'
        USING ERRCODE = 'BZ042', HINT = '{"type":"notFound"}';
    END IF;
  END IF;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION quick_step_delete(p_mailbox_id BIGINT, p_id BIGINT) RETURNS VOID AS $$
  DELETE FROM quick_steps WHERE id = p_id AND mailbox_id = p_mailbox_id;  -- R3: ownership in WHERE
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION quick_step_apply(
  p_mailbox_id BIGINT, p_id BIGINT, p_message_id BIGINT, p_received_at TIMESTAMPTZ
) RETURNS VOID AS $$
DECLARE
  v_actions JSONB;
  v_action  JSONB;
  v_type    TEXT;
BEGIN
  SELECT actions INTO v_actions FROM quick_steps
  WHERE id = p_id AND mailbox_id = p_mailbox_id;       -- R1: filter by mailbox
  IF v_actions IS NULL THEN
    RAISE EXCEPTION 'quick step not found'
      USING ERRCODE = 'BZ042', HINT = '{"type":"notFound"}';
  END IF;

  -- Guard: the message must belong to this mailbox (R3 / no TOCTOU).
  PERFORM 1 FROM messages
    WHERE id = p_message_id AND received_at = p_received_at AND mailbox_id = p_mailbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'message not in mailbox'
      USING ERRCODE = 'BZ042', HINT = '{"type":"notFound"}';
  END IF;

  FOR v_action IN SELECT * FROM jsonb_array_elements(v_actions) LOOP
    v_type := v_action->>'type';
    -- Re-enforce the allowlist at apply time. A row that predates the set-time
    -- guard (or was tampered with) cannot smuggle a privileged action.
    IF NOT quick_step_action_allowed(v_type) THEN
      RAISE EXCEPTION 'quick step action type not allowed: %', COALESCE(v_type, '(null)')
        USING ERRCODE = 'BZ043', HINT = '{"type":"forbiddenAction"}';
    END IF;
    -- p_rule_id is NULL: only add_header reads it, and add_header is not allowed.
    PERFORM apply_action(p_message_id, p_received_at, p_mailbox_id, v_action, NULL);
  END LOOP;

  -- apply_action already pushes per-action via notify_state_change; a final
  -- mailbox-wide bump guarantees a state change even for a macro whose actions
  -- all no-op'd (e.g. categorize a category already present).
  PERFORM notify_state_change(p_mailbox_id, NULL);
END;
$$ LANGUAGE plpgsql;
