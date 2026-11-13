-- JMAP Mailbox/* reducers (RFC 8621 §2)

-- normalize_tag_color: server-side whitelist for user-tag (label) colors. The
-- webmail picker offers exactly the 8 TAG_COLORS hues; any other value (arbitrary
-- client text) is rejected to NULL so a client can never store an unbounded/garbage
-- color. Shared by Mailbox/set create + update so the two paths can't drift.
CREATE OR REPLACE FUNCTION normalize_tag_color(p_color TEXT)
RETURNS TEXT AS $$
  SELECT CASE
    WHEN p_color IN ('blue','teal','green','amber','orange','rose','purple','gray')
    THEN p_color
    ELSE NULL
  END;
$$ LANGUAGE sql IMMUTABLE;

-- jmap_mailbox_get: return Mailbox objects for the given account.
-- If p_ids is NULL, returns all tags (mailboxes) for the account.
CREATE OR REPLACE FUNCTION jmap_mailbox_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[] DEFAULT NULL,
  p_properties TEXT[]   DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_row       RECORD;
  v_state     BIGINT;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  -- Verify account exists and fetch state
  SELECT jmap_mailbox_state INTO v_state
  FROM mailboxes WHERE id = p_mailbox_id;
  IF v_state IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  FOR v_row IN
    SELECT t.*, mb.display_name AS mailbox_name, md.permission AS share_permission
    FROM tags t
    JOIN mailboxes mb ON mb.id = t.mailbox_id
    LEFT JOIN mailbox_delegates md ON md.mailbox_id = mb.id AND md.user_id = (
      -- The user behind the caller's mailbox via the one resolver seam (ADR-003),
      -- not a hand-join of `mailboxes` (which re-introduces the user_id/mailbox_id
      -- confusion + the shared-mailbox NULL edge). NULL user_id (shared mailbox)
      -- yields no delegate match — identical to the prior hand-join.
      SELECT user_id FROM account_scope(p_mailbox_id)
    )
    WHERE (t.mailbox_id = p_mailbox_id OR md.permission IS NOT NULL)
      AND (p_ids IS NULL OR t.id = ANY(p_ids))
    ORDER BY t.sort_order, t.name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'name', v_row.name,
      'parentId', CASE WHEN v_row.parent_id IS NOT NULL THEN v_row.parent_id::TEXT END,
      'color', v_row.color,
      'role', CASE
        WHEN v_row.name = 'Inbox' THEN 'inbox'
        WHEN v_row.name = 'Sent' THEN 'sent'
        WHEN v_row.name = 'Drafts' THEN 'drafts'
        WHEN v_row.name = 'Trash' THEN 'trash'
        WHEN v_row.name = 'Spam' THEN 'spam'
        WHEN v_row.name = 'Archive' THEN 'archive'
        WHEN v_row.name = 'Templates' THEN 'templates'
        WHEN v_row.name = 'Snoozed' THEN 'snoozed'
        WHEN v_row.name = 'Scheduled' THEN 'scheduled'
        ELSE NULL
      END,
      'sortOrder', v_row.sort_order,
      'totalEmails', v_row.total_count,
      'unreadEmails', v_row.unread_count,
      'totalThreads', v_row.total_count,
      'unreadThreads', v_row.unread_count,
      'myRights', jsonb_build_object(
        'mayReadItems', true,
        'mayAddItems', v_row.share_permission IS NULL OR v_row.share_permission IN ('full_access','send_as','send_on_behalf'),
        'mayRemoveItems', v_row.share_permission IS NULL OR v_row.share_permission = 'full_access',
        'maySetSeen', true,
        'maySetKeywords', v_row.share_permission IS NULL OR v_row.share_permission IN ('full_access','send_as'),
        'mayCreateChild', v_row.share_permission IS NULL,
        'mayRename', v_row.share_permission IS NULL AND v_row.tag_type = 'user',
        'mayDelete', v_row.share_permission IS NULL AND v_row.tag_type = 'user',
        'maySubmit', v_row.share_permission IN ('send_as','send_on_behalf','full_access')
      ),
      'isSubscribed', v_row.imap_expose
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

-- jmap_mailbox_changes: return mailbox ids that changed since p_since_state.
CREATE OR REPLACE FUNCTION jmap_mailbox_changes(
  p_mailbox_id   BIGINT,
  p_since_state  TEXT
) RETURNS JSONB AS $$
DECLARE
  v_current BIGINT;
BEGIN
  SELECT jmap_mailbox_state INTO v_current
  FROM mailboxes WHERE id = p_mailbox_id;
  IF v_current IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  -- BZ011 on any state mismatch: future state (client ahead) OR gap (state advanced
  -- with no folder-change journal) — both cases are "cannot calculate changes".
  -- Equal state (no changes) falls through to the empty-but-correct return.
  IF p_since_state::BIGINT != v_current THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', p_since_state,
    'newState', v_current::TEXT,
    'hasMoreChanges', false,
    'created', '[]'::JSONB,
    'updated', '[]'::JSONB,
    'destroyed', '[]'::JSONB
  );
END;
$$ LANGUAGE plpgsql;

-- bump_mailbox_set_state: bump jmap_mailbox_state for the account and push on the
-- canonical 'tag:{mailbox_id}' channel (the channel the WS/IMAP consumers
-- subscribe to). Shared by the create/update/destroy halves of Mailbox/set so a
-- folder create/rename/destroy reaches the webmail. Returns the new state.
CREATE OR REPLACE FUNCTION bump_mailbox_set_state(
  p_mailbox_id BIGINT,
  p_event      TEXT
) RETURNS BIGINT AS $$
DECLARE
  v_new_state BIGINT;
BEGIN
  UPDATE mailboxes SET jmap_mailbox_state = jmap_mailbox_state + 1
  WHERE id = p_mailbox_id
  RETURNING jmap_mailbox_state INTO v_new_state;

  PERFORM app_notify('tag:' || p_mailbox_id,
    json_build_object('event', p_event, 'state', v_new_state)::TEXT);

  RETURN v_new_state;
END;
$$ LANGUAGE plpgsql;

-- jmap_mailbox_set_create: create new user mailboxes (tags). A "mailbox" in this
-- system is a TAG (a folder is a tag); creating one inserts a user tag
-- (tag_type='user', imap_expose=TRUE) so it surfaces over IMAP + JMAP. System
-- mailboxes (Inbox/Sent/Drafts/Trash/Spam and the other location/snooze/quarantine
-- exclusive-group tags) are NOT creatable here — those carry product semantics and
-- already exist per mailbox — so a create that names one is rejected as notCreated.
-- p_creates maps a client create-key to a JMAP Mailbox object {name, parentId?,
-- sortOrder?, isSubscribed?}. The 'created' map echoes each key -> the new tag id.
CREATE OR REPLACE FUNCTION jmap_mailbox_set_create(
  p_mailbox_id BIGINT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_key         TEXT;
  v_obj         JSONB;
  v_created     JSONB := '{}'::JSONB;
  v_notCreated  JSONB := '{}'::JSONB;
  v_new_id      BIGINT;
  v_name        TEXT;
  v_parent_id   BIGINT;
  v_changed     BOOLEAN := FALSE;
  v_new_state   BIGINT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM mailboxes WHERE id = p_mailbox_id) THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  FOR v_key, v_obj IN SELECT * FROM jsonb_each(p_creates)
  LOOP
    BEGIN
      v_name := NULLIF(btrim(COALESCE(v_obj->>'name', '')), '');

      -- A name is required and must not collide with an exclusive-group system
      -- tag (Inbox/Sent/Drafts/Trash/Spam/Snoozed/Scheduled/Quarantined etc),
      -- which are product-reserved and created automatically per mailbox.
      IF v_name IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_key,
          jsonb_build_object('type', 'invalidProperties',
            'properties', jsonb_build_array('name'),
            'description', 'name is required'));
        CONTINUE;
      END IF;

      IF EXISTS (
        SELECT 1 FROM tags
        WHERE mailbox_id = p_mailbox_id
          AND tag_type = 'system'
          AND LOWER(name) = LOWER(v_name)
      ) THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_key,
          jsonb_build_object('type', 'forbidden',
            'description', 'cannot create a system mailbox'));
        CONTINUE;
      END IF;

      -- parentId, if given, must be an existing tag in the SAME mailbox (R3).
      v_parent_id := NULL;
      IF v_obj ? 'parentId' AND v_obj->>'parentId' IS NOT NULL THEN
        v_parent_id := (v_obj->>'parentId')::BIGINT;
        IF NOT EXISTS (SELECT 1 FROM tags WHERE id = v_parent_id AND mailbox_id = p_mailbox_id) THEN
          v_notCreated := v_notCreated || jsonb_build_object(v_key,
            jsonb_build_object('type', 'invalidProperties',
              'properties', jsonb_build_array('parentId'),
              'description', 'parent mailbox not found'));
          CONTINUE;
        END IF;
      END IF;

      INSERT INTO tags (mailbox_id, parent_id, name, color, tag_type, sort_order, imap_expose)
      VALUES (
        p_mailbox_id, v_parent_id, v_name, normalize_tag_color(v_obj->>'color'), 'user',
        COALESCE((v_obj->>'sortOrder')::INT, 100),
        COALESCE((v_obj->>'isSubscribed')::BOOL, TRUE)
      )
      RETURNING id INTO v_new_id;

      v_created := v_created || jsonb_build_object(v_key,
        jsonb_build_object('id', v_new_id::TEXT));
      v_changed := TRUE;
    EXCEPTION
      WHEN unique_violation THEN
        -- A user tag with this name already exists in the mailbox.
        v_notCreated := v_notCreated || jsonb_build_object(v_key,
          jsonb_build_object('type', 'invalidProperties',
            'properties', jsonb_build_array('name'),
            'description', 'a mailbox with this name already exists'));
      WHEN OTHERS THEN
        v_notCreated := v_notCreated || jsonb_build_object(v_key,
          jsonb_build_object('type', 'invalidArguments',
            'description', 'create failed'));
    END;
  END LOOP;

  IF v_changed THEN
    v_new_state := bump_mailbox_set_state(p_mailbox_id, 'mailbox_created');
  ELSE
    SELECT jmap_mailbox_state INTO v_new_state FROM mailboxes WHERE id = p_mailbox_id;
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', CASE WHEN v_changed THEN (v_new_state - 1)::TEXT ELSE v_new_state::TEXT END,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_mailbox_set_destroy: destroy user mailboxes (tags). Per RFC 8621 §2.5 a
-- Mailbox may only be destroyed when empty (no Email belongs to it) — here that
-- means the tag has no message_tags rows; a non-empty tag returns notDestroyed
-- with a mailboxHasEmail SetError (NOT a cascade delete — message_tags has
-- ON DELETE CASCADE on tag_id, so a blind DELETE would silently strip the label
-- off live mail). System tags are never destroyable (forbidden). R3: every probe
-- and the DELETE are scoped to p_mailbox_id, so a foreign tag id is notFound.
CREATE OR REPLACE FUNCTION jmap_mailbox_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_destroyed   JSONB := '[]'::JSONB;
  v_notDestroyed JSONB := '{}'::JSONB;
  v_tag_type    TEXT;
  v_has_email   BOOLEAN;
  v_has_child   BOOLEAN;
  v_changed     BOOLEAN := FALSE;
  v_new_state   BIGINT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM mailboxes WHERE id = p_mailbox_id) THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  FOREACH v_id IN ARRAY COALESCE(p_ids, ARRAY[]::BIGINT[])
  LOOP
    BEGIN
      SELECT tag_type INTO v_tag_type
      FROM tags WHERE id = v_id AND mailbox_id = p_mailbox_id;

      IF v_tag_type IS NULL THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'mailbox not found'));
        CONTINUE;
      END IF;

      -- System tags (Inbox/Sent/Drafts/Trash/Spam, location/snooze/quarantine
      -- exclusive groups) carry product semantics and are never destroyable.
      IF v_tag_type = 'system' THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'forbidden', 'description', 'cannot destroy a system mailbox'));
        CONTINUE;
      END IF;

      -- A mailbox can only be destroyed when it holds no Email (RFC 8621 §2.5).
      v_has_email := EXISTS (SELECT 1 FROM message_tags WHERE tag_id = v_id);
      IF v_has_email THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'mailboxHasEmail', 'description', 'mailbox is not empty'));
        CONTINUE;
      END IF;

      -- Refuse to orphan child mailboxes (RFC 8621 §2.5 — must have no children).
      v_has_child := EXISTS (SELECT 1 FROM tags WHERE parent_id = v_id AND mailbox_id = p_mailbox_id);
      IF v_has_child THEN
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'mailboxHasChild', 'description', 'mailbox has child mailboxes'));
        CONTINUE;
      END IF;

      DELETE FROM tags WHERE id = v_id AND mailbox_id = p_mailbox_id AND tag_type = 'user';
      IF FOUND THEN
        v_destroyed := v_destroyed || to_jsonb(v_id::TEXT);
        v_changed := TRUE;
      ELSE
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'mailbox not found'));
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'destroy failed'));
    END;
  END LOOP;

  IF v_changed THEN
    v_new_state := bump_mailbox_set_state(p_mailbox_id, 'mailbox_destroyed');
  ELSE
    SELECT jmap_mailbox_state INTO v_new_state FROM mailboxes WHERE id = p_mailbox_id;
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', CASE WHEN v_changed THEN (v_new_state - 1)::TEXT ELSE v_new_state::TEXT END,
    'newState', v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_mailbox_set_update: update mailbox properties (name, parentId, sortOrder, isSubscribed).
-- Does NOT handle create or destroy.
CREATE OR REPLACE FUNCTION jmap_mailbox_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_patch       JSONB;
  v_updated     JSONB := '[]'::JSONB;
  v_notUpdated  JSONB := '{}'::JSONB;
  v_new_state   BIGINT;
  v_new_parent  BIGINT;
BEGIN
  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      -- Prevent rename/reparent/recolor of system tags (Inbox/Sent/… carry product
      -- semantics + render with icons, not user hues — recolor is meaningless there).
      IF EXISTS (SELECT 1 FROM tags WHERE id = v_id AND mailbox_id = p_mailbox_id AND tag_type = 'system'  -- #478: own tags only
                 AND (v_patch ? 'name' OR v_patch ? 'parentId' OR v_patch ? 'color')) THEN
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'invalidArguments', 'description', 'Cannot modify system tag'));
        CONTINUE;
      END IF;

      -- Validate parentId when the patch sets it. set_create only checks
      -- same-mailbox existence (a fresh tag has no descendants); set_update must
      -- ALSO reject self-parent and cycles, since reparenting an existing tag
      -- under its own descendant would form a loop a recursive client tree-builder
      -- could spin on. Without this, the bare COALESCE accepted ANY parentId value
      -- (incl. a foreign mailbox's tag id).
      IF v_patch ? 'parentId' AND v_patch->>'parentId' IS NOT NULL THEN
        v_new_parent := (v_patch->>'parentId')::BIGINT;
        IF v_new_parent = v_id
           OR NOT EXISTS (SELECT 1 FROM tags WHERE id = v_new_parent AND mailbox_id = p_mailbox_id)
           OR EXISTS (
             WITH RECURSIVE anc(id, parent_id) AS (
               SELECT id, parent_id FROM tags WHERE id = v_new_parent AND mailbox_id = p_mailbox_id
               UNION ALL
               SELECT t.id, t.parent_id FROM tags t
                 JOIN anc ON t.id = anc.parent_id
                WHERE t.mailbox_id = p_mailbox_id
             )
             SELECT 1 FROM anc WHERE id = v_id
           ) THEN
          v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
            jsonb_build_object('type', 'invalidProperties',
              'properties', jsonb_build_array('parentId'),
              'description', 'invalid parent mailbox'));
          CONTINUE;
        END IF;
      END IF;

      -- color: patch-present + whitelist guarded in one COALESCE — an absent key or
      -- an out-of-whitelist hue both normalize to NULL and keep the existing color;
      -- only a present, whitelisted hue recolors the user tag.
      UPDATE tags SET
        name = COALESCE(v_patch->>'name', name),
        color = COALESCE(normalize_tag_color(v_patch->>'color'), color),
        parent_id = CASE WHEN v_patch ? 'parentId' THEN (v_patch->>'parentId')::BIGINT ELSE parent_id END,
        sort_order = COALESCE((v_patch->>'sortOrder')::INT, sort_order),
        imap_expose = COALESCE((v_patch->>'isSubscribed')::BOOL, imap_expose),
        updated_at = now()
      WHERE id = v_id AND mailbox_id = p_mailbox_id;

      IF FOUND THEN
        v_updated := v_updated || to_jsonb(v_id);
      ELSE
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'tag not found'));
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'update failed'));
    END;
  END LOOP;

  -- Bump the mailbox/tag-level state and push on the canonical
  -- 'tag:{mailbox_id}' channel (the channel the WS/IMAP consumers subscribe
  -- to). The legacy 'mailbox:{id}' channel had NO subscriber, so Mailbox/set
  -- (folder rename/reparent/subscribe) never reached the webmail. The push
  -- payload carries 'state' so the consumer wakes and re-reads jmap_mailbox_state.
  v_new_state := bump_mailbox_set_state(p_mailbox_id, 'mailbox_updated');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', (v_new_state - 1)::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_mailbox_query: search mailboxes (tags) with filter/sort/pagination.
-- Returns {accountId, state, position, total, ids} per JMAP /query pattern.
CREATE OR REPLACE FUNCTION jmap_mailbox_query(
  p_mailbox_id BIGINT,
  p_filter     JSONB DEFAULT NULL,
  p_sort       JSONB DEFAULT NULL,
  p_position   INT   DEFAULT 0,
  p_limit      INT   DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_state     BIGINT;
  v_total     BIGINT;
  v_ids       JSONB;
  v_where     TEXT := '';
  v_order     TEXT := 'ORDER BY t.sort_order, t.name';
  v_limit     INT  := COALESCE(p_limit, 50);
  v_filter_name TEXT;
  v_filter_role TEXT;
BEGIN
  IF v_limit < 1 THEN v_limit := 1; END IF;
  IF v_limit > 256 THEN v_limit := 256; END IF;

  SELECT jmap_mailbox_state INTO v_state FROM mailboxes WHERE id = p_mailbox_id;
  IF v_state IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  v_where := format('t.mailbox_id = %s', p_mailbox_id);

  IF p_filter IS NOT NULL THEN
    IF p_filter ? 'parentId' AND p_filter->>'parentId' IS NOT NULL THEN
      v_where := v_where || format(' AND t.parent_id = %s', (p_filter->>'parentId')::BIGINT);
    END IF;
    IF p_filter ? 'name' AND p_filter->>'name' IS NOT NULL THEN
      v_filter_name := p_filter->>'name';
      v_filter_name := '%' || v_filter_name || '%';
      v_where := v_where || format(' AND t.name ILIKE %L', v_filter_name);
    END IF;
    IF p_filter ? 'role' AND p_filter->>'role' IS NOT NULL THEN
      v_filter_role := p_filter->>'role';
      v_where := v_where || format(' AND LOWER(t.name) = LOWER(%L)', v_filter_role);
    END IF;
    IF p_filter ? 'hasAnyRole' AND (p_filter->>'hasAnyRole')::BOOL THEN
      v_where := v_where || ' AND LOWER(t.name) IN (''inbox'',''sent'',''drafts'',''trash'',''spam'',''archive'',''templates'')';
    END IF;
    IF p_filter ? 'isSubscribed' THEN
      v_where := v_where || format(' AND t.imap_expose = %L', (p_filter->>'isSubscribed')::BOOL);
    END IF;
  END IF;

  IF p_sort IS NOT NULL AND jsonb_array_length(p_sort) > 0 THEN
    v_order := 'ORDER BY ';
    FOR i IN 0..jsonb_array_length(p_sort)-1 LOOP
      DECLARE
        v_sort_obj JSONB := p_sort->i;
        v_prop     TEXT := v_sort_obj->>'property';
        v_asc      BOOL := COALESCE(v_sort_obj->>'isAscending', 'true') = 'true';
      BEGIN
        IF i > 0 THEN v_order := v_order || ', '; END IF;
        IF v_prop = 'sortOrder' THEN
          v_order := v_order || 't.sort_order ' || CASE WHEN v_asc THEN 'ASC' ELSE 'DESC' END;
        ELSIF v_prop = 'name' THEN
          v_order := v_order || 't.name ' || CASE WHEN v_asc THEN 'ASC' ELSE 'DESC' END;
        ELSE
          v_order := v_order || 't.sort_order ASC';
        END IF;
      END;
    END LOOP;
  END IF;

  EXECUTE 'SELECT COUNT(*) FROM tags t WHERE ' || v_where INTO v_total;
  EXECUTE 'SELECT COALESCE(to_jsonb(array_agg(id::TEXT)), ''[]''::JSONB) FROM (SELECT id FROM tags t WHERE ' || v_where || ' ' || v_order || ' LIMIT ' || v_limit || ' OFFSET ' || p_position || ') sub'
    INTO v_ids;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state', v_state::TEXT,
    'canCalculateChanges', true,
    'position', p_position,
    'total', v_total,
    'ids', COALESCE(v_ids, '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_mailbox_query_changes: return mailbox ids that changed since a query state.
CREATE OR REPLACE FUNCTION jmap_mailbox_query_changes(
  p_mailbox_id         BIGINT,
  p_filter             JSONB DEFAULT NULL,
  p_sort               JSONB DEFAULT NULL,
  p_since_query_state  TEXT DEFAULT '0'
) RETURNS JSONB AS $$
DECLARE
  v_current_state BIGINT;
  v_since_state   BIGINT;
BEGIN
  v_since_state := p_since_query_state::BIGINT;

  SELECT jmap_mailbox_state INTO v_current_state FROM mailboxes WHERE id = p_mailbox_id;
  IF v_current_state IS NULL THEN
    RAISE EXCEPTION 'Account not found'
      USING ERRCODE = 'BZ006', HINT = '{"type":"accountNotFound"}';
  END IF;

  -- BZ011 on any state mismatch: jmap_mailbox_set_destroy hard-DELETEs the tag
  -- row with no tombstone, so a "removed" folder can never be enumerated once
  -- state has advanced past it — the naive '[]' removed was always wrong for a
  -- destroy. Byte-follow jmap_mailbox_changes' guard: equal state (no changes)
  -- is the only case answerable correctly; any diff forces the client to
  -- re-query from scratch instead of silently keeping a destroyed folder.
  IF v_since_state != v_current_state THEN
    RAISE EXCEPTION 'Cannot calculate changes'
      USING ERRCODE = 'BZ011', HINT = '{"type":"cannotCalculateChanges"}';
  END IF;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldQueryState', p_since_query_state,
    'newQueryState', v_current_state::TEXT,
    'removed', '[]'::JSONB,
    'added', '[]'::JSONB
  );
END;
$$ LANGUAGE plpgsql;
