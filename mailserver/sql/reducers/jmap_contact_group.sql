-- Personal contact-group reducers (A4 — user-created distribution lists).
--
-- contact_groups is a mailbox-owned named recipient list (distinct from the
-- admin/SCIM org-wide distribution_groups). A group expands to its members at
-- compose time. Membership is either a saved contact (contact_id) or a free-typed
-- address (email); exactly one is set per member row (CHECK cgm_one_target).
--
-- R1–R4 are enforced by p_mailbox_id (the caller's MAILBOX id) propagation:
--   * every SELECT/UPDATE/DELETE filters contact_groups.mailbox_id = p_mailbox_id;
--   * INSERT sets mailbox_id from p_mailbox_id, never from request input;
--   * member mutation + expand gate on the group's ownership in the SAME statement
--     (no TOCTOU). expand returns '[]' (not an error) for a foreign caller so the
--     send path stays quiet; member mutation raises BZ045.
-- Mutating reducers bump the group's jmap_state AND the owning mailbox's
-- addressbooks.jmap_state (groups live in the contacts jmap_state domain) and push
-- on the contact: channel.
--
-- Errors:
--   BZ044  contact_group_name_taken — duplicate group name (case-insensitive)
--   BZ045  contact_group_forbidden  — group not owned by the calling mailbox

-- ── internal: bump the owning mailbox's contacts-DOMAIN state + push ─────────
-- Decision B: the addressbook-DOMAIN bump+push is routed through the one contact
-- seam (notify_contact_state) — groups share the contacts (addressbooks)
-- jmap_state domain, so clients resync contacts + groups off that one token. This
-- thin wrapper is kept as the named call site the group reducers use; it owns NO
-- inline UPDATE/pg_notify of its own. The per-GROUP token (contact_groups.jmap_state,
-- read by ContactGroup/get) is a DIFFERENT, group-scoped token and is bumped by the
-- group reducers themselves — never here.
CREATE OR REPLACE FUNCTION bump_contact_group_state(p_mailbox_id BIGINT) RETURNS VOID AS $$
BEGIN
  PERFORM notify_contact_state(p_mailbox_id, 'contact_group_changed', NULL);
END;
$$ LANGUAGE plpgsql;

-- ── ContactGroup/get ─────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION jmap_contact_group_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
  v_state  BIGINT;
  v_members JSONB;
  v_found  TEXT[] := ARRAY[]::TEXT[];
BEGIN
  SELECT COALESCE(MAX(jmap_state), 0) INTO v_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  FOR v_row IN
    SELECT g.*
    FROM contact_groups g
    WHERE g.mailbox_id = p_mailbox_id
      AND (p_ids IS NULL OR g.id = ANY(p_ids))
    ORDER BY lower(g.name)
  LOOP
    -- Resolve members: contact members carry their display name + primary email;
    -- free-email members carry the bare address.
    SELECT COALESCE(jsonb_agg(m ORDER BY m->>'displayName'), '[]'::JSONB) INTO v_members
    FROM (
      SELECT jsonb_build_object(
        'contactId', cm.contact_id::TEXT,
        'email',     COALESCE(cm.email, contact_primary_email(c.emails)),
        'displayName', COALESCE(c.display_name, cm.email)
      ) AS m
      FROM contact_group_members cm
      LEFT JOIN contacts c ON c.id = cm.contact_id
      WHERE cm.group_id = v_row.id
    ) sub;

    v_result := v_result || jsonb_build_object(
      'id',          v_row.id::TEXT,
      'name',        v_row.name,
      'memberCount', (SELECT COUNT(*) FROM contact_group_members WHERE group_id = v_row.id),
      'members',     v_members
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

-- contact_primary_email: first is_primary email, else first email, from the
-- contacts.emails JSONB array ([{type,address,is_primary}]).
CREATE OR REPLACE FUNCTION contact_primary_email(p_emails JSONB) RETURNS TEXT AS $$
  SELECT COALESCE(
    (SELECT e->>'address' FROM jsonb_array_elements(COALESCE(p_emails, '[]'::JSONB)) e
       WHERE (e->>'is_primary')::BOOL IS TRUE LIMIT 1),
    (SELECT e->>'address' FROM jsonb_array_elements(COALESCE(p_emails, '[]'::JSONB)) e LIMIT 1)
  );
$$ LANGUAGE sql IMMUTABLE;

-- ── ContactGroup/query ───────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION jmap_contact_group_query(
  p_mailbox_id BIGINT,
  p_filter     JSONB DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_state BIGINT;
  v_ids   TEXT[];  -- JMAP Id[] is strings; numeric ids 400 in ContactGroup/get ([]string)
  v_total INT;
  v_text  TEXT;
BEGIN
  SELECT COALESCE(MAX(jmap_state), 0) INTO v_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  v_text := NULLIF(TRIM(COALESCE(p_filter->>'text', '')), '');

  SELECT array_agg(id::TEXT ORDER BY lower(name)), COUNT(*)
    INTO v_ids, v_total
  FROM contact_groups
  WHERE mailbox_id = p_mailbox_id
    AND (v_text IS NULL OR name ILIKE '%' || v_text || '%');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'state',     v_state::TEXT,
    'total',     COALESCE(v_total, 0),
    'ids',       COALESCE(to_jsonb(v_ids), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;

-- ── ContactGroup/set create ──────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION jmap_contact_group_set_create(
  p_mailbox_id BIGINT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_client_key TEXT;
  v_obj        JSONB;
  v_id         BIGINT;
  v_name       TEXT;
  v_created    JSONB := '{}'::JSONB;
  v_notCreated JSONB := '{}'::JSONB;
  v_old_state  BIGINT;
  v_new_state  BIGINT;
  v_changed    BOOLEAN := FALSE;
BEGIN
  SELECT COALESCE(MAX(jmap_state), 0) INTO v_old_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  FOR v_client_key, v_obj IN SELECT * FROM jsonb_each(p_creates)
  LOOP
    BEGIN
      v_name := NULLIF(TRIM(COALESCE(v_obj->>'name', '')), '');
      IF v_name IS NULL THEN
        RAISE EXCEPTION 'Group name is required'
          USING ERRCODE = 'BZ044', HINT = '{"type":"contact_group_name_taken"}';
      END IF;

      IF EXISTS (SELECT 1 FROM contact_groups
                 WHERE mailbox_id = p_mailbox_id AND lower(name) = lower(v_name)) THEN
        RAISE EXCEPTION 'Group name already in use: %', v_name
          USING ERRCODE = 'BZ044', HINT = '{"type":"contact_group_name_taken"}';
      END IF;

      INSERT INTO contact_groups (mailbox_id, name, jmap_state)
      VALUES (p_mailbox_id, v_name, 1)
      RETURNING id INTO v_id;
      v_changed := TRUE;

      v_created := v_created || jsonb_build_object(
        v_client_key, jsonb_build_object('id', v_id::TEXT, 'memberCount', 0)
      );
    EXCEPTION
      WHEN SQLSTATE 'BZ044' THEN
        v_notCreated := v_notCreated || jsonb_build_object(
          v_client_key, jsonb_build_object('type', 'invalidArguments',
            'description', 'group name already in use'));
      WHEN OTHERS THEN
        v_notCreated := v_notCreated || jsonb_build_object(
          v_client_key, jsonb_build_object('type', 'invalidArguments',
            'description', 'creation failed'));
    END;
  END LOOP;

  IF v_changed THEN PERFORM bump_contact_group_state(p_mailbox_id); END IF;

  SELECT COALESCE(MAX(jmap_state), 0) INTO v_new_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState',  v_old_state::TEXT,
    'newState',  v_new_state::TEXT,
    'created',   v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

-- ── ContactGroup/set update (rename) ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION jmap_contact_group_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id         BIGINT;
  v_patch      JSONB;
  v_name       TEXT;
  v_updated    JSONB := '[]'::JSONB;
  v_notUpdated JSONB := '{}'::JSONB;
  v_old_state  BIGINT;
  v_new_state  BIGINT;
  v_changed    BOOLEAN := FALSE;
BEGIN
  SELECT COALESCE(MAX(jmap_state), 0) INTO v_old_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      v_name := NULLIF(TRIM(COALESCE(v_patch->>'name', '')), '');

      IF v_name IS NOT NULL AND EXISTS (
        SELECT 1 FROM contact_groups
        WHERE mailbox_id = p_mailbox_id AND lower(name) = lower(v_name) AND id <> v_id
      ) THEN
        RAISE EXCEPTION 'Group name already in use: %', v_name
          USING ERRCODE = 'BZ044', HINT = '{"type":"contact_group_name_taken"}';
      END IF;

      UPDATE contact_groups SET
        name       = COALESCE(v_name, name),
        updated_at = now(),
        jmap_state = jmap_state + 1
      WHERE id = v_id AND mailbox_id = p_mailbox_id;

      IF FOUND THEN
        v_changed := TRUE;
        v_updated := v_updated || to_jsonb(v_id);
      ELSE
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'group not found'));
      END IF;
    EXCEPTION
      WHEN SQLSTATE 'BZ044' THEN
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'invalidArguments', 'description', 'group name already in use'));
      WHEN OTHERS THEN
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'invalidArguments', 'description', 'update failed'));
    END;
  END LOOP;

  IF v_changed THEN PERFORM bump_contact_group_state(p_mailbox_id); END IF;

  SELECT COALESCE(MAX(jmap_state), 0) INTO v_new_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState',  v_old_state::TEXT,
    'newState',  v_new_state::TEXT,
    'updated',   v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

-- ── ContactGroup/set destroy ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION jmap_contact_group_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_destroyed   JSONB := '[]'::JSONB;
  v_notDestroyed JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
  v_changed     BOOLEAN := FALSE;
BEGIN
  SELECT COALESCE(MAX(jmap_state), 0) INTO v_old_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  FOREACH v_id IN ARRAY p_ids
  LOOP
    DELETE FROM contact_groups WHERE id = v_id AND mailbox_id = p_mailbox_id;
    IF FOUND THEN
      v_changed := TRUE;
      v_destroyed := v_destroyed || to_jsonb(v_id);
    ELSE
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'notFound', 'description', 'group not found'));
    END IF;
  END LOOP;

  IF v_changed THEN PERFORM bump_contact_group_state(p_mailbox_id); END IF;

  SELECT COALESCE(MAX(jmap_state), 0) INTO v_new_state
  FROM contact_groups WHERE mailbox_id = p_mailbox_id;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState',  v_old_state::TEXT,
    'newState',  v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;

-- ── contact_group_members_set: add/remove members ───────────────────────────
-- p_add / p_remove are JSONB arrays of {contactId} | {email}. Ownership is gated
-- once up front (BZ045 if the group is not the caller's) and every member write is
-- scoped to that already-validated group id.
CREATE OR REPLACE FUNCTION contact_group_members_set(
  p_mailbox_id BIGINT,
  p_group_id   BIGINT,
  p_add        JSONB DEFAULT '[]'::JSONB,
  p_remove     JSONB DEFAULT '[]'::JSONB
) RETURNS JSONB AS $$
DECLARE
  v_item       JSONB;
  v_contact_id BIGINT;
  v_email      TEXT;
BEGIN
  -- R1/R3 ownership gate (no TOCTOU): the group must belong to the caller.
  IF NOT EXISTS (SELECT 1 FROM contact_groups WHERE id = p_group_id AND mailbox_id = p_mailbox_id) THEN
    RAISE EXCEPTION 'Contact group not owned by caller'
      USING ERRCODE = 'BZ045', HINT = '{"type":"contact_group_forbidden"}';
  END IF;

  -- Adds.
  FOR v_item IN SELECT * FROM jsonb_array_elements(COALESCE(p_add, '[]'::JSONB))
  LOOP
    v_contact_id := NULLIF(v_item->>'contactId', '')::BIGINT;
    v_email      := NULLIF(TRIM(COALESCE(v_item->>'email', '')), '');

    IF v_contact_id IS NOT NULL THEN
      -- The contact must belong to the caller's address books (R1/R2).
      IF EXISTS (
        SELECT 1 FROM contacts c
        JOIN addressbooks ab ON ab.id = c.addressbook_id
        WHERE c.id = v_contact_id AND ab.mailbox_id = p_mailbox_id
      ) THEN
        INSERT INTO contact_group_members (group_id, contact_id)
        VALUES (p_group_id, v_contact_id)
        ON CONFLICT DO NOTHING;
      END IF;
    ELSIF v_email IS NOT NULL THEN
      INSERT INTO contact_group_members (group_id, email)
      VALUES (p_group_id, v_email)
      ON CONFLICT DO NOTHING;
    END IF;
  END LOOP;

  -- Removes.
  FOR v_item IN SELECT * FROM jsonb_array_elements(COALESCE(p_remove, '[]'::JSONB))
  LOOP
    v_contact_id := NULLIF(v_item->>'contactId', '')::BIGINT;
    v_email      := NULLIF(TRIM(COALESCE(v_item->>'email', '')), '');

    IF v_contact_id IS NOT NULL THEN
      DELETE FROM contact_group_members
      WHERE group_id = p_group_id AND contact_id = v_contact_id;
    ELSIF v_email IS NOT NULL THEN
      DELETE FROM contact_group_members
      WHERE group_id = p_group_id AND lower(email) = lower(v_email);
    END IF;
  END LOOP;

  -- Bump the group's own state + the contacts domain state.
  UPDATE contact_groups SET jmap_state = jmap_state + 1, updated_at = now()
  WHERE id = p_group_id AND mailbox_id = p_mailbox_id;
  PERFORM bump_contact_group_state(p_mailbox_id);

  RETURN jsonb_build_object(
    'accountId',   p_mailbox_id::TEXT,
    'groupId',     p_group_id::TEXT,
    'memberCount', (SELECT COUNT(*) FROM contact_group_members WHERE group_id = p_group_id)
  );
END;
$$ LANGUAGE plpgsql;

-- ── expand_contact_group: group → recipient list ────────────────────────────
-- Returns a JSONB array [{name,email}] of the group's recipients. The ownership
-- gate returns '[]' (NOT an exception) for a foreign caller so the send path stays
-- silent. Contact members resolve to their primary email; free-email members pass
-- through. Rows with no resolvable email are dropped.
CREATE OR REPLACE FUNCTION expand_contact_group(
  p_mailbox_id BIGINT,
  p_group_id   BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM contact_groups WHERE id = p_group_id AND mailbox_id = p_mailbox_id) THEN
    RETURN '[]'::JSONB;
  END IF;

  SELECT COALESCE(jsonb_agg(r ORDER BY r->>'email'), '[]'::JSONB) INTO v_result
  FROM (
    SELECT jsonb_build_object(
      'name',  COALESCE(c.display_name, ''),
      'email', COALESCE(cm.email, contact_primary_email(c.emails))
    ) AS r
    FROM contact_group_members cm
    LEFT JOIN contacts c ON c.id = cm.contact_id
    WHERE cm.group_id = p_group_id
      AND COALESCE(cm.email, contact_primary_email(c.emails)) IS NOT NULL
  ) sub;

  RETURN v_result;
END;
$$ LANGUAGE plpgsql;
