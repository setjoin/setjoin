-- JMAP Contact/* reducers (JMAP Contacts draft)

CREATE OR REPLACE FUNCTION jmap_addressbook_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_row       RECORD;
  v_state     BIGINT;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  v_state := entity_state(p_mailbox_id, 'AddressBook');

  FOR v_row IN
    SELECT ab.*, (SELECT COUNT(*) FROM contacts WHERE addressbook_id = ab.id) AS contact_count
    FROM addressbooks ab
    WHERE ab.mailbox_id = p_mailbox_id
      AND (p_ids IS NULL OR ab.id = ANY(p_ids))
    ORDER BY ab.name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'name', v_row.name,
      'description', v_row.description,
      'isDefault', v_row.is_default,
      'isShared', v_row.is_shared,
      'myRights', jsonb_build_object(
        'mayReadItems', true,
        'mayAddItems', true,
        'mayRemoveItems', true,
        'mayUpdatePrivate', true,
        'mayDelete', NOT v_row.is_default
      )
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

-- Real AddressBook/changes deltas (A4 wave 1). trg_journal_addressbook (V096)
-- records created/updated/destroyed into jmap_changes_journal at each bump of the
-- 'AddressBook' entity_state counter; this delegates to the shared reader.
CREATE OR REPLACE FUNCTION jmap_addressbook_changes(
  p_mailbox_id   BIGINT,
  p_since_state  TEXT
) RETURNS JSONB AS $$
  SELECT jmap_entity_changes(p_mailbox_id, 'AddressBook', p_since_state, NULL);
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION jmap_addressbook_set_create(
  p_mailbox_id BIGINT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_client_key  TEXT;
  v_obj         JSONB;
  v_id          BIGINT;
  v_created     JSONB := '{}'::JSONB;
  v_notCreated  JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'AddressBook');

  FOR v_client_key, v_obj IN SELECT * FROM jsonb_each(p_creates)
  LOOP
    BEGIN
      IF (v_obj->>'isDefault')::BOOL = true THEN
        UPDATE addressbooks SET is_default = FALSE
        WHERE mailbox_id = p_mailbox_id AND is_default = TRUE;
      END IF;

      INSERT INTO addressbooks (mailbox_id, name, description, is_default, jmap_state)
      VALUES (
        p_mailbox_id,
        COALESCE(v_obj->>'name', 'Address Book'),
        v_obj->>'description',
        COALESCE((v_obj->>'isDefault')::BOOL, FALSE),
        1
      )
      RETURNING id INTO v_id;

      v_created := v_created || jsonb_build_object(
        v_client_key, jsonb_build_object('id', v_id::TEXT)
      );
    EXCEPTION WHEN OTHERS THEN
      v_notCreated := v_notCreated || jsonb_build_object(
        v_client_key, jsonb_build_object('type', 'invalidArguments', 'description', 'creation failed')
      );
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'AddressBook');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_addressbook_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_patch       JSONB;
  v_updated     JSONB := '[]'::JSONB;
  v_notUpdated  JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'AddressBook');

  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      IF (v_patch->>'isDefault')::BOOL = true THEN
        UPDATE addressbooks SET is_default = FALSE
        WHERE mailbox_id = p_mailbox_id AND is_default = TRUE;
      END IF;

      UPDATE addressbooks SET
        name = COALESCE(v_patch->>'name', name),
        description = COALESCE(v_patch->>'description', description),
        is_default = COALESCE((v_patch->>'isDefault')::BOOL, is_default),
        updated_at = now(),
        jmap_state = jmap_state + 1
      WHERE id = v_id AND mailbox_id = p_mailbox_id;

      v_updated := v_updated || to_jsonb(v_id);
    EXCEPTION WHEN OTHERS THEN
      v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'update failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'AddressBook');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_addressbook_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_destroyed   JSONB := '[]'::JSONB;
  v_notDestroyed JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
  v_had_contacts BOOLEAN;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'AddressBook');

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      -- F1 (ghost-contact guard): the DELETE cascades this book's contacts away
      -- (contacts.addressbook_id → addressbooks ON DELETE CASCADE). The per-contact
      -- DELETE trigger can't resolve mailbox_id once the parent row is gone, so
      -- capture whether contacts existed and emit a ContactCard resync sentinel
      -- below — a client syncing across the deletion gets BZ011 (full resync)
      -- instead of ghost contacts.
      v_had_contacts := EXISTS (SELECT 1 FROM contacts WHERE addressbook_id = v_id);

      DELETE FROM addressbooks
      WHERE id = v_id AND mailbox_id = p_mailbox_id AND is_default = FALSE;

      IF FOUND THEN
        IF v_had_contacts THEN
          PERFORM append_change(p_mailbox_id, 'ContactCard',
                                bump_entity_state(p_mailbox_id, 'ContactCard'), NULL, 'resync');
        END IF;
        v_destroyed := v_destroyed || to_jsonb(v_id);
      ELSE
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'addressbook not found or is default'));
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'serverFail', 'description', 'destroy failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'AddressBook');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_contact_get(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_result    JSONB := '[]'::JSONB;
  v_row       RECORD;
  v_state     BIGINT;
  v_found     TEXT[] := ARRAY[]::TEXT[];
BEGIN
  -- A4: the ContactCard /changes token is the monotonic entity_state counter
  -- (bumped by trg_journal_contact), decoupled from AddressBook.
  v_state := entity_state(p_mailbox_id, 'ContactCard');

  FOR v_row IN
    SELECT c.*, ab.mailbox_id
    FROM contacts c
    JOIN addressbooks ab ON ab.id = c.addressbook_id
    WHERE ab.mailbox_id = p_mailbox_id
      AND c.id = ANY(p_ids)
    ORDER BY c.display_name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'addressbookId', v_row.addressbook_id::TEXT,
      'uid', v_row.vcard_uid,
      'firstName', v_row.first_name,
      'lastName', v_row.last_name,
      'nickName', NULL,
      'displayName', v_row.display_name,
      'company', v_row.company,
      'jobTitle', v_row.job_title,
      'department', v_row.department,
      'emails', v_row.emails,
      'phones', v_row.phones,
      'addresses', v_row.addresses,
      'urls', v_row.urls,
      'instantMessengers', v_row.instant_msgs,
      'notes', v_row.notes,
      'birthday', v_row.birthday,
      'anniversary', v_row.anniversary,
      'avatar', CASE WHEN v_row.avatar_sha256 IS NOT NULL
        THEN jsonb_build_object('blobId', v_row.avatar_sha256) END,
      'categories', v_row.categories
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

CREATE OR REPLACE FUNCTION jmap_contact_query(
  p_mailbox_id  BIGINT,
  p_filter      JSONB DEFAULT NULL,
  p_sort        JSONB DEFAULT NULL,
  p_position    INT   DEFAULT 0,
  p_limit       INT   DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_state       BIGINT;
  v_ids         TEXT[];  -- JMAP Id[] is strings; numeric ids 400 in ContactCard/get ([]string)
  v_total       INT;
  v_where       TEXT := 'ab.mailbox_id = $1';
  v_order       TEXT := 'c.display_name ASC';
  v_pat         TEXT;
BEGIN
  -- A4: the ContactCard /changes token is the monotonic entity_state counter
  -- (bumped by trg_journal_contact), decoupled from AddressBook.
  v_state := entity_state(p_mailbox_id, 'ContactCard');

  IF p_filter IS NOT NULL THEN
    IF p_filter ? 'inAddressBook' THEN
      v_where := v_where || format(' AND c.addressbook_id = %s', (p_filter->>'inAddressBook')::BIGINT);
    END IF;
    IF p_filter ? 'text' THEN
      v_pat := '%' || (p_filter->>'text') || '%';
      v_where := v_where || format(
        ' AND (c.display_name ILIKE %L OR c.company ILIKE %L OR c.emails::TEXT ILIKE %L)',
        v_pat, v_pat, v_pat
      );
    END IF;
  END IF;

  EXECUTE format('SELECT COUNT(*) FROM contacts c JOIN addressbooks ab ON ab.id = c.addressbook_id WHERE %s', v_where)
    INTO v_total USING p_mailbox_id;

  EXECUTE format(
    'SELECT array_agg(id::TEXT) FROM (
      SELECT c.id FROM contacts c JOIN addressbooks ab ON ab.id = c.addressbook_id WHERE %s ORDER BY %s LIMIT %s OFFSET %s
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

-- Real ContactCard/changes deltas (A4 wave 1). trg_journal_contact (V096) records
-- created/updated/destroyed into jmap_changes_journal at each bump of the
-- 'ContactCard' entity_state counter; this delegates to the shared reader. An
-- address-book deletion cascades its contacts away — the per-contact DELETE trigger
-- can't resolve mailbox_id once the parent is gone, so jmap_addressbook_set_destroy
-- emits a ContactCard resync sentinel and a client syncing across it gets BZ011.
CREATE OR REPLACE FUNCTION jmap_contact_changes(
  p_mailbox_id   BIGINT,
  p_since_state  TEXT
) RETURNS JSONB AS $$
  SELECT jmap_entity_changes(p_mailbox_id, 'ContactCard', p_since_state, NULL);
$$ LANGUAGE sql;

CREATE OR REPLACE FUNCTION jmap_contact_set_create(
  p_mailbox_id BIGINT,
  p_creates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_client_key  TEXT;
  v_obj         JSONB;
  v_id          BIGINT;
  v_ab_id       BIGINT;
  v_uid         TEXT;
  v_created     JSONB := '{}'::JSONB;
  v_notCreated  JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'ContactCard');

  FOR v_client_key, v_obj IN SELECT * FROM jsonb_each(p_creates)
  LOOP
    BEGIN
      v_ab_id := COALESCE((v_obj->>'addressbookId')::BIGINT,
        (SELECT id FROM addressbooks WHERE mailbox_id = p_mailbox_id AND is_default = TRUE LIMIT 1));

      IF v_ab_id IS NULL THEN
        v_notCreated := v_notCreated || jsonb_build_object(
          v_client_key, jsonb_build_object('type', 'invalidArguments', 'description', 'no addressbook specified and no default exists')
        );
        CONTINUE;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM addressbooks WHERE id = v_ab_id AND mailbox_id = p_mailbox_id) THEN
        v_notCreated := v_notCreated || jsonb_build_object(
          v_client_key, jsonb_build_object('type', 'invalidArguments', 'description', 'addressbook not found')
        );
        CONTINUE;
      END IF;

      v_uid := COALESCE(v_obj->>'uid', gen_random_uuid()::TEXT);

      INSERT INTO contacts (
        addressbook_id, vcard_uid, display_name, first_name, last_name,
        company, job_title, department, emails, phones, addresses, urls,
        instant_msgs, notes, birthday, anniversary, avatar_sha256, categories, etag
      ) VALUES (
        v_ab_id, v_uid,
        COALESCE(NULLIF(TRIM(COALESCE(v_obj->>'firstName', '') || ' ' || COALESCE(v_obj->>'lastName', '')), ''), COALESCE(v_obj->>'displayName', 'Unnamed Contact')),
        v_obj->>'firstName', v_obj->>'lastName',
        v_obj->>'company', v_obj->>'jobTitle', v_obj->>'department',
        COALESCE(v_obj->'emails', '[]'::JSONB),
        COALESCE(v_obj->'phones', '[]'::JSONB),
        COALESCE(v_obj->'addresses', '[]'::JSONB),
        COALESCE(v_obj->'urls', '[]'::JSONB),
        COALESCE(v_obj->'instantMessengers', '[]'::JSONB),
        v_obj->>'notes',
        (v_obj->>'birthday')::DATE,
        (v_obj->>'anniversary')::DATE,
        v_obj->>'avatar',
        COALESCE(array(SELECT jsonb_array_elements_text(v_obj->'categories')), '{}'),
        encode(digest(v_uid || now()::TEXT, 'md5'), 'hex')
      )
      RETURNING id INTO v_id;

      -- Bump the contacts-domain state + push on 'contact:{mailbox_id}' through the
      -- contact seam.
      PERFORM notify_contact_state(p_mailbox_id, 'contact_created', v_id);

      v_created := v_created || jsonb_build_object(
        v_client_key, jsonb_build_object('id', v_id::TEXT)
      );
    EXCEPTION WHEN OTHERS THEN
      v_notCreated := v_notCreated || jsonb_build_object(
        v_client_key, jsonb_build_object('type', 'invalidArguments', 'description', 'creation failed')
      );
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'ContactCard');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'created', v_created,
    'notCreated', v_notCreated
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_contact_set_update(
  p_mailbox_id BIGINT,
  p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_patch       JSONB;
  v_updated     JSONB := '[]'::JSONB;
  v_notUpdated  JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'ContactCard');

  FOR v_id, v_patch IN SELECT * FROM jsonb_each(p_updates)
  LOOP
    BEGIN
      UPDATE contacts c SET
        display_name = COALESCE(v_patch->>'displayName', c.display_name),
        first_name = COALESCE(v_patch->>'firstName', c.first_name),
        last_name = COALESCE(v_patch->>'lastName', c.last_name),
        company = COALESCE(v_patch->>'company', c.company),
        job_title = COALESCE(v_patch->>'jobTitle', c.job_title),
        department = COALESCE(v_patch->>'department', c.department),
        emails = COALESCE(v_patch->'emails', c.emails),
        phones = COALESCE(v_patch->'phones', c.phones),
        addresses = COALESCE(v_patch->'addresses', c.addresses),
        urls = COALESCE(v_patch->'urls', c.urls),
        instant_msgs = COALESCE(v_patch->'instantMessengers', c.instant_msgs),
        notes = COALESCE(v_patch->>'notes', c.notes),
        birthday = COALESCE((v_patch->>'birthday')::DATE, c.birthday),
        anniversary = COALESCE((v_patch->>'anniversary')::DATE, c.anniversary),
        avatar_sha256 = COALESCE(v_patch->>'avatar', c.avatar_sha256),
        categories = COALESCE(array(SELECT jsonb_array_elements_text(v_patch->'categories')), c.categories),
        updated_at = now(),
        etag = encode(digest(c.vcard_uid || now()::TEXT, 'md5'), 'hex')
        -- No inline jmap_state bump: the contacts domain token is
        -- addressbooks.jmap_state, advanced by notify_contact_state below.
      FROM addressbooks ab
      WHERE c.id = v_id AND c.addressbook_id = ab.id AND ab.mailbox_id = p_mailbox_id;

      IF FOUND THEN
        v_updated := v_updated || to_jsonb(v_id);
        PERFORM notify_contact_state(p_mailbox_id, 'contact_updated', v_id);
      ELSE
        v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'contact not found'));
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_notUpdated := v_notUpdated || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'invalidArguments', 'description', 'update failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'ContactCard');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'updated', v_updated,
    'notUpdated', v_notUpdated
  );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION jmap_contact_set_destroy(
  p_mailbox_id BIGINT,
  p_ids        BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_id          BIGINT;
  v_destroyed   JSONB := '[]'::JSONB;
  v_notDestroyed JSONB := '{}'::JSONB;
  v_old_state   BIGINT;
  v_new_state   BIGINT;
BEGIN
  v_old_state := entity_state(p_mailbox_id, 'ContactCard');

  FOREACH v_id IN ARRAY p_ids
  LOOP
    BEGIN
      DELETE FROM contacts c
      USING addressbooks ab
      WHERE c.id = v_id AND c.addressbook_id = ab.id AND ab.mailbox_id = p_mailbox_id;

      IF FOUND THEN
        v_destroyed := v_destroyed || to_jsonb(v_id);
        PERFORM notify_contact_state(p_mailbox_id, 'contact_destroyed', v_id);
      ELSE
        v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
          jsonb_build_object('type', 'notFound', 'description', 'contact not found'));
      END IF;
    EXCEPTION WHEN OTHERS THEN
      v_notDestroyed := v_notDestroyed || jsonb_build_object(v_id::TEXT,
        jsonb_build_object('type', 'serverFail', 'description', 'destroy failed'));
    END;
  END LOOP;

  v_new_state := entity_state(p_mailbox_id, 'ContactCard');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', v_old_state::TEXT,
    'newState', v_new_state::TEXT,
    'destroyed', v_destroyed,
    'notDestroyed', v_notDestroyed
  );
END;
$$ LANGUAGE plpgsql;

-- gal_search: search the Global Address List (company directory).
-- ORG-WIDE + address-aware (ADR-004, docs/adr/ARCH-004-directory-org-scope.md):
-- a deployment is ONE org, so the GAL spans every domain/forest — the old
-- `u.domain_id = <home domain>` filter is GONE (it fragmented one org across its
-- own AD domains). Scope + the address set come from the shared
-- `directory_visible_users(p_mailbox_id)` seam (the SAME rule directory_members /
-- directory_search / directory_tree use, so they can't drift). The query matches
-- the WHOLE address set (primary ∪ aliases ∪ UPN) via `address_blob`, and each
-- result card returns every address under `addresses` (Exchange GAL parity).
CREATE OR REPLACE FUNCTION gal_search(
  p_mailbox_id BIGINT,
  p_text       TEXT DEFAULT '',
  p_limit      INT  DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  FOR v_row IN
    SELECT v.*
    FROM directory_visible_users(p_mailbox_id) v
    WHERE (p_text = '' OR v.display_name ILIKE '%' || p_text || '%'
                       OR v.address_blob ILIKE '%' || p_text || '%'
                       OR v.first_name ILIKE '%' || p_text || '%'
                       OR v.last_name ILIKE '%' || p_text || '%')
    ORDER BY v.display_name
    LIMIT p_limit
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'email', v_row.email,
      'addresses', v_row.addresses,
      'displayName', v_row.display_name,
      'firstName', v_row.first_name,
      'lastName', v_row.last_name,
      'phone', v_row.phone,
      'jobTitle', v_row.job_title,
      'department', v_row.dept_name,
      'avatar', CASE WHEN v_row.avatar_sha256 IS NOT NULL
        THEN jsonb_build_object('blobId', v_row.avatar_sha256) END
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql;

-- contact_find_duplicates: group the caller's contacts (across ALL their address
-- books) by lower(email address) and return every cluster with ≥2 members, e.g.
-- [{"email":"a@x","contactIds":[1,2]}, …]. Email-exact only (no fuzzy name match).
-- R1: scoped via JOIN addressbooks ON mailbox_id = p_mailbox_id. STABLE (read-only).
CREATE OR REPLACE FUNCTION contact_find_duplicates(
  p_mailbox_id BIGINT
) RETURNS JSONB AS $$
  SELECT COALESCE(
    jsonb_agg(jsonb_build_object('email', addr, 'contactIds', ids) ORDER BY addr),
    '[]'::JSONB)
  FROM (
    SELECT lower(e->>'address')            AS addr,
           array_agg(DISTINCT c.id ORDER BY c.id) AS ids
    FROM contacts c
    JOIN addressbooks ab ON ab.id = c.addressbook_id
    CROSS JOIN LATERAL jsonb_array_elements(c.emails) AS e
    WHERE ab.mailbox_id = p_mailbox_id
      AND NULLIF(TRIM(e->>'address'), '') IS NOT NULL
    GROUP BY lower(e->>'address')
    HAVING COUNT(DISTINCT c.id) > 1
  ) grp;
$$ LANGUAGE sql STABLE;

-- contact_merge: merge duplicate contact p_drop_id INTO keeper p_keep_id in ONE
-- atomic txn. Ownership (R3, no TOCTOU) is resolved IN THE WHERE via
-- JOIN addressbooks ON mailbox_id = p_mailbox_id; a missing/foreign row → BZ112.
-- Field union onto the keeper: emails/phones unioned (keeper wins is_primary),
-- categories array-unioned, scalar fields COALESCE(NULLIF(keep,''), drop), keeper's
-- display_name kept, etag bumped. Group memberships are re-pointed to the keeper
-- BEFORE the delete (collisions against the cgm_contact_uniq (group_id, contact_id)
-- index are de-duped first). Bumps the contacts domain token + pushes twice via the
-- notify_contact_state seam (keeper updated, loser destroyed). Returns {merged:keep}.
CREATE OR REPLACE FUNCTION contact_merge(
  p_mailbox_id BIGINT,
  p_keep_id    BIGINT,
  p_drop_id    BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_keep       contacts%ROWTYPE;
  v_drop       contacts%ROWTYPE;
  v_emails     JSONB;
  v_phones     JSONB;
  v_categories TEXT[];
BEGIN
  -- Keeper: resolve + ownership in the WHERE (R3).
  SELECT c.* INTO v_keep
  FROM contacts c
  JOIN addressbooks ab ON ab.id = c.addressbook_id
  WHERE c.id = p_keep_id AND ab.mailbox_id = p_mailbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Contact % not found in mailbox %', p_keep_id, p_mailbox_id
      USING ERRCODE = 'BZ112',
            HINT = jsonb_build_object('type', 'contact_merge_not_found',
                                      'contact_id', p_keep_id)::TEXT;
  END IF;

  -- keep == drop: nothing to merge; keeper already verified owned → no-op.
  IF p_keep_id = p_drop_id THEN
    RETURN jsonb_build_object('merged', p_keep_id);
  END IF;

  -- Loser: resolve + ownership in the WHERE (R3).
  SELECT c.* INTO v_drop
  FROM contacts c
  JOIN addressbooks ab ON ab.id = c.addressbook_id
  WHERE c.id = p_drop_id AND ab.mailbox_id = p_mailbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Contact % not found in mailbox %', p_drop_id, p_mailbox_id
      USING ERRCODE = 'BZ112',
            HINT = jsonb_build_object('type', 'contact_merge_not_found',
                                      'contact_id', p_drop_id)::TEXT;
  END IF;

  -- emails: keeper's entries verbatim ∪ drop entries whose lower(address) isn't
  -- already in keeper; appended drop entries lose is_primary (keeper's primary wins).
  SELECT COALESCE(jsonb_agg(e ORDER BY grp, idx), '[]'::JSONB) INTO v_emails
  FROM (
    SELECT ke.kv AS e, 0 AS grp, ke.ord AS idx
      FROM jsonb_array_elements(v_keep.emails) WITH ORDINALITY AS ke(kv, ord)
    UNION ALL
    SELECT (de.dv || jsonb_build_object('is_primary', false)) AS e, 1 AS grp, de.ord AS idx
      FROM jsonb_array_elements(v_drop.emails) WITH ORDINALITY AS de(dv, ord)
     WHERE NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(v_keep.emails) AS k(kv)
       WHERE lower(k.kv->>'address') = lower(de.dv->>'address'))
  ) u;

  -- phones: union on the digits-only normalized number.
  SELECT COALESCE(jsonb_agg(e ORDER BY grp, idx), '[]'::JSONB) INTO v_phones
  FROM (
    SELECT kp.kv AS e, 0 AS grp, kp.ord AS idx
      FROM jsonb_array_elements(v_keep.phones) WITH ORDINALITY AS kp(kv, ord)
    UNION ALL
    SELECT dp.dv AS e, 1 AS grp, dp.ord AS idx
      FROM jsonb_array_elements(v_drop.phones) WITH ORDINALITY AS dp(dv, ord)
     WHERE NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(v_keep.phones) AS k(kv)
       WHERE regexp_replace(k.kv->>'number', '[^0-9]', '', 'g')
           = regexp_replace(dp.dv->>'number', '[^0-9]', '', 'g'))
  ) u;

  -- categories: keeper's ∪ drop-only (array union, keeper order preserved).
  v_categories := v_keep.categories || ARRAY(
    SELECT cat FROM unnest(v_drop.categories) cat
    WHERE NOT (cat = ANY(v_keep.categories)));

  -- Re-point group memberships to the keeper BEFORE the delete. De-dup first: drop
  -- the loser's membership rows whose (group) already has the keeper (else the
  -- cgm_contact_uniq (group_id, contact_id) unique index would reject the UPDATE);
  -- then UPDATE the rest. Rows are keyed by the already-owner-verified p_drop_id.
  DELETE FROM contact_group_members m
  WHERE m.contact_id = p_drop_id
    AND EXISTS (SELECT 1 FROM contact_group_members k
                WHERE k.group_id = m.group_id AND k.contact_id = p_keep_id);
  UPDATE contact_group_members
  SET contact_id = p_keep_id
  WHERE contact_id = p_drop_id;

  -- Field union onto the keeper (display_name kept; etag regenerated).
  UPDATE contacts c SET
    emails        = v_emails,
    phones        = v_phones,
    categories    = v_categories,
    first_name    = COALESCE(NULLIF(c.first_name, ''),    v_drop.first_name),
    last_name     = COALESCE(NULLIF(c.last_name, ''),     v_drop.last_name),
    company       = COALESCE(NULLIF(c.company, ''),       v_drop.company),
    job_title     = COALESCE(NULLIF(c.job_title, ''),     v_drop.job_title),
    department    = COALESCE(NULLIF(c.department, ''),     v_drop.department),
    notes         = COALESCE(NULLIF(c.notes, ''),         v_drop.notes),
    birthday      = COALESCE(c.birthday,    v_drop.birthday),
    anniversary   = COALESCE(c.anniversary, v_drop.anniversary),
    avatar_sha256 = COALESCE(NULLIF(c.avatar_sha256, ''), v_drop.avatar_sha256),
    updated_at    = now(),
    etag          = encode(digest(c.vcard_uid || now()::TEXT, 'md5'), 'hex')
  WHERE c.id = p_keep_id;

  -- Delete the loser (R3-scoped delete: id + ownership in the same statement).
  DELETE FROM contacts c
  USING addressbooks ab
  WHERE c.id = p_drop_id AND c.addressbook_id = ab.id AND ab.mailbox_id = p_mailbox_id;

  -- State: bump the contacts domain token + push (keeper updated, loser destroyed).
  PERFORM notify_contact_state(p_mailbox_id, 'contact_updated', p_keep_id);
  PERFORM notify_contact_state(p_mailbox_id, 'contact_destroyed', p_drop_id);

  RETURN jsonb_build_object('merged', p_keep_id);
END;
$$ LANGUAGE plpgsql;
