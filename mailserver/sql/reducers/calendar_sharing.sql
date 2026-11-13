-- calendar_sharing.sql — ACL-aware shared-calendar reads + share grant/revoke/list.
--
-- SECURITY MODEL (A3). The same-mailbox guard in the Go gateway's parseAccountID is
-- NEVER relaxed: a viewer cannot pass another user's accountId. Instead these reducers
-- take the *viewer* (the authenticated user's users.id, from user.UserID) and an *owner*
-- target, and return only calendars/events the viewer holds a calendar_acls grant on.
-- A 'freebusy' grant strips everything but the time block (title→'Busy', no location /
-- description). R1/R3 ownership lives in the same WHERE via the EXISTS(calendar_acls)
-- gate keyed on the viewer's users.id.

-- jmap_calendar_get_shared: calendars belonging to p_owner_email that p_viewer_id has a
-- calendar_acls grant on. myRights reflects the granted level.
-- DEFAULTS LAYER (sharing.defaults, D11): when the toggle is ON, the owner's
-- PRIMARY calendar (D6) is also listed at the calendar_effective_acl level when
-- the viewer holds no explicit row on it (the resolver folds in the org/OU/
-- group/user defaults ladder). Toggle OFF ⇒ v_default_cal stays NULL and the
-- LEFT JOIN + predicate below degrade to the original inner join — byte-identical.
CREATE OR REPLACE FUNCTION jmap_calendar_get_shared(
  p_viewer_id   BIGINT,
  p_owner_email TEXT
) RETURNS JSONB AS $$
DECLARE
  v_owner_mbox    BIGINT;
  v_owner_uid     BIGINT;
  v_result        JSONB := '[]'::JSONB;
  v_row           RECORD;
  v_default_cal   BIGINT;
  v_default_level TEXT;
BEGIN
  -- Resolve the owner by ANY of their addresses (primary ∪ alias ∪ UPN) through
  -- the one address-aware seam (ADR-004) — not by users.email only, which missed
  -- an owner addressed by a sister-domain alias or their UPN.
  SELECT user_id, primary_mailbox INTO v_owner_uid, v_owner_mbox
  FROM resolve_identity(p_owner_email);

  IF v_owner_mbox IS NULL THEN
    RETURN jsonb_build_object(
      'accountId', p_viewer_id::TEXT, 'ownerEmail', p_owner_email, 'list', '[]'::JSONB);
  END IF;

  -- Defaults layer (ON only): the visibility decision routes through
  -- calendar_effective_acl; only freebusy/read can come from the ladder.
  IF v_owner_uid IS NOT NULL
     AND COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'sharing.defaults'), FALSE) THEN
    v_default_level := calendar_effective_acl(p_viewer_id, v_owner_uid);
    IF v_default_level IN ('freebusy', 'read') THEN
      SELECT c.id INTO v_default_cal FROM calendars c
       WHERE c.mailbox_id = v_owner_mbox
       ORDER BY c.is_default DESC, c.id LIMIT 1;
      -- an explicit row on the primary calendar is already emitted by the join
      IF v_default_cal IS NOT NULL AND EXISTS (
           SELECT 1 FROM calendar_acls
            WHERE calendar_id = v_default_cal AND user_id = p_viewer_id) THEN
        v_default_cal := NULL;
      END IF;
    END IF;
  END IF;

  FOR v_row IN
    SELECT c.*, COALESCE(a.permission, v_default_level) AS grant_level
    FROM calendars c
    LEFT JOIN calendar_acls a ON a.calendar_id = c.id AND a.user_id = p_viewer_id
    WHERE c.mailbox_id = v_owner_mbox
      AND (a.user_id IS NOT NULL OR c.id = v_default_cal)
    ORDER BY c.name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'name', v_row.name,
      'description', v_row.description,
      'color', v_row.color,
      'timeZone', v_row.timezone,
      'isShared', TRUE,
      'isReadOnly', TRUE,
      'ownerEmail', p_owner_email,
      'myRights', jsonb_build_object(
        'mayReadItems', TRUE,
        'mayReadFreeBusy', TRUE,
        'mayReadDetails', v_row.grant_level <> 'freebusy',
        'mayAddItems', FALSE,
        'mayRemoveItems', FALSE,
        'mayRSVP', FALSE,
        'mayDelete', FALSE
      ),
      'shareLevel', v_row.grant_level
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_viewer_id::TEXT,
    'ownerEmail', p_owner_email,
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql STABLE;

-- jmap_calendar_event_get_shared: events on p_owner_email's calendars the viewer holds a
-- grant on, within [p_after, p_before]. A 'freebusy' grant — OR a PRIVATE/CONFIDENTIAL
-- event (classification <> 'PUBLIC') — redacts title/location/description to a 'Busy'
-- block; a 'read'+ grant returns full details only for PUBLIC events.
-- DEFAULTS LAYER (sharing.defaults, D11): mirrors jmap_calendar_get_shared —
-- when ON, events on the owner's PRIMARY calendar (D6) are visible at the
-- calendar_effective_acl level for a viewer with no explicit row there, with
-- the SAME redaction contract (a freebusy-level default, or any non-PUBLIC
-- event, shows only a 'Busy' block). Toggle OFF ⇒ byte-identical explicit join.
CREATE OR REPLACE FUNCTION jmap_calendar_event_get_shared(
  p_viewer_id   BIGINT,
  p_owner_email TEXT,
  p_after       TIMESTAMPTZ DEFAULT NULL,
  p_before      TIMESTAMPTZ DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_owner_mbox    BIGINT;
  v_owner_uid     BIGINT;
  v_result        JSONB := '[]'::JSONB;
  v_row           RECORD;
  v_fb_only       BOOLEAN;
  v_default_cal   BIGINT;
  v_default_level TEXT;
BEGIN
  -- Owner resolved address-aware (primary ∪ alias ∪ UPN), one seam (ADR-004).
  SELECT user_id, primary_mailbox INTO v_owner_uid, v_owner_mbox
  FROM resolve_identity(p_owner_email);

  IF v_owner_mbox IS NULL THEN
    RETURN jsonb_build_object(
      'accountId', p_viewer_id::TEXT, 'ownerEmail', p_owner_email, 'list', '[]'::JSONB);
  END IF;

  -- Defaults layer (ON only): the visibility decision routes through
  -- calendar_effective_acl (explicit ▸ defaults ladder ▸ none).
  IF v_owner_uid IS NOT NULL
     AND COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'sharing.defaults'), FALSE) THEN
    v_default_level := calendar_effective_acl(p_viewer_id, v_owner_uid);
    IF v_default_level IN ('freebusy', 'read') THEN
      SELECT c.id INTO v_default_cal FROM calendars c
       WHERE c.mailbox_id = v_owner_mbox
       ORDER BY c.is_default DESC, c.id LIMIT 1;
      IF v_default_cal IS NOT NULL AND EXISTS (
           SELECT 1 FROM calendar_acls
            WHERE calendar_id = v_default_cal AND user_id = p_viewer_id) THEN
        v_default_cal := NULL;
      END IF;
    END IF;
  END IF;

  FOR v_row IN
    SELECT ce.*, COALESCE(a.permission, v_default_level) AS grant_level
    FROM calendar_events ce
    JOIN calendars c ON c.id = ce.calendar_id
    LEFT JOIN calendar_acls a ON a.calendar_id = c.id AND a.user_id = p_viewer_id
    WHERE c.mailbox_id = v_owner_mbox
      AND (a.user_id IS NOT NULL OR c.id = v_default_cal)
      AND ce.status <> 'cancelled'
      AND (p_after  IS NULL OR ce.end_at   > p_after)
      AND (p_before IS NULL OR ce.start_at < p_before)
    ORDER BY ce.start_at
  LOOP
    -- SECURITY (redaction contract): a non-owner shared-calendar viewer sees
    -- only a 'Busy' block for (a) a freebusy grant OR (b) a PRIVATE/CONFIDENTIAL
    -- event, REGARDLESS of grant level — a `read`+ viewer must NOT see a private
    -- event's title/location/description/rrule. This is the ONLY non-owner event
    -- detail path; ANY new non-owner read path MUST redact the same way.
    v_fb_only := (v_row.grant_level = 'freebusy')
              OR (v_row.classification <> 'PUBLIC');
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'calendarId', v_row.calendar_id::TEXT,
      'isReadOnly', TRUE,
      'start', v_row.start_at,
      'end', v_row.end_at,
      'isAllDay', v_row.all_day,
      'timeZone', v_row.timezone,
      'status', v_row.status,
      -- Redaction gate: freebusy grants expose only the time block.
      'title', CASE WHEN v_fb_only THEN 'Busy' ELSE v_row.title END,
      'location', CASE WHEN v_fb_only THEN NULL ELSE v_row.location END,
      'description', CASE WHEN v_fb_only THEN NULL ELSE v_row.description END,
      'recurrenceRule', CASE WHEN v_fb_only THEN NULL ELSE v_row.rrule END
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_viewer_id::TEXT,
    'ownerEmail', p_owner_email,
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql STABLE;

-- jmap_calendar_share_get: list the grants on a calendar the account owns.
CREATE OR REPLACE FUNCTION jmap_calendar_share_get(
  p_mailbox_id  BIGINT,
  p_calendar_id BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  -- Ownership: the calendar must belong to the account's mailbox.
  IF NOT EXISTS (
    SELECT 1 FROM calendars WHERE id = p_calendar_id AND mailbox_id = p_mailbox_id
  ) THEN
    RAISE EXCEPTION 'Calendar not found in this account'
      USING ERRCODE = 'BZ001',
            HINT = '{"type":"forbidden","calendar_id":"' || p_calendar_id || '"}';
  END IF;

  FOR v_row IN
    SELECT a.permission, u.email, u.display_name
    FROM calendar_acls a
    JOIN users u ON u.id = a.user_id
    WHERE a.calendar_id = p_calendar_id
    ORDER BY u.email
  LOOP
    v_result := v_result || jsonb_build_object(
      'userEmail', v_row.email,
      'name', v_row.display_name,
      'level', v_row.permission
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'calendarId', p_calendar_id::TEXT,
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql STABLE;

-- jmap_calendar_share_set: grant/revoke calendar_acls rows. Only the calendar owner (the
-- account whose mailbox owns it) or a viewer holding an 'admin' grant may change shares.
--   p_grants  = [{userEmail, level}]   level ∈ {freebusy,read,write,admin}
--   p_revokes = [{userEmail}]
CREATE OR REPLACE FUNCTION jmap_calendar_share_set(
  p_mailbox_id  BIGINT,
  p_calendar_id BIGINT,
  p_grants      JSONB DEFAULT '[]'::JSONB,
  p_revokes     JSONB DEFAULT '[]'::JSONB
) RETURNS JSONB AS $$
DECLARE
  v_owner_mbox BIGINT;
  v_caller_uid BIGINT;
  v_is_owner   BOOLEAN := FALSE;
  v_is_admin   BOOLEAN := FALSE;
  v_grant      JSONB;
  v_revoke     JSONB;
  v_target_uid BIGINT;
  v_level      TEXT;
BEGIN
  SELECT mailbox_id INTO v_owner_mbox FROM calendars WHERE id = p_calendar_id;
  IF v_owner_mbox IS NULL THEN
    RAISE EXCEPTION 'Calendar not found'
      USING ERRCODE = 'BZ001', HINT = '{"type":"forbidden"}';
  END IF;

  -- Owner = the account's mailbox owns the calendar.
  v_is_owner := (v_owner_mbox = p_mailbox_id);

  -- Admin grantee: the caller's user holds an 'admin' grant on this calendar.
  -- Resolve the user behind the caller's mailbox via the one resolver seam
  -- (ADR-003), not a hand-join of `mailboxes`. NULL (shared mailbox) → no admin
  -- grant, identical to the prior hand-join.
  SELECT user_id INTO v_caller_uid FROM account_scope(p_mailbox_id);
  IF v_caller_uid IS NOT NULL THEN
    v_is_admin := EXISTS (
      SELECT 1 FROM calendar_acls
      WHERE calendar_id = p_calendar_id AND user_id = v_caller_uid AND permission = 'admin'
    );
  END IF;

  IF NOT (v_is_owner OR v_is_admin) THEN
    RAISE EXCEPTION 'Not authorized to manage shares on this calendar'
      USING ERRCODE = 'BZ001',
            HINT = '{"type":"forbidden","calendar_id":"' || p_calendar_id || '"}';
  END IF;

  -- Apply grants (upsert).
  IF jsonb_typeof(p_grants) = 'array' THEN
    FOR v_grant IN SELECT * FROM jsonb_array_elements(p_grants)
    LOOP
      v_level := v_grant->>'level';
      IF v_level NOT IN ('freebusy', 'read', 'write', 'admin') THEN
        CONTINUE;  -- ignore unknown levels (enum enforcement is also at the CHECK)
      END IF;
      -- Resolve the grantee address-aware (primary ∪ alias ∪ UPN) through the one
      -- seam (ADR-004) — a grantee addressed by an alias/UPN previously no-op'd.
      SELECT user_id INTO v_target_uid FROM resolve_identity(v_grant->>'userEmail');
      IF v_target_uid IS NULL THEN
        CONTINUE;
      END IF;
      INSERT INTO calendar_acls (calendar_id, user_id, permission)
      VALUES (p_calendar_id, v_target_uid, v_level)
      ON CONFLICT (calendar_id, user_id) DO UPDATE SET permission = EXCLUDED.permission;
    END LOOP;
  END IF;

  -- Apply revokes.
  IF jsonb_typeof(p_revokes) = 'array' THEN
    FOR v_revoke IN SELECT * FROM jsonb_array_elements(p_revokes)
    LOOP
      -- Revoke grantee resolved address-aware (primary ∪ alias ∪ UPN), one seam.
      SELECT user_id INTO v_target_uid FROM resolve_identity(v_revoke->>'userEmail');
      IF v_target_uid IS NOT NULL THEN
        DELETE FROM calendar_acls WHERE calendar_id = p_calendar_id AND user_id = v_target_uid;
      END IF;
    END LOOP;
  END IF;

  -- Reflect whether any grant remains on is_shared (the business UPDATE); the
  -- jmap_state bump + push route through the calendar seam (no event) below.
  UPDATE calendars
  SET is_shared = EXISTS (SELECT 1 FROM calendar_acls WHERE calendar_id = p_calendar_id),
      updated_at = now()
  WHERE id = p_calendar_id;

  -- Bump calendars.jmap_state (scoped to the owner mailbox) + push
  -- {event:'calendar_shared', calendar_id} on calendar:{owner_mailbox_id}.
  PERFORM notify_calendar_state(v_owner_mbox, NULL, p_calendar_id, 'calendar_shared');

  RETURN jsonb_build_object(
    'ok', TRUE,
    'calendarId', p_calendar_id::TEXT,
    'newState', (SELECT jmap_state FROM calendars WHERE id = p_calendar_id)::TEXT
  );
END;
$$ LANGUAGE plpgsql;
