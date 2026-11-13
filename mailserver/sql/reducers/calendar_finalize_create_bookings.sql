-- calendar_finalize_create_bookings: resolve + book the room/equipment resources
-- invited on freshly-created CalendarEvent/set events, INSIDE the database.
--
-- This is the reducer half of the CalendarEvent/set *create* side-effect that used to
-- live in the Go gateway (`bookResourcesForCreatedEvents`): per created event, each
-- attendee with role='resource' is resolved by email to a room/equipment calendar and
-- booked via the existing calendar_book_resource (which owns the conflict / booking-policy
-- logic, UNCHANGED). The gateway is left with response assembly only.
--
-- ADR-003 (docs/adr/ARCH-003-account-scope-currency.md): the account slot p_mailbox_id is
-- a MAILBOX id (parseAccountID). calendar_book_resource's p_booked_by argument is a
-- users.id (it does `SELECT email FROM users WHERE id = p_booked_by`), so this reducer
-- resolves the booker's user id via account_scope(p_mailbox_id).user_id — NOT the mailbox
-- id. Passing the mailbox id would match zero users rows under divergent ids (the bug the
-- divergent-id pgTAP guards). p_mailbox_id itself is still passed straight through to
-- calendar_book_resource's own p_mailbox_id slot (correct — that one IS a mailbox id).
--
-- Returns a JSONB object keyed by EVENT id (TEXT) → { roomEmail → book-outcome }, e.g.
--   { "16": { "roomZ@x": {"status":"confirmed","bookingId":"17","conflicts":[]} } }
-- The gateway remaps event-id keys back to the client create-keys (it owns the
-- created-key→event-id map) before merging into the `resourceBookings` response field, so
-- the wire shape mergeResourceBookings emits is byte-identical to the old Go path. Events
-- with no resource attendees (or unresolvable room emails) contribute no key — an empty
-- result means "nothing booked", exactly as the old Go path returned nil.
--
-- Room resolution is by mailboxes.email (a resource ownership lookup, NOT a person
-- lookup), so it is correct without resolve_identity (rooms have no aliases/UPN).
CREATE OR REPLACE FUNCTION calendar_finalize_create_bookings(
  p_mailbox_id        BIGINT,
  p_created_event_ids BIGINT[]
) RETURNS JSONB AS $$
DECLARE
  v_user_id   BIGINT;
  v_event_id  BIGINT;
  v_att       RECORD;
  v_room_cal  BIGINT;
  v_outcome   JSONB;
  v_per_event JSONB;
  v_result    JSONB := '{}'::JSONB;
BEGIN
  IF p_created_event_ids IS NULL OR array_length(p_created_event_ids, 1) IS NULL THEN
    RETURN '{}'::JSONB;
  END IF;

  -- ADR-003: the booker is the users.id behind the caller's mailbox, resolved through
  -- the one seam. NULL for a shared/resource caller mailbox (account_scope returns the
  -- nullable user_id as-is); calendar_book_resource then records a NULL booker email,
  -- which is the same it would for any user_id with no users row.
  SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;

  FOREACH v_event_id IN ARRAY p_created_event_ids
  LOOP
    v_per_event := '{}'::JSONB;

    -- Only events actually owned by this mailbox can have their resources booked from
    -- this account; a foreign event id contributes nothing (the JOIN filters it out).
    FOR v_att IN
      SELECT ea.email AS room_email
      FROM event_attendees ea
      JOIN calendar_events ce ON ce.id = ea.event_id
      JOIN calendars c        ON c.id = ce.calendar_id
      WHERE ea.event_id = v_event_id
        AND c.mailbox_id = p_mailbox_id
        AND ea.role = 'resource'
        AND ea.email IS NOT NULL
        AND ea.email <> ''
      ORDER BY ea.id
    LOOP
      -- Resolve the room/equipment calendar from the resource attendee's email (the
      -- N+1 SELECT that used to run in Go, now one query inside the DB).
      SELECT c.id INTO v_room_cal
      FROM calendars c
      JOIN mailboxes mb ON mb.id = c.mailbox_id
      WHERE mb.email = v_att.room_email
        AND c.resource_type IN ('room', 'equipment')
      LIMIT 1;

      IF v_room_cal IS NULL THEN
        CONTINUE;  -- unresolvable room email: skipped, same as the old Go `continue`
      END IF;

      -- calendar_book_resource owns conflict / booking-policy. p_mailbox_id is the
      -- booker's mailbox id (correct), p_booked_by is the booker's users.id (ADR-003).
      v_outcome := calendar_book_resource(p_mailbox_id, v_room_cal, v_event_id, v_user_id);
      v_per_event := v_per_event || jsonb_build_object(v_att.room_email, v_outcome);
    END LOOP;

    IF v_per_event <> '{}'::JSONB THEN
      v_result := v_result || jsonb_build_object(v_event_id::TEXT, v_per_event);
    END IF;
  END LOOP;

  RETURN v_result;
END;
$$ LANGUAGE plpgsql;
