-- iTIP/iMIP: RSVP and invite sending reducers.

-- jmap_calendar_event_rsvp: update attendee participation status.
--
-- p_on_behalf_of (optional): the users.id of a delegate responding on the calendar
-- owner's behalf. When set, the delegate must hold a mailbox_delegates grant
-- (full_access or manage_calendar) on the owner's primary mailbox, else the call is
-- forbidden and no attendee row is flipped. When NULL the existing self-RSVP path runs
-- unchanged (ownership is the caller's own account).
CREATE OR REPLACE FUNCTION jmap_calendar_event_rsvp(
  p_mailbox_id     BIGINT,
  p_event_id       BIGINT,
  p_attendee_email TEXT,
  p_status         TEXT,
  p_on_behalf_of   BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_event     RECORD;
  v_new_state BIGINT;
BEGIN
  IF p_status NOT IN ('accepted', 'tentative', 'declined') THEN
    RETURN jsonb_build_object('type', 'invalidArguments',
      'description', 'status must be accepted, tentative, or declined');
  END IF;

  SELECT ce.*, c.mailbox_id INTO v_event
  FROM calendar_events ce
  JOIN calendars c ON c.id = ce.calendar_id
  WHERE ce.id = p_event_id AND c.mailbox_id = p_mailbox_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('type', 'notFound',
      'description', 'Event not found in this account');
  END IF;

  -- Delegate respond: verify the actor holds a calendar-respond delegation on the
  -- owner mailbox before flipping the owner's attendee row on their behalf.
  IF p_on_behalf_of IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM mailbox_delegates
      WHERE mailbox_id = v_event.mailbox_id
        AND user_id = p_on_behalf_of
        AND permission IN ('full_access', 'manage_calendar')
    ) THEN
      RETURN jsonb_build_object('type', 'forbidden',
        'description', 'Not authorized to respond on behalf of this mailbox');
    END IF;
  END IF;

  -- Ownership is already established: v_event was SELECTed above under
  -- c.mailbox_id = p_mailbox_id (NOT FOUND → notFound). These UPDATEs gate on the
  -- already-validated p_event_id; the prior re-proving EXISTS subqueries were dead weight.
  UPDATE event_attendees SET status = p_status
  WHERE event_id = p_event_id AND email = p_attendee_email;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('type', 'notFound',
      'description', 'Attendee not found for this event');
  END IF;

  UPDATE calendar_events SET
    sequence = sequence + 1,
    jmap_state = jmap_state + 1,
    updated_at = now(),
    etag = generate_etag()
  WHERE id = p_event_id;

  PERFORM app_notify(
    'calendar:' || v_event.mailbox_id,
    json_build_object(
      'event', 'rsvp',
      'event_id', p_event_id,
      'attendee', p_attendee_email,
      'status', p_status
    )::text
  );

  -- A4: the CalendarEvent /changes token is the monotonic entity_state counter
  -- (the UPDATE above fired trg_journal_calendar_event → journaled 'updated' at a
  -- fresh bump), not MAX(calendar_events.jmap_state).
  v_new_state := entity_state(p_mailbox_id, 'CalendarEvent');

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'oldState', (v_new_state - 1)::TEXT,
    'newState', v_new_state::TEXT,
    'updated', to_jsonb(p_event_id)
  );
END;
$$ LANGUAGE plpgsql;

-- calendar_send_invite: generate iMIP email payload for event attendees.
-- Returns JSONB with the email details for the gateway to send.
CREATE OR REPLACE FUNCTION calendar_send_invite(
  p_event_id        BIGINT,
  p_organizer_email TEXT,
  p_mailbox_id      BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_event     RECORD;
  v_attendees JSONB;
  v_ical_uid  TEXT;
  v_result    JSONB;
BEGIN
  IF p_mailbox_id IS NOT NULL THEN
    -- p_mailbox_id is the caller's primary mailbox id (parseAccountID), so the organizer
    -- address must belong to THIS mailbox (id), not be a user_id of some other mailbox.
    PERFORM 1 FROM mailboxes WHERE email = p_organizer_email AND id = p_mailbox_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Organizer mailbox not found' USING ERRCODE = 'BZ001';
    END IF;
  END IF;

  SELECT ce.*, c.mailbox_id INTO v_event
  FROM calendar_events ce
  JOIN calendars c ON c.id = ce.calendar_id
  WHERE ce.id = p_event_id AND c.mailbox_id = p_mailbox_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('type', 'notFound', 'description', 'Event not found');
  END IF;

  IF NOT v_event.is_meeting THEN
    RETURN jsonb_build_object('type', 'notMeeting', 'description', 'Event is not a meeting');
  END IF;

  SELECT jsonb_agg(jsonb_build_object(
    'email', ea.email,
    'name', ea.name,
    'role', ea.role,
    'participationStatus', ea.status,
    'expectReply', ea.rsvp
  )) INTO v_attendees
  FROM event_attendees ea
  WHERE ea.event_id = p_event_id
    AND ea.role != 'resource'
    AND ea.email != v_event.organizer_email;

  IF v_attendees IS NULL OR jsonb_array_length(v_attendees) = 0 THEN
    RETURN jsonb_build_object('type', 'noRecipients', 'description', 'No external attendees to invite');
  END IF;

  v_ical_uid := v_event.uid;

  v_result := jsonb_build_object(
    'eventId', p_event_id::TEXT,
    'uid', v_ical_uid,
    'organizerEmail', v_event.organizer_email,
    'organizerName', v_event.organizer_name,
    'title', v_event.title,
    'description', v_event.description,
    'location', v_event.location,
    'start', v_event.start_at,
    'end', v_event.end_at,
    'allDay', v_event.all_day,
    'timezone', v_event.timezone,
    'status', v_event.status,
    'sequence', v_event.sequence,
    'rrule', v_event.rrule,
    'attendees', v_attendees,
    'meetingUrl', v_event.meeting_url
  );

  RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- calendar_process_itip_reply: process an incoming iTIP REPLY.
-- Called by the gateway when an iMIP email with METHOD:REPLY is received.
CREATE OR REPLACE FUNCTION calendar_process_itip_reply(
  p_uid             TEXT,
  p_attendee_email  TEXT,
  p_attendee_name   TEXT,
  p_status          TEXT,
  p_sequence        INT DEFAULT 0,
  p_mailbox_id      BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_event_id BIGINT;
  v_account_id BIGINT;
BEGIN
  IF p_mailbox_id IS NOT NULL THEN
    -- p_mailbox_id (when a JMAP caller ever supplies it) is a mailbox id, so scope by
    -- mb.id, consistent with the c.mailbox_id = p_mailbox_id filter used just below.
    PERFORM 1 FROM calendar_events ce
    JOIN calendars c ON c.id = ce.calendar_id
    JOIN mailboxes mb ON mb.id = c.mailbox_id
    WHERE ce.uid = p_uid AND mb.id = p_mailbox_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Event not found' USING ERRCODE = 'BZ001';
    END IF;
  END IF;

  SELECT ce.id, c.mailbox_id INTO v_event_id, v_account_id
  FROM calendar_events ce
  JOIN calendars c ON c.id = ce.calendar_id
  WHERE ce.uid = p_uid
    AND ce.is_meeting = TRUE
    AND (p_mailbox_id IS NULL OR c.mailbox_id = p_mailbox_id)
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('type', 'notFound', 'description', 'No matching event for UID');
  END IF;

  -- When p_mailbox_id is NULL (SMTP iMIP delivery path), verify the attendee email
  -- belongs to a local user whose primary mailbox owns this calendar event.
  -- Address-aware (ADR-004): resolve the attendee by ANY of their addresses
  -- (primary ∪ alias ∪ UPN) through the one seam, so an attendee who replied from
  -- an alias or whose UPN differs from their SMTP address is still authorized —
  -- the bug class that previously refused a legitimate REPLY as "not authorized".
  IF p_mailbox_id IS NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM resolve_identity(p_attendee_email) ri
      WHERE ri.primary_mailbox = v_account_id
    ) THEN
      RETURN jsonb_build_object('type', 'forbidden',
        'description', 'Attendee is not authorized to modify this event');
    END IF;
  END IF;

  IF p_status IN ('accepted', 'tentative', 'declined') THEN
    UPDATE event_attendees SET
      status = p_status,
      name = COALESCE(p_attendee_name, name)
    WHERE event_id = v_event_id AND email = p_attendee_email;

    IF NOT FOUND THEN
      INSERT INTO event_attendees (event_id, email, name, role, status, rsvp)
      VALUES (v_event_id, p_attendee_email, p_attendee_name, 'required', p_status, FALSE);
    END IF;

    UPDATE calendar_events SET
      sequence = GREATEST(sequence, p_sequence),
      jmap_state = jmap_state + 1,
      updated_at = now(),
      etag = generate_etag()
    WHERE id = v_event_id;

    PERFORM app_notify(
      'calendar:' || v_account_id,
      json_build_object(
        'event', 'itip_reply',
        'event_id', v_event_id,
        'attendee', p_attendee_email,
        'status', p_status
      )::text
    );
  END IF;

  RETURN jsonb_build_object('eventId', v_event_id::TEXT, 'processed', TRUE);
END;
$$ LANGUAGE plpgsql;

-- calendar_process_itip_cancel: process an incoming iTIP CANCEL.
-- Drop the pre-organizer-scope 2-arg signature AND the pre-tenant-binding 3-arg
-- signature so no unscoped overload survives an incremental reload (a survivor
-- would let a 3-arg call reach the UNRESTRICTED sweep instead of failing).
DROP FUNCTION IF EXISTS calendar_process_itip_cancel(TEXT, BIGINT);
DROP FUNCTION IF EXISTS calendar_process_itip_cancel(TEXT, BIGINT, TEXT);
--
-- p_organizer_email (iMIP/SMTP path only): the verified organizer of the cancelled
-- meeting (the Go caller authenticates the sender == organizer before calling). It
-- BOUNDS the blast radius: only copies whose organizer_email matches are cancelled,
-- so a cross-tenant UID collision (RFC-5545 UIDs are *meant* to be globally unique,
-- but nothing enforces it across tenants) cannot let one org's CANCEL nuke an
-- unrelated event that happens to share the UID. Required on the iMIP path.
--
-- p_signer_domain (iMIP/SMTP path only, round 4 tenant binding — Astra HOLD,
-- D-MAILSERVER-INTERNAL-CALDAV-004): the DNS domain of the transport evidence that
-- authenticated the sender (the Go caller derives it from the verified DKIM
-- alignment / S/MIME signer email / SPF'd envelope). organizer_email matching alone
-- still sweeps EVERY tenant whose copies share the uid+organizer, so trust earned
-- under one tenant's S/MIME anchor pool could cancel another tenant's copies. The
-- sweep below therefore joins through the calendar owner mailbox and cancels only
-- copies whose owner domain == p_signer_domain. Required on the iMIP path (BZ002).
CREATE OR REPLACE FUNCTION calendar_process_itip_cancel(
  p_uid             TEXT,
  p_mailbox_id      BIGINT DEFAULT NULL,
  p_organizer_email TEXT DEFAULT NULL,
  p_signer_domain   TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_event_id   BIGINT;
  v_account_id BIGINT;
  v_rec        RECORD;
  v_count      INT := 0;
BEGIN
  IF p_mailbox_id IS NOT NULL THEN
    -- JMAP caller: p_mailbox_id is a mailbox id; cancel ONLY the caller's own copy.
    SELECT ce.id, c.mailbox_id INTO v_event_id, v_account_id
    FROM calendar_events ce
    JOIN calendars c ON c.id = ce.calendar_id
    WHERE ce.uid = p_uid AND c.mailbox_id = p_mailbox_id
    LIMIT 1;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'Event not found' USING ERRCODE = 'BZ001';
    END IF;

    UPDATE calendar_events SET
      status = 'cancelled', jmap_state = jmap_state + 1, updated_at = now(), etag = generate_etag()
    WHERE id = v_event_id;

    PERFORM app_notify('calendar:' || v_account_id,
      json_build_object('event', 'itip_cancel', 'event_id', v_event_id)::text);

    RETURN jsonb_build_object('eventId', v_event_id::TEXT, 'cancelled', TRUE);
  END IF;

  -- iMIP (SMTP) path: the organizer cancelled the meeting (organizer authority is
  -- verified by the Go caller before this is invoked). EVERY local copy of this UID
  -- that shares the SAME organizer_email — the organizer's and each attendee's —
  -- belongs to the cancelled meeting. Cancel them ALL and push per mailbox. The old
  -- `LIMIT 1` without ORDER BY cancelled an arbitrary storage-order copy, leaving the
  -- others active (e.g. cancelled for the organizer but not the invitees).
  --
  -- Scope by organizer_email: a UID is only globally unique by RFC convention, not by
  -- DB constraint across tenants, so an unrelated event in another org that collides
  -- on UID must NOT be cancelled. Legitimate attendee copies all carry the meeting's
  -- organizer_email, so the real blast radius is unchanged; a colliding event with a
  -- different organizer is left untouched. The organizer is mandatory here.
  --
  -- Round 4 additionally bounds the sweep by the SIGNER's tenant domain: only copies
  -- whose calendar owner mailbox belongs to p_signer_domain are cancellable, so a
  -- signer trusted via one tenant's evidence (S/MIME anchors / DKIM key / SPF) can
  -- never cancel another tenant's copies, whatever uid+organizer pair they carry.
  IF p_organizer_email IS NULL THEN
    RAISE EXCEPTION 'iMIP CANCEL requires the verified organizer email'
      USING ERRCODE = 'BZ002',
            HINT = jsonb_build_object('type', 'invalidArguments', 'uid', p_uid)::TEXT;
  END IF;

  -- Tenant binding (round 4): the signer's trust domain bounds the sweep.
  -- Without it, evidence authenticated under one tenant's trust pool (its
  -- S/MIME anchors, its DKIM key) authorizes cancelling copies owned by every
  -- other tenant that happens to share the uid+organizer pair.
  IF p_signer_domain IS NULL THEN
    RAISE EXCEPTION 'iMIP CANCEL requires the authenticated signer domain'
      USING ERRCODE = 'BZ002',
            HINT = jsonb_build_object('type', 'invalidArguments', 'uid', p_uid)::TEXT;
  END IF;

  FOR v_rec IN
    UPDATE calendar_events ce SET
      status = 'cancelled', jmap_state = ce.jmap_state + 1, updated_at = now(), etag = generate_etag()
    FROM calendars c
    JOIN mailboxes mb ON mb.id = c.mailbox_id
    JOIN domains d ON d.id = mb.domain_id
    WHERE c.id = ce.calendar_id
      AND ce.uid = p_uid
      AND lower(ce.organizer_email) = lower(p_organizer_email)
      AND lower(d.name) = lower(p_signer_domain)
      AND ce.status <> 'cancelled'
    RETURNING ce.id AS event_id, c.mailbox_id AS mailbox_id
  LOOP
    v_count := v_count + 1;
    v_event_id := v_rec.event_id;
    PERFORM app_notify('calendar:' || v_rec.mailbox_id,
      json_build_object('event', 'itip_cancel', 'event_id', v_rec.event_id)::text);
  END LOOP;

  IF v_count = 0 THEN
    RETURN jsonb_build_object('type', 'notFound', 'description', 'No matching event for UID');
  END IF;

  RETURN jsonb_build_object('eventId', v_event_id::TEXT, 'cancelled', TRUE, 'count', v_count);
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_event_send_update: re-issue an iTIP REQUEST for an existing meeting.
-- Bumps SEQUENCE (so attendees' clients treat it as an update, not a duplicate), bumps
-- the event jmap_state, and returns the calendar_send_invite payload for the Go gateway
-- to enqueue as an iMIP REQUEST. Ownership (R1/R3): the event must belong to
-- p_mailbox_id (= the calendar's mailbox_id), else BZ001. Non-meetings return notMeeting
-- without any mutation.
CREATE OR REPLACE FUNCTION jmap_calendar_event_send_update(
  p_mailbox_id BIGINT,
  p_event_id   BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_event   RECORD;
  v_payload JSONB;
BEGIN
  SELECT ce.*, c.mailbox_id AS cal_mailbox_id INTO v_event
  FROM calendar_events ce
  JOIN calendars c ON c.id = ce.calendar_id
  WHERE ce.id = p_event_id AND c.mailbox_id = p_mailbox_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Event not found in this account'
      USING ERRCODE = 'BZ001',
            HINT = '{"type":"forbidden","event_id":"' || p_event_id || '"}';
  END IF;

  IF NOT v_event.is_meeting THEN
    RETURN jsonb_build_object('type', 'notMeeting',
      'description', 'Event is not a meeting');
  END IF;

  UPDATE calendar_events SET
    sequence   = sequence + 1,
    jmap_state = jmap_state + 1,
    updated_at = now(),
    etag       = generate_etag()
  WHERE id = p_event_id AND calendar_id = v_event.calendar_id;

  -- Bump calendars.jmap_state + push through the calendar seam. The owner mailbox
  -- is v_event.cal_mailbox_id (the calendar's mailbox), NOT p_mailbox_id — here
  -- they coincide, but on the iMIP SMTP path p_mailbox_id can be NULL, so the
  -- owner local is always the correct argument.
  PERFORM notify_calendar_state(v_event.cal_mailbox_id, p_event_id,
                                v_event.calendar_id, 'event_updated');

  -- calendar_send_invite builds the iTIP REQUEST payload (with the now-bumped sequence,
  -- attendees, organizer). It returns notMeeting / noRecipients shapes too; pass through.
  v_payload := calendar_send_invite(p_event_id, v_event.organizer_email, p_mailbox_id);

  RETURN v_payload;
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_event_counter: an INVITEE proposes new times to the organizer (outbound
-- iTIP COUNTER — RFC 5546 §3.2.7). The reply-direction twin of calendar_send_invite: it
-- returns a payload the gateway serializes as a COUNTER iMIP (attendee→organizer), but is
-- NON-MUTATING — a counter is only a proposal, so the invitee's own copy (sequence /
-- jmap_state / etag / attendee status) is NOT touched. It changes only if the organizer
-- later accepts the counter (that inbound path is deferred — ProcessITIP default-warns on
-- COUNTER today).
--
-- Ownership (R1/R3): the event must be a copy on THIS mailbox's calendar (the invitee's own
-- copy), else BZ001 — same code + shape as jmap_calendar_event_send_update. Gate: only an
-- actual attendee of the event may counter (else BZ002 forbidden). start/end are the PROPOSED
-- times; they ride the payload untouched and become the wire DTSTART/DTEND. Attendee display
-- name comes from the STORED event_attendees row (not trusted from the client) unless the
-- gateway supplies one.
CREATE OR REPLACE FUNCTION jmap_calendar_event_counter(
  p_mailbox_id     BIGINT,
  p_event_id       BIGINT,
  p_start          TIMESTAMPTZ,
  p_end            TIMESTAMPTZ,
  p_attendee_email TEXT,
  p_attendee_name  TEXT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_event    RECORD;
  v_att_name TEXT;
BEGIN
  SELECT ce.*, c.mailbox_id AS cal_mailbox_id INTO v_event
  FROM calendar_events ce
  JOIN calendars c ON c.id = ce.calendar_id
  WHERE ce.id = p_event_id AND c.mailbox_id = p_mailbox_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Event not found in this account'
      USING ERRCODE = 'BZ001',
            HINT = '{"type":"forbidden","event_id":"' || p_event_id || '"}';
  END IF;

  -- Gate: the caller must be an actual attendee of this event to counter-propose. Also
  -- pull the stored display name so the wire ATTENDEE line has a name without trusting a
  -- client field.
  SELECT ea.name INTO v_att_name
  FROM event_attendees ea
  WHERE ea.event_id = p_event_id AND ea.email = p_attendee_email;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Not an attendee of this event' USING ERRCODE = 'BZ002';
  END IF;

  -- NON-MUTATING: no sequence / jmap_state / etag bump. The proposal lives only in the
  -- outbound COUNTER; the invitee's stored copy stays as-is until the organizer accepts.
  RETURN jsonb_build_object(
    'uid',            v_event.uid,
    'title',          v_event.title,
    'description',    v_event.description,
    'location',       v_event.location,
    'allDay',         v_event.all_day,
    'timezone',       v_event.timezone,
    'sequence',       v_event.sequence,
    'organizerEmail', v_event.organizer_email,
    'organizerName',  v_event.organizer_name,
    'attendeeEmail',  p_attendee_email,
    'attendeeName',   COALESCE(NULLIF(p_attendee_name, ''), v_att_name, ''),
    'start',          p_start,
    'end',            p_end
  );
END;
$$ LANGUAGE plpgsql;
