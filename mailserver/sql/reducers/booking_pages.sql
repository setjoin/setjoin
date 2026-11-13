-- booking_pages.sql — self-service booking pages. Owner CRUD + public read +
-- booking state machine. Public reducers take p_slug (no caller identity) and
-- are the trust boundary: they resolve the owner internally and expose ONLY
-- slot availability, never event details. R1-R4 per DATABASE_SECURITY.md.
--
-- BZ codes (this file): BZ134 page-not-found/disabled · BZ135 invalid-slot/
-- range (incl. a missing required answer) · BZ136 slot-taken · BZ137 bad/
-- expired token · BZ138 daily-cap-reached (allocated, not raised in v1 — the
-- daily cap is enforced by silently excluding that day's slots, so a booker
-- never sees more than "no slots that day"; reserved for a future explicit
-- signal if product wants to distinguish it from ordinary unavailability).

-- ============================================================
-- Owner CRUD (authenticated; p_mailbox_id is the caller's PRIMARY mailbox id)
-- ============================================================

CREATE OR REPLACE FUNCTION booking_page_upsert(
    p_mailbox_id BIGINT,
    p_page       JSONB
) RETURNS JSONB AS $$
DECLARE
    v_id BIGINT := (p_page->>'id')::BIGINT;
BEGIN
    PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Mailbox not found' USING ERRCODE = 'BZ001';
    END IF;

    IF v_id IS NULL THEN
        INSERT INTO booking_pages (
            mailbox_id, slug, title, description, duration_minutes,
            buffer_minutes, max_per_day, min_notice_minutes, max_advance_days,
            availability, questions, timezone, enabled
        ) VALUES (
            p_mailbox_id,                       -- R2: from auth, never p_page
            lower(p_page->>'slug'),
            p_page->>'title',
            p_page->>'description',
            COALESCE((p_page->>'durationMinutes')::INT, 30),
            COALESCE((p_page->>'bufferMinutes')::INT, 0),
            COALESCE((p_page->>'maxPerDay')::INT, 8),
            COALESCE((p_page->>'minNoticeMinutes')::INT, 120),
            COALESCE((p_page->>'maxAdvanceDays')::INT, 60),
            -- ponytail: default mirrors the column DEFAULT literal (V113) rather
            -- than parsing information_schema.columns.column_default (that text
            -- is the DDL expression, e.g. `'[...]'::jsonb`, not bare JSON — casting
            -- it directly raised "invalid input syntax for type json").
            COALESCE(p_page->'availability',
              '[{"dow":1,"start":"09:00","end":"17:00"},{"dow":2,"start":"09:00","end":"17:00"},{"dow":3,"start":"09:00","end":"17:00"},{"dow":4,"start":"09:00","end":"17:00"},{"dow":5,"start":"09:00","end":"17:00"}]'::JSONB),
            COALESCE(p_page->'questions', '[]'::JSONB),
            COALESCE(p_page->>'timezone', 'UTC'),
            COALESCE((p_page->>'enabled')::BOOLEAN, TRUE)
        ) RETURNING id INTO v_id;
    ELSE
        UPDATE booking_pages SET                -- R3: ownership in the same WHERE
            slug             = COALESCE(lower(p_page->>'slug'), slug),
            title            = COALESCE(p_page->>'title', title),
            description      = COALESCE(p_page->>'description', description),
            duration_minutes = COALESCE((p_page->>'durationMinutes')::INT, duration_minutes),
            buffer_minutes   = COALESCE((p_page->>'bufferMinutes')::INT, buffer_minutes),
            max_per_day      = COALESCE((p_page->>'maxPerDay')::INT, max_per_day),
            min_notice_minutes = COALESCE((p_page->>'minNoticeMinutes')::INT, min_notice_minutes),
            max_advance_days = COALESCE((p_page->>'maxAdvanceDays')::INT, max_advance_days),
            availability     = COALESCE(p_page->'availability', availability),
            questions        = COALESCE(p_page->'questions', questions),
            timezone         = COALESCE(p_page->>'timezone', timezone),
            enabled          = COALESCE((p_page->>'enabled')::BOOLEAN, enabled),
            updated_at       = now()
        WHERE id = v_id AND mailbox_id = p_mailbox_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Booking page not found' USING ERRCODE = 'BZ134';
        END IF;
    END IF;
    RETURN jsonb_build_object('id', v_id::TEXT);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION booking_page_delete(
    p_mailbox_id BIGINT,
    p_page_id    BIGINT
) RETURNS JSONB AS $$
BEGIN
    DELETE FROM booking_pages
     WHERE id = p_page_id AND mailbox_id = p_mailbox_id;   -- R3
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Booking page not found' USING ERRCODE = 'BZ134';
    END IF;
    RETURN jsonb_build_object('deleted', p_page_id::TEXT);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION booking_page_list(
    p_mailbox_id BIGINT
) RETURNS JSONB AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id', bp.id::TEXT, 'slug', bp.slug, 'title', bp.title,
        'description', bp.description,
        'durationMinutes', bp.duration_minutes, 'bufferMinutes', bp.buffer_minutes,
        'maxPerDay', bp.max_per_day, 'minNoticeMinutes', bp.min_notice_minutes,
        'maxAdvanceDays', bp.max_advance_days,
        'availability', bp.availability, 'questions', bp.questions,
        'timezone', bp.timezone, 'enabled', bp.enabled
    ) ORDER BY bp.created_at), '[]'::JSONB)
    FROM booking_pages bp
    WHERE bp.mailbox_id = p_mailbox_id;                    -- R1
$$ LANGUAGE sql STABLE;

-- ============================================================
-- Public read (unauthenticated; p_slug only — the reducer IS the trust
-- boundary). Returns busy-only slot geometry, never event/attendee detail.
-- ============================================================

CREATE OR REPLACE FUNCTION booking_page_public_get(
    p_slug TEXT
) RETURNS JSONB AS $$
    -- Public metadata ONLY: what an external booker needs to render the page.
    -- Owner identity is limited to display name; no email, no mailbox ids.
    SELECT jsonb_build_object(
        'slug', bp.slug, 'title', bp.title, 'description', bp.description,
        'durationMinutes', bp.duration_minutes, 'timezone', bp.timezone,
        'questions', bp.questions,
        'ownerName', COALESCE(u.display_name, '')
    )
    FROM booking_pages bp
    JOIN mailboxes m ON m.id = bp.mailbox_id
    LEFT JOIN users u ON u.id = m.user_id
    WHERE bp.slug = lower(p_slug) AND bp.enabled;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION booking_slots(
    p_slug TEXT,
    p_from DATE,
    p_to   DATE
) RETURNS JSONB AS $$
DECLARE
    v_page      RECORD;
    v_cal_id    BIGINT;
    v_busy      JSONB;
    v_slots     JSONB := '[]'::JSONB;
    v_day       DATE;
    v_win       JSONB;
    v_cursor    TIMESTAMPTZ;
    v_slot_end  TIMESTAMPTZ;
    v_win_start TIMESTAMPTZ;
    v_win_end   TIMESTAMPTZ;
    v_conflict  BOOLEAN;
    v_i         JSONB;
    v_day_used  INT;
    v_earliest  TIMESTAMPTZ;
    v_horizon   TIMESTAMPTZ;
    v_buf       INTERVAL;
BEGIN
    SELECT bp.* INTO v_page FROM booking_pages bp
     WHERE bp.slug = lower(p_slug) AND bp.enabled;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Booking page not found' USING ERRCODE = 'BZ134';
    END IF;
    IF p_to < p_from OR (p_to - p_from) > 31 THEN
        RAISE EXCEPTION 'Invalid date range' USING ERRCODE = 'BZ135';
    END IF;

    v_buf      := (v_page.buffer_minutes || ' minutes')::INTERVAL;
    v_earliest := now() + (v_page.min_notice_minutes || ' minutes')::INTERVAL;
    v_horizon  := now() + (v_page.max_advance_days || ' days')::INTERVAL;

    SELECT c.id INTO v_cal_id FROM calendars c
     WHERE c.mailbox_id = v_page.mailbox_id AND c.is_default = TRUE LIMIT 1;
    IF v_cal_id IS NULL THEN
        RETURN '[]'::JSONB;   -- owner has no calendar: nothing bookable
    END IF;

    -- Real free/busy through the ONE existing seam (recurrence + exceptions
    -- included). Only interval geometry is used; details never leave this fn.
    v_busy := calendar_busy_intervals(NULL, v_cal_id,
                (p_from::TIMESTAMPTZ - v_buf), ((p_to + 1)::TIMESTAMPTZ + v_buf));

    -- Live booking requests (pending awaiting verification + confirmed) are
    -- busy too: pending holds the slot until it verifies or expires.
    v_busy := v_busy || COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'start', br.slot_start, 'end', br.slot_end, 'status', 'busy'))
        FROM booking_requests br
        WHERE br.page_id = v_page.id
          AND br.status IN ('pending','confirmed')
          AND br.slot_end   > p_from::TIMESTAMPTZ - v_buf
          AND br.slot_start < (p_to + 1)::TIMESTAMPTZ + v_buf
    ), '[]'::JSONB);

    v_day := p_from;
    WHILE v_day <= p_to LOOP
        -- daily cap over live bookings, counted in the page's timezone
        SELECT COUNT(*) INTO v_day_used FROM booking_requests br
         WHERE br.page_id = v_page.id AND br.status IN ('pending','confirmed')
           AND (br.slot_start AT TIME ZONE v_page.timezone)::DATE = v_day;

        IF v_day_used < v_page.max_per_day THEN
            FOR v_win IN SELECT * FROM jsonb_array_elements(v_page.availability)
            LOOP
                CONTINUE WHEN (v_win->>'dow')::INT
                              != EXTRACT(DOW FROM v_day)::INT;
                -- window bounds are page-LOCAL times → tstz via AT TIME ZONE
                v_win_start := (v_day + (v_win->>'start')::TIME)
                                 AT TIME ZONE v_page.timezone;
                v_win_end   := (v_day + (v_win->>'end')::TIME)
                                 AT TIME ZONE v_page.timezone;
                v_cursor := v_win_start;
                WHILE v_cursor + (v_page.duration_minutes || ' minutes')::INTERVAL
                      <= v_win_end LOOP
                    v_slot_end := v_cursor
                        + (v_page.duration_minutes || ' minutes')::INTERVAL;
                    IF v_cursor >= v_earliest AND v_slot_end <= v_horizon THEN
                        v_conflict := FALSE;
                        FOR v_i IN SELECT * FROM jsonb_array_elements(v_busy)
                        LOOP
                            IF COALESCE(v_i->>'status','busy') != 'free'
                               AND (v_cursor - v_buf, v_slot_end + v_buf) OVERLAPS
                                   ((v_i->>'start')::TIMESTAMPTZ,
                                    (v_i->>'end')::TIMESTAMPTZ) THEN
                                v_conflict := TRUE;
                                EXIT;
                            END IF;
                        END LOOP;
                        IF NOT v_conflict THEN
                            v_slots := v_slots || jsonb_build_object(
                                'start', v_cursor, 'end', v_slot_end);
                        END IF;
                    END IF;
                    v_cursor := v_cursor
                        + (v_page.duration_minutes || ' minutes')::INTERVAL;
                END LOOP;
            END LOOP;
        END IF;
        v_day := v_day + 1;
    END LOOP;

    RETURN v_slots;   -- ONLY {start,end} pairs — the no-leak contract
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================
-- Booking state machine (unauthenticated; token-gated)
-- ============================================================

CREATE OR REPLACE FUNCTION booking_create(
    p_slug              TEXT,
    p_start             TIMESTAMPTZ,
    p_booker_email      TEXT,
    p_booker_name       TEXT,
    p_answers           JSONB,
    p_verify_token_hash TEXT,
    p_ip                INET
) RETURNS JSONB AS $$
DECLARE
    v_page RECORD;
    v_end  TIMESTAMPTZ;
    v_id   BIGINT;
    v_open BOOLEAN;
    v_q    JSONB;
BEGIN
    SELECT bp.* INTO v_page FROM booking_pages bp
     WHERE bp.slug = lower(p_slug) AND bp.enabled;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Booking page not found' USING ERRCODE = 'BZ134';
    END IF;
    v_end := p_start + (v_page.duration_minutes || ' minutes')::INTERVAL;

    -- required-question enforcement
    FOR v_q IN SELECT * FROM jsonb_array_elements(v_page.questions) LOOP
        IF COALESCE((v_q->>'required')::BOOLEAN, FALSE)
           AND COALESCE(p_answers->>(v_q->>'id'), '') = '' THEN
            RAISE EXCEPTION 'Missing required answer' USING ERRCODE = 'BZ135';
        END IF;
    END LOOP;

    -- Serialize per-page so slot re-check + insert are atomic vs. rivals.
    PERFORM pg_advisory_xact_lock(hashtext('booking_page:' || v_page.id::TEXT));

    -- The requested start must be one of the CURRENT open slots — same seam
    -- the public GET used (windows ∩ free/busy ∩ caps ∩ notice/horizon).
    SELECT EXISTS (
        SELECT 1 FROM jsonb_array_elements(
            booking_slots(p_slug,
                (p_start AT TIME ZONE v_page.timezone)::DATE,
                (p_start AT TIME ZONE v_page.timezone)::DATE)) s(v)
        WHERE (s.v->>'start')::TIMESTAMPTZ = p_start
    ) INTO v_open;
    IF NOT v_open THEN
        RAISE EXCEPTION 'Slot not available' USING ERRCODE = 'BZ136';
    END IF;

    BEGIN
        INSERT INTO booking_requests (
            page_id, mailbox_id, booker_email, booker_name, answers,
            slot_start, slot_end, status, verify_token_hash,
            verify_expires_at, created_ip
        ) VALUES (
            v_page.id, v_page.mailbox_id, lower(p_booker_email), COALESCE(p_booker_name, ''),
            COALESCE(p_answers, '{}'::JSONB),
            p_start, v_end, 'pending', p_verify_token_hash,
            now() + INTERVAL '24 hours', p_ip
        ) RETURNING id INTO v_id;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'Slot not available' USING ERRCODE = 'BZ136';
    END;

    -- ownerEmail/pageTitle ride along so the Go verification-email builder
    -- (internal/booking/email.go) never needs its own ad-hoc SQL query —
    -- the reducer stays the single source for anything derived from
    -- booking_pages/mailboxes.
    RETURN jsonb_build_object('requestId', v_id::TEXT,
                              'verifyExpiresAt', now() + INTERVAL '24 hours',
                              'ownerEmail', (SELECT m.email FROM mailboxes m WHERE m.id = v_page.mailbox_id),
                              'pageTitle', v_page.title);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION booking_confirm(
    p_verify_token_hash TEXT,
    p_cancel_token_hash TEXT
) RETURNS JSONB AS $$
DECLARE
    v_req      RECORD;
    v_page     RECORD;
    v_owner    RECORD;
    v_created  JSONB;
    v_event_id BIGINT;
    v_payload  JSONB;
    v_open     BOOLEAN;
BEGIN
    SELECT br.* INTO v_req FROM booking_requests br
     WHERE br.verify_token_hash = p_verify_token_hash
       AND br.status = 'pending' AND br.verify_expires_at > now()
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid or expired token' USING ERRCODE = 'BZ137';
    END IF;
    SELECT bp.* INTO v_page FROM booking_pages bp WHERE bp.id = v_req.page_id;
    IF NOT FOUND OR NOT v_page.enabled THEN
        RAISE EXCEPTION 'Booking page not found' USING ERRCODE = 'BZ134';
    END IF;

    SELECT m.id AS mailbox_id, m.email, m.user_id, u.display_name
      INTO v_owner
      FROM mailboxes m LEFT JOIN users u ON u.id = m.user_id
     WHERE m.id = v_page.mailbox_id;

    PERFORM pg_advisory_xact_lock(hashtext('booking_page:' || v_page.id::TEXT));

    -- Re-check REAL free/busy at confirm time (owner may have gained a
    -- conflicting event since the request was created). Own pending row is
    -- already counted busy by booking_slots — check overlap directly instead.
    SELECT NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(
            calendar_busy_intervals(NULL,
              (SELECT c.id FROM calendars c
                WHERE c.mailbox_id = v_page.mailbox_id AND c.is_default LIMIT 1),
              v_req.slot_start - (v_page.buffer_minutes || ' minutes')::INTERVAL,
              v_req.slot_end   + (v_page.buffer_minutes || ' minutes')::INTERVAL)
        ) b(v)
        WHERE COALESCE(b.v->>'status','busy') != 'free'
    ) INTO v_open;
    IF NOT v_open THEN
        UPDATE booking_requests SET status = 'cancelled' WHERE id = v_req.id;
        RAISE EXCEPTION 'Slot not available' USING ERRCODE = 'BZ136';
    END IF;

    -- Create the event through the EXISTING create seam (state bump + push
    -- + attendee rows all included).
    v_created := jmap_calendar_event_set_create(
        v_page.mailbox_id, v_owner.user_id, v_owner.email,
        jsonb_build_object('bk', jsonb_build_object(
            'title', v_page.title || ' — ' ||
                     COALESCE(NULLIF(v_req.booker_name, ''), v_req.booker_email),
            'description', (
                SELECT COALESCE(string_agg(q.v->>'label' || E'\n' ||
                    COALESCE(v_req.answers->>(q.v->>'id'), ''), E'\n\n'), '')
                FROM jsonb_array_elements(v_page.questions) q(v)),
            'start', v_req.slot_start, 'end', v_req.slot_end,
            'timeZone', v_page.timezone,
            'attendees', jsonb_build_array(jsonb_build_object(
                'email', v_req.booker_email, 'name', v_req.booker_name,
                'role', 'required', 'participationStatus', 'accepted',
                'expectReply', FALSE))
        )));
    v_event_id := (v_created->'created'->>'bk')::BIGINT;
    IF v_event_id IS NULL THEN
        RAISE EXCEPTION 'Event creation failed' USING ERRCODE = 'BZ135';
    END IF;

    -- Mark as a meeting with an explicit organizer so calendar_send_invite
    -- produces a well-formed iMIP payload (from = owner).
    UPDATE calendar_events
       SET is_meeting = TRUE,
           organizer_email = v_owner.email,
           organizer_name  = v_owner.display_name
     WHERE id = v_event_id;

    UPDATE booking_requests
       SET status = 'confirmed', event_id = v_event_id,
           cancel_token_hash = p_cancel_token_hash,
           verify_token_hash = 'used:' || verify_token_hash   -- single-use
     WHERE id = v_req.id;

    v_payload := calendar_send_invite(v_event_id, v_owner.email, v_page.mailbox_id);

    RETURN v_payload || jsonb_build_object(
        'ownerEmail', v_owner.email,
        'bookerEmail', v_req.booker_email,
        'slotStart', v_req.slot_start, 'slotEnd', v_req.slot_end,
        'pageTitle', v_page.title, 'pageTimezone', v_page.timezone);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION booking_cancel(
    p_cancel_token_hash TEXT
) RETURNS JSONB AS $$
DECLARE
    v_req RECORD;
BEGIN
    UPDATE booking_requests
       SET status = 'cancelled',
           cancel_token_hash = 'used:' || cancel_token_hash
     WHERE cancel_token_hash = p_cancel_token_hash AND status = 'confirmed'
    RETURNING * INTO v_req;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid or expired token' USING ERRCODE = 'BZ137';
    END IF;
    IF v_req.event_id IS NOT NULL THEN
        UPDATE calendar_events SET status = 'cancelled' WHERE id = v_req.event_id;
        PERFORM notify_calendar_state(
            v_req.mailbox_id,
            v_req.event_id,
            (SELECT ce.calendar_id FROM calendar_events ce WHERE ce.id = v_req.event_id),
            'event_updated');
    END IF;
    RETURN jsonb_build_object('cancelled', TRUE);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION booking_expire_due() RETURNS INT AS $$
DECLARE
    v_n INT;
BEGIN
    UPDATE booking_requests SET status = 'expired'
     WHERE status = 'pending' AND verify_expires_at <= now();
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END;
$$ LANGUAGE plpgsql;
