-- calendar_free_busy_multi: batch free/busy query for multiple calendars (Roadmap 3.4).
-- Used by the scheduling assistant POST /caldav/freebusy/batch endpoint.
-- Returns a JSONB array of {entity_id, email, type, intervals} for all requested calendars.
--
-- SHARING DEFAULTS (D11): when sharing.defaults is ON, personal-calendar
-- targets are gated through calendar_effective_acl(viewer, owner) exactly like
-- calendar_free_busy — 'none' yields an EMPTY interval list (shape preserved,
-- fail-closed D10); rooms/equipment stay org-open (booking needs their busy
-- blocks). OFF ⇒ byte-identical to the pre-toggle path.
--
-- p_account_id: caller's account mailbox id (parseAccountID); validated as a real user
-- p_cal_ids: array of calendar IDs (user mailboxes + room calendars)
-- p_start, p_end: time range to query
--
-- NOTE (ADR-003 exception): param 1 stays `p_account_id`, not `p_mailbox_id`. Frozen
-- migration V061__calendar_transp_exdate.sql redefines this function inline with
-- `p_account_id`; V001 \i-includes this reducer first, so renaming the param makes V061's
-- replay fail ("cannot change name of input parameter"). Migrations are frozen, so this
-- one account-scope param keeps the legacy name (still a mailbox id).
CREATE OR REPLACE FUNCTION calendar_free_busy_multi(
    p_account_id BIGINT,
    p_cal_ids    BIGINT[],
    p_start      TIMESTAMPTZ,
    p_end        TIMESTAMPTZ
) RETURNS JSONB AS $$
DECLARE
    v_result     JSONB := '[]'::JSONB;
    v_cal_id     BIGINT;
    v_user_id    BIGINT;
    v_email      TEXT;
    v_intervals  JSONB;
    v_type       TEXT;
    v_cal        RECORD;
    v_gate       BOOLEAN;
    v_viewer_uid BIGINT;
BEGIN
    -- Defaults gate (computed once; see header). OFF ⇒ org-open, byte-identical.
    v_gate := COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'sharing.defaults'), FALSE);
    -- Verify the caller is a real account. p_account_id is the caller's primary
    -- MAILBOX id (parseAccountID — never a users.id; see the ADR-003 NOTE above),
    -- so this is a mailbox-existence check, mirroring calendar_free_busy's siblings
    -- (calendar_check_conflict / calendar_book_resource). A `users WHERE id =
    -- p_account_id` predicate would match zero rows in production (user_id !=
    -- mailbox_id) and spuriously raise — silently breaking batch free/busy.
    PERFORM 1 FROM mailboxes WHERE id = p_account_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Calendar not found' USING ERRCODE = 'BZ001';
    END IF;
    IF v_gate THEN
        SELECT user_id INTO v_viewer_uid FROM account_scope(p_account_id);
    END IF;

    FOREACH v_cal_id IN ARRAY p_cal_ids
    LOOP
        -- Resolve calendar: can be a user's default calendar (mailbox_id) or a resource calendar
        SELECT c.id, c.mailbox_id, c.resource_type, c.name
        INTO v_cal
        FROM calendars c
        WHERE c.id = v_cal_id;

        IF NOT FOUND THEN
            -- Skip unknown calendar IDs
            CONTINUE;
        END IF;

        -- Get email and user_id for the mailbox owner
        SELECT u.email, u.id INTO v_email, v_user_id
        FROM users u
        JOIN mailboxes m ON m.user_id = u.id
        WHERE m.id = v_cal.mailbox_id;

        -- Determine entity type
        IF v_cal.resource_type = 'room' OR v_cal.resource_type = 'equipment' THEN
            v_type := v_cal.resource_type;
            v_email := COALESCE(v_email, v_cal.name || '@resources');
        ELSE
            v_type := 'user';
        END IF;

        -- Defaults gate (ON only): a personal owner the viewer resolves to
        -- 'none' for yields an empty interval list, fail-closed (D10).
        IF v_gate AND v_type = 'user' AND v_user_id IS NOT NULL
           AND (v_viewer_uid IS NULL
                OR calendar_effective_acl(v_viewer_uid, v_user_id) = 'none') THEN
            v_result := v_result || jsonb_build_object(
                'entity_id', v_cal_id::TEXT,
                'email', COALESCE(v_email, ''),
                'type', v_type,
                'intervals', '[]'::JSONB
            );
            CONTINUE;
        END IF;

        -- Busy intervals for this calendar (recurrence expansion + exception
        -- folding live in the shared calendar_busy_intervals helper).
        v_intervals := calendar_busy_intervals(NULL, v_cal_id, p_start, p_end);

        -- Append to result
        v_result := v_result || jsonb_build_object(
            'entity_id', v_cal_id::TEXT,
            'email', COALESCE(v_email, ''),
            'type', v_type,
            'intervals', v_intervals
        );
    END LOOP;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE;
