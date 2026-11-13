-- reminders_actions.sql: Reminders window user-actions — dismiss / dismiss-all /
-- snooze. Every statement is owner-scoped by p_mailbox_id (the mailbox id) in the
-- same UPDATE (R3); a wrong-account action matches no row and raises BZ038. Each
-- mutation bumps jmap_reminder_state + pushes a 'reminder_changed' event.
--
-- Error contract: BZ038 = reminder not found / not owned; BZ039 = snooze time not
-- in the future.

-- bump_reminder_state: increment the mailbox's reminder JMAP state + push. The
-- reminder secondary seam — every reminder mutation (dismiss/snooze + the
-- scheduled remind handler) routes its bump+push here instead of open-coding
-- UPDATE mailboxes SET jmap_reminder_state + pg_notify('tag:'||…).
--
-- p_event / p_detail are OPTIONAL and default to the historical 'reminder_changed'
-- shape, so existing callers are unchanged. The event string is cosmetic to the
-- current consumer (the StateChange path only re-reads jmap_reminder_state off the
-- tag: channel — it ignores the event name), so scheduled_action_remind can pass
-- its bespoke 'reminder_fired' + {reminderId} through p_event/p_detail and still
-- share this one seam.
--   p_event  — event name carried in the payload (default 'reminder_changed').
--   p_detail — extra JSONB keys merged into the payload (default '{}' — e.g.
--              the remind handler passes {reminderId}). 'event' + 'state' always win.
CREATE OR REPLACE FUNCTION bump_reminder_state(
    p_mailbox_id BIGINT,
    p_event      TEXT  DEFAULT 'reminder_changed',
    p_detail     JSONB DEFAULT '{}'::JSONB
) RETURNS BIGINT AS $$
DECLARE
    v_state BIGINT;
BEGIN
    UPDATE mailboxes SET jmap_reminder_state = jmap_reminder_state + 1
    WHERE id = p_mailbox_id
    RETURNING jmap_reminder_state INTO v_state;

    PERFORM app_notify(
        'tag:' || p_mailbox_id,
        (COALESCE(p_detail, '{}'::JSONB)
           || jsonb_build_object('event', COALESCE(p_event, 'reminder_changed'),
                                 'state', v_state))::TEXT);
    RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- reminder_dismiss: mark a single reminder dismissed (owner-scoped, R3).
CREATE OR REPLACE FUNCTION reminder_dismiss(
    p_mailbox_id  BIGINT,
    p_reminder_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_found INT;
BEGIN
    WITH upd AS (
        UPDATE reminders
        SET dismissed_at = now()
        WHERE id = p_reminder_id AND mailbox_id = p_mailbox_id
        RETURNING 1
    )
    SELECT count(*) INTO v_found FROM upd;

    IF v_found = 0 THEN
        RAISE EXCEPTION 'Reminder not found'
            USING ERRCODE = 'BZ038',
                  HINT = jsonb_build_object('type','reminder_not_found','reminder_id',p_reminder_id)::TEXT;
    END IF;

    PERFORM bump_reminder_state(p_mailbox_id);
    RETURN jsonb_build_object('dismissed', TRUE, 'reminderId', p_reminder_id::TEXT);
END;
$$ LANGUAGE plpgsql;

-- reminder_dismiss_all: dismiss every active reminder for the owner.
CREATE OR REPLACE FUNCTION reminder_dismiss_all(
    p_mailbox_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_count INT;
BEGIN
    WITH upd AS (
        UPDATE reminders
        SET dismissed_at = now()
        WHERE mailbox_id = p_mailbox_id AND dismissed_at IS NULL
        RETURNING 1
    )
    SELECT count(*) INTO v_count FROM upd;

    IF v_count > 0 THEN
        PERFORM bump_reminder_state(p_mailbox_id);
    END IF;
    RETURN jsonb_build_object('dismissed', v_count);
END;
$$ LANGUAGE plpgsql;

-- reminder_snooze: re-arm a reminder for a later time (owner-scoped, R3). Rejects
-- a non-future snooze time with BZ039. Clears dismissed_at so the reminder
-- re-surfaces at the new time.
CREATE OR REPLACE FUNCTION reminder_snooze(
    p_mailbox_id  BIGINT,
    p_reminder_id BIGINT,
    p_until       TIMESTAMPTZ
) RETURNS JSONB AS $$
DECLARE
    v_found INT;
BEGIN
    IF p_until IS NULL OR p_until <= now() THEN
        RAISE EXCEPTION 'Snooze time must be in the future'
            USING ERRCODE = 'BZ039',
                  HINT = jsonb_build_object('type','reminder_snooze_past','until',p_until)::TEXT;
    END IF;

    WITH upd AS (
        UPDATE reminders
        SET snoozed_until = p_until, dismissed_at = NULL
        WHERE id = p_reminder_id AND mailbox_id = p_mailbox_id
        RETURNING 1
    )
    SELECT count(*) INTO v_found FROM upd;

    IF v_found = 0 THEN
        RAISE EXCEPTION 'Reminder not found'
            USING ERRCODE = 'BZ038',
                  HINT = jsonb_build_object('type','reminder_not_found','reminder_id',p_reminder_id)::TEXT;
    END IF;

    PERFORM bump_reminder_state(p_mailbox_id);
    RETURN jsonb_build_object('snoozed', TRUE, 'reminderId', p_reminder_id::TEXT, 'until', p_until);
END;
$$ LANGUAGE plpgsql;
