-- scheduled_action_remind.sql: the `remind` handler. Upserts the fire-once
-- reminders ledger row for the source (event / task / flag), then routes the
-- jmap_reminder_state bump + 'reminder_fired' push through the bump_reminder_state
-- seam (passing the bespoke event name + {reminderId} via the seam's optional
-- p_event/p_detail). Pure DB write, idempotent: the ledger UNIQUE
-- (mailbox_id, source_type, source_id, fire_at) guarantees a re-run (post-crash
-- reclaim) inserts nothing.
--
-- payload = {source_type, source_id, mailbox_id, fire_at, title, body?}.
-- jmap_reminder_state is its own JMAP channel (mirrors the email/tag pattern); it
-- is intentionally outside the notify_state_change seam, which owns only the
-- message/tag email-state channels.
CREATE OR REPLACE FUNCTION scheduled_action_remind(p_action scheduled_actions)
RETURNS JSONB AS $$
DECLARE
    v_mailbox_id  BIGINT := p_action.mailbox_id;
    v_source_type TEXT;
    v_source_id   BIGINT;
    v_fire_at     TIMESTAMPTZ;
    v_title       TEXT;
    v_body        TEXT;
    v_reminder_id BIGINT;
    v_state       BIGINT;
BEGIN
    v_source_type := p_action.payload->>'source_type';
    v_source_id   := (p_action.payload->>'source_id')::BIGINT;
    v_fire_at     := COALESCE((p_action.payload->>'fire_at')::TIMESTAMPTZ, p_action.fire_at);
    v_title       := COALESCE(p_action.payload->>'title', 'Reminder');
    v_body        := p_action.payload->>'body';

    IF v_mailbox_id IS NULL OR v_source_type IS NULL OR v_source_id IS NULL THEN
        RETURN jsonb_build_object('status', 'permanent_fail', 'note', 'remind action missing source reference');
    END IF;

    -- Fire-once: upsert the ledger row. ON CONFLICT DO NOTHING means a second fire
    -- (reclaim) is a clean no-op and returns no id.
    INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, fired_at, title, body)
    VALUES (v_mailbox_id, v_source_type, v_source_id, v_fire_at, now(), v_title, v_body)
    ON CONFLICT (mailbox_id, source_type, source_id, fire_at) DO NOTHING
    RETURNING id INTO v_reminder_id;

    IF v_reminder_id IS NULL THEN
        -- Already fired for this source+instant; nothing to push.
        RETURN jsonb_build_object('status', 'ok', 'note', 'already fired');
    END IF;

    -- Bump the reminder JMAP state + push through the reminder seam, carrying the
    -- bespoke 'reminder_fired' event name + {reminderId} via the seam's optional
    -- params (the event string is cosmetic to the current consumer, which only
    -- re-reads jmap_reminder_state off the tag: channel).
    v_state := bump_reminder_state(
        v_mailbox_id,
        'reminder_fired',
        jsonb_build_object('reminderId', v_reminder_id));

    RETURN jsonb_build_object('status', 'ok', 'note', 'fired');
END;
$$ LANGUAGE plpgsql;
