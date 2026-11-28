-- reminders_get.sql: Reminder/get read path. Returns the active reminders for the
-- owner (R1): fired, not dismissed, and not currently snoozed into the future.
-- Active := fired_at IS NOT NULL AND dismissed_at IS NULL
--           AND (snoozed_until IS NULL OR snoozed_until <= now()).
CREATE OR REPLACE FUNCTION reminders_get(
    p_mailbox_id BIGINT,
    p_limit      INT DEFAULT 100
) RETURNS JSONB AS $$
DECLARE
    v_list  JSONB;
    v_state BIGINT;
BEGIN
    SELECT jmap_reminder_state INTO v_state FROM mailboxes WHERE id = p_mailbox_id;

    SELECT COALESCE(jsonb_agg(row ORDER BY (row->>'fireAt') DESC), '[]'::JSONB) INTO v_list
    FROM (
        SELECT jsonb_build_object(
            'id', r.id::TEXT,
            'sourceType', r.source_type,
            'sourceId', r.source_id::TEXT,
            'fireAt', r.fire_at,
            'firedAt', r.fired_at,
            'title', r.title,
            'body', r.body
        ) AS row
        FROM reminders r
        WHERE r.mailbox_id = p_mailbox_id          -- R1: ownership
          AND r.fired_at IS NOT NULL
          AND r.dismissed_at IS NULL
          AND (r.snoozed_until IS NULL OR r.snoozed_until <= now())
        ORDER BY r.fire_at DESC
        LIMIT LEAST(GREATEST(p_limit, 1), 500)
    ) sub;

    RETURN jsonb_build_object(
        'accountId', p_mailbox_id::TEXT,
        'state', COALESCE(v_state, 0)::TEXT,
        'list', v_list
    );
END;
$$ LANGUAGE plpgsql;
