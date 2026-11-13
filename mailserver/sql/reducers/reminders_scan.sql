-- reminders_scan.sql: scan_due_reminders() — the cron reducer that enqueues a
-- `remind` scheduled_action for each due reminder source whose firing instant has
-- passed. Run by the Go cron worker (scan-due-reminders, @every 1m) on the
-- worker's privileged connection.
--
-- Sources (A6 scope — ABSOLUTE fire-times only):
--   * calendar_events.valarm — each array element whose `trigger` parses as an
--     absolute DATE-TIME <= now(). Relative-duration triggers (e.g. '-PT15M') do
--     not parse as a timestamptz and are skipped (DEFERRED follow-up, with RRULE
--     recurrence expansion).
--   * tasks.reminder_at <= now() (non-recurring).
--   * flagged messages past flag_due_at — GUARDED behind a column-exists check on
--     A2's messages.flag_due_at; skipped entirely until A2 lands.
--
-- Idempotent: a source+instant that already has a pending/processing `remind`
-- action (matched on payload) is not re-enqueued; the ledger UNIQUE is the
-- downstream fire-once backstop.
CREATE OR REPLACE FUNCTION scan_due_reminders()
RETURNS SETOF UUID AS $$
DECLARE
    v_rec      RECORD;
    v_fire     TIMESTAMPTZ;
    v_payload  JSONB;
    v_id       UUID;
    v_has_flag BOOLEAN;
BEGIN
    -- ── Event VALARM (absolute triggers only) ──
    FOR v_rec IN
        SELECT e.id AS source_id, e.title, c.mailbox_id, alarm.value AS alarm
        FROM calendar_events e
        JOIN calendars c ON c.id = e.calendar_id
        CROSS JOIN LATERAL jsonb_array_elements(COALESCE(e.valarm, '[]'::JSONB)) AS alarm(value)
        WHERE e.valarm IS NOT NULL
    LOOP
        -- Parse the trigger as an absolute timestamp; skip relative/unparseable.
        BEGIN
            v_fire := (v_rec.alarm->>'trigger')::TIMESTAMPTZ;
        EXCEPTION WHEN OTHERS THEN
            CONTINUE;
        END;

        IF v_fire IS NULL OR v_fire > now() THEN
            CONTINUE;
        END IF;

        v_payload := jsonb_build_object(
            'source_type', 'event', 'source_id', v_rec.source_id,
            'mailbox_id', v_rec.mailbox_id, 'fire_at', v_fire, 'title', v_rec.title);

        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'remind'
              AND mailbox_id = v_rec.mailbox_id
              AND status IN ('pending','processing')
              AND payload @> jsonb_build_object('source_type','event','source_id',v_rec.source_id,'fire_at',v_fire)
        ) AND NOT EXISTS (
            -- Already fired (ledger row exists): never re-enqueue. The ledger UNIQUE
            -- is (mailbox_id, source_type, source_id, fire_at); without this guard a
            -- done action no longer blocks and the queue grows one dead row/minute.
            SELECT 1 FROM reminders
            WHERE mailbox_id = v_rec.mailbox_id
              AND source_type = 'event'
              AND source_id = v_rec.source_id
              AND fire_at = v_fire
        ) THEN
            v_id := enqueue_scheduled_action('remind', v_fire, v_payload, v_rec.mailbox_id);
            RETURN NEXT v_id;
        END IF;
    END LOOP;

    -- ── Task reminder_at ──
    FOR v_rec IN
        SELECT t.id AS source_id, t.title, t.mailbox_id, t.reminder_at AS fire_at
        FROM tasks t
        WHERE t.reminder_at IS NOT NULL
          AND t.reminder_at <= now()
          AND t.status <> 'completed'
    LOOP
        v_payload := jsonb_build_object(
            'source_type', 'task', 'source_id', v_rec.source_id,
            'mailbox_id', v_rec.mailbox_id, 'fire_at', v_rec.fire_at, 'title', v_rec.title);

        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'remind'
              AND mailbox_id = v_rec.mailbox_id
              AND status IN ('pending','processing')
              AND payload @> jsonb_build_object('source_type','task','source_id',v_rec.source_id,'fire_at',v_rec.fire_at)
        ) AND NOT EXISTS (
            -- Already fired (ledger row exists): never re-enqueue. tasks.reminder_at
            -- keeps matching until cleared, so the ledger is the fire-once gate here.
            SELECT 1 FROM reminders
            WHERE mailbox_id = v_rec.mailbox_id
              AND source_type = 'task'
              AND source_id = v_rec.source_id
              AND fire_at = v_rec.fire_at
        ) THEN
            v_id := enqueue_scheduled_action('remind', v_rec.fire_at, v_payload, v_rec.mailbox_id);
            RETURN NEXT v_id;
        END IF;
    END LOOP;

    -- ── Flagged messages past due (A2) — GUARDED until messages.flag_due_at lands ──
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'flag_due_at'
    ) INTO v_has_flag;

    IF v_has_flag THEN
        -- A2-dependent branch. Enqueue a `remind` per flagged message past flag_due_at.
        -- Implemented with dynamic SQL so this file loads before A2 adds the column.
        FOR v_id IN
            EXECUTE $dyn$
                SELECT enqueue_scheduled_action('remind', m.flag_due_at,
                    jsonb_build_object('source_type','flag','source_id',m.id,
                        'mailbox_id',m.mailbox_id,'fire_at',m.flag_due_at,'title',m.subject),
                    m.mailbox_id)
                FROM messages m
                WHERE m.flag_due_at IS NOT NULL AND m.flag_due_at <= now()
                  AND NOT EXISTS (
                    SELECT 1 FROM scheduled_actions sa
                    WHERE sa.action_kind='remind' AND sa.mailbox_id = m.mailbox_id
                      AND sa.status IN ('pending','processing')
                      AND sa.payload @> jsonb_build_object('source_type','flag','source_id',m.id,'fire_at',m.flag_due_at))
                  AND NOT EXISTS (
                    SELECT 1 FROM reminders r
                    WHERE r.mailbox_id = m.mailbox_id AND r.source_type='flag'
                      AND r.source_id = m.id AND r.fire_at = m.flag_due_at)
            $dyn$
        LOOP
            RETURN NEXT v_id;
        END LOOP;
    END IF;
END;
$$ LANGUAGE plpgsql;
