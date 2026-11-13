-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V061: Calendar TRANSP + EXDATE fixes for RFC 4791/5545 compliance.
--
-- 1. Add transp (transparency) column: OPAQUE (default, blocks time) or TRANSPARENT.
--    Per RFC 5545 §3.8.2.7, TRANSPARENT events do not affect free/busy.
--    Per RFC 4791 §7.9, free/busy queries must exclude TRANSPARENT events.
--
-- 2. Fix expand_recurrence_bysetpos calls in calendar_free_busy and
--    calendar_free_busy_multi to pass exdate/rdate columns so that
--    recurrence exception dates are honoured.

ALTER TABLE calendar_events
    ADD COLUMN IF NOT EXISTS transp TEXT NOT NULL DEFAULT 'OPAQUE'
        CHECK (transp IN ('OPAQUE', 'TRANSPARENT'));

-- Update calendar_free_busy to pass exdate and filter TRANSPARENT
CREATE OR REPLACE FUNCTION calendar_free_busy(
  p_account_id BIGINT,
  p_user_ids   BIGINT[],
  p_start      TIMESTAMPTZ,
  p_end        TIMESTAMPTZ
) RETURNS JSONB AS $$
DECLARE
  v_result  JSONB := '[]'::JSONB;
  v_uid     BIGINT;
  v_intervals JSONB;
BEGIN
  FOREACH v_uid IN ARRAY p_user_ids
  LOOP
    -- Non-recurring events: exclude TRANSPARENT
    WITH non_recurring AS (
      SELECT ce.start_at, ce.end_at, ce.status
      FROM calendar_events ce
      JOIN calendars c ON c.id = ce.calendar_id
      WHERE c.mailbox_id = v_uid
        AND ce.start_at < p_end
        AND ce.end_at > p_start
        AND ce.recurrence_id IS NULL
        AND (ce.rrule IS NULL OR ce.rrule = '')
        AND (ce.transp IS NULL OR ce.transp != 'TRANSPARENT')
    ),
    -- Recurring events: expand with BYSETPOS + RECURRENCE-ID handling.
    -- Pass rdate/exdate so exception dates are excluded from expansion.
    recurring AS (
      SELECT
        COALESCE(exc.start_at, occ_start) AS start_at,
        COALESCE(exc.end_at, occ_end)     AS end_at,
        COALESCE(exc.status, ce.status)   AS status
      FROM calendar_events ce
      JOIN calendars c ON c.id = ce.calendar_id
      CROSS JOIN LATERAL expand_recurrence_bysetpos(
        ce.start_at, ce.end_at, ce.rrule, p_start, p_end, ce.rdate, ce.exdate
      )
      LEFT JOIN calendar_events exc ON
        exc.parent_event_uid = ce.uid
        AND date_trunc('day', exc.recurrence_override) = date_trunc('day', occ_start)
      WHERE c.mailbox_id = v_uid
        AND ce.recurrence_id IS NULL
        AND ce.rrule IS NOT NULL
        AND ce.rrule != ''
        AND ce.start_at < p_end
        AND (exc.id IS NULL OR exc.status != 'cancelled')
        AND (ce.transp IS NULL OR ce.transp != 'TRANSPARENT')
    ),
    all_intervals AS (
      SELECT * FROM non_recurring
      UNION ALL SELECT * FROM recurring
    )
    SELECT jsonb_agg(jsonb_build_object(
      'start', start_at,
      'end', end_at,
      'status', CASE
        WHEN status = 'cancelled' THEN 'free'
        WHEN status = 'tentative' THEN 'tentative'
        ELSE 'busy'
      END
    )) INTO v_intervals
    FROM all_intervals
    ORDER BY start_at;

    v_result := v_result || jsonb_build_object(
      'userId', v_uid::TEXT,
      'intervals', COALESCE(v_intervals, '[]'::JSONB)
    );
  END LOOP;

  RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- Update calendar_free_busy_multi to pass exdate and filter TRANSPARENT
CREATE OR REPLACE FUNCTION calendar_free_busy_multi(
    p_account_id BIGINT,
    p_cal_ids    BIGINT[],
    p_start      TIMESTAMPTZ,
    p_end        TIMESTAMPTZ
) RETURNS JSONB AS $$
DECLARE
    v_result      JSONB := '[]'::JSONB;
    v_cal_id      BIGINT;
    v_mailbox_id  BIGINT;
    v_user_id     BIGINT;
    v_email       TEXT;
    v_intervals   JSONB;
    v_type        TEXT;
    v_cal         RECORD;
BEGIN
    PERFORM 1 FROM users WHERE id = p_account_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account not found' USING ERRCODE = 'BZ006';
    END IF;

    FOREACH v_cal_id IN ARRAY p_cal_ids
    LOOP
        SELECT c.id, c.mailbox_id, c.resource_type, c.name
        INTO v_cal
        FROM calendars c
        WHERE c.id = v_cal_id;

        IF NOT FOUND THEN
            CONTINUE;
        END IF;

        v_mailbox_id := v_cal.mailbox_id;

        SELECT u.email, u.id INTO v_email, v_user_id
        FROM users u
        JOIN mailboxes m ON m.user_id = u.id
        WHERE m.id = v_mailbox_id;

        IF v_cal.resource_type = 'room' OR v_cal.resource_type = 'equipment' THEN
            v_type := v_cal.resource_type;
            v_email := COALESCE(v_email, v_cal.name || '@resources');
        ELSE
            v_type := 'user';
        END IF;

        v_intervals := NULL;

        -- Non-recurring events: exclude TRANSPARENT
        WITH non_recurring AS (
            SELECT ce.start_at, ce.end_at, ce.status
            FROM calendar_events ce
            WHERE ce.calendar_id = v_cal_id
              AND ce.start_at < p_end
              AND ce.end_at > p_start
              AND ce.recurrence_id IS NULL
              AND (ce.rrule IS NULL OR ce.rrule = '')
              AND (ce.transp IS NULL OR ce.transp != 'TRANSPARENT')
        ),
        -- Recurring events: pass rdate/exdate so exception dates are excluded
        recurring AS (
            SELECT
                COALESCE(exc.start_at, occ_start) AS start_at,
                COALESCE(exc.end_at, occ_end)     AS end_at,
                COALESCE(exc.status, ce.status)   AS status
            FROM calendar_events ce
            CROSS JOIN LATERAL expand_recurrence_bysetpos(
                ce.start_at, ce.end_at, ce.rrule, p_start, p_end, ce.rdate, ce.exdate
            )
            LEFT JOIN calendar_events exc ON
                exc.parent_event_uid = ce.uid
                AND date_trunc('day', exc.recurrence_override) = date_trunc('day', occ_start)
            WHERE ce.calendar_id = v_cal_id
              AND ce.recurrence_id IS NULL
              AND ce.rrule IS NOT NULL
              AND ce.rrule != ''
              AND ce.start_at < p_end
              AND (exc.id IS NULL OR exc.status != 'cancelled')
              AND (ce.transp IS NULL OR ce.transp != 'TRANSPARENT')
        ),
        all_intervals AS (
            SELECT * FROM non_recurring
            UNION ALL SELECT * FROM recurring
        )
        SELECT jsonb_agg(jsonb_build_object(
            'start', ai.start_at,
            'end', ai.end_at,
            'status', CASE
                WHEN ai.status = 'cancelled' THEN 'free'
                WHEN ai.status = 'tentative' THEN 'tentative'
                ELSE 'busy'
            END
        ) ORDER BY ai.start_at)
        INTO v_intervals
        FROM all_intervals ai;

        v_result := v_result || jsonb_build_object(
            'entity_id', v_cal_id::TEXT,
            'email', COALESCE(v_email, ''),
            'type', v_type,
            'intervals', COALESCE(v_intervals, '[]'::JSONB)
        );
    END LOOP;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE;
