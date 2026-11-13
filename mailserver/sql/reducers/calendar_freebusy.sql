-- Free/busy queries, conflict detection, and resource booking.

-- Expand a recurring event's occurrences within a date range.
-- Handles FREQ (DAILY/WEEKLY/MONTHLY/YEARLY), INTERVAL, UNTIL, COUNT,
-- and BY* rule parts: BYDAY, BYMONTHDAY, BYYEARDAY, BYMONTH, BYWEEKNO, WKST.
-- Also handles RDATE (additional dates) and EXDATE (excluded dates).
-- BYSETPOS filtering is handled by the expand_recurrence_bysetpos wrapper.
-- RECURRENCE-ID exceptions are handled at the caller level (calendar_free_busy).
CREATE OR REPLACE FUNCTION expand_recurrence(
    p_start_at    TIMESTAMPTZ,
    p_end_at      TIMESTAMPTZ,
    p_rrule       TEXT,
    p_range_start TIMESTAMPTZ,
    p_range_end   TIMESTAMPTZ,
    p_rdate       TIMESTAMPTZ[] DEFAULT NULL,
    p_exdate      TIMESTAMPTZ[] DEFAULT NULL,
    p_max_count   INT DEFAULT 366
) RETURNS TABLE(occ_start TIMESTAMPTZ, occ_end TIMESTAMPTZ) AS $$
DECLARE
    v_freq       TEXT;
    v_interval   INT := 1;
    v_until      TIMESTAMPTZ;
    v_count      INT;
    v_duration   INTERVAL := p_end_at - p_start_at;
    v_current    TIMESTAMPTZ := p_start_at;
    v_i          INT := 0;
    v_emitted    INT := 0;   -- RFC 5545 COUNT: number of generated occurrences, not steps
    v_step       INTERVAL;
    v_byday      TEXT;
    v_bymonthday TEXT;
    v_byyearday  TEXT;
    v_bymonth    TEXT;
    v_byweekno   TEXT;
    v_wkst       TEXT := 'MO';
    v_dow        INT;
    v_daynum     INT;
    v_monthnum   INT;
    v_yearday    INT;
    v_candidate  TIMESTAMPTZ;
    v_days       TEXT[];
    v_day        TEXT;
    v_pos        INT;
    v_target_dow INT;
    v_nth_day    TIMESTAMPTZ;
BEGIN
    IF p_rrule IS NULL THEN RETURN; END IF;

    -- Parse core RRULE parts
    v_freq := upper(substring(p_rrule FROM 'FREQ=(\w+)'));
    v_interval := COALESCE(substring(p_rrule FROM 'INTERVAL=(\d+)')::INT, 1);
    v_until := substring(p_rrule FROM 'UNTIL=(\d+T\d+)')::TIMESTAMPTZ;
    v_count := substring(p_rrule FROM 'COUNT=(\d+)')::INT;
    v_byday := substring(p_rrule FROM 'BYDAY=([^;]+)');
    v_bymonthday := substring(p_rrule FROM 'BYMONTHDAY=([^;]+)');
    v_byyearday := substring(p_rrule FROM 'BYYEARDAY=([^;]+)');
    v_bymonth := substring(p_rrule FROM 'BYMONTH=([^;]+)');
    v_byweekno := substring(p_rrule FROM 'BYWEEKNO=([^;]+)');
    v_wkst := COALESCE(substring(p_rrule FROM 'WKST=(\w+)'), 'MO');

    IF v_count IS NULL THEN v_count := p_max_count; END IF;

    CASE v_freq
        WHEN 'DAILY'   THEN v_step := make_interval(days => v_interval);
        WHEN 'WEEKLY'  THEN v_step := make_interval(days => 7 * v_interval);
        WHEN 'MONTHLY' THEN v_step := make_interval(months => v_interval);
        WHEN 'YEARLY'  THEN v_step := make_interval(years => v_interval);
        ELSE RETURN;
    END CASE;

    -- RDATE: emit explicit recurrence dates
    IF p_rdate IS NOT NULL AND array_length(p_rdate, 1) > 0 THEN
        FOR v_i IN 1..array_length(p_rdate, 1)
        LOOP
            v_candidate := p_rdate[v_i];
            IF v_candidate >= p_range_start AND v_candidate < p_range_end
               AND (v_until IS NULL OR v_candidate < v_until)
               AND is_byweekno_match(v_candidate, v_byweekno)
            THEN
                occ_start := v_candidate;
                occ_end := v_candidate + v_duration;
                RETURN NEXT;
            END IF;
        END LOOP;
    END IF;

    v_i := 0;
    v_current := p_start_at;

    -- Expand by FREQ step, applying BY* filters.
    -- COUNT (RFC 5545 §3.3.10) limits the number of GENERATED occurrences from DTSTART,
    -- not the number of FREQ steps: a WEEKLY+BYDAY=MO,WE,FR step generates 3 occurrences,
    -- a MONTHLY+BYMONTHDAY step one per listed day, etc. We therefore terminate on
    -- v_emitted (occurrences generated from DTSTART, counted BEFORE the query-window /
    -- EXDATE filters so windowed queries still honour COUNT) rather than the old v_i
    -- step counter, which over-generated up to N×COUNT occurrences for multi-emit rules.
    -- Termination is still guaranteed: v_current advances by v_step each step, so the
    -- EXIT-on-window below always fires for unbounded rules; v_until bounds UNTIL rules.
    WHILE v_emitted < v_count AND v_current < COALESCE(v_until, 'infinity'::TIMESTAMPTZ)
    LOOP
        IF v_freq = 'WEEKLY' AND v_byday IS NOT NULL AND v_byday != '' THEN
            -- BYDAY for WEEKLY: only emit days specified in BYDAY
            v_days := string_to_array(upper(v_byday), ',');
            FOREACH v_day IN ARRAY v_days
            LOOP
                v_target_dow := day_of_week_num(v_day, v_wkst);
                -- Adjust from v_current to the correct day of the week
                v_dow := EXTRACT(DOW FROM v_current AT TIME ZONE 'UTC')::INT;
                v_candidate := v_current + make_interval(days => (v_target_dow - v_dow + 7) % 7);
                v_emitted := v_emitted + 1;   -- generated occurrence (counts toward COUNT)
                IF v_candidate >= p_range_start AND v_candidate < p_range_end
                   AND v_candidate < COALESCE(v_until, 'infinity'::TIMESTAMPTZ)
                THEN
                    occ_start := v_candidate;
                    occ_end := v_candidate + v_duration;
                    IF NOT is_excluded(v_candidate, p_exdate) AND is_byweekno_match(v_candidate, v_byweekno) THEN
                        RETURN NEXT;
                    END IF;
                END IF;
                EXIT WHEN v_emitted >= v_count;
            END LOOP;
        ELSIF v_freq = 'MONTHLY' AND v_bymonthday IS NOT NULL AND v_bymonthday != '' THEN
            -- BYMONTHDAY for MONTHLY: each specified day of the month
            v_days := string_to_array(v_bymonthday, ',');
            FOREACH v_day IN ARRAY v_days
            LOOP
                v_daynum := v_day::INT;
                v_candidate := nth_month_day(v_current, v_daynum);
                v_emitted := v_emitted + 1;   -- generated occurrence (counts toward COUNT)
                IF v_candidate >= p_range_start AND v_candidate < p_range_end
                   AND v_candidate < COALESCE(v_until, 'infinity'::TIMESTAMPTZ)
                THEN
                    -- If BYDAY also specified, check DOW filter
                    IF v_byday IS NULL OR v_byday = '' OR day_in_byday(v_candidate, v_byday, v_wkst) THEN
                        occ_start := v_candidate;
                        occ_end := v_candidate + v_duration;
                        IF NOT is_excluded(v_candidate, p_exdate) AND is_byweekno_match(v_candidate, v_byweekno) THEN
                            RETURN NEXT;
                        END IF;
                    END IF;
                END IF;
                EXIT WHEN v_emitted >= v_count;
            END LOOP;
        ELSIF v_freq = 'MONTHLY' AND v_byday IS NOT NULL AND v_byday != '' THEN
            -- BYDAY for MONTHLY (positional): e.g., "2TU" = second Tuesday, "-1SU" = last Sunday
            v_days := string_to_array(upper(v_byday), ',');
            FOREACH v_day IN ARRAY v_days
            LOOP
                v_pos := positional_week(v_day);
                v_target_dow := day_of_week_num(v_day, v_wkst);
                v_nth_day := nth_day_of_week_in_month(v_current, v_pos, v_target_dow);
                v_emitted := v_emitted + 1;   -- generated occurrence (counts toward COUNT)
                IF v_nth_day >= p_range_start AND v_nth_day < p_range_end
                   AND v_nth_day < COALESCE(v_until, 'infinity'::TIMESTAMPTZ)
                THEN
                    occ_start := v_nth_day;
                    occ_end := v_nth_day + v_duration;
                    IF NOT is_excluded(v_nth_day, p_exdate) AND is_byweekno_match(v_nth_day, v_byweekno) THEN
                        RETURN NEXT;
                    END IF;
                END IF;
                EXIT WHEN v_emitted >= v_count;
            END LOOP;
        ELSIF v_freq = 'YEARLY' AND v_bymonth IS NOT NULL AND v_bymonth != '' THEN
            -- BYMONTH for YEARLY: each specified month
            v_days := string_to_array(v_bymonth, ',');
            FOREACH v_day IN ARRAY v_days
            LOOP
                v_monthnum := v_day::INT;
                v_candidate := date_trunc('year', v_current) + make_interval(months => v_monthnum - 1);
                v_candidate := v_candidate + (v_current - date_trunc('year', v_current));
                v_emitted := v_emitted + 1;   -- generated occurrence (counts toward COUNT)
                IF v_candidate >= p_range_start AND v_candidate < p_range_end
                   AND v_candidate < COALESCE(v_until, 'infinity'::TIMESTAMPTZ)
                THEN
                    occ_start := v_candidate;
                    occ_end := v_candidate + v_duration;
                    IF NOT is_excluded(v_candidate, p_exdate) AND is_byweekno_match(v_candidate, v_byweekno) THEN
                        RETURN NEXT;
                    END IF;
                END IF;
                EXIT WHEN v_emitted >= v_count;
            END LOOP;
        ELSIF v_freq = 'YEARLY' AND v_byyearday IS NOT NULL AND v_byyearday != '' THEN
            -- BYYEARDAY for YEARLY: each specified day of the year
            v_days := string_to_array(v_byyearday, ',');
            FOREACH v_day IN ARRAY v_days
            LOOP
                v_yearday := v_day::INT;
                v_candidate := date_trunc('year', v_current) + make_interval(days => v_yearday - 1);
                v_candidate := v_candidate + (v_current - date_trunc('day', v_current));
                v_emitted := v_emitted + 1;   -- generated occurrence (counts toward COUNT)
                IF v_candidate >= p_range_start AND v_candidate < p_range_end
                   AND v_candidate < COALESCE(v_until, 'infinity'::TIMESTAMPTZ)
                THEN
                    occ_start := v_candidate;
                    occ_end := v_candidate + v_duration;
                    IF NOT is_excluded(v_candidate, p_exdate) AND is_byweekno_match(v_candidate, v_byweekno) THEN
                        RETURN NEXT;
                    END IF;
                END IF;
                EXIT WHEN v_emitted >= v_count;
            END LOOP;
        ELSE
            -- Simple step-based expansion, with optional BYDAY filter (e.g. DAILY+BYDAY).
            -- One occurrence per FREQ step (counts toward COUNT, as the old step counter did).
            v_emitted := v_emitted + 1;
            IF v_current + v_duration > p_range_start AND v_current < p_range_end
               AND (v_byday IS NULL OR v_byday = '' OR day_in_byday(v_current, v_byday, v_wkst))
            THEN
                occ_start := v_current;
                occ_end := v_current + v_duration;
                IF NOT is_excluded(v_current, p_exdate) AND is_byweekno_match(v_current, v_byweekno) THEN
                    RETURN NEXT;
                END IF;
            END IF;
        END IF;

        -- Advance to the next FREQ step. Termination is guaranteed because v_emitted
        -- reaches v_count, v_until is hit (WHILE guard), or the early-exit below fires.
        v_current := v_current + v_step;

        -- Early exit once v_current is past the query window: nothing more to emit.
        EXIT WHEN v_current > p_range_end;
    END LOOP;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Phase 40: expand_recurrence_bysetpos — wrapper that applies BYSETPOS filtering.
-- Collects all occurrences from expand_recurrence, sorts by date, then selects
-- the BYSETPOS positions. Supports positive (1=first, 2=second) and negative
-- (-1=last, -2=second-to-last) values.
CREATE OR REPLACE FUNCTION expand_recurrence_bysetpos(
    p_start_at    TIMESTAMPTZ,
    p_end_at      TIMESTAMPTZ,
    p_rrule       TEXT,
    p_range_start TIMESTAMPTZ,
    p_range_end   TIMESTAMPTZ,
    p_rdate       TIMESTAMPTZ[] DEFAULT NULL,
    p_exdate      TIMESTAMPTZ[] DEFAULT NULL,
    p_max_count   INT DEFAULT 366
) RETURNS TABLE(occ_start TIMESTAMPTZ, occ_end TIMESTAMPTZ) AS $$
DECLARE
    v_bysetpos TEXT;
    v_pos_val  TEXT;
    v_pos_int  INT;
    v_starts   TIMESTAMPTZ[];
    v_ends     TIMESTAMPTZ[];
    v_rec      RECORD;
    v_idx      INT;
    v_total    INT := 0;
BEGIN
    v_bysetpos := substring(p_rrule FROM 'BYSETPOS=([^;]+)');
    IF v_bysetpos IS NULL OR v_bysetpos = '' THEN
        -- No BYSETPOS: passthrough to base expander
        RETURN QUERY SELECT * FROM expand_recurrence(p_start_at, p_end_at, p_rrule,
            p_range_start, p_range_end, p_rdate, p_exdate, p_max_count);
        RETURN;
    END IF;

    -- Collect all occurrences into typed arrays (RECORD[] is not valid in PL/pgSQL).
    FOR v_rec IN SELECT * FROM expand_recurrence(p_start_at, p_end_at, p_rrule,
        p_range_start, p_range_end, p_rdate, p_exdate, p_max_count)
    LOOP
        v_starts := array_append(v_starts, v_rec.occ_start);
        v_ends := array_append(v_ends, v_rec.occ_end);
        v_total := v_total + 1;
    END LOOP;

    IF v_total = 0 THEN RETURN; END IF;

    -- Apply BYSETPOS: select only the nth occurrences
    FOR v_pos_val IN SELECT unnest(string_to_array(v_bysetpos, ','))
    LOOP
        v_pos_int := v_pos_val::INT;
        IF v_pos_int > 0 AND v_pos_int <= v_total THEN
            v_idx := v_pos_int;
        ELSIF v_pos_int < 0 AND v_total + v_pos_int + 1 >= 1 THEN
            v_idx := v_total + v_pos_int + 1;
        ELSE
            CONTINUE;
        END IF;
        occ_start := v_starts[v_idx];
        occ_end := v_ends[v_idx];
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: convert BYDAY code to day-of-week number (0=Sun, 1=Mon, ..., 6=Sat).
-- Handles codes like "MO", "-1SU", "2TU" by stripping the positional prefix.
CREATE OR REPLACE FUNCTION day_of_week_num(p_byday TEXT, p_wkst TEXT DEFAULT 'MO') RETURNS INT AS $$
DECLARE
    v_code TEXT;
BEGIN
    v_code := upper(regexp_replace(p_byday, '^[+-]?\d+', ''));
    CASE v_code
        WHEN 'SU' THEN RETURN 0; WHEN 'MO' THEN RETURN 1;
        WHEN 'TU' THEN RETURN 2; WHEN 'WE' THEN RETURN 3;
        WHEN 'TH' THEN RETURN 4; WHEN 'FR' THEN RETURN 5;
        WHEN 'SA' THEN RETURN 6;
        ELSE RETURN 0;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: extract positional week number from BYDAY code (-1 = last, 1 = first, 2 = second, etc.)
CREATE OR REPLACE FUNCTION positional_week(p_byday TEXT) RETURNS INT AS $$
DECLARE
    v_match TEXT;
BEGIN
    v_match := substring(p_byday FROM '^[+-]?\d+');
    IF v_match IS NULL THEN RETURN 0; END IF;
    RETURN v_match::INT;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: find the Nth occurrence of a day-of-week within a month.
-- p_pos: -1 = last, 1 = first, 2 = second, etc.
CREATE OR REPLACE FUNCTION nth_day_of_week_in_month(
    p_ref    TIMESTAMPTZ,
    p_pos    INT,
    p_dow    INT
) RETURNS TIMESTAMPTZ AS $$
DECLARE
    v_first_day TIMESTAMPTZ;
    v_last_day  TIMESTAMPTZ;
    v_candidate  TIMESTAMPTZ;
    v_day_dow    INT;
BEGIN
    v_first_day := date_trunc('month', p_ref);
    v_last_day := v_first_day + interval '1 month' - interval '1 day';

    IF p_pos > 0 THEN
        -- Find the p_pos-th occurrence of p_dow in the month
        v_candidate := v_first_day;
        WHILE v_candidate <= v_last_day
        LOOP
            v_day_dow := EXTRACT(DOW FROM v_candidate AT TIME ZONE 'UTC')::INT;
            IF v_day_dow = p_dow THEN
                p_pos := p_pos - 1;
                IF p_pos = 0 THEN
                    RETURN v_candidate + (p_ref - date_trunc('day', p_ref));
                END IF;
            END IF;
            v_candidate := v_candidate + interval '1 day';
        END LOOP;
    ELSE
        -- Find the |p_pos|-th from the end
        p_pos := -p_pos;
        v_candidate := v_last_day;
        WHILE v_candidate >= v_first_day
        LOOP
            v_day_dow := EXTRACT(DOW FROM v_candidate AT TIME ZONE 'UTC')::INT;
            IF v_day_dow = p_dow THEN
                p_pos := p_pos - 1;
                IF p_pos = 0 THEN
                    RETURN v_candidate + (p_ref - date_trunc('day', p_ref));
                END IF;
            END IF;
            v_candidate := v_candidate - interval '1 day';
        END LOOP;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: check if a date falls on a day in a BYDAY list.
CREATE OR REPLACE FUNCTION day_in_byday(
    p_ts    TIMESTAMPTZ,
    p_byday TEXT,
    p_wkst  TEXT
) RETURNS BOOL AS $$
DECLARE
    v_dow INT;
    v_days TEXT[];
    v_day TEXT;
BEGIN
    v_dow := EXTRACT(DOW FROM p_ts AT TIME ZONE 'UTC')::INT;
    v_days := string_to_array(upper(p_byday), ',');
    FOREACH v_day IN ARRAY v_days
    LOOP
        IF day_of_week_num(v_day, p_wkst) = v_dow THEN
            RETURN TRUE;
        END IF;
    END LOOP;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: compute the Nth day of a month (handles negative numbers for from-end).
CREATE OR REPLACE FUNCTION nth_month_day(
    p_ref     TIMESTAMPTZ,
    p_day_num INT
) RETURNS TIMESTAMPTZ AS $$
DECLARE
    v_first_day TIMESTAMPTZ;
    v_last_day  TIMESTAMPTZ;
    v_time_part TIME;
BEGIN
    v_time_part := p_ref::TIME;
    IF p_day_num > 0 THEN
        v_first_day := date_trunc('month', p_ref) + make_interval(days => p_day_num - 1);
        RETURN v_first_day + v_time_part;
    ELSE
        -- Negative: count from end of month
        v_last_day := date_trunc('month', p_ref) + interval '1 month' - interval '1 day';
        RETURN v_last_day + make_interval(days => p_day_num + 1) + v_time_part;
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: check if a date is in the EXDATE exclusion list.
CREATE OR REPLACE FUNCTION is_excluded(
    p_ts     TIMESTAMPTZ,
    p_exdate TIMESTAMPTZ[]
) RETURNS BOOL AS $$
DECLARE
    v_i INT;
BEGIN
    IF p_exdate IS NULL OR array_length(p_exdate, 1) IS NULL THEN
        RETURN FALSE;
    END IF;
    FOR v_i IN 1..array_length(p_exdate, 1)
    LOOP
        IF date_trunc('day', p_exdate[v_i]) = date_trunc('day', p_ts) THEN
            RETURN TRUE;
        END IF;
    END LOOP;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: check if a date's ISO week number is in a BYWEEKNO list.
CREATE OR REPLACE FUNCTION is_byweekno_match(
    p_ts       TIMESTAMPTZ,
    p_byweekno TEXT
) RETURNS BOOL AS $$
DECLARE
    v_week  INT;
    v_weeks TEXT[];
    v_w     TEXT;
BEGIN
    IF p_byweekno IS NULL OR p_byweekno = '' THEN
        RETURN TRUE;
    END IF;
    v_week := EXTRACT(WEEK FROM p_ts AT TIME ZONE 'UTC')::INT;
    v_weeks := string_to_array(p_byweekno, ',');
    FOREACH v_w IN ARRAY v_weeks LOOP
        IF NULLIF(TRIM(v_w), '')::INT = v_week THEN
            RETURN TRUE;
        END IF;
    END LOOP;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- calendar_busy_intervals: pure projection of busy intervals in [p_start, p_end)
-- for a single mailbox (p_mailbox_id) OR a single calendar (p_calendar_id) — pass
-- the one you filter on, NULL the other. Returns a JSONB array of
-- {start,end,status} (status ∈ busy|tentative|free). Shared by calendar_free_busy
-- (per-mailbox) and calendar_free_busy_multi (per-calendar) so the recurrence
-- expansion + exception-folding logic lives in ONE place (a prior drift left the
-- parent_event_uid IS NULL guard on only one copy). No ACL — callers own the gate.
CREATE OR REPLACE FUNCTION calendar_busy_intervals(
  p_mailbox_id  BIGINT,
  p_calendar_id BIGINT,
  p_start       TIMESTAMPTZ,
  p_end         TIMESTAMPTZ
) RETURNS JSONB AS $$
  -- Non-recurring events (excludes recurrence exception children, which are
  -- handled by the recurring CTE via the LEFT JOIN on parent_event_uid).
  WITH non_recurring AS (
    SELECT ce.start_at, ce.end_at, ce.status
    FROM calendar_events ce
    JOIN calendars c ON c.id = ce.calendar_id
    WHERE (p_mailbox_id IS NULL OR c.mailbox_id = p_mailbox_id)
      AND (p_calendar_id IS NULL OR ce.calendar_id = p_calendar_id)
      AND ce.start_at < p_end
      AND ce.end_at > p_start
      AND ce.recurrence_id IS NULL
      AND (ce.rrule IS NULL OR ce.rrule = '')
      AND ce.parent_event_uid IS NULL
  ),
  -- Recurring events: expand occurrences with BYSETPOS + RECURRENCE-ID handling.
  -- LEFT JOIN folds exception children (cancelled excluded; time-changed override
  -- via COALESCE) onto their series occurrence.
  recurring AS (
    SELECT
      COALESCE(exc.start_at, occ_start) AS start_at,
      COALESCE(exc.end_at, occ_end)     AS end_at,
      COALESCE(exc.status, ce.status)   AS status
    FROM calendar_events ce
    JOIN calendars c ON c.id = ce.calendar_id
    CROSS JOIN LATERAL expand_recurrence_bysetpos(ce.start_at, ce.end_at, ce.rrule, p_start, p_end)
    LEFT JOIN calendar_events exc ON
      exc.parent_event_uid = ce.uid
      AND date_trunc('day', exc.recurrence_override) = date_trunc('day', occ_start)
    WHERE (p_mailbox_id IS NULL OR c.mailbox_id = p_mailbox_id)
      AND (p_calendar_id IS NULL OR ce.calendar_id = p_calendar_id)
      AND ce.recurrence_id IS NULL
      AND ce.rrule IS NOT NULL
      AND ce.rrule != ''
      AND ce.start_at < p_end
      AND (exc.id IS NULL OR exc.status != 'cancelled')
  ),
  all_intervals AS (
    SELECT * FROM non_recurring
    UNION ALL SELECT * FROM recurring
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'start', start_at,
    'end', end_at,
    'status', CASE
      WHEN status = 'cancelled' THEN 'free'
      WHEN status = 'tentative' THEN 'tentative'
      ELSE 'busy'
    END
  ) ORDER BY start_at), '[]'::JSONB)
  FROM all_intervals;
$$ LANGUAGE sql STABLE;

-- calendar_free_busy: return busy intervals per user in a time range.
-- Expands recurring events within the query window.
-- FREE/BUSY VISIBILITY (recorded product decision): free/busy is org-OPEN by
-- design WHILE the sharing.defaults toggle is OFF. p_user_ids is then NOT
-- ACL-gated against the caller — any authenticated user may query any
-- colleague's mailbox-id busy blocks, matching the Exchange default and the
-- sibling org-shared reducers in this file (jmap_calendar_resource_list,
-- calendar_check_conflict). Only coarse time blocks + busy/tentative/free
-- status are returned — NEVER titles, locations, attendees, or any event
-- detail (the ACL-gated CalendarEvent/getShared path is the seam for detail).
--
-- SHARING DEFAULTS (D11): when sharing.defaults is ON, each personal target is
-- gated through calendar_effective_acl(viewer, owner) — 'none' yields an EMPTY
-- interval list (shape preserved, fail-closed D10). Rooms/equipment/shared
-- mailboxes (user_id IS NULL) stay org-open (booking needs their busy blocks).
-- An org that flips the toggle recreates the open behavior with an org-scope
-- freebusy-for-everyone default.
--
-- NOTE (ADR-003 exception): param 1 stays `p_account_id`, not `p_mailbox_id`.
-- Frozen migration V061__calendar_transp_exdate.sql does an inline
-- `CREATE OR REPLACE FUNCTION calendar_free_busy(p_account_id ...)`. Because V001
-- \i-includes this reducer first, renaming the param here makes V061's replay fail
-- with "cannot change name of input parameter" (Postgres forbids a param rename via
-- CREATE OR REPLACE). Migrations are frozen, so this one account-scope param keeps the
-- legacy name. It is still a mailbox id (parseAccountID); see calendar_free_busy_multi.
CREATE OR REPLACE FUNCTION calendar_free_busy(
  p_account_id BIGINT,
  p_user_ids   BIGINT[],
  p_start      TIMESTAMPTZ,
  p_end        TIMESTAMPTZ
) RETURNS JSONB AS $$
DECLARE
  v_result     JSONB := '[]'::JSONB;
  v_uid        BIGINT;
  v_intervals  JSONB;
  v_gate       BOOLEAN;
  v_viewer_uid BIGINT;
  v_owner_uid  BIGINT;
BEGIN
  -- Defaults gate (computed once): ON ⇒ personal targets route through
  -- calendar_effective_acl; OFF ⇒ org-open, byte-identical to the pre-toggle path.
  v_gate := COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'sharing.defaults'), FALSE);
  IF v_gate THEN
    SELECT user_id INTO v_viewer_uid FROM account_scope(p_account_id);
  END IF;

  FOREACH v_uid IN ARRAY p_user_ids
  LOOP
    -- v_uid is a MAILBOX id (see header note). Gate personal owners only.
    IF v_gate THEN
      SELECT user_id INTO v_owner_uid FROM mailboxes WHERE id = v_uid;
      IF v_owner_uid IS NOT NULL
         AND (v_viewer_uid IS NULL
              OR calendar_effective_acl(v_viewer_uid, v_owner_uid) = 'none') THEN
        -- fail-closed (D10): shape preserved, intervals empty.
        v_result := v_result || jsonb_build_object(
          'userId', v_uid::TEXT, 'intervals', '[]'::JSONB);
        CONTINUE;
      END IF;
    END IF;
    -- Busy intervals for this mailbox (recurrence expansion + exception folding
    -- live in the shared calendar_busy_intervals helper).
    v_intervals := calendar_busy_intervals(v_uid, NULL, p_start, p_end);

    v_result := v_result || jsonb_build_object(
      'userId', v_uid::TEXT,
      'intervals', v_intervals
    );
  END LOOP;

  RETURN v_result;
END;
$$ LANGUAGE plpgsql;

-- calendar_check_conflict: return event IDs that overlap a proposed time range.
CREATE OR REPLACE FUNCTION calendar_check_conflict(
  p_mailbox_id        BIGINT,
  p_calendar_id      BIGINT,
  p_start            TIMESTAMPTZ,
  p_end              TIMESTAMPTZ,
  p_exclude_event_id BIGINT DEFAULT NULL,
  p_owner_mailbox_id BIGINT DEFAULT NULL
) RETURNS BIGINT[] AS $$
DECLARE
  v_conflicts BIGINT[];
BEGIN
  -- Existence + R1 auth-context only. The target calendar is fully pinned by
  -- ce.calendar_id = p_calendar_id below, and rooms are org-shared resources (never owned
  -- by the booker), so we do NOT couple the calendar to the caller via ownership. We
  -- validate the calendar exists and the caller is a real mailbox (p_mailbox_id is a
  -- mailbox id from parseAccountID — NOT a users.id; an `m.user_id = p_mailbox_id`
  -- predicate would be a type-confusion bug that broke decline-conflict for every room).
  PERFORM 1 FROM calendars c WHERE c.id = p_calendar_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Calendar not found' USING ERRCODE = 'BZ001';
  END IF;
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Calendar not found' USING ERRCODE = 'BZ001';
  END IF;

  -- Conflicts are scoped solely to the target calendar (p_calendar_id), pinned by
  -- ce.calendar_id = p_calendar_id. No separate mailbox filter — a room's mailbox_id
  -- differs from the booker's, and booking authorization is governed by booking_policy.
  SELECT array_agg(ce.id) INTO v_conflicts
  FROM calendar_events ce
  WHERE ce.calendar_id = p_calendar_id
    AND ce.start_at < p_end
    AND ce.end_at > p_start
    AND ce.status != 'cancelled'
    AND ce.recurrence_id IS NULL
    AND (p_exclude_event_id IS NULL OR ce.id != p_exclude_event_id);

  RETURN COALESCE(v_conflicts, '{}'::BIGINT[]);
END;
$$ LANGUAGE plpgsql;

-- calendar_find_free_slots: ranked free time slots for a group of attendees.
-- Given a date range, desired meeting duration, and working hours, finds all
-- time slots where every attendee is free and ranks them by preference score.
CREATE OR REPLACE FUNCTION calendar_find_free_slots(
  p_mailbox_id        BIGINT,
  p_user_ids          BIGINT[],
  p_start             TIMESTAMPTZ,
  p_end               TIMESTAMPTZ,
  p_duration_minutes  INT DEFAULT 30,
  p_slot_interval_min INT DEFAULT 15,
  p_working_start     TIME DEFAULT '09:00',
  p_working_end       TIME DEFAULT '17:00',
  p_max_slots         INT DEFAULT 20
) RETURNS JSONB AS $$
DECLARE
  v_free_busy      JSONB;
  v_slot_candidate TIMESTAMPTZ;
  v_slot_end       TIMESTAMPTZ;
  v_free           BOOLEAN;
  v_busy           RECORD;
  v_user_busy      JSONB;
  v_interval       JSONB;
  v_slots          JSONB := '[]'::JSONB;
  v_slot_count     INT := 0;
  v_score          FLOAT;
  v_now            TIMESTAMPTZ := NOW();
  v_day_start      TIMESTAMPTZ;
  v_day_end        TIMESTAMPTZ;
  v_day            DATE;
  v_block_start    TIMESTAMPTZ;
  v_block_end      TIMESTAMPTZ;
  v_block_min      INT;
  v_free_count     INT := 0;
  v_conflict_count INT;
  v_user_conflict  BOOLEAN;
BEGIN
  IF array_length(p_user_ids, 1) IS NULL OR array_length(p_user_ids, 1) = 0 THEN
    RETURN jsonb_build_object('type', 'invalidArguments', 'description', 'At least one userId required');
  END IF;
  IF p_duration_minutes < 5 THEN
    RETURN jsonb_build_object('type', 'invalidArguments', 'description', 'Duration must be at least 5 minutes');
  END IF;
  IF p_start >= p_end THEN
    RETURN jsonb_build_object('type', 'invalidArguments', 'description', 'start must be before end');
  END IF;

  v_free_busy := calendar_free_busy(p_mailbox_id, p_user_ids, p_start, p_end);

  -- ponytail: v_free_count (not total appended) drives early-exit, so the scan
  -- still stops as soon as p_max_slots FULLY-FREE slots are found — identical
  -- perf/behavior to pre-conflict-ranking code when the org isn't double-booked.
  -- v_slot_count is also capped (10x) as a safety valve against a genuinely
  -- double-booked org forcing a full-range scan of every candidate; raise if a
  -- real deployment needs more than 10x p_max_slots conflict candidates ranked.
  v_slot_candidate := p_start;
  WHILE v_slot_candidate + (p_duration_minutes || ' minutes')::INTERVAL <= p_end
        AND v_free_count < p_max_slots
        AND v_slot_count < p_max_slots * 10 LOOP
    v_slot_end := v_slot_candidate + (p_duration_minutes || ' minutes')::INTERVAL;

    -- Only consider slots within working hours on each day
    v_day := v_slot_candidate::DATE;
    v_day_start := (v_day + p_working_start)::TIMESTAMPTZ;
    v_day_end := (v_day + p_working_end)::TIMESTAMPTZ;

    IF v_slot_candidate >= v_day_start AND v_slot_end <= v_day_end THEN
      v_conflict_count := 0;

      -- Check against every user's busy intervals: count each attendee whose
      -- intervals overlap the candidate (not just EXIT on the first conflict),
      -- so partial-conflict candidates can still be ranked/surfaced.
      FOR v_user_busy IN SELECT * FROM jsonb_array_elements(v_free_busy) LOOP
        v_user_conflict := FALSE;
        FOR v_interval IN SELECT * FROM jsonb_array_elements(v_user_busy->'intervals') LOOP
          IF (v_interval->>'status' != 'free' AND v_interval->>'status' IS NOT NULL) THEN
            IF (v_slot_candidate, v_slot_end) OVERLAPS
               ((v_interval->>'start')::TIMESTAMPTZ, (v_interval->>'end')::TIMESTAMPTZ) THEN
              v_user_conflict := TRUE;
              EXIT;
            END IF;
          END IF;
        END LOOP;
        IF v_user_conflict THEN v_conflict_count := v_conflict_count + 1; END IF;
      END LOOP;
      v_free := (v_conflict_count = 0);

      -- Compute contiguous free block duration around this slot regardless of
      -- free status — same score formula applies to conflict candidates too.
      BEGIN
        -- Contiguous free block around this slot. Alias the unnested interval as
        -- `ivl` (NOT v_interval — a column alias matching the PL/pgSQL variable is
        -- ambiguous). The filtered MIN/MAX reduce across all intervals; LEAST/
        -- GREATEST (scalar) cap to the working day. No OUTER aggregate — nesting
        -- aggregate calls (MIN(LEAST(...MIN...))) is a hard Postgres error.
        SELECT LEAST(
          v_day_end,
          COALESCE(
            MIN((ivl->>'start')::TIMESTAMPTZ) FILTER (
              WHERE (ivl->>'status') != 'free'
                AND (ivl->>'start')::TIMESTAMPTZ > v_slot_candidate
            ),
            v_day_end
          )
        ) INTO v_block_end
        FROM jsonb_array_elements(v_free_busy) AS ub,
             jsonb_array_elements(ub->'intervals') AS vi(ivl);

        SELECT GREATEST(
          v_day_start,
          COALESCE(
            MAX((ivl->>'end')::TIMESTAMPTZ) FILTER (
              WHERE (ivl->>'status') != 'free'
                AND (ivl->>'end')::TIMESTAMPTZ < v_slot_candidate
            ),
            v_day_start
          )
        ) INTO v_block_start
        FROM jsonb_array_elements(v_free_busy) AS ub,
             jsonb_array_elements(ub->'intervals') AS vi(ivl);

        v_block_min := EXTRACT(EPOCH FROM (COALESCE(v_block_end, v_day_end) -
                                           COALESCE(v_block_start, v_day_start)))::INT / 60;

        -- Score: prefer mid-morning (9–11 = highest), proximity to now, contiguous block size
        v_score := 0.0;

        -- Time-of-day preference (peak 10:00 = score 1.0, linear falloff toward edges)
        v_score := v_score +
          (1.0 - ABS(EXTRACT(HOUR FROM v_slot_candidate::TIME + (p_duration_minutes/2 || ' minutes')::INTERVAL) - 10) / 6.0) * 50;

        -- Proximity to now (closer = higher, max 50 points)
        IF v_slot_candidate > v_now THEN
          v_score := v_score + GREATEST(0, 50 - EXTRACT(EPOCH FROM (v_slot_candidate - v_now))::FLOAT / 3600 * 2);
        END IF;

        -- Contiguous block bonus (up to 20 points)
        v_score := v_score + LEAST(v_block_min::FLOAT / p_duration_minutes, 1.0) * 20;

        -- Skip weekend penalty
        IF EXTRACT(DOW FROM v_slot_candidate) IN (0, 6) THEN
          v_score := v_score * 0.7;
        END IF;

        -- Conflict penalty: keeps fully-free slots (conflictCount=0) sorting
        -- ahead of partial-conflict ones on score alone, but the final
        -- ORDER BY (below) sorts by conflictCount first regardless.
        v_score := v_score - v_conflict_count * 25;

        v_slots := v_slots || jsonb_build_object(
          'start', v_slot_candidate,
          'end', v_slot_end,
          'score', ROUND(v_score::NUMERIC, 1),
          'contiguousFreeMinutes', v_block_min,
          'conflictCount', v_conflict_count
        );
        v_slot_count := v_slot_count + 1;
        IF v_free THEN v_free_count := v_free_count + 1; END IF;
      END;
    END IF;

    v_slot_candidate := v_slot_candidate + (p_slot_interval_min || ' minutes')::INTERVAL;
  END LOOP;

  -- Sort by fewest conflicts first, then score descending; return top slots.
  -- Backward-compatible: when ≥p_max_slots fully-free slots exist, every
  -- returned slot has conflictCount=0 and this is byte-identical to the old
  -- score-only ordering. LIMIT is applied BEFORE the aggregate (v_slots can
  -- now hold up to 10x p_max_slots conflict candidates — see the WHILE guard
  -- above — so limiting after jsonb_agg, as the pre-existing code did, would
  -- no longer be a no-op and would silently return an oversized array).
  RETURN (
    SELECT COALESCE(jsonb_agg(sub.v), '[]'::JSONB)
    FROM (
      SELECT v FROM jsonb_array_elements(v_slots) AS v
      ORDER BY (v->>'conflictCount')::INT ASC, (v->>'score')::FLOAT DESC
      LIMIT p_max_slots
    ) sub
  );
END;
$$ LANGUAGE plpgsql;

-- calendar_book_resource: book a room/equipment calendar for an event.
CREATE OR REPLACE FUNCTION calendar_book_resource(
  p_mailbox_id            BIGINT,
  p_resource_calendar_id BIGINT,
  p_event_id             BIGINT,
  p_booked_by            BIGINT,
  p_owner_mailbox_id     BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_cal        RECORD;
  v_event      RECORD;
  v_booking_id BIGINT;
  v_conflicts  BIGINT[];
BEGIN
  SELECT * INTO v_cal FROM calendars WHERE id = p_resource_calendar_id
    AND (p_owner_mailbox_id IS NULL OR mailbox_id = p_owner_mailbox_id);
  IF NOT FOUND THEN
    RETURN jsonb_build_object('type', 'notFound', 'description', 'Resource calendar not found');
  END IF;

  -- The resource calendar is org-shared (never owned by the booker), so authorization is
  -- governed by booking_policy (below), not per-calendar ownership. Here we only validate
  -- the caller is a real mailbox: p_mailbox_id is the booker's primary mailbox id from
  -- parseAccountID — NOT a users.id; an `m.user_id = p_mailbox_id` predicate would be a
  -- type-confusion bug that rejected EVERY real room booking (room mailbox user_id IS NULL).
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Calendar not found' USING ERRCODE = 'BZ001';
  END IF;

  IF v_cal.resource_type = 'personal' THEN
    RETURN jsonb_build_object('type', 'forbidden', 'description', 'Cannot book a personal calendar as a resource');
  END IF;

  SELECT ce.*, c.mailbox_id INTO v_event
  FROM calendar_events ce
  JOIN calendars c ON c.id = ce.calendar_id
  WHERE ce.id = p_event_id
    AND (p_owner_mailbox_id IS NULL OR c.mailbox_id = p_owner_mailbox_id);

  IF NOT FOUND THEN
    RETURN jsonb_build_object('type', 'notFound', 'description', 'Event not found');
  END IF;

  v_conflicts := calendar_check_conflict(
    p_mailbox_id, p_resource_calendar_id, v_event.start_at, v_event.end_at, NULL
  );

  IF v_cal.booking_policy = 'decline-conflict' AND array_length(v_conflicts, 1) > 0 THEN
    RETURN jsonb_build_object(
      'type', 'conflict',
      'description', 'Resource has conflicting bookings',
      'conflictingEventIds', v_conflicts
    );
  END IF;

  INSERT INTO calendar_events (
    calendar_id, uid, title, description, location,
    start_at, end_at, all_day, timezone, status,
    is_meeting, organizer_email, organizer_name,
    etag, jmap_state
  ) VALUES (
    p_resource_calendar_id,
    v_event.uid || '-resource-' || p_resource_calendar_id,
    v_event.title,
    'Booked by user ' || p_booked_by,
    v_event.location,
    v_event.start_at,
    v_event.end_at,
    v_event.all_day,
    COALESCE(v_event.timezone, 'UTC'),
    CASE WHEN v_cal.booking_policy = 'manual' THEN 'tentative' ELSE 'confirmed' END,
    TRUE,
    (SELECT email FROM users WHERE id = p_booked_by),
    (SELECT display_name FROM users WHERE id = p_booked_by),
    generate_etag(),
    1
  ) RETURNING id INTO v_booking_id;

  INSERT INTO event_attendees (event_id, email, name, role, status, rsvp)
  VALUES (
    p_event_id,
    'calendar-' || p_resource_calendar_id || '@resources',
    v_cal.name,
    'resource',
    CASE WHEN v_cal.booking_policy = 'manual' THEN 'tentative' ELSE 'accepted' END,
    FALSE
  );

  PERFORM app_notify(
    'calendar:' || v_cal.mailbox_id,
    json_build_object(
      'event', 'resource_booked',
      'calendar_id', p_resource_calendar_id,
      'event_id', v_booking_id,
      'status', CASE WHEN v_cal.booking_policy = 'manual' THEN 'tentative' ELSE 'confirmed' END
    )::text
  );

  RETURN jsonb_build_object(
    'bookingId', v_booking_id::TEXT,
    'status', CASE WHEN v_cal.booking_policy = 'manual' THEN 'tentative' ELSE 'confirmed' END,
    'conflicts', COALESCE(to_jsonb(v_conflicts), '[]'::JSONB)
  );
END;
$$ LANGUAGE plpgsql;

-- jmap_calendar_resource_list: bookable room/equipment calendars for the RoomFinder UI.
-- Returns calendars whose resource_type is 'room' or 'equipment' (personal calendars are
-- excluded), projecting id, name, resourceType, capacity, bookingPolicy. Org-wide
-- discovery is intentional — rooms are shared resources anyone may invite — so the list
-- is not narrowed to a single mailbox, but it never exposes a personal calendar's events.
CREATE OR REPLACE FUNCTION jmap_calendar_resource_list(
  p_mailbox_id BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  -- p_mailbox_id is required for R1 auth-context propagation (the caller must be a real
  -- account); rooms themselves are org-shared, so the projection lists all of them.
  PERFORM 1 FROM mailboxes WHERE id = p_mailbox_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('accountId', p_mailbox_id::TEXT, 'list', '[]'::JSONB);
  END IF;

  FOR v_row IN
    SELECT c.id, c.name, c.resource_type, c.capacity, c.booking_policy, mb.email
    FROM calendars c
    JOIN mailboxes mb ON mb.id = c.mailbox_id
    WHERE c.resource_type IN ('room', 'equipment')
    ORDER BY c.name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'name', v_row.name,
      'email', v_row.email,
      'resourceType', v_row.resource_type,
      'capacity', v_row.capacity,
      'bookingPolicy', v_row.booking_policy
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql STABLE;
