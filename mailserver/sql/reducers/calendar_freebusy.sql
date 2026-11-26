-- Free/busy queries, conflict detection, and resource booking.

-- Validate an RFC 5545 RRULE string at input boundaries.
-- Returns NULL when p_rrule is NULL/empty or uses only supported date-level parts;
-- returns a human-readable error message when FREQ is missing/duplicate/unsupported
-- or when unsupported sub-day / Easter parts (BYHOUR, BYMINUTE, BYSECOND, BYEASTER) appear.
CREATE OR REPLACE FUNCTION validate_rrule(
    p_rrule TEXT
) RETURNS TEXT AS $$
DECLARE
    v_trimmed   TEXT;
    v_parts     TEXT[];
    v_part      TEXT;
    v_eq_pos    INT;
    v_key       TEXT;
    v_val       TEXT;
    v_freq      TEXT;
    v_seen_freq BOOLEAN := FALSE;
BEGIN
    IF p_rrule IS NULL THEN
        RETURN NULL;
    END IF;
    v_trimmed := btrim(p_rrule, E' \t\r\n');
    IF v_trimmed = '' THEN
        RETURN NULL;
    END IF;

    -- Strip optional leading case-insensitive "RRULE:" prefix. A bare "RRULE:"
    -- (nothing left after stripping) falls through to missing-FREQ rejection.
    IF upper(left(v_trimmed, 6)) = 'RRULE:' THEN
        v_trimmed := btrim(substring(v_trimmed FROM 7), E' \t\r\n');
    END IF;

    v_parts := string_to_array(v_trimmed, ';');
    FOREACH v_part IN ARRAY v_parts
    LOOP
        v_part := btrim(v_part, E' \t\r\n');
        IF v_part = '' THEN
            CONTINUE;
        END IF;
        v_eq_pos := position('=' IN v_part);
        IF v_eq_pos > 0 THEN
            v_key := upper(btrim(substring(v_part FROM 1 FOR v_eq_pos - 1), E' \t\r\n'));
            v_val := upper(btrim(substring(v_part FROM v_eq_pos + 1), E' \t\r\n'));
        ELSE
            v_key := upper(v_part);
            v_val := '';
        END IF;

        IF v_key = 'FREQ' THEN
            IF v_seen_freq THEN
                RETURN 'Duplicate FREQ part in RRULE';
            END IF;
            v_seen_freq := TRUE;
            v_freq := v_val;
        ELSIF v_key IN ('BYHOUR', 'BYMINUTE', 'BYSECOND', 'BYEASTER') THEN
            RETURN 'Unsupported RRULE part: ' || v_key ||
                   ' (only DAILY, WEEKLY, MONTHLY, YEARLY date-level rules are supported)';
        END IF;
    END LOOP;

    IF v_freq IS NULL OR v_freq = '' THEN
        RETURN 'RRULE missing required FREQ part';
    END IF;

    IF v_freq NOT IN ('DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY') THEN
        RETURN 'Unsupported RRULE frequency: ' || v_freq ||
               ' (supported: DAILY, WEEKLY, MONTHLY, YEARLY)';
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Expand a recurring event's occurrences within a date range.
-- Handles FREQ (DAILY/WEEKLY/MONTHLY/YEARLY), INTERVAL, UNTIL (DATE and DATE-TIME,
-- inclusive per RFC 5545), COUNT, and BY* rule parts: BYDAY, BYMONTHDAY, BYYEARDAY,
-- BYMONTH, BYWEEKNO (positive and negative), WKST.
-- Also handles RDATE (additional dates) and EXDATE (exact-instant excluded dates).
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
    v_rrule          TEXT;
    v_freq           TEXT;
    v_interval       INT := 1;
    v_until_raw      TEXT;
    v_until          TIMESTAMPTZ;
    v_count          INT;
    v_duration       INTERVAL := p_end_at - p_start_at;
    v_start_utc      TIMESTAMP := p_start_at AT TIME ZONE 'UTC';
    v_start_date     DATE := date_trunc('day', v_start_utc)::DATE;
    v_start_year     INT := EXTRACT(YEAR FROM v_start_utc)::INT;
    v_start_month    INT := EXTRACT(MONTH FROM v_start_utc)::INT;
    v_start_day      INT := EXTRACT(DAY FROM v_start_utc)::INT;
    v_start_dow      INT := EXTRACT(DOW FROM v_start_utc)::INT;
    v_time_part      INTERVAL := v_start_utc - date_trunc('day', v_start_utc);
    v_i              INT := 0;
    v_step_idx       INT := 0;
    v_emitted        INT := 0;   -- RFC 5545 COUNT: number of generated occurrences, not steps
    v_empty_steps    INT := 0;
    v_done           BOOLEAN := FALSE;
    v_byday          TEXT;
    v_bymonthday     TEXT;
    v_byyearday      TEXT;
    v_bymonth        TEXT;
    v_byweekno       TEXT;
    v_wkst           TEXT := 'MO';
    v_wkst_dow       INT;
    v_bymonth_arr    INT[];
    v_bymonthday_arr INT[];
    v_byyearday_arr  INT[];
    v_byday_arr      TEXT[];
    v_base_week      DATE;
    v_week_start     DATE;
    v_period_start   TIMESTAMPTZ;
    v_year           INT;
    v_month          INT;
    v_total_months   INT;
    v_year_start     DATE;
    v_year_days      INT;
    v_jan1_dow       INT;
    v_dec31_dow      INT;
    v_months         INT[];
    v_m              INT;
    v_m_first        DATE;
    v_m_days         INT;
    v_m_first_dow    INT;
    v_m_ref          TIMESTAMPTZ;
    v_d              INT;
    v_day            INT;
    v_cand_date      DATE;
    v_cand_year      INT;
    v_cand_month     INT;
    v_cand_day       INT;
    v_cand_doy       INT;
    v_cand_mdays     INT;
    v_cand_ydays     INT;
    v_candidate      TIMESTAMPTZ;
    v_candidates     TIMESTAMPTZ[];
    v_tok            TEXT;
    v_pos            INT;
    v_target_dow     INT;
    v_offset         INT;
    v_nth_day        TIMESTAMPTZ;
    v_period_had_hit BOOLEAN;
    v_max_mdays      CONSTANT INT[] := ARRAY[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    v_possible       BOOLEAN;
    v_next_month     DATE;
BEGIN
    IF p_rrule IS NULL THEN RETURN; END IF;

    v_rrule := upper(btrim(p_rrule, E' \t\r\n'));
    IF left(v_rrule, 6) = 'RRULE:' THEN
        v_rrule := btrim(substring(v_rrule FROM 7), E' \t\r\n');
    END IF;

    -- Parse core RRULE parts (case-insensitive via v_rrule).
    v_freq := substring(v_rrule FROM 'FREQ=(\w+)');
    v_interval := COALESCE(substring(v_rrule FROM 'INTERVAL=(\d+)')::INT, 1);
    IF v_interval < 1 THEN v_interval := 1; END IF;

    -- Parse UNTIL in either DATE (YYYYMMDD) or DATE-TIME (YYYYMMDDTHHMMSS[Z]) form
    -- in UTC regardless of session timezone (anchored to segment boundaries so
    -- malformed values like UNTIL=19970905T0900 are not partially matched).
    v_until_raw := substring(v_rrule FROM '(?:^|;)UNTIL=(\d{8}(?:T\d{6}Z?)?)(?:;|$)');
    IF v_until_raw IS NOT NULL THEN
        IF length(v_until_raw) = 8 THEN
            v_until_raw := v_until_raw || 'T000000Z';
        ELSIF right(v_until_raw, 1) != 'Z' THEN
            v_until_raw := v_until_raw || 'Z';
        END IF;
        v_until := v_until_raw::TIMESTAMPTZ;
    END IF;

    v_count := substring(v_rrule FROM 'COUNT=(\d+)')::INT;
    v_byday := substring(v_rrule FROM 'BYDAY=([^;]+)');
    v_bymonthday := substring(v_rrule FROM 'BYMONTHDAY=([^;]+)');
    v_byyearday := substring(v_rrule FROM 'BYYEARDAY=([^;]+)');
    v_bymonth := substring(v_rrule FROM 'BYMONTH=([^;]+)');
    v_byweekno := substring(v_rrule FROM 'BYWEEKNO=([^;]+)');
    v_wkst := COALESCE(substring(v_rrule FROM 'WKST=([A-Z]{2})'), 'MO');
    v_wkst_dow := day_of_week_num(v_wkst);

    IF v_count IS NULL THEN v_count := p_max_count; END IF;

    IF v_freq NOT IN ('DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY') THEN
        RETURN;
    END IF;

    -- Pre-parse BY* lists into typed arrays.
    IF v_bymonth IS NOT NULL AND v_bymonth != '' THEN
        SELECT array_agg(btrim(x)::INT) INTO v_bymonth_arr
        FROM unnest(string_to_array(v_bymonth, ',')) AS x
        WHERE btrim(x) ~ '^[+-]?\d+$';
    END IF;
    IF v_bymonthday IS NOT NULL AND v_bymonthday != '' THEN
        SELECT array_agg(btrim(x)::INT) INTO v_bymonthday_arr
        FROM unnest(string_to_array(v_bymonthday, ',')) AS x
        WHERE btrim(x) ~ '^[+-]?\d+$';
    END IF;
    IF v_byyearday IS NOT NULL AND v_byyearday != '' THEN
        SELECT array_agg(btrim(x)::INT) INTO v_byyearday_arr
        FROM unnest(string_to_array(v_byyearday, ',')) AS x
        WHERE btrim(x) ~ '^[+-]?\d+$';
    END IF;
    IF v_byday IS NOT NULL AND v_byday != '' THEN
        SELECT array_agg(btrim(x)) INTO v_byday_arr
        FROM unnest(string_to_array(v_byday, ',')) AS x
        WHERE btrim(x) != '';
    END IF;

    -- RDATE: emit explicit recurrence dates (inclusive UNTIL, half-open range_end).
    IF p_rdate IS NOT NULL AND array_length(p_rdate, 1) > 0 THEN
        FOR v_i IN 1..array_length(p_rdate, 1)
        LOOP
            v_candidate := p_rdate[v_i];
            IF (v_candidate >= p_range_start OR v_candidate + v_duration > p_range_start)
               AND v_candidate < p_range_end
               AND (v_until IS NULL OR v_candidate <= v_until)
               AND NOT is_excluded(v_candidate, p_exdate)
               AND is_byweekno_match(v_candidate, v_byweekno)
            THEN
                occ_start := v_candidate;
                occ_end := v_candidate + v_duration;
                RETURN NEXT;
            END IF;
        END LOOP;
    END IF;

    -- Short-circuit statically impossible BYMONTH / BYMONTHDAY / BYYEARDAY combinations
    -- (e.g. BYMONTH=2;BYMONTHDAY=31) so unbounded DAILY/WEEKLY/MONTHLY/YEARLY rules
    -- cannot spin when p_range_end = 'infinity'.
    IF v_bymonth_arr IS NOT NULL THEN
        v_possible := FALSE;
        FOREACH v_m IN ARRAY v_bymonth_arr LOOP
            IF v_m >= 1 AND v_m <= 12 THEN
                IF v_bymonthday_arr IS NULL THEN
                    v_possible := TRUE;
                    EXIT;
                END IF;
                FOREACH v_d IN ARRAY v_bymonthday_arr LOOP
                    IF v_d != 0 AND abs(v_d) <= v_max_mdays[v_m] THEN
                        v_possible := TRUE;
                        EXIT;
                    END IF;
                END LOOP;
                EXIT WHEN v_possible;
            END IF;
        END LOOP;
        IF NOT v_possible THEN RETURN; END IF;
    ELSIF v_bymonthday_arr IS NOT NULL THEN
        v_possible := FALSE;
        FOREACH v_d IN ARRAY v_bymonthday_arr LOOP
            IF v_d != 0 AND abs(v_d) <= 31 THEN
                v_possible := TRUE;
                EXIT;
            END IF;
        END LOOP;
        IF NOT v_possible THEN RETURN; END IF;
    END IF;

    IF v_byyearday_arr IS NOT NULL THEN
        v_possible := FALSE;
        FOREACH v_d IN ARRAY v_byyearday_arr LOOP
            IF v_d != 0 AND abs(v_d) <= 366 THEN
                v_possible := TRUE;
                EXIT;
            END IF;
        END LOOP;
        IF NOT v_possible THEN RETURN; END IF;
    END IF;

    -- Anchor WEEKLY expansion to the WKST day of DTSTART's week.
    v_base_week := v_start_date - ((v_start_dow - v_wkst_dow + 7) % 7);

    -- Expand period by period. Every period collects valid UTC candidates,
    -- deduplicates and sorts chronologically, then applies >= p_start_at,
    -- <= v_until, COUNT (v_emitted), window overlap, and EXDATE.
    WHILE v_emitted < v_count AND NOT v_done
    LOOP
        v_candidates := ARRAY[]::TIMESTAMPTZ[];

        IF v_freq = 'YEARLY' THEN
            v_year := v_start_year + v_step_idx * v_interval;
            EXIT WHEN v_year > 9999;
            v_period_start := make_timestamp(v_year, 1, 1, 0, 0, 0) AT TIME ZONE 'UTC';
            EXIT WHEN v_period_start > COALESCE(v_until, 'infinity'::TIMESTAMPTZ);
            EXIT WHEN v_period_start >= p_range_end;

            v_year_start := make_date(v_year, 1, 1);
            v_year_days := (make_date(v_year + 1, 1, 1) - v_year_start);

            IF v_byyearday_arr IS NOT NULL THEN
                FOREACH v_d IN ARRAY v_byyearday_arr LOOP
                    IF v_d > 0 AND v_d <= v_year_days THEN
                        v_cand_date := v_year_start + (v_d - 1);
                    ELSIF v_d < 0 AND -v_d <= v_year_days THEN
                        v_cand_date := v_year_start + (v_year_days + v_d);
                    ELSE
                        CONTINUE;
                    END IF;
                    v_cand_month := EXTRACT(MONTH FROM v_cand_date)::INT;
                    IF v_bymonth_arr IS NOT NULL AND NOT (v_cand_month = ANY(v_bymonth_arr)) THEN
                        CONTINUE;
                    END IF;
                    IF v_bymonthday_arr IS NOT NULL THEN
                        v_cand_day := EXTRACT(DAY FROM v_cand_date)::INT;
                        v_cand_mdays := EXTRACT(DAY FROM (make_date(v_year, v_cand_month, 1) + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
                        IF NOT (v_cand_day = ANY(v_bymonthday_arr) OR (v_cand_day - v_cand_mdays - 1) = ANY(v_bymonthday_arr)) THEN
                            CONTINUE;
                        END IF;
                    END IF;
                    v_candidate := (v_cand_date::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
                    IF (v_byday_arr IS NULL OR day_in_byday(v_candidate, v_byday, v_wkst))
                       AND is_byweekno_match(v_candidate, v_byweekno)
                    THEN
                        v_candidates := array_append(v_candidates, v_candidate);
                    END IF;
                END LOOP;
            ELSIF v_bymonth_arr IS NOT NULL OR v_bymonthday_arr IS NOT NULL THEN
                v_months := COALESCE(v_bymonth_arr, ARRAY[v_start_month]);
                FOREACH v_m IN ARRAY v_months LOOP
                    IF v_m < 1 OR v_m > 12 THEN CONTINUE; END IF;
                    v_m_first := make_date(v_year, v_m, 1);
                    v_m_days := EXTRACT(DAY FROM (v_m_first + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
                    v_m_ref := (make_timestamp(v_year, v_m, 1, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';

                    IF v_bymonthday_arr IS NOT NULL THEN
                        FOREACH v_d IN ARRAY v_bymonthday_arr LOOP
                            v_candidate := nth_month_day(v_m_ref, v_d);
                            IF v_candidate IS NULL THEN CONTINUE; END IF;
                            IF (v_byday_arr IS NULL OR day_in_byday(v_candidate, v_byday, v_wkst))
                               AND is_byweekno_match(v_candidate, v_byweekno)
                            THEN
                                v_candidates := array_append(v_candidates, v_candidate);
                            END IF;
                        END LOOP;
                    ELSIF v_byday_arr IS NOT NULL THEN
                        v_m_first_dow := EXTRACT(DOW FROM v_m_first)::INT;
                        FOREACH v_tok IN ARRAY v_byday_arr LOOP
                            v_pos := positional_week(v_tok);
                            v_target_dow := day_of_week_num(v_tok, v_wkst);
                            IF v_pos = 0 THEN
                                v_day := 1 + ((v_target_dow - v_m_first_dow + 7) % 7);
                                WHILE v_day <= v_m_days LOOP
                                    v_candidate := (make_timestamp(v_year, v_m, v_day, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';
                                    IF is_byweekno_match(v_candidate, v_byweekno) THEN
                                        v_candidates := array_append(v_candidates, v_candidate);
                                    END IF;
                                    v_day := v_day + 7;
                                END LOOP;
                            ELSE
                                v_nth_day := nth_day_of_week_in_month(v_m_ref, v_pos, v_target_dow);
                                IF v_nth_day IS NOT NULL AND is_byweekno_match(v_nth_day, v_byweekno) THEN
                                    v_candidates := array_append(v_candidates, v_nth_day);
                                END IF;
                            END IF;
                        END LOOP;
                    ELSE
                        IF v_start_day <= v_m_days THEN
                            v_candidate := (make_timestamp(v_year, v_m, v_start_day, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';
                            IF is_byweekno_match(v_candidate, v_byweekno) THEN
                                v_candidates := array_append(v_candidates, v_candidate);
                            END IF;
                        END IF;
                    END IF;
                END LOOP;
            ELSIF v_byday_arr IS NOT NULL THEN
                v_jan1_dow := EXTRACT(DOW FROM v_year_start)::INT;
                v_dec31_dow := EXTRACT(DOW FROM make_date(v_year, 12, 31))::INT;
                FOREACH v_tok IN ARRAY v_byday_arr LOOP
                    v_pos := positional_week(v_tok);
                    v_target_dow := day_of_week_num(v_tok, v_wkst);
                    IF v_pos = 0 THEN
                        v_offset := (v_target_dow - v_jan1_dow + 7) % 7;
                        WHILE v_offset < v_year_days LOOP
                            v_cand_date := v_year_start + v_offset;
                            v_candidate := (v_cand_date::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
                            IF is_byweekno_match(v_candidate, v_byweekno) THEN
                                v_candidates := array_append(v_candidates, v_candidate);
                            END IF;
                            v_offset := v_offset + 7;
                        END LOOP;
                    ELSIF v_pos > 0 THEN
                        v_offset := ((v_target_dow - v_jan1_dow + 7) % 7) + (v_pos - 1) * 7;
                        IF v_offset >= 0 AND v_offset < v_year_days THEN
                            v_candidate := ((v_year_start + v_offset)::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
                            IF is_byweekno_match(v_candidate, v_byweekno) THEN
                                v_candidates := array_append(v_candidates, v_candidate);
                            END IF;
                        END IF;
                    ELSE
                        v_offset := (v_year_days - 1) - ((v_dec31_dow - v_target_dow + 7) % 7) + (v_pos + 1) * 7;
                        IF v_offset >= 0 AND v_offset < v_year_days THEN
                            v_candidate := ((v_year_start + v_offset)::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
                            IF is_byweekno_match(v_candidate, v_byweekno) THEN
                                v_candidates := array_append(v_candidates, v_candidate);
                            END IF;
                        END IF;
                    END IF;
                END LOOP;
            ELSIF v_byweekno IS NOT NULL AND v_byweekno != '' THEN
                v_jan1_dow := EXTRACT(DOW FROM v_year_start)::INT;
                v_offset := (v_start_dow - v_jan1_dow + 7) % 7;
                WHILE v_offset < v_year_days LOOP
                    v_candidate := ((v_year_start + v_offset)::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
                    IF is_byweekno_match(v_candidate, v_byweekno) THEN
                        v_candidates := array_append(v_candidates, v_candidate);
                    END IF;
                    v_offset := v_offset + 7;
                END LOOP;
            ELSE
                v_m_days := EXTRACT(DAY FROM (make_date(v_year, v_start_month, 1) + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
                IF v_start_day <= v_m_days THEN
                    v_candidate := (make_timestamp(v_year, v_start_month, v_start_day, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';
                    v_candidates := array_append(v_candidates, v_candidate);
                END IF;
            END IF;

        ELSIF v_freq = 'MONTHLY' THEN
            -- Derive (year, month) from step index so day-31 anchors never drift (Jan 31 -> Mar 31).
            v_total_months := (v_start_year * 12 + (v_start_month - 1)) + v_step_idx * v_interval;
            v_year := v_total_months / 12;
            v_month := (v_total_months % 12) + 1;
            EXIT WHEN v_year > 9999;
            v_period_start := make_timestamp(v_year, v_month, 1, 0, 0, 0) AT TIME ZONE 'UTC';
            EXIT WHEN v_period_start > COALESCE(v_until, 'infinity'::TIMESTAMPTZ);
            EXIT WHEN v_period_start >= p_range_end;

            IF v_bymonth_arr IS NULL OR (v_month = ANY(v_bymonth_arr)) THEN
                v_m_first := make_date(v_year, v_month, 1);
                v_m_days := EXTRACT(DAY FROM (v_m_first + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
                v_m_ref := (make_timestamp(v_year, v_month, 1, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';

                IF v_bymonthday_arr IS NOT NULL THEN
                    FOREACH v_d IN ARRAY v_bymonthday_arr LOOP
                        v_candidate := nth_month_day(v_m_ref, v_d);
                        IF v_candidate IS NULL THEN CONTINUE; END IF;
                        IF v_byday_arr IS NOT NULL AND NOT day_in_byday(v_candidate, v_byday, v_wkst) THEN
                            CONTINUE;
                        END IF;
                        IF v_byyearday_arr IS NOT NULL THEN
                            v_cand_date := (v_candidate AT TIME ZONE 'UTC')::DATE;
                            v_cand_doy := EXTRACT(DOY FROM v_cand_date)::INT;
                            v_cand_ydays := (make_date(v_year + 1, 1, 1) - make_date(v_year, 1, 1));
                            IF NOT (v_cand_doy = ANY(v_byyearday_arr) OR (v_cand_doy - v_cand_ydays - 1) = ANY(v_byyearday_arr)) THEN
                                CONTINUE;
                            END IF;
                        END IF;
                        IF is_byweekno_match(v_candidate, v_byweekno) THEN
                            v_candidates := array_append(v_candidates, v_candidate);
                        END IF;
                    END LOOP;
                ELSIF v_byday_arr IS NOT NULL THEN
                    v_m_first_dow := EXTRACT(DOW FROM v_m_first)::INT;
                    FOREACH v_tok IN ARRAY v_byday_arr LOOP
                        v_pos := positional_week(v_tok);
                        v_target_dow := day_of_week_num(v_tok, v_wkst);
                        IF v_pos = 0 THEN
                            -- Unqualified weekday (e.g. BYDAY=TU,TH): emit all matching days in month.
                            v_day := 1 + ((v_target_dow - v_m_first_dow + 7) % 7);
                            WHILE v_day <= v_m_days LOOP
                                v_candidate := (make_timestamp(v_year, v_month, v_day, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';
                                IF is_byweekno_match(v_candidate, v_byweekno) THEN
                                    IF v_byyearday_arr IS NULL THEN
                                        v_candidates := array_append(v_candidates, v_candidate);
                                    ELSE
                                        v_cand_date := make_date(v_year, v_month, v_day);
                                        v_cand_doy := EXTRACT(DOY FROM v_cand_date)::INT;
                                        v_cand_ydays := (make_date(v_year + 1, 1, 1) - make_date(v_year, 1, 1));
                                        IF v_cand_doy = ANY(v_byyearday_arr) OR (v_cand_doy - v_cand_ydays - 1) = ANY(v_byyearday_arr) THEN
                                            v_candidates := array_append(v_candidates, v_candidate);
                                        END IF;
                                    END IF;
                                END IF;
                                v_day := v_day + 7;
                            END LOOP;
                        ELSE
                            v_nth_day := nth_day_of_week_in_month(v_m_ref, v_pos, v_target_dow);
                            IF v_nth_day IS NOT NULL AND is_byweekno_match(v_nth_day, v_byweekno) THEN
                                IF v_byyearday_arr IS NULL THEN
                                    v_candidates := array_append(v_candidates, v_nth_day);
                                ELSE
                                    v_cand_date := (v_nth_day AT TIME ZONE 'UTC')::DATE;
                                    v_cand_doy := EXTRACT(DOY FROM v_cand_date)::INT;
                                    v_cand_ydays := (make_date(v_year + 1, 1, 1) - make_date(v_year, 1, 1));
                                    IF v_cand_doy = ANY(v_byyearday_arr) OR (v_cand_doy - v_cand_ydays - 1) = ANY(v_byyearday_arr) THEN
                                        v_candidates := array_append(v_candidates, v_nth_day);
                                    END IF;
                                END IF;
                            END IF;
                        END IF;
                    END LOOP;
                ELSE
                    IF v_start_day <= v_m_days THEN
                        v_candidate := (make_timestamp(v_year, v_month, v_start_day, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';
                        IF is_byweekno_match(v_candidate, v_byweekno) THEN
                            IF v_byyearday_arr IS NULL THEN
                                v_candidates := array_append(v_candidates, v_candidate);
                            ELSE
                                v_cand_date := make_date(v_year, v_month, v_start_day);
                                v_cand_doy := EXTRACT(DOY FROM v_cand_date)::INT;
                                v_cand_ydays := (make_date(v_year + 1, 1, 1) - make_date(v_year, 1, 1));
                                IF v_cand_doy = ANY(v_byyearday_arr) OR (v_cand_doy - v_cand_ydays - 1) = ANY(v_byyearday_arr) THEN
                                    v_candidates := array_append(v_candidates, v_candidate);
                                END IF;
                            END IF;
                        END IF;
                    END IF;
                END IF;
            END IF;

        ELSIF v_freq = 'WEEKLY' THEN
            v_week_start := v_base_week + (v_step_idx * 7 * v_interval);
            v_year := EXTRACT(YEAR FROM v_week_start)::INT;
            EXIT WHEN v_year > 9999;
            v_period_start := (v_week_start::TIMESTAMP) AT TIME ZONE 'UTC';
            EXIT WHEN v_period_start > COALESCE(v_until, 'infinity'::TIMESTAMPTZ);
            EXIT WHEN v_period_start >= p_range_end;

            IF v_byday_arr IS NOT NULL THEN
                FOREACH v_tok IN ARRAY v_byday_arr LOOP
                    v_target_dow := day_of_week_num(v_tok, v_wkst);
                    v_cand_date := v_week_start + ((v_target_dow - v_wkst_dow + 7) % 7);
                    v_cand_year := EXTRACT(YEAR FROM v_cand_date)::INT;
                    IF v_cand_year > 9999 THEN CONTINUE; END IF;
                    v_cand_month := EXTRACT(MONTH FROM v_cand_date)::INT;
                    IF v_bymonth_arr IS NOT NULL AND NOT (v_cand_month = ANY(v_bymonth_arr)) THEN
                        CONTINUE;
                    END IF;
                    IF v_bymonthday_arr IS NOT NULL THEN
                        v_cand_day := EXTRACT(DAY FROM v_cand_date)::INT;
                        v_cand_mdays := EXTRACT(DAY FROM (make_date(v_cand_year, v_cand_month, 1) + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
                        IF NOT (v_cand_day = ANY(v_bymonthday_arr) OR (v_cand_day - v_cand_mdays - 1) = ANY(v_bymonthday_arr)) THEN
                            CONTINUE;
                        END IF;
                    END IF;
                    IF v_byyearday_arr IS NOT NULL THEN
                        v_cand_doy := EXTRACT(DOY FROM v_cand_date)::INT;
                        v_cand_ydays := (make_date(v_cand_year + 1, 1, 1) - make_date(v_cand_year, 1, 1));
                        IF NOT (v_cand_doy = ANY(v_byyearday_arr) OR (v_cand_doy - v_cand_ydays - 1) = ANY(v_byyearday_arr)) THEN
                            CONTINUE;
                        END IF;
                    END IF;
                    v_candidate := (v_cand_date::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
                    IF is_byweekno_match(v_candidate, v_byweekno) THEN
                        v_candidates := array_append(v_candidates, v_candidate);
                    END IF;
                END LOOP;
            ELSE
                v_cand_date := v_start_date + (v_step_idx * 7 * v_interval);
                v_cand_year := EXTRACT(YEAR FROM v_cand_date)::INT;
                EXIT WHEN v_cand_year > 9999;
                v_cand_month := EXTRACT(MONTH FROM v_cand_date)::INT;
                v_candidate := (v_cand_date::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
                IF (v_bymonth_arr IS NULL OR v_cand_month = ANY(v_bymonth_arr))
                   AND is_byweekno_match(v_candidate, v_byweekno)
                THEN
                    v_possible := TRUE;
                    IF v_bymonthday_arr IS NOT NULL THEN
                        v_cand_day := EXTRACT(DAY FROM v_cand_date)::INT;
                        v_cand_mdays := EXTRACT(DAY FROM (make_date(v_cand_year, v_cand_month, 1) + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
                        IF NOT (v_cand_day = ANY(v_bymonthday_arr) OR (v_cand_day - v_cand_mdays - 1) = ANY(v_bymonthday_arr)) THEN
                            v_possible := FALSE;
                        END IF;
                    END IF;
                    IF v_possible AND v_byyearday_arr IS NOT NULL THEN
                        v_cand_doy := EXTRACT(DOY FROM v_cand_date)::INT;
                        v_cand_ydays := (make_date(v_cand_year + 1, 1, 1) - make_date(v_cand_year, 1, 1));
                        IF NOT (v_cand_doy = ANY(v_byyearday_arr) OR (v_cand_doy - v_cand_ydays - 1) = ANY(v_byyearday_arr)) THEN
                            v_possible := FALSE;
                        END IF;
                    END IF;
                    IF v_possible THEN
                        v_candidates := array_append(v_candidates, v_candidate);
                    END IF;
                END IF;
            END IF;

        ELSE
            -- DAILY: apply ALL BY* filters BEFORE incrementing v_emitted.
            v_cand_date := v_start_date + (v_step_idx * v_interval);
            v_cand_year := EXTRACT(YEAR FROM v_cand_date)::INT;
            EXIT WHEN v_cand_year > 9999;
            v_period_start := (v_cand_date::TIMESTAMP + v_time_part) AT TIME ZONE 'UTC';
            EXIT WHEN v_period_start > COALESCE(v_until, 'infinity'::TIMESTAMPTZ);
            EXIT WHEN v_period_start >= p_range_end;

            v_cand_month := EXTRACT(MONTH FROM v_cand_date)::INT;
            IF v_bymonth_arr IS NOT NULL AND NOT (v_cand_month = ANY(v_bymonth_arr)) THEN
                IF v_interval = 1 THEN
                    v_next_month := (make_date(v_cand_year, v_cand_month, 1) + INTERVAL '1 month')::DATE;
                    v_empty_steps := v_empty_steps + (v_next_month - v_cand_date);
                    v_step_idx := v_next_month - v_start_date;
                    EXIT WHEN v_empty_steps > 146100;
                    CONTINUE;
                END IF;
                v_empty_steps := v_empty_steps + 1;
                v_step_idx := v_step_idx + 1;
                EXIT WHEN v_empty_steps > 146100;
                CONTINUE;
            END IF;

            v_possible := TRUE;
            IF v_bymonthday_arr IS NOT NULL THEN
                v_cand_day := EXTRACT(DAY FROM v_cand_date)::INT;
                v_cand_mdays := EXTRACT(DAY FROM (make_date(v_cand_year, v_cand_month, 1) + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
                IF NOT (v_cand_day = ANY(v_bymonthday_arr) OR (v_cand_day - v_cand_mdays - 1) = ANY(v_bymonthday_arr)) THEN
                    v_possible := FALSE;
                END IF;
            END IF;
            IF v_possible AND v_byyearday_arr IS NOT NULL THEN
                v_cand_doy := EXTRACT(DOY FROM v_cand_date)::INT;
                v_cand_ydays := (make_date(v_cand_year + 1, 1, 1) - make_date(v_cand_year, 1, 1));
                IF NOT (v_cand_doy = ANY(v_byyearday_arr) OR (v_cand_doy - v_cand_ydays - 1) = ANY(v_byyearday_arr)) THEN
                    v_possible := FALSE;
                END IF;
            END IF;
            IF v_possible AND v_byday_arr IS NOT NULL AND NOT day_in_byday(v_period_start, v_byday, v_wkst) THEN
                v_possible := FALSE;
            END IF;
            IF v_possible AND NOT is_byweekno_match(v_period_start, v_byweekno) THEN
                v_possible := FALSE;
            END IF;
            IF v_possible THEN
                v_candidates := ARRAY[v_period_start];
            END IF;
        END IF;

        -- Deduplicate and sort period candidates chronologically, then filter & emit.
        v_period_had_hit := FALSE;
        IF array_length(v_candidates, 1) IS NOT NULL AND array_length(v_candidates, 1) > 0 THEN
            IF array_length(v_candidates, 1) > 1 THEN
                SELECT array_agg(DISTINCT ts ORDER BY ts) INTO v_candidates
                FROM unnest(v_candidates) AS ts
                WHERE ts IS NOT NULL;
            END IF;

            IF v_candidates IS NOT NULL AND array_length(v_candidates, 1) > 0 THEN
                FOREACH v_candidate IN ARRAY v_candidates LOOP
                    IF v_candidate IS NULL THEN CONTINUE; END IF;
                    IF v_candidate < p_start_at THEN CONTINUE; END IF;
                    IF v_until IS NOT NULL AND v_candidate > v_until THEN
                        v_done := TRUE;
                        EXIT;
                    END IF;
                    IF v_candidate >= p_range_end THEN
                        v_done := TRUE;
                        EXIT;
                    END IF;

                    v_period_had_hit := TRUE;
                    v_emitted := v_emitted + 1;

                    IF v_candidate >= p_range_start OR v_candidate + v_duration > p_range_start THEN
                        IF NOT is_excluded(v_candidate, p_exdate) THEN
                            occ_start := v_candidate;
                            occ_end := v_candidate + v_duration;
                            RETURN NEXT;
                        END IF;
                    END IF;

                    EXIT WHEN v_emitted >= v_count;
                END LOOP;
            END IF;
        END IF;

        IF v_period_had_hit THEN
            v_empty_steps := 0;
        ELSE
            v_empty_steps := v_empty_steps + 1;
            EXIT WHEN v_freq = 'DAILY' AND v_empty_steps > 146100;
        END IF;

        v_step_idx := v_step_idx + 1;
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
    v_bysetpos := substring(upper(p_rrule) FROM 'BYSETPOS=([^;]+)');
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

-- Helper: find the Nth occurrence of a day-of-week within a month (UTC).
-- p_pos: -1 = last, 1 = first, 2 = second, etc.; 0 or out-of-range returns NULL.
CREATE OR REPLACE FUNCTION nth_day_of_week_in_month(
    p_ref    TIMESTAMPTZ,
    p_pos    INT,
    p_dow    INT
) RETURNS TIMESTAMPTZ AS $$
DECLARE
    v_utc           TIMESTAMP := p_ref AT TIME ZONE 'UTC';
    v_year          INT := EXTRACT(YEAR FROM v_utc)::INT;
    v_month         INT := EXTRACT(MONTH FROM v_utc)::INT;
    v_time_part     INTERVAL := v_utc - date_trunc('day', v_utc);
    v_first_day     DATE := make_date(v_year, v_month, 1);
    v_last_day      DATE := (v_first_day + INTERVAL '1 month' - INTERVAL '1 day')::DATE;
    v_days_in_month INT := EXTRACT(DAY FROM v_last_day)::INT;
    v_first_dow     INT := EXTRACT(DOW FROM v_first_day)::INT;
    v_last_dow      INT := EXTRACT(DOW FROM v_last_day)::INT;
    v_day           INT;
BEGIN
    IF p_pos IS NULL OR p_pos = 0 THEN
        RETURN NULL;
    END IF;

    IF p_pos > 0 THEN
        v_day := 1 + ((p_dow - v_first_dow + 7) % 7) + (p_pos - 1) * 7;
    ELSE
        v_day := v_days_in_month - ((v_last_dow - p_dow + 7) % 7) + (p_pos + 1) * 7;
    END IF;

    IF v_day < 1 OR v_day > v_days_in_month THEN
        RETURN NULL;
    END IF;

    RETURN (make_timestamp(v_year, v_month, v_day, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';
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

-- Helper: compute the Nth day of a month in UTC (negative counts from end of month).
-- Returns NULL when p_day_num = 0 or |p_day_num| exceeds the month's day count (no rollover).
CREATE OR REPLACE FUNCTION nth_month_day(
    p_ref     TIMESTAMPTZ,
    p_day_num INT
) RETURNS TIMESTAMPTZ AS $$
DECLARE
    v_utc           TIMESTAMP := p_ref AT TIME ZONE 'UTC';
    v_year          INT := EXTRACT(YEAR FROM v_utc)::INT;
    v_month         INT := EXTRACT(MONTH FROM v_utc)::INT;
    v_time_part     INTERVAL := v_utc - date_trunc('day', v_utc);
    v_days_in_month INT := EXTRACT(DAY FROM (make_date(v_year, v_month, 1) + INTERVAL '1 month' - INTERVAL '1 day'))::INT;
    v_day           INT;
BEGIN
    IF p_day_num IS NULL OR p_day_num = 0 THEN
        RETURN NULL;
    END IF;

    IF p_day_num > 0 THEN
        v_day := p_day_num;
    ELSE
        v_day := v_days_in_month + p_day_num + 1;
    END IF;

    IF v_day < 1 OR v_day > v_days_in_month THEN
        RETURN NULL;
    END IF;

    RETURN (make_timestamp(v_year, v_month, v_day, 0, 0, 0) + v_time_part) AT TIME ZONE 'UTC';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: check if an exact instant is in the EXDATE exclusion list.
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
        IF p_exdate[v_i] = p_ts THEN
            RETURN TRUE;
        END IF;
    END LOOP;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper: check if a date's ISO week number is in a BYWEEKNO list (supports negative values).
CREATE OR REPLACE FUNCTION is_byweekno_match(
    p_ts       TIMESTAMPTZ,
    p_byweekno TEXT
) RETURNS BOOL AS $$
DECLARE
    v_utc           TIMESTAMP := p_ts AT TIME ZONE 'UTC';
    v_week          INT;
    v_isoyear       INT;
    v_weeks_in_year INT;
    v_weeks         TEXT[];
    v_w             TEXT;
    v_target        INT;
BEGIN
    IF p_byweekno IS NULL OR p_byweekno = '' THEN
        RETURN TRUE;
    END IF;
    v_week := EXTRACT(WEEK FROM v_utc)::INT;
    v_isoyear := EXTRACT(ISOYEAR FROM v_utc)::INT;
    -- Dec 28 always falls in the last ISO week (52 or 53) of its ISO week-year.
    v_weeks_in_year := EXTRACT(WEEK FROM make_date(v_isoyear, 12, 28))::INT;
    v_weeks := string_to_array(p_byweekno, ',');
    FOREACH v_w IN ARRAY v_weeks LOOP
        v_w := btrim(v_w);
        IF v_w !~ '^[+-]?\d+$' THEN
            CONTINUE;
        END IF;
        v_target := v_w::INT;
        IF v_target < 0 THEN
            v_target := v_weeks_in_year + v_target + 1;
        END IF;
        IF v_target = v_week THEN
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
