-- mailserver/sql/reducers/drive_alarm_create.sql
-- Task 6: moves alarm-rule creation off Go raw DML (audit.go createAlarm)
-- onto the reducer rail. Gate + validation are app-level-primary here (the
-- V117 drive_audit_alarms_admin FORCE-RLS policy is the backstop, same
-- belt-and-suspenders shape as every other drive.manage-gated reducer).
-- drive_alarm_validate_action_pattern (Task 6 dedup follow-up).
CREATE OR REPLACE FUNCTION drive_alarm_create(
  p_user_id BIGINT, p_space_id BIGINT, p_action_pattern TEXT,
  p_threshold INT, p_window_minutes INT
) RETURNS BIGINT AS $$
DECLARE
  v_id     BIGINT;
BEGIN
  IF NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'drive.manage required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"alarm rules are a drive.manage admin knob"}';
  END IF;

  -- action_pattern is either an exact drive_audit_actions() entry or a
  -- "prefix.*" glob whose prefix is a left()-substring of at least one
  -- catalog action (mirrors the Go validActionPattern / the sweep's
  -- evaluator in drive_maintenance_sweep.sql — never a LIKE over user text).
  -- Single-homed validator: reused by drive_alarm_update.sql too.
  PERFORM drive_alarm_validate_action_pattern(p_action_pattern);

  INSERT INTO drive_audit_alarms (space_id, action_pattern, threshold, window_minutes, created_by)
  VALUES (p_space_id, p_action_pattern, COALESCE(p_threshold, 5), COALESCE(p_window_minutes, 10), p_user_id)
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql;
