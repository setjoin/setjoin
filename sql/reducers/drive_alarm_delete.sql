-- mailserver/sql/reducers/drive_alarm_delete.sql
-- Task 6: moves alarm-rule deletion off Go raw DML (audit.go deleteAlarm)
-- onto the reducer rail.
CREATE OR REPLACE FUNCTION drive_alarm_delete(
  p_user_id BIGINT, p_id BIGINT
) RETURNS VOID AS $$
DECLARE v_rows INT;
BEGIN
  IF NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'drive.manage required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"alarm rules are a drive.manage admin knob"}';
  END IF;

  DELETE FROM drive_audit_alarms WHERE id = p_id;
  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows = 0 THEN
    RAISE EXCEPTION 'alarm rule not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"alarm rule not found"}';
  END IF;
END;
$$ LANGUAGE plpgsql;
