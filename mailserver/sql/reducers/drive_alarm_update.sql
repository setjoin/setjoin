-- mailserver/sql/reducers/drive_alarm_update.sql
-- Task 6: replaces audit.go updateAlarm's 5 sequential field-guarded UPDATEs
-- with one jsonb-patch-driven UPDATE (field-driven: absent key = unchanged,
-- same PATCH semantics the Go handler used). p_patch keys mirror the wire
-- body exactly: actionPattern, threshold, windowMinutes, enabled, spaceId.
-- drive_alarm_validate_action_pattern (Task 6 dedup follow-up).
CREATE OR REPLACE FUNCTION drive_alarm_update(
  p_user_id BIGINT, p_id BIGINT, p_patch JSONB
) RETURNS VOID AS $$
DECLARE
  v_action_pattern TEXT;
  v_rows           INT;
BEGIN
  IF NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'drive.manage required' USING ERRCODE='BZ140',
      HINT='{"type":"forbidden","detail":"alarm rules are a drive.manage admin knob"}';
  END IF;

  -- Only validate when the patch actually carries a new action pattern —
  -- an absent key means "leave the stored pattern unchanged", so it must
  -- not be re-validated (and re-validating it would be pointless: it was
  -- already validated on create/last update).
  IF p_patch ? 'actionPattern' THEN
    v_action_pattern := p_patch->>'actionPattern';
    PERFORM drive_alarm_validate_action_pattern(v_action_pattern);
  END IF;

  -- Guard numeric/boolean fields BEFORE casting: a malformed patch (e.g.
  -- {"threshold":"abc"}) must raise a clean BZ141, not let ::int/::boolean
  -- throw a raw 22P02 that the Go handler can only map to a 500.
  IF p_patch ? 'threshold' AND jsonb_typeof(p_patch->'threshold') != 'number' THEN
    RAISE EXCEPTION 'threshold must be a number' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"threshold must be a number"}';
  END IF;
  IF p_patch ? 'windowMinutes' AND jsonb_typeof(p_patch->'windowMinutes') != 'number' THEN
    RAISE EXCEPTION 'windowMinutes must be a number' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"windowMinutes must be a number"}';
  END IF;
  IF p_patch ? 'enabled' AND jsonb_typeof(p_patch->'enabled') != 'boolean' THEN
    RAISE EXCEPTION 'enabled must be a boolean' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"enabled must be a boolean"}';
  END IF;
  IF p_patch ? 'spaceId' AND jsonb_typeof(p_patch->'spaceId') != 'number' THEN
    RAISE EXCEPTION 'spaceId must be a number' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"spaceId must be a number"}';
  END IF;

  UPDATE drive_audit_alarms SET
    action_pattern = COALESCE(v_action_pattern, action_pattern),
    threshold      = COALESCE((p_patch->>'threshold')::int, threshold),
    window_minutes = COALESCE((p_patch->>'windowMinutes')::int, window_minutes),
    enabled        = COALESCE((p_patch->>'enabled')::boolean, enabled),
    space_id       = CASE WHEN p_patch ? 'spaceId' THEN (p_patch->>'spaceId')::bigint ELSE space_id END
  WHERE id = p_id;

  GET DIAGNOSTICS v_rows = ROW_COUNT;
  IF v_rows = 0 THEN
    RAISE EXCEPTION 'alarm rule not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"alarm rule not found"}';
  END IF;
END;
$$ LANGUAGE plpgsql;
