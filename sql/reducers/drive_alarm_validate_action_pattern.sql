-- mailserver/sql/reducers/drive_alarm_validate_action_pattern.sql
-- Task 6 dedup follow-up (simplify pass): drive_alarm_create.sql and
-- drive_alarm_update.sql carried a byte-identical ~13-line action_pattern
-- validation block (exact drive_audit_actions() membership, or a "prefix.*"
-- glob whose prefix left()-matches at least one catalog action). Single-
-- homed here, reusing the match semantics drive_alarm_evaluate.sql already
-- extracted (drive_alarm_action_matches) instead of re-deriving the left()
-- comparison a third time. A bare "*" (empty prefix) is still explicitly
-- rejected — drive_alarm_action_matches alone would treat it as matching
-- every catalog action.
-- Same invoker-rights posture as drive_alarm_create/drive_alarm_action_matches
-- (app-gated by the caller's drive.manage check, no apply_worker_ownership
-- footer).
CREATE OR REPLACE FUNCTION drive_alarm_validate_action_pattern(p_pattern TEXT) RETURNS void AS $$
DECLARE
  v_prefix TEXT;
BEGIN
  IF p_pattern LIKE '%*' THEN
    v_prefix := left(p_pattern, length(p_pattern) - 1);
  END IF;

  IF (p_pattern LIKE '%*' AND v_prefix = '') OR NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements_text(drive_audit_actions()) a
     WHERE drive_alarm_action_matches(a, p_pattern)
  ) THEN
    RAISE EXCEPTION 'unrecognized action pattern' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"action pattern matches no catalog action"}';
  END IF;
END;
$$ LANGUAGE plpgsql;
