-- mailserver/sql/reducers/drive_alarm_evaluate.sql
-- Task 10 (C6 part 1): extracted from drive_maintenance_sweep.sql's
-- audit-alarm leg (P6 Task 5, spec §9.3) — DETECTION, not maintenance, so it
-- gets its own reducer; the sweep just calls it. Same invoker-rights posture
-- as drive_maintenance_sweep/drive_node_destroy_hard (worker-only, never
-- granted/revoked explicitly, relies on the fixed Go route table never
-- naming it — no apply_worker_ownership footer, matching the sweep it was
-- pulled out of).
--
-- Prefix match is left()-based, NOT LIKE — a pattern like 'lock.*' must
-- never treat user-controlled action text as a wildcard pattern. The old
-- sweep body had this CASE written out twice (once for the threshold COUNT,
-- once for the global-rule hit-space GROUP BY); they were byte-identical
-- modulo whitespace, so this extraction collapses them into the one
-- drive_alarm_action_matches() helper both queries call.
CREATE OR REPLACE FUNCTION drive_alarm_action_matches(p_action TEXT, p_pattern TEXT) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN right(p_pattern, 1) = '*'
              THEN left(p_action, length(p_pattern) - 1) = left(p_pattern, length(p_pattern) - 1)
              ELSE p_action = p_pattern END;
$$;

CREATE OR REPLACE FUNCTION drive_alarm_evaluate() RETURNS INT AS $$
DECLARE
  v_fired INT; v_rule RECORD; v_hits BIGINT; v_hit_space BIGINT;
BEGIN
  v_fired := 0;
  FOR v_rule IN SELECT * FROM drive_audit_alarms WHERE enabled LOOP
    SELECT count(*) INTO v_hits
      FROM drive_audit_log a
     WHERE (v_rule.space_id IS NULL OR a.space_id = v_rule.space_id)
       AND a.occurred_at > now() - make_interval(mins => v_rule.window_minutes)
       AND a.action <> 'alarm.fire'
       AND drive_alarm_action_matches(a.action, v_rule.action_pattern);
    IF v_hits >= v_rule.threshold THEN
      -- once per rule per window (self-dedupe on the chain itself — no extra
      -- state; alarm.fire rows for this rule ID are checked across ALL
      -- spaces since a global rule's locus can move between windows).
      IF NOT EXISTS (
        SELECT 1 FROM drive_audit_log
         WHERE action = 'alarm.fire' AND target_type = 'alarm' AND target_id = v_rule.id
           AND occurred_at > now() - make_interval(mins => v_rule.window_minutes)
      ) THEN
        IF v_rule.space_id IS NULL THEN
          -- global rules record on the space with the most hits in the
          -- window (the storm's locus).
          SELECT a.space_id INTO v_hit_space FROM drive_audit_log a
           WHERE a.occurred_at > now() - make_interval(mins => v_rule.window_minutes)
             AND a.action <> 'alarm.fire'
             AND drive_alarm_action_matches(a.action, v_rule.action_pattern)
           GROUP BY a.space_id ORDER BY count(*) DESC, a.space_id LIMIT 1;
        ELSE
          v_hit_space := v_rule.space_id;
        END IF;
        PERFORM drive_access_audit(NULL, v_hit_space, 'alarm.fire', 'alarm', v_rule.id,
                                   NULL,
                                   jsonb_build_object('pattern', v_rule.action_pattern,
                                                      'hits', v_hits,
                                                      'windowMinutes', v_rule.window_minutes),
                                   NULL, 'threshold crossed');
        PERFORM app_notify('drive-alarm', json_build_object(
          'ruleId', v_rule.id, 'spaceId', v_hit_space, 'pattern', v_rule.action_pattern,
          'hits', v_hits)::text);
        v_fired := v_fired + 1;
      END IF;
    END IF;
  END LOOP;
  RETURN v_fired;
END;
$$ LANGUAGE plpgsql;
