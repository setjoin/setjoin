-- rule_engine_or.sql: Phase 5 — OR-grouping conditions for the rule engine.
-- Adds eval_conditions() which supports nested AND/OR condition groups.

-- Evaluate a single condition or a condition group recursively.
-- Simple condition:  {"field":"subject","op":"contains","value":"test"}
-- Condition group:   {"operator":"OR","conditions":[...]}
CREATE OR REPLACE FUNCTION eval_conditions(
  v_msg     RECORD,
  v_conds   JSONB
) RETURNS BOOL AS $$
DECLARE
  v_operator TEXT;
  v_item     JSONB;
BEGIN
  -- If this is a simple condition (has 'field'), evaluate it directly
  IF v_conds ? 'field' THEN
    RETURN eval_condition(v_msg, v_conds);
  END IF;

  -- Otherwise it's a group
  v_operator := upper(coalesce(v_conds->>'operator', 'AND'));

  IF v_operator = 'AND' THEN
    FOR v_item IN SELECT * FROM jsonb_array_elements(coalesce(v_conds->'conditions', '[]')) LOOP
      IF NOT eval_conditions(v_msg, v_item) THEN
        RETURN FALSE;
      END IF;
    END LOOP;
    RETURN TRUE;
  ELSIF v_operator = 'OR' THEN
    FOR v_item IN SELECT * FROM jsonb_array_elements(coalesce(v_conds->'conditions', '[]')) LOOP
      IF eval_conditions(v_msg, v_item) THEN
        RETURN TRUE;
      END IF;
    END LOOP;
    RETURN FALSE;
  ELSIF v_operator = 'NOT' THEN
    FOR v_item IN SELECT * FROM jsonb_array_elements(coalesce(v_conds->'conditions', '[]')) LOOP
      IF eval_conditions(v_msg, v_item) THEN
        RETURN FALSE;
      END IF;
    END LOOP;
    RETURN TRUE;
  ELSE
    RETURN FALSE;
  END IF;
END;
$$ LANGUAGE plpgsql STABLE;

-- Update apply_rules() to use eval_conditions() instead of flat AND loop.
-- This is backward-compatible: old flat arrays still work because
-- jsonb_array_elements on a flat array yields individual conditions,
-- and eval_conditions handles both simple conditions and groups.
-- p_organize_only (retro sweep): when TRUE, apply_action no-ops send-time actions
--   (forward_to/redirect/bcc/append_footer/add_header) so a retroactive re-run over
--   historical mail cannot mass re-send. Default FALSE = normal delivery/send path.
-- p_rule_id (single-rule apply): when non-NULL, only that one rule is evaluated;
--   NULL (default) = all enabled rules, the original behaviour.
CREATE OR REPLACE FUNCTION apply_rules(
  p_message_id  BIGINT,
  p_received_at TIMESTAMPTZ,
  p_mailbox_id  BIGINT,
  p_side        TEXT,
  p_organize_only BOOLEAN DEFAULT FALSE,
  p_rule_id     BIGINT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_msg       RECORD;
  v_rule      RECORD;
  v_item      JSONB;
  v_action    JSONB;
  v_matched   BOOL;
BEGIN
  -- Bound delivery-path latency only. The retro sweep (p_organize_only=TRUE)
  -- runs up to c_cap statements in ONE transaction as a background scheduled
  -- action; a transaction-wide 1s statement cap there just makes the sweep
  -- flaky on large/busy databases (CI saw 'canceling statement due to
  -- statement timeout' inside apply_rules' messages lookup).
  IF NOT p_organize_only THEN
    PERFORM set_config('statement_timeout', '1000ms', true);
  END IF;

  IF p_side NOT IN ('server', 'outbound') THEN
    RAISE EXCEPTION 'invalid rule evaluation side: %', p_side USING ERRCODE = 'BZ010';
  END IF;

  -- Guard: prevent runaway rule count from degrading delivery performance
  IF (SELECT COUNT(*) FROM rules r
      WHERE r.enabled = TRUE
        AND r.run_on IN ('server', 'both')
        AND (
          (r.is_transport_rule = TRUE)
          OR (p_side = 'server' AND r.is_transport_rule = FALSE AND r.mailbox_id = p_mailbox_id)
        )) > 200 THEN
    RAISE WARNING 'too_many_rules: mailbox % has >200 active rules, delivery performance may degrade', p_mailbox_id;
  END IF;

  SELECT * INTO v_msg FROM messages
  WHERE id = p_message_id AND received_at = p_received_at
    AND mailbox_id = p_mailbox_id;

  FOR v_rule IN
    SELECT r.* FROM rules r
    WHERE r.enabled = TRUE
      AND r.run_on IN ('server', 'both')
      AND (p_rule_id IS NULL OR r.id = p_rule_id)
      AND (
        (r.is_transport_rule = TRUE)
        OR
        (p_side = 'server'
         AND r.is_transport_rule = FALSE
         AND r.mailbox_id = p_mailbox_id)
      )
    ORDER BY r.is_transport_rule DESC, r.priority ASC, r.id ASC
  LOOP
    BEGIN
      -- Evaluate conditions using the new group-aware function.
      -- If conditions is a flat array, eval_conditions handles each element.
      -- If conditions is a single group object, it handles that too.
      v_matched := TRUE;
      IF jsonb_typeof(v_rule.conditions) = 'array' THEN
        -- Flat array of conditions — implicit AND
        FOR v_item IN SELECT * FROM jsonb_array_elements(v_rule.conditions) LOOP
          IF NOT eval_conditions(v_msg, v_item) THEN
            v_matched := FALSE;
            EXIT;
          END IF;
        END LOOP;
      ELSIF jsonb_typeof(v_rule.conditions) = 'object' THEN
        -- Single condition or group object
        v_matched := eval_conditions(v_msg, v_rule.conditions);
      END IF;

      IF NOT v_matched THEN
        CONTINUE;
      END IF;

      FOR v_action IN SELECT * FROM jsonb_array_elements(v_rule.actions) LOOP
        PERFORM apply_action(p_message_id, p_received_at, p_mailbox_id, v_action, v_rule.id, p_organize_only);
        SELECT * INTO v_msg FROM messages
        WHERE id = p_message_id AND received_at = p_received_at;
      END LOOP;

      PERFORM trace(v_msg.message_id, 'rule_applied', v_msg.from_addr, '',
        NULL, jsonb_build_object('rule_id', v_rule.id, 'rule_name', v_rule.name));

      IF v_rule.stop_processing THEN
        EXIT;
      END IF;

    EXCEPTION
      WHEN invalid_text_representation OR invalid_regular_expression THEN
        PERFORM trace(v_msg.message_id, 'rule_applied', v_msg.from_addr, '',
          NULL, jsonb_build_object('rule_id', v_rule.id, 'status', 'skipped_invalid_condition'));
        CONTINUE;
      WHEN OTHERS THEN
        PERFORM trace(v_msg.message_id, 'rule_applied', v_msg.from_addr, '',
          NULL, jsonb_build_object('rule_id', v_rule.id, 'status', 'skipped_error', 'error', 'rule evaluation failed'));
        CONTINUE;
    END;
  END LOOP;
END;
$$ LANGUAGE plpgsql;
