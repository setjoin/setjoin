-- set_session_control.sql — §6.1 single write-validator over BOTH the actions
-- verb set AND the session_control object, so neither can be saved malformed.
-- BZ098 on any invalid shape; BZ081 on unknown policy_id.
-- Writes both columns + bumps updated_at; writes admin_audit_log (CA-0b) in the
-- same txn; PERFORMs ca_notify_policy_change per F2 choke-point contract.
CREATE OR REPLACE FUNCTION set_session_control(
  p_policy_id       BIGINT,
  p_actions         JSONB,
  p_session_control JSONB,
  p_actor           BIGINT,
  p_ip              INET
) RETURNS VOID AS $$
DECLARE
  v_action TEXT := ca_policy_effective_action(p_actions);
  v_key    TEXT;
  v_before JSONB;
  v_after  JSONB;
  v_known_actions TEXT[] := ARRAY['allow','block','step_up','notify','require_acr','limited_web',
                                  'require_strength','require_terms','require_risk_remediation'];
  v_known_sc_keys TEXT[] := ARRAY['sign_in_frequency','persistent_session',
                                  'idle_timeout_minutes','require_token_binding',
                                  'strict_location','cae'];
BEGIN
  -- Universal CA lock order: reachability advisory fence before any policy
  -- row lock. The later ca_lockout_guard call re-enters the same xact lock.
  PERFORM ca_reachability_fence();

  -- The complete document and its canonical/schema-v1 discriminators must be
  -- valid before extracting the runtime-equivalent effective action.
  IF NOT ca_validate_policy_document('{}'::jsonb, p_actions)
     OR NOT ca_grant_discriminators_valid(p_actions)
     OR v_action IS NULL
     OR NOT (v_action = ANY (v_known_actions)) THEN
    RAISE EXCEPTION 'unknown action verb %', v_action
      USING ERRCODE='BZ098', HINT=jsonb_build_object('type','bad_action','action',v_action)::TEXT;
  END IF;

  -- No unknown keys in session_control.
  FOR v_key IN SELECT jsonb_object_keys(p_session_control) LOOP
    IF NOT (v_key = ANY (v_known_sc_keys)) THEN
      RAISE EXCEPTION 'unknown session_control key %', v_key
        USING ERRCODE='BZ098', HINT=jsonb_build_object('type','bad_key','key',v_key)::TEXT;
    END IF;
  END LOOP;

  -- Enum validations.
  IF p_session_control ? 'persistent_session'
     AND (p_session_control->>'persistent_session') NOT IN ('never','always','user_choice') THEN
    RAISE EXCEPTION 'bad persistent_session %', p_session_control->>'persistent_session'
      USING ERRCODE='BZ098', HINT='{"type":"bad_enum","field":"persistent_session"}';
  END IF;
  IF p_session_control ? 'require_token_binding'
     AND (p_session_control->>'require_token_binding') NOT IN ('off','report_only','enforce') THEN
    RAISE EXCEPTION 'bad require_token_binding %', p_session_control->>'require_token_binding'
      USING ERRCODE='BZ098', HINT='{"type":"bad_enum","field":"require_token_binding"}';
  END IF;
  IF p_session_control ? 'cae'
     AND (p_session_control->>'cae') NOT IN ('enabled','disabled') THEN
    RAISE EXCEPTION 'bad cae %', p_session_control->>'cae'
      USING ERRCODE='BZ098', HINT='{"type":"bad_enum","field":"cae"}';
  END IF;
  IF p_session_control ? 'idle_timeout_minutes' THEN
    BEGIN
      IF (p_session_control->>'idle_timeout_minutes')::int NOT BETWEEN 1 AND 1440 THEN
        RAISE EXCEPTION 'idle_timeout_minutes out of range'
          USING ERRCODE='BZ098', HINT='{"type":"bad_range","field":"idle_timeout_minutes"}';
      END IF;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'idle_timeout_minutes must be an integer'
        USING ERRCODE='BZ098', HINT='{"type":"bad_type","field":"idle_timeout_minutes"}';
    END;
  END IF;

  -- Type guard: strict_location must be a JSON boolean (not a string "true"/"yes"/...).
  -- policy_session_view casts via (session_control->>'strict_location')::bool;
  -- a non-boolean stored value causes a runtime cast error on every read (fail-open on reads).
  IF p_session_control ? 'strict_location'
     AND jsonb_typeof(p_session_control->'strict_location') <> 'boolean' THEN
    RAISE EXCEPTION 'strict_location must be a JSON boolean'
      USING ERRCODE='BZ098', HINT='{"type":"bad_type","field":"strict_location"}';
  END IF;

  -- Shape guard: sign_in_frequency must be {value: <number>, unit: 'hours'|'days'}.
  -- The enforcement engine reads .unit to compute the expiry; a non-object or wrong
  -- unit silently skips frequency enforcement (fail-open on security control).
  IF p_session_control ? 'sign_in_frequency' THEN
    IF jsonb_typeof(p_session_control->'sign_in_frequency') <> 'object'
       OR NOT (p_session_control->'sign_in_frequency' ? 'value')
       OR NOT (p_session_control->'sign_in_frequency' ? 'unit')
       OR jsonb_typeof(p_session_control->'sign_in_frequency'->'value') <> 'number'
       OR (p_session_control->'sign_in_frequency'->>'unit') NOT IN ('hours','days')
    THEN
      RAISE EXCEPTION 'bad sign_in_frequency — expected {value:<int>,unit:"hours"|"days"}'
        USING ERRCODE='BZ098', HINT='{"type":"bad_shape","field":"sign_in_frequency"}';
    END IF;
  END IF;

  -- NOT-FOUND guard: bail before mutating; capture before_state for audit.
  -- ca_policy_upsert and ca_named_location_set both guard this way (BZ081).
  SELECT to_jsonb(c) INTO v_before
    FROM conditional_access_policies c WHERE id = p_policy_id
    FOR UPDATE;
  IF v_before IS NULL THEN
    RAISE EXCEPTION 'policy not found'
      USING ERRCODE='BZ081', HINT='no conditional_access_policies row with the given id';
  END IF;

  -- This reducer is also a standalone writer. Preserve the database lockout
  -- floor using the stored state/scope/exclusions plus proposed actions.
  PERFORM ca_lockout_guard(
    v_before->>'state',
    v_before->>'scope_type',
    p_actions,
    COALESCE(v_before->'exclude_users', '[]'::jsonb),
    COALESCE(v_before->'exclude_groups', '[]'::jsonb)
  );

  UPDATE conditional_access_policies
     SET actions = p_actions, session_control = p_session_control, updated_at = now()
   WHERE id = p_policy_id;

  SELECT to_jsonb(c) INTO v_after
    FROM conditional_access_policies c WHERE id = p_policy_id;

  -- CA-0b: every security-enforcement write must be audited (same pattern as
  -- ca_policy_upsert / ca_named_location_set — p_actor + p_ip from caller).
  PERFORM audit_write(p_actor, 'ca_session_control_update', 'conditional_access_policy', p_policy_id, v_before, v_after, p_ip, NULL, 'core');

  -- F2: single choke point so both servers' CA LISTEN consumers get one notification.
  PERFORM ca_notify_policy_change('session_control_update');
END;
$$ LANGUAGE plpgsql VOLATILE;
