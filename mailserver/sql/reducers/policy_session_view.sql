-- policy_session_view.sql — §6.1 single read-model: one projection the admin UI
-- and the what-if/preview tool both consume, so the effective control is never
-- computed two different ways. STABLE; no notify; no state bump.
CREATE OR REPLACE FUNCTION policy_session_view(p_policy_id BIGINT)
RETURNS JSONB AS $$
  SELECT jsonb_build_object(
    'policy_id', id,
    'action',    ca_policy_effective_action(actions),
    'limited_web', (ca_policy_effective_action(actions) = 'limited_web'),
    'sign_in_frequency',     session_control->'sign_in_frequency',
    'persistent_session',    COALESCE(session_control->>'persistent_session','always'),
    'idle_timeout_minutes',  session_control->'idle_timeout_minutes',
    'require_token_binding',  COALESCE(session_control->>'require_token_binding','off'),
    'strict_location',       COALESCE((session_control->>'strict_location')::bool, FALSE),
    'cae',                   COALESCE(session_control->>'cae','enabled')
  )
  FROM conditional_access_policies WHERE id = p_policy_id;
$$ LANGUAGE sql STABLE;
