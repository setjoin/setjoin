-- ca_signin_log_append.sql (CA-0b): single-statement INSERT of one per-evaluation
-- telemetry row from a JSON payload built by the Go SignInRecorder. Best-effort —
-- the caller ignores any error so a failed insert NEVER fails the sign-in (Spec L6).
-- No state bump / no notify: telemetry, not a domain mutation.
-- ponytail: no SECURITY DEFINER needed — ca_signin_log_app_insert RLS policy allows
--   setjoin_app to INSERT; upgrade if per-row restriction is needed in CA-2.
CREATE OR REPLACE FUNCTION ca_signin_log_append(p_row jsonb) RETURNS void AS $$
BEGIN
  INSERT INTO ca_signin_log (
    user_id, source_ip, protocol, client_type, device_fp, country,
    matched_policy_id, decision, would_decision, report_only, correlation_id, evaluated)
  VALUES (
    (p_row->>'user_id')::bigint,
    (p_row->>'source_ip')::inet,
    p_row->>'protocol',
    p_row->>'client_type',
    p_row->>'device_fp',
    p_row->>'country',
    (p_row->>'matched_policy_id')::bigint,
    p_row->>'decision',                              -- NOT NULL in schema; no COALESCE — let the constraint fire on bad payload
    p_row->>'would_decision',
    coalesce((p_row->>'report_only')::boolean, false),
    p_row->>'correlation_id',
    coalesce(p_row->'evaluated', '[]'::jsonb));
END;
$$ LANGUAGE plpgsql;
