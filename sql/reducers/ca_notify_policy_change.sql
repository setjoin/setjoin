-- ca_notify_policy_change.sql — the single choke point that announces a
-- Conditional Access policy/exclude/break-glass change to the in-memory caches.
-- Every CA mutating reducer/handler PERFORMs this instead of pg_notify directly,
-- so both servers' policy-cache LISTEN consumers subscribe to exactly ONE fixed
-- channel ('conditional_access'). Inert when no listener is attached.
-- Errors: BZ079 (reserved; raised only on a malformed reason, defensive).
CREATE OR REPLACE FUNCTION ca_notify_policy_change(p_reason TEXT)
RETURNS VOID AS $$
BEGIN
  IF p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
    RAISE EXCEPTION 'ca_notify_policy_change requires a non-empty reason'
      USING ERRCODE = 'BZ079',
            HINT = 'pass a short change reason, e.g. ''policy_saved'' or ''exclude_changed''';
  END IF;
  PERFORM app_notify('conditional_access',
                     json_build_object('reason', p_reason, 'at', now())::text);
END;
$$ LANGUAGE plpgsql;
