-- Invoker adapter for JMAP native discovery device registration (#260).
-- Preserves the authenticated caller's app.current_user_id and
-- app.current_mailbox_id GUCs so offline_device_register passes FORCE RLS on
-- devices and user_devices under setjoin_app.
CREATE OR REPLACE FUNCTION jmap_session_device_register(
    p_mailbox_id bigint, p_fingerprint text, p_platform text
) RETURNS bigint
LANGUAGE sql
AS $$
    SELECT offline_device_register(p_mailbox_id, p_fingerprint, p_platform);
$$;
