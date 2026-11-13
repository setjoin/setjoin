-- Frozen Go CallScoped sets only the mailbox GUC for offline_device_register.
-- Preserve that scope (including its user_devices RLS failure on setjoin_app).
-- PostgreSQL restores the caller's user GUC when this invoker function exits.
CREATE OR REPLACE FUNCTION jmap_session_device_register(
    p_mailbox_id bigint, p_fingerprint text, p_platform text
) RETURNS bigint
LANGUAGE sql
SET app.current_user_id = ''
AS $$
    SELECT offline_device_register(p_mailbox_id, p_fingerprint, p_platform);
$$;
