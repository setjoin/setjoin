-- Compatibility entry point retained for pre-V209 clients. It changes only
-- opt-in/window and preserves any newer QoS preferences already stored for the
-- authenticated user's device.
CREATE OR REPLACE FUNCTION offline_device_opt_in(
    p_mailbox_id BIGINT,
    p_device_id BIGINT,
    p_opt_in BOOLEAN,
    p_window_days INT
) RETURNS VOID AS $$
DECLARE
    v_user_id BIGINT;
    v_background_sync_enabled BOOLEAN := true;
    v_automatic_network_pref TEXT := 'unmetered';
    v_attachment_prefetch_pref TEXT := 'never';
BEGIN
    SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
    IF v_user_id IS NULL THEN
        RETURN; -- Preserve the pre-V209 unknown-mailbox fail-safe contract.
    END IF;
    SELECT background_sync_enabled, automatic_network_pref,
           attachment_prefetch_pref
      INTO v_background_sync_enabled, v_automatic_network_pref,
           v_attachment_prefetch_pref
     FROM user_devices
     WHERE id=p_device_id AND user_id=v_user_id;

    -- A known mailbox with a missing/foreign device still fails loudly through
    -- the canonical reducer, matching the old R3 ownership behavior.

    PERFORM offline_device_set_preferences(
        p_mailbox_id,p_device_id,p_opt_in,p_window_days,
        COALESCE(v_background_sync_enabled,true),
        COALESCE(v_automatic_network_pref,'unmetered'),
        COALESCE(v_attachment_prefetch_pref,'never'));
END;
$$ LANGUAGE plpgsql VOLATILE;
