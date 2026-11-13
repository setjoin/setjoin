-- offline_device_wipe_ack.sql
-- Offline mail #2b (NATIVE-OFFLINE PIVOT). The native client, on its next online
-- session after receiving an offline.wipe push, confirms it dropped its offline-core
-- 'mail' store + destroyed its key (held via guard-core). Sets user_devices.wipe_acked_at
-- (best-effort; the DURABLE deny is #2a seed-withholding — this is only telemetry
-- that the fast push landed).
--
-- p_device_id is the canonical devices.id (user_devices.device_id FK), NOT
-- user_devices.id: the client echoes back the same id the offline.wipe push
-- targeted it by (offline_device_revoke pushes devices.id — the only id the
-- client can read about itself), so the ack keys user_devices on device_id.
--
-- R3: ownership (user_id = account_scope(p_mailbox_id).user_id) is in the SAME
-- UPDATE WHERE as the device_id match — no TOCTOU. A device that is not the
-- caller's, or has no pending wipe, matches zero rows → BZ101 (malformed transition).
--
CREATE OR REPLACE FUNCTION offline_device_wipe_ack(
    p_mailbox_id BIGINT,
    p_device_id  BIGINT
) RETURNS VOID AS $$
DECLARE
    v_user_id BIGINT;
    v_rows    INT;
BEGIN
    SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account mailbox % not found', p_mailbox_id
            USING ERRCODE = 'BZ101',
                  HINT = jsonb_build_object('type','not_found','account_id',p_mailbox_id)::TEXT;
    END IF;

    UPDATE user_devices
       SET wipe_acked_at = now()
     WHERE device_id  = p_device_id     -- canonical devices.id the client echoes back
       AND user_id    = v_user_id       -- R3: ownership in the same mutation, no TOCTOU
       AND wipe_requested = TRUE;       -- transition guard: only a pending wipe is ackable
    GET DIAGNOSTICS v_rows = ROW_COUNT;

    IF v_rows = 0 THEN
        RAISE EXCEPTION 'No pending wipe to acknowledge for device %', p_device_id
            USING ERRCODE = 'BZ101',
                  HINT = jsonb_build_object(
                             'type','invalid_transition',
                             'device_id', p_device_id,
                             'reason','device not owned by caller or has no pending wipe'
                          )::TEXT;
    END IF;

    PERFORM audit_write(v_user_id, 'offline_device_wipe_ack', 'user_device', p_device_id,
            NULL, jsonb_build_object('wipe_acked_at', now()), NULL, NULL, 'core');

    -- Refresh caller's other sessions so they see the confirmed-wiped device state.
    PERFORM app_notify('tag:'||p_mailbox_id, '{"type":"capsChanged"}');
END;
$$ LANGUAGE plpgsql;
