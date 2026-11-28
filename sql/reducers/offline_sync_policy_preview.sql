-- Authorized admin preview using the same resolver as the JMAP session. The
-- live persisted permission+scope decision runs before any explicit target or
-- device lookup; unauthorized, missing, and out-of-scope targets are opaque.
CREATE OR REPLACE FUNCTION offline_sync_policy_preview(
    p_actor_user_id BIGINT,
    p_target_user_id BIGINT,
    p_device_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_mailbox_id BIGINT;
    v_projection JSONB;
BEGIN
    IF NOT admin_can_manage_with_permission(
        p_actor_user_id, p_target_user_id, 'mail.offline_policy') THEN
        RAISE EXCEPTION 'offline policy preview unavailable'
          USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;

    SELECT m.id INTO v_mailbox_id
      FROM mailboxes m
     WHERE m.user_id=p_target_user_id
     ORDER BY m.is_primary DESC, m.id ASC
     LIMIT 1;

    IF v_mailbox_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM user_devices d
         WHERE d.id=p_device_id AND d.user_id=p_target_user_id) THEN
        RAISE EXCEPTION 'offline policy preview unavailable'
          USING ERRCODE='BZ002', HINT='{"type":"forbidden"}';
    END IF;

    v_projection := offline_effective_policy_snapshot(v_mailbox_id, p_device_id);
    RETURN jsonb_build_object(
        'mailboxId', v_mailbox_id::TEXT,
        'deviceId', p_device_id::TEXT,
        'projection', v_projection);
END;
$$ LANGUAGE plpgsql STABLE;
