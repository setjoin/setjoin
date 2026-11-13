-- offline_device_deny.sql
-- Admin transition → 'denied'. Legal only FROM 'pending' (denied was never
-- trusted; an approved/revoked device cannot be "denied"). BZ100 otherwise.
CREATE OR REPLACE FUNCTION offline_device_deny(
    p_actor_user_id BIGINT, p_device_id BIGINT
) RETURNS VOID AS $$
DECLARE v_cur TEXT; v_user BIGINT;
BEGIN
    SELECT offline_approval, user_id INTO v_cur, v_user
      FROM user_devices WHERE id = p_device_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'device % not found', p_device_id USING ERRCODE='BZ100',
          HINT=jsonb_build_object('type','not_found','id',p_device_id)::TEXT;
    END IF;
    IF v_cur <> 'pending' THEN
        RAISE EXCEPTION 'illegal transition % → denied', v_cur USING ERRCODE='BZ100',
          HINT=jsonb_build_object('type','bad_transition','from',v_cur,'to','denied')::TEXT;
    END IF;
    UPDATE user_devices SET offline_approval='denied',
        offline_approval_at=now(), offline_approval_by=p_actor_user_id
      WHERE id=p_device_id AND offline_approval=v_cur;   -- atomic: concurrent race or RLS filter → FOUND=false
    IF NOT FOUND THEN
        RAISE EXCEPTION 'transition race or RLS filter: deny for device %', p_device_id
          USING ERRCODE='BZ100',
            HINT=jsonb_build_object('type','stale_transition','id',p_device_id)::TEXT;
    END IF;
    PERFORM audit_write(p_actor_user_id,'offline_device_deny','user_device',p_device_id,
            NULL, jsonb_build_object('offline_approval','denied'), NULL, NULL, 'core');
    PERFORM app_notify('tag:'||(SELECT id FROM mailboxes WHERE user_id=v_user LIMIT 1),
                       '{"type":"capsChanged"}');
END;
$$ LANGUAGE plpgsql;
