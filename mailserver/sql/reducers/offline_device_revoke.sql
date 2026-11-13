-- offline_device_revoke.sql
-- Admin transition approved → 'revoked'. Sets the device's wipe intent on
-- user_devices (native devices have no mdm_device_state row — that table is
-- ios/android-only; desktop + the offline path use user_devices) and pushes an
-- offline.wipe control payload. The #2b client handler turns that push into a
-- window.setjoinNative.wipe (drop the native SQLCipher DB + destroy the
-- guard-core key) — NOT a web IndexedDB clear (offline is native-only post-pivot).
-- BZ100 on illegal transition. The DURABLE deny is the revoked state itself
-- (seed withheld next session, F4); the push is the fast path. deps: app_notify
CREATE OR REPLACE FUNCTION offline_device_revoke(
    p_actor_user_id BIGINT, p_device_id BIGINT
) RETURNS VOID AS $$
DECLARE v_cur TEXT; v_user BIGINT; v_mb BIGINT; v_dev BIGINT;
BEGIN
    SELECT offline_approval, user_id, device_id INTO v_cur, v_user, v_dev
      FROM user_devices WHERE id = p_device_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'device % not found', p_device_id USING ERRCODE='BZ100',
          HINT=jsonb_build_object('type','not_found','id',p_device_id)::TEXT;
    END IF;
    IF v_cur <> 'approved' THEN
        RAISE EXCEPTION 'illegal transition % → revoked', v_cur USING ERRCODE='BZ100',
          HINT=jsonb_build_object('type','bad_transition','from',v_cur,'to','revoked')::TEXT;
    END IF;
    UPDATE user_devices SET offline_approval='revoked',
        offline_approval_at=now(), offline_approval_by=p_actor_user_id,
        wipe_requested=true, wipe_type='selective', wipe_at=now()
      WHERE id=p_device_id AND offline_approval=v_cur;   -- atomic: concurrent race or RLS filter → FOUND=false
    IF NOT FOUND THEN
        RAISE EXCEPTION 'transition race or RLS filter: revoke for device %', p_device_id
          USING ERRCODE='BZ100',
            HINT=jsonb_build_object('type','stale_transition','id',p_device_id)::TEXT;
    END IF;
    PERFORM audit_write(p_actor_user_id,'offline_device_revoke','user_device',p_device_id,
            NULL, jsonb_build_object('offline_approval','revoked','wipe_requested',true), NULL, NULL, 'core');
    SELECT id INTO v_mb FROM mailboxes WHERE user_id=v_user AND is_primary=TRUE LIMIT 1;
    -- The push fans out on the user's shared tag:{mailbox} channel to EVERY
    -- connected session, so 'deviceId' is the TARGETING key. It MUST be the
    -- canonical devices.id (user_devices.device_id FK) — that is the ONLY id the
    -- client knows about itself: it lives in the native secure store under
    -- 'device_id' and is what deviceProof/X-Device-ID present (verified against
    -- devices.hmac_secret). Do NOT push user_devices.id here — the client can't
    -- read it, so a targeted wipe would match nothing. offline/wipe.ts fires the
    -- wipe only on the device whose own devices.id matches; a sibling no-ops.
    -- Register always sets device_id for an approved device, so v_dev is non-null
    -- here; guard anyway so a data-integrity gap degrades to "no fast push" (the
    -- durable revoked-state deny still holds) rather than a NULL deviceId, which
    -- the client would read as an all-my-devices wipe and over-wipe every session.
    IF v_dev IS NOT NULL THEN
        PERFORM app_notify('tag:'||v_mb,
            json_build_object('type','offline.wipe','deviceId',v_dev)::TEXT);
    END IF;
END;
$$ LANGUAGE plpgsql;
