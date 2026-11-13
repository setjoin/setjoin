-- offline_device_register.sql
-- §6.0 NATIVE device registration upsert (offline is native-only post-pivot;
-- p_platform is desktop/ios/android and p_device_fp is the guard-core native
-- device identity — a plain browser never calls this). Creates the user_devices
-- row the approval state machine keys on. R2: user_id from the authenticated
-- mailbox scope, never req.*. Joins the canonical devices row (CA-F §2 F3); if no
-- devices row exists for this fingerprint, resolve-or-create one here.
-- New rows land offline_approval='pending' (deny-by-default).
CREATE OR REPLACE FUNCTION offline_device_register(
    p_mailbox_id BIGINT,
    p_device_fp  TEXT,
    p_platform   TEXT
) RETURNS BIGINT AS $$
DECLARE
    v_user_id   BIGINT;
    v_device_id BIGINT;
    v_fp_hash   BYTEA := sha256(p_device_fp::bytea);
    v_id        BIGINT;
    v_inserted  BOOLEAN;
BEGIN
    SELECT s.user_id INTO v_user_id FROM account_scope(p_mailbox_id) s;
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Account mailbox % not found', p_mailbox_id
            USING ERRCODE = 'BZ001',
                  HINT = jsonb_build_object('type','not_found','account_id',p_mailbox_id)::TEXT;
    END IF;

    -- Resolve-or-create the canonical devices row for this fingerprint (CA-F join).
    SELECT id INTO v_device_id
      FROM devices WHERE user_id = v_user_id AND fingerprint = p_device_fp;
    IF v_device_id IS NULL THEN
        INSERT INTO devices (user_id, fingerprint, hmac_secret, platform)
        VALUES (v_user_id, p_device_fp, encode(gen_random_bytes(32),'hex'), p_platform)
        RETURNING id INTO v_device_id;
    END IF;

    INSERT INTO user_devices (user_id, device_id, device_name, platform,
                              fingerprint_hash, last_seen_at, offline_approval)
    VALUES (v_user_id, v_device_id, 'native/'||p_platform, p_platform,
            v_fp_hash, now(), 'pending')
    ON CONFLICT (user_id, fingerprint_hash) WHERE fingerprint_hash IS NOT NULL
    DO UPDATE SET last_seen_at = now(), device_id = EXCLUDED.device_id
    RETURNING id, (xmax = 0) AS v_inserted INTO v_id, v_inserted;

    -- WP3 audit coverage: a NEW device registration (deny-by-default pending
    -- approval) is a device-lifecycle transition; the re-seen upsert arm is a
    -- heartbeat, not a lifecycle event, and writes no audit row.
    IF v_inserted THEN
        PERFORM audit_write(
            v_user_id, 'offline_device_register', 'device', v_device_id,
            NULL,
            jsonb_build_object('platform', p_platform,
                               'offline_approval', 'pending',
                               'user_devices_id', v_id),
            NULL, NULL, 'core');
    END IF;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql;
