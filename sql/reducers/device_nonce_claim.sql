-- device_nonce_claim.sql — atomic, deployment-wide single-use claim of a
-- device HMAC proof nonce (med-shard2-006, D-AUTHSERVER-INTERNAL-DEVICE-001/002).
--
-- The device auth seam (shared/device.VerifyDeviceRequest) calls this AFTER the
-- HMAC verifies and BEFORE the request is accepted. PRIMARY KEY (device_id,
-- nonce) on device_auth_nonces makes the claim atomic across every verifier
-- replica sharing the database: two concurrent claims of one captured proof
-- let exactly one INSERT win; the loser raises BZ095 (HINT type nonce_replay)
-- and the request is rejected — a captured proof cannot be double-spent even
-- concurrently.
--
-- Lifecycle: rows expire (p_window_seconds from claim time). A proof can only
-- be accepted while its timestamp is fresh, so an expired nonce can never be
-- replayed; every claim first purges THIS device's expired rows, which bounds
-- the table without a cron dependency.
--
-- Errors (all ERRCODE 'BZ095', the device band; the HINT type disambiguates):
--   invalidArguments — p_nonce is NULL/empty/oversized or p_window_seconds is
--                      NULL/≤ 0
--   device_not_found — unknown p_device_id
--   nonce_replay     — the (device_id, nonce) pair is already claimed and
--                      unexpired (the replay itself)
--
CREATE OR REPLACE FUNCTION device_nonce_claim(
    p_device_id      BIGINT,
    p_nonce          TEXT,
    p_window_seconds INTEGER
) RETURNS VOID AS $$
DECLARE
    v_expires TIMESTAMPTZ;
BEGIN
    IF p_nonce IS NULL OR p_nonce = '' OR length(p_nonce) > 128 THEN
        RAISE EXCEPTION 'device_nonce_claim: invalid nonce'
            USING ERRCODE = 'BZ095',
                  HINT = '{"type":"invalidArguments","field":"nonce"}'::TEXT;
    END IF;
    IF p_window_seconds IS NULL OR p_window_seconds <= 0 THEN
        RAISE EXCEPTION 'device_nonce_claim: invalid claim window'
            USING ERRCODE = 'BZ095',
                  HINT = '{"type":"invalidArguments","field":"window_seconds"}'::TEXT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM devices WHERE id = p_device_id) THEN
        RAISE EXCEPTION 'Device % not found', p_device_id
            USING ERRCODE = 'BZ095',
                  HINT = jsonb_build_object('type','device_not_found',
                                            'device_id', p_device_id)::TEXT;
    END IF;

    v_expires := now() + make_interval(secs => p_window_seconds);

    -- Bound the table: drop this device's expired claims. An expired nonce can
    -- never be replayed (its proof timestamp is stale long before this), so a
    -- purged nonce may legitimately be reclaimed by a NEW request that happens
    -- to draw the same random value.
    DELETE FROM device_auth_nonces
     WHERE device_id = p_device_id AND expires_at < now();

    -- THE atomic claim: the PK unique index arbitrates across replicas.
    INSERT INTO device_auth_nonces (device_id, nonce, expires_at)
    VALUES (p_device_id, p_nonce, v_expires)
    ON CONFLICT (device_id, nonce) DO NOTHING;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'device nonce already claimed (replay detected)'
            USING ERRCODE = 'BZ095',
                  HINT = jsonb_build_object('type','nonce_replay',
                                            'device_id', p_device_id)::TEXT;
    END IF;
END;
$$ LANGUAGE plpgsql;
