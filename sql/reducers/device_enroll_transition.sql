-- device_enroll_transition.sql — CA-2 device enrollment lifecycle reducer.
-- Validates and applies a transition on devices.enroll_state, writes a
-- device_enroll_events audit row, stamps approved/revoked metadata, and (on
-- revoke) PERFORMs ca_notify_policy_change so both servers' policy/credential
-- caches invalidate (live-proof revocation, CA-F §F2).
--
-- Legal transitions: unenrolled->enrolled, enrolled->approved,
--                    enrolled->revoked, approved->revoked.
-- Errors: BZ095 (unknown device OR illegal transition).
--
-- R1/R3: SELECT and UPDATE are both keyed on p_device_id only; the actor is
-- recorded in the audit row and metadata columns, not used as a WHERE filter
-- on devices (an admin may act on any device — ownership is on user_id, not
-- actor_user_id). If per-user scoping is needed later, add p_account_id as
-- an additional WHERE predicate.
--
CREATE OR REPLACE FUNCTION device_enroll_transition(
    p_actor_user_id BIGINT,
    p_device_id     BIGINT,
    p_to_state      TEXT,
    p_reason        TEXT
) RETURNS JSONB AS $$
DECLARE
    v_from  TEXT;
    v_legal BOOLEAN;
BEGIN
    SELECT enroll_state INTO v_from FROM devices WHERE id = p_device_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Device % not found', p_device_id
            USING ERRCODE = 'BZ095',
                  HINT = jsonb_build_object('type','device_not_found',
                                            'device_id', p_device_id)::TEXT;
    END IF;

    v_legal := (v_from = 'unenrolled' AND p_to_state = 'enrolled')
            OR (v_from = 'enrolled'   AND p_to_state = 'approved')
            OR (v_from IN ('enrolled','approved') AND p_to_state = 'revoked');

    IF NOT v_legal THEN
        RAISE EXCEPTION 'Illegal device enrollment transition % -> %', v_from, p_to_state
            USING ERRCODE = 'BZ095',
                  HINT = jsonb_build_object('type','illegal_transition',
                                            'from', v_from, 'to', p_to_state)::TEXT;
    END IF;

    -- On revoke the stored hmac_secret is ROTATED to a fresh random value
    -- (med-shard2-006): a revoked device must lose its trust-channel
    -- credential outright, so any copy of the old secret (exfiltrated before
    -- revocation, restored from a stale backup, or left on wiped storage)
    -- can never re-authenticate even if a later code path were to consult it.
    -- Revocation is terminal (no revoked->X transition), so the original
    -- secret is never needed again.
    UPDATE devices
       SET enroll_state = p_to_state,
           enrolled_by  = CASE WHEN p_to_state = 'enrolled'  THEN p_actor_user_id ELSE enrolled_by END,
           approved_by  = CASE WHEN p_to_state = 'approved'  THEN p_actor_user_id ELSE approved_by END,
           approved_at  = CASE WHEN p_to_state = 'approved'  THEN now()           ELSE approved_at END,
           revoked_at   = CASE WHEN p_to_state = 'revoked'   THEN now()           ELSE revoked_at  END,
           hmac_secret  = CASE WHEN p_to_state = 'revoked'
                               THEN encode(gen_random_bytes(32), 'hex') ELSE hmac_secret END,
           updated_at   = now()
     WHERE id = p_device_id;

    INSERT INTO device_enroll_events (device_id, actor_user_id, from_state, to_state, reason)
    VALUES (p_device_id, p_actor_user_id, v_from, p_to_state, p_reason);

    -- WP3 audit coverage: enrollment state transitions are core device-lifecycle
    -- authority — durable admin_audit_log evidence alongside the existing
    -- device_enroll_events trail (which this does not replace).
    PERFORM audit_write(
        p_actor_user_id, 'device_enroll_transition', 'device', p_device_id,
        jsonb_build_object('enroll_state', v_from),
        jsonb_build_object('enroll_state', p_to_state, 'reason', p_reason),
        NULL, p_reason, 'core');

    -- ponytail: only revoke fires NOTIFY — enroll/approve are admin-local operations
    -- that don't affect in-flight policy decisions; revoke must propagate immediately
    -- (fail-closed: an un-notified revoke leaves the engine with a stale approved device).
    IF p_to_state = 'revoked' THEN
        PERFORM ca_notify_policy_change('device_revoked');
    END IF;

    RETURN jsonb_build_object('device_id',  p_device_id,
                              'from_state', v_from,
                              'to_state',   p_to_state);
END;
$$ LANGUAGE plpgsql;
