-- Frozen Go's shared/device.Transition calls the reducer on the request pool
-- without RunUserScoped. Match that missing user GUC even when the Rust command
-- executor scopes its transaction: under setjoin_app the event INSERT is refused
-- and the transition rolls back, including for the admin's own device. Do not
-- repair that Go bug during the port (ARCH-029). Function-local SET restores the
-- authenticated caller's GUC on return; invoker rights never bypass RLS.
--
-- Owner-approved security fix 2026-11-05 (#435): a domain-scoped admin may only
-- transition devices of users inside its reach. The caller computes p_in_scope in the
-- mutating statement (admin_can_reach_perm over the device owner stored on the row,
-- evaluated before the function-local GUC reset); a device outside the reach answers
-- exactly like a missing one (BZ095 device_not_found), so there is no existence oracle.
DROP FUNCTION IF EXISTS rust_device_enroll_transition(bigint, bigint, text, text);
CREATE OR REPLACE FUNCTION rust_device_enroll_transition(
    p_actor_user_id bigint,
    p_device_id bigint,
    p_to_state text,
    p_reason text,
    p_in_scope boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET app.current_user_id = '' AS $$
BEGIN
    IF p_in_scope IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Device % not found', p_device_id
            USING ERRCODE = 'BZ095',
                  HINT = jsonb_build_object('type','device_not_found',
                                            'device_id', p_device_id)::TEXT;
    END IF;
    RETURN public.device_enroll_transition(p_actor_user_id, p_device_id, p_to_state, p_reason);
END;
$$;
