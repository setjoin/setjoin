-- #341: frozen authserver/internal/device HandleCheckin effects after the
-- device proof (RequireDeviceHMAC -> shared/device.VerifyDeviceRequest, whose
-- device_nonce_claim commits first in its own statement). One transaction:
-- the effective policy (mdm_effective_policy, resolved BEFORE any write as in
-- Go), the reported events in request order through the worker-owned
-- mdm_checkin_event_append seam (a NULL return - the device row did not
-- resolve - aborts the whole command), then Go's UpdateLastSeen statement.
--
-- SECURITY INVOKER on purpose: frozen Go runs `UPDATE devices SET last_seen`
-- on the request pool with no user GUC and discards its error; under
-- devices_self (FORCE RLS) as setjoin_app it matches no row. The heartbeat is
-- mirrored under the caller's own credential (functional parity; follow-up
-- #345), never widened through a definer. Go committed each event separately;
-- the reducer invariant makes the check-in atomic (fault-only difference).
-- More than 100 events is refused (owner-approved security fix, #341: Go had
-- no bound; the HTTP layer refuses first, before the proof).
--
-- R1/R2/R3: every read and write is keyed on p_device_id, which the caller
-- passes only from a VerifiedDevice (HMAC + body digest + freshness + committed
-- nonce). No audit/notify/state bump: Go's device check-in writes none.
CREATE OR REPLACE FUNCTION rust_device_checkin(p_device_id bigint, p_events jsonb)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public AS $$
DECLARE
    v_policy jsonb;
    v_event  jsonb;
BEGIN
    IF p_device_id IS NULL OR p_device_id <= 0 THEN
        RAISE EXCEPTION 'rust_device_checkin: invalid device id'
            USING ERRCODE = 'BZ095',
                  HINT = '{"type":"invalidArguments","field":"device_id"}'::TEXT;
    END IF;
    IF p_events IS NULL THEN
        p_events := '[]'::jsonb;
    END IF;
    IF jsonb_typeof(p_events) <> 'array' THEN
        RAISE EXCEPTION 'rust_device_checkin: events must be an array'
            USING ERRCODE = 'BZ095',
                  HINT = '{"type":"invalidArguments","field":"events"}'::TEXT;
    END IF;
    IF jsonb_array_length(p_events) > 100 THEN
        RAISE EXCEPTION 'rust_device_checkin: too many events'
            USING ERRCODE = 'BZ095',
                  HINT = '{"type":"invalidArguments","field":"events"}'::TEXT;
    END IF;

    v_policy := mdm_effective_policy(p_device_id);

    FOR v_event IN
        SELECT e.value FROM jsonb_array_elements(p_events) WITH ORDINALITY AS e(value, n)
         ORDER BY e.n
    LOOP
        IF mdm_checkin_event_append(
               p_device_id,
               COALESCE(v_event->>'type', ''),
               jsonb_build_object('data', COALESCE(v_event->>'data', ''))) IS NULL THEN
            RAISE EXCEPTION 'Device % not found', p_device_id
                USING ERRCODE = 'BZ095',
                      HINT = jsonb_build_object('type','device_not_found',
                                                'device_id', p_device_id)::TEXT;
        END IF;
    END LOOP;

    -- Go: `_, _ = pool.Exec(UPDATE devices SET last_seen = now() WHERE id = $1)`.
    BEGIN
        UPDATE devices SET last_seen = now() WHERE id = p_device_id;
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;

    RETURN v_policy;
END;
$$;
