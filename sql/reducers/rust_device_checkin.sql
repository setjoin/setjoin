-- #341 / #345: device check-in effects after the device proof
-- (RequireDeviceHMAC -> DeviceResolver::verify_request, whose
-- device_nonce_claim commits first in its own statement). One transaction:
-- the effective policy (mdm_effective_policy, resolved BEFORE any write),
-- the reported events in request order through the worker-owned
-- mdm_checkin_event_append seam (a NULL return — the device row did not
-- resolve — aborts the whole command), then an R3-scoped heartbeat UPDATE
-- (`devices.last_seen = now() WHERE id = p_device_id`).
--
-- SECURITY DEFINER owned by setjoin_worker (#345): device check-in runs on the
-- request pool (`setjoin_app`) without a user GUC because authentication is by
-- per-device HMAC proof rather than user session. Under `devices_self`
-- (FORCE RLS), an invoker-rights UPDATE silently matched zero rows and left
-- `devices.last_seen` stale forever. Worker-owned SECURITY DEFINER (matching
-- `rust_device_secret_reseal` and V254's `mdm_effective_policy` /
-- `mdm_checkin_event_append`) updates `last_seen` for ONLY the proven
-- `p_device_id`, while a failed proof never invokes this reducer.
--
-- More than 100 events is refused (owner-approved security fix, #341: the HTTP
-- layer refuses first, before the proof).
--
-- R1/R2/R3: every read and write is keyed on p_device_id, which the caller
-- passes only from a VerifiedDevice (HMAC + body digest + freshness + committed
-- nonce). No audit/notify/state bump.
CREATE OR REPLACE FUNCTION rust_device_checkin(p_device_id bigint, p_events jsonb)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
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

    -- #345: R3-scoped heartbeat for the proven device only.
    UPDATE public.devices
       SET last_seen = now()
     WHERE id = p_device_id;

    RETURN v_policy;
END;
$$;
SELECT apply_worker_ownership('rust_device_checkin(bigint,jsonb)'::regprocedure);
