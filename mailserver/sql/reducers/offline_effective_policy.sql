-- Public device-aware offline capability. The legacy five-key JSON shape is
-- byte-for-byte key compatible while either rollout gate is OFF; syncQoS is
-- projected only when both feature.offline_mail and the new program flag are ON.
CREATE OR REPLACE FUNCTION offline_effective_policy(
    p_mailbox_id BIGINT,
    p_device_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_projection JSONB;
    v_offline_enabled BOOLEAN;
    v_connectivity_enabled BOOLEAN;
BEGIN
    v_projection := offline_effective_policy_snapshot(p_mailbox_id, p_device_id);
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.offline_mail'), false),
           COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.connectivity_aware_sync'), false)
      INTO v_offline_enabled, v_connectivity_enabled;

    IF NOT (v_offline_enabled AND v_connectivity_enabled) THEN
        RETURN v_projection - 'syncQoS';
    END IF;
    RETURN v_projection;
END;
$$ LANGUAGE plpgsql STABLE;
