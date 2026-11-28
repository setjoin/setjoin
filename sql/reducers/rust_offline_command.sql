-- Frozen Go calls these reducers on its request pool without RunUserScoped.
-- Preserve that scope (including RLS-filtered admin device transitions), restore
-- the caller's GUC on return, and keep invoker rights. Actor/mailbox are sealed
-- auth parameters; the JSON payload contains validated operation fields only.
--
-- Owner-approved security fix 2026-11-05 (#440): the device transitions (approve, deny,
-- revoke, wipe) act only inside the admin's reach. The caller computes p_reach in the
-- mutating statement from the owner stored on the user_devices row
-- (admin_can_reach_perm over mam.write, evaluated before the function-local GUC reset);
-- a device outside the reach answers exactly like a missing one (BZ100 not_found), so a
-- domain-scoped admin cannot wipe, approve or deny another domain's devices and cannot
-- tell whether they exist. Other actions ignore p_reach.
DROP FUNCTION IF EXISTS rust_offline_command(bigint, bigint, text, jsonb);
CREATE OR REPLACE FUNCTION rust_offline_command(
    p_actor_user_id bigint, p_mailbox_id bigint, p_action text, p_payload jsonb,
    p_reach boolean
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET app.current_user_id = '' AS $$
DECLARE v_id bigint;
BEGIN
    IF p_action IN ('approve','deny','revoke','wipe') AND p_reach IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'device % not found', (p_payload->>'id')::bigint USING ERRCODE='BZ100',
          HINT=jsonb_build_object('type','not_found','id',(p_payload->>'id')::bigint)::TEXT;
    END IF;
    CASE p_action
    WHEN 'create', 'update' THEN
        IF COALESCE((p_payload->>'connectivity_fields_provided')::boolean,false) THEN
            v_id := public.offline_policy_set_v2(p_actor_user_id,
                (p_payload->>'id')::bigint,p_payload->>'name',p_payload->>'scope_type',
                (p_payload->>'scope_id')::bigint,(p_payload->>'enabled')::boolean,
                (p_payload->>'max_offline_days')::int,(p_payload->>'require_approval')::boolean,
                p_payload->>'wipe_on_logout',(p_payload->>'priority')::int,
                (p_payload->>'background_sync_allowed')::boolean,p_payload->>'automatic_network_max',
                p_payload->>'attachment_prefetch_max',(p_payload->>'opportunistic_requires_charging')::boolean,
                p_payload->>'connectivity_sync_mode');
        ELSE
            v_id := public.offline_policy_set(p_actor_user_id,
                (p_payload->>'id')::bigint,p_payload->>'name',p_payload->>'scope_type',
                (p_payload->>'scope_id')::bigint,(p_payload->>'enabled')::boolean,
                (p_payload->>'max_offline_days')::int,(p_payload->>'require_approval')::boolean,
                p_payload->>'wipe_on_logout',(p_payload->>'priority')::int);
        END IF;
        RETURN v_id::text;
    WHEN 'ack' THEN
        PERFORM public.offline_device_wipe_ack(p_mailbox_id,(p_payload->>'device_id')::bigint);
        RETURN '';
    WHEN 'approve' THEN
        PERFORM public.offline_device_approve(p_actor_user_id,(p_payload->>'id')::bigint);
        RETURN '';
    WHEN 'deny' THEN
        PERFORM public.offline_device_deny(p_actor_user_id,(p_payload->>'id')::bigint);
        RETURN '';
    WHEN 'revoke', 'wipe' THEN
        PERFORM public.offline_device_revoke(p_actor_user_id,(p_payload->>'id')::bigint);
        RETURN '';
    WHEN 'toggle' THEN
        INSERT INTO public.feature_toggles(key,enabled) VALUES('feature.offline_mail',(p_payload->>'enabled')::boolean)
        ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled;
        PERFORM public.audit_write(p_actor_user_id,'offline_toggle','feature_toggle',NULL,NULL,
            jsonb_build_object('enabled',(p_payload->>'enabled')::boolean),NULL,'','core');
        -- Go logs a notify error then Commit fails on the aborted transaction.
        -- Do not catch it here: data and audit must roll back together.
        PERFORM public.app_notify('caps:offline','{"type":"capsChanged"}');
        RETURN '';
    WHEN 'delete' THEN
        PERFORM public.offline_policy_delete((p_payload->>'id')::bigint,p_actor_user_id);
        RETURN '';
    ELSE
        RAISE EXCEPTION 'unknown offline command' USING ERRCODE='22023';
    END CASE;
END;
$$;
