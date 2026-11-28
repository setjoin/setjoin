-- offline_policy_delete.sql
-- Hard-delete an offline_policies row. Writes an audit row and broadcasts a
-- capsChanged so live sessions re-pull caps. No jmap_*_state bump (org config).
-- BZ099 (not found or global-seed guard) → handler maps to 404/409.

CREATE OR REPLACE FUNCTION offline_policy_delete(
    p_id              BIGINT,
    p_actor_user_id   BIGINT
) RETURNS VOID AS $$
DECLARE
    v_before JSONB;
BEGIN
    SELECT to_jsonb(p) INTO v_before FROM offline_policies p WHERE id = p_id;
    IF v_before IS NULL THEN
        RAISE EXCEPTION 'offline policy % not found', p_id
            USING ERRCODE = 'BZ099',
                  HINT = jsonb_build_object('type', 'not_found', 'id', p_id)::TEXT;
    END IF;

    -- ponytail: block deletion of the global seed row so the resolver always
    -- has a fallback. Upgrade path: allow if a second global row exists.
    IF (v_before->>'scope_type') = 'global' AND
       (SELECT count(*) FROM offline_policies WHERE scope_type = 'global') = 1 THEN
        RAISE EXCEPTION 'cannot delete the last global offline policy'
            USING ERRCODE = 'BZ099',
                  HINT = jsonb_build_object('type', 'last_global')::TEXT;
    END IF;

    DELETE FROM offline_policies WHERE id = p_id;

    PERFORM audit_write(p_actor_user_id, 'offline_policy_delete', 'offline_policy', p_id, v_before, NULL, NULL, NULL, 'core');

    PERFORM app_notify('caps:offline', '{"type":"capsChanged"}');
END;
$$ LANGUAGE plpgsql VOLATILE;
