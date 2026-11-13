-- ca_named_location_restore.sql — CA-1 D1 fix: atomically restore a soft-deleted named_location.
--
-- Single UPDATE ... WHERE deleted_at IS NOT NULL (R3 — no separate SELECT, no TOCTOU).
-- Raises BZ081 if 0 rows affected (not found or not deleted).
-- Catches 23505 unique_violation (partial index named_locations_name_unique_idx) and
-- re-raises as BZ093 so callers get 409 instead of an opaque 500.
-- Writes admin_audit_log in-txn (same transaction as the UPDATE — audit never orphaned).
-- PERFORMs ca_notify_policy_change (F2 choke point). VOLATILE.

CREATE OR REPLACE FUNCTION ca_named_location_restore(
    p_id    BIGINT,
    p_actor BIGINT,
    p_ip    INET
) RETURNS BIGINT AS $$
DECLARE
    v_before JSONB;
    v_after  JSONB;
BEGIN
    -- Capture before_state in the same txn; check deleted_at IS NOT NULL.
    SELECT to_jsonb(nl) INTO v_before
      FROM named_locations nl
     WHERE id = p_id AND deleted_at IS NOT NULL;

    IF v_before IS NULL THEN
        RAISE EXCEPTION 'named_location not found or not deleted'
            USING ERRCODE = 'BZ081',
                  HINT = 'no soft-deleted named_locations row with the given id';
    END IF;

    BEGIN
        UPDATE named_locations
           SET deleted_at = NULL, updated_at = now()
         WHERE id = p_id AND deleted_at IS NOT NULL;
    EXCEPTION WHEN unique_violation THEN
        -- 23505: another active row holds the same name (partial index WHERE deleted_at IS NULL).
        -- Re-raise as BZ093 so callers get 409, not an opaque 500.
        RAISE EXCEPTION 'cannot restore named_location %: name is already in use by an active location', p_id
            USING ERRCODE = 'BZ093',
                  HINT = 'rename or delete the conflicting active named_location first';
    END;

    SELECT to_jsonb(nl) INTO v_after FROM named_locations nl WHERE id = p_id;

    PERFORM audit_write(p_actor, 'ca_named_location_restore', 'named_location', p_id, v_before, v_after, p_ip, NULL, 'core');

    PERFORM ca_notify_policy_change('ca_named_location_restore');

    RETURN p_id;
END;
$$ LANGUAGE plpgsql VOLATILE;
