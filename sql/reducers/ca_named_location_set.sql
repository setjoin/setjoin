-- ca_named_location_set.sql — CA-1 C1: upsert or soft-delete a named_locations row.
--
-- p_id NULL/0 = insert; non-null = update (or soft-delete when p_deleted=true).
-- ip_ranges is stored as jsonb array of CIDR strings; p_cidrs is cast here.
-- In-txn: admin_audit_log row (with ip) + PERFORM ca_notify_policy_change (F2 choke point).
-- R2/R3: actor stored from p_actor; ip stored from p_ip.
-- Update path guards: only touches rows with deleted_at IS NULL (no tombstone resurrection).
-- Returns the row id. VOLATILE.

CREATE OR REPLACE FUNCTION ca_named_location_set(
    p_id          BIGINT,
    p_name        TEXT,
    p_description TEXT,
    p_cidrs       CIDR[],
    p_countries   TEXT[],
    p_trusted     BOOLEAN,
    p_deleted     BOOLEAN,
    p_actor       BIGINT,
    p_ip          INET
) RETURNS BIGINT AS $$
DECLARE
    v_id     BIGINT := CASE WHEN p_id = 0 THEN NULL ELSE p_id END;
    v_before JSONB;
    v_after  JSONB;
    v_action TEXT;
    -- ponytail: cast cidr[] → jsonb array via to_json; avoids a hand-rolled loop
    v_ranges JSONB := to_json(p_cidrs)::jsonb;
    v_cntry  JSONB := to_json(p_countries)::jsonb;
BEGIN
    IF v_id IS NULL THEN
        INSERT INTO named_locations (name, description, ip_ranges, countries, is_trusted)
        VALUES (p_name, COALESCE(p_description, ''), v_ranges, v_cntry, COALESCE(p_trusted, false))
        RETURNING id INTO v_id;
        v_action := 'ca_named_location_create';
    ELSIF p_deleted THEN
        -- R3: include deleted_at IS NULL in WHERE to avoid double-deleting
        SELECT to_jsonb(nl) INTO v_before FROM named_locations nl WHERE id = v_id AND deleted_at IS NULL;
        IF v_before IS NULL THEN
            RAISE EXCEPTION 'named_location not found'
                USING ERRCODE = 'BZ081',
                      HINT = 'no named_locations row with the given id';
        END IF;

        UPDATE named_locations SET deleted_at = now(), updated_at = now()
         WHERE id = v_id AND deleted_at IS NULL;
        v_action := 'ca_named_location_delete';
    ELSE
        -- R3: filter deleted_at IS NULL so tombstoned rows are never silently resurrected
        SELECT to_jsonb(nl) INTO v_before FROM named_locations nl WHERE id = v_id AND deleted_at IS NULL;
        IF v_before IS NULL THEN
            RAISE EXCEPTION 'named_location not found'
                USING ERRCODE = 'BZ081',
                      HINT = 'no named_locations row with the given id';
        END IF;

        UPDATE named_locations SET
            name        = p_name,
            description = COALESCE(p_description, description),
            ip_ranges   = v_ranges,
            countries   = v_cntry,
            is_trusted  = COALESCE(p_trusted, is_trusted),
            updated_at  = now()
        WHERE id = v_id AND deleted_at IS NULL;
        v_action := 'ca_named_location_update';
    END IF;

    SELECT to_jsonb(nl) INTO v_after FROM named_locations nl WHERE id = v_id;

    PERFORM audit_write(p_actor, v_action, 'named_location', v_id, v_before, v_after, p_ip, NULL, 'core');

    PERFORM ca_notify_policy_change(v_action);

    RETURN v_id;
END;
$$ LANGUAGE plpgsql VOLATILE;
