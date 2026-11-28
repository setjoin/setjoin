-- ca_auth_strength_set.sql — CA-1 C1: upsert or soft-delete an auth_strengths row.
--
-- p_id NULL/0 = insert; non-null = update (or soft-delete when p_deleted=true).
-- Built-in rows (builtin=true) cannot be soft-deleted or mutated — guard raises a
-- plain EXCEPTION (no BZ code — this is a 400-class caller error, not a domain
-- invariant; the Go handler maps the generic message → HTTP 400).
-- ponytail: auth_strengths has no deleted_at column (V030 omits it);
-- custom-row p_deleted=true is a no-op (not an error) until a migration adds
-- deleted_at — YAGNI; drop the no-op return silently, caller gets v_id back.
-- If deleted_at lands on auth_strengths later, extend here then.
-- In-txn: admin_audit_log (with ip) + PERFORM ca_notify_policy_change (F2). VOLATILE.

CREATE OR REPLACE FUNCTION ca_auth_strength_set(
    p_id           BIGINT,
    p_slug         TEXT,
    p_name         TEXT,
    p_combinations JSONB,
    p_min_acr      TEXT,
    p_deleted      BOOLEAN,
    p_actor        BIGINT,
    p_ip           INET
) RETURNS BIGINT AS $$
DECLARE
    v_id      BIGINT := CASE WHEN p_id = 0 THEN NULL ELSE p_id END;
    v_before  JSONB;
    v_after   JSONB;
    v_action  TEXT;
    v_builtin BOOLEAN;
BEGIN
    IF p_deleted AND v_id IS NOT NULL THEN
        -- Verify the row exists and check builtin flag in one SELECT.
        SELECT builtin INTO v_builtin FROM auth_strengths WHERE id = v_id;
        IF v_builtin IS NULL THEN
            RAISE EXCEPTION 'auth_strength not found'
                USING ERRCODE = 'BZ081',
                      HINT = 'no auth_strengths row with the given id';
        END IF;
        IF v_builtin THEN
            RAISE EXCEPTION 'cannot delete built-in auth strength'
                USING ERRCODE = 'BZ094',
                      HINT = 'built-in auth strengths cannot be deleted';
        END IF;
        -- ponytail: auth_strengths has no deleted_at column — custom-row delete is
        -- a no-op until the schema gains it; return the id so callers don't fail.
        SELECT to_jsonb(a) INTO v_before FROM auth_strengths a WHERE id = v_id;
        v_after  := v_before;
        v_action := 'ca_auth_strength_delete_noop';

        PERFORM audit_write(p_actor, v_action, 'auth_strength', v_id, v_before, v_after, p_ip, NULL, 'core');

        PERFORM ca_notify_policy_change(v_action);
        RETURN v_id;
    END IF;

    IF v_id IS NULL THEN
        INSERT INTO auth_strengths (slug, name, requirement, min_acr)
        VALUES (
            p_slug,
            p_name,
            COALESCE(p_combinations, '[]'::jsonb),
            COALESCE(p_min_acr, 'aal1')
        )
        RETURNING id INTO v_id;
        v_action := 'ca_auth_strength_create';
    ELSE
        SELECT to_jsonb(a) INTO v_before FROM auth_strengths a WHERE id = v_id;
        IF v_before IS NULL THEN
            RAISE EXCEPTION 'auth_strength not found'
                USING ERRCODE = 'BZ081',
                      HINT = 'no auth_strengths row with the given id';
        END IF;

        -- R3: guard builtin rows from mutation (UPDATE path)
        SELECT builtin INTO v_builtin FROM auth_strengths WHERE id = v_id;
        IF v_builtin THEN
            RAISE EXCEPTION 'cannot mutate built-in auth strength'
                USING ERRCODE = 'BZ094',
                      HINT = 'built-in auth strengths cannot be modified';
        END IF;

        UPDATE auth_strengths SET
            slug        = COALESCE(p_slug, slug),
            name        = COALESCE(p_name, name),
            requirement = COALESCE(p_combinations, requirement),
            min_acr     = COALESCE(p_min_acr, min_acr),
            updated_at  = now()
        WHERE id = v_id AND builtin = false;
        v_action := 'ca_auth_strength_update';
    END IF;

    SELECT to_jsonb(a) INTO v_after FROM auth_strengths a WHERE id = v_id;

    PERFORM audit_write(p_actor, v_action, 'auth_strength', v_id, v_before, v_after, p_ip, NULL, 'core');

    PERFORM ca_notify_policy_change(v_action);

    RETURN v_id;
END;
$$ LANGUAGE plpgsql VOLATILE;
