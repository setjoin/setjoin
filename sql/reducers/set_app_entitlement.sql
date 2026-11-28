-- set_app_entitlement.sql
-- Admin CRUD reducer for per-user app entitlements (B8.5).
--
-- Validates that the target user exists, upserts the user_app_entitlements row,
-- and appends one admin_audit_log row for tamper-evident audit of every change.
--
-- Error codes:
--   BZ033 / entitlement_user_not_found — p_target_user_id does not reference an
--           existing row in users. Raised before any DML so the transaction is clean.
--
-- No state bump (user_app_entitlements is not a JMAP resource; capabilities are
-- re-read on the next /jmap/session request). No pg_notify.
-- VOLATILE (writes to user_app_entitlements + admin_audit_log).

CREATE OR REPLACE FUNCTION set_app_entitlement(
    p_target_user_id BIGINT,
    p_app            TEXT,
    p_enabled        BOOLEAN,
    p_admin_user_id  BIGINT
) RETURNS VOID AS $$
DECLARE
    v_exists BOOLEAN;
BEGIN
    -- Validate that the target user exists (R2: identity from auth, never from request).
    SELECT EXISTS (SELECT 1 FROM users WHERE id = p_target_user_id)
      INTO v_exists;

    IF NOT v_exists THEN
        RAISE EXCEPTION 'Target user not found'
            USING ERRCODE = 'BZ033',
                  HINT = '{"type":"entitlement_user_not_found"}';
    END IF;

    IF is_guest_account(p_target_user_id) THEN
        RAISE EXCEPTION 'Guest app entitlement is profile-derived'
            USING ERRCODE = 'BZ226',
                  HINT = '{"type":"conflict","detail":"guest app entitlement is profile-derived"}';
    END IF;

    -- Upsert the entitlement row.
    -- The CHECK constraint on app column will raise a standard DB error if an
    -- unknown app value is supplied — callers must validate before calling.
    INSERT INTO user_app_entitlements (user_id, app, enabled, updated_at, updated_by)
    VALUES (p_target_user_id, p_app, p_enabled, now(), p_admin_user_id)
    ON CONFLICT (user_id, app) DO UPDATE
        SET enabled    = EXCLUDED.enabled,
            updated_at = now(),
            updated_by = p_admin_user_id;

    -- Append one audit row per call (each toggle is an auditable event).
    PERFORM audit_write(
        p_admin_user_id,
        'set_app_entitlement',
        'user',
        p_target_user_id,
        NULL,
        jsonb_build_object('app', p_app, 'enabled', p_enabled),
        NULL,
        NULL,
        'core'
    );
END;
$$ LANGUAGE plpgsql VOLATILE;
