-- check_user_app_entitlement.sql -- User-id app entitlement authority (Guest G2).
-- SECURITY DEFINER is required because mailbox-less guests are hidden by the
-- FORCE-RLS guest_accounts policy from an unscoped app-pool lookup.
CREATE OR REPLACE FUNCTION check_user_app_entitlement(
    p_user_id BIGINT,
    p_app     TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
    v_toggle_key     TEXT;
    v_toggle_enabled BOOLEAN;
    v_is_guest       BOOLEAN;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id) THEN
        RETURN FALSE;
    END IF;

    CASE p_app
    WHEN 'mail'     THEN v_toggle_key := NULL;
    WHEN 'calendar' THEN v_toggle_key := 'feature.caldav';
    WHEN 'contacts' THEN v_toggle_key := 'feature.carddav';
    WHEN 'tasks'    THEN v_toggle_key := 'feature.tasks';
    WHEN 'drive'    THEN v_toggle_key := 'feature.drive';
    WHEN 'chat'     THEN v_toggle_key := 'feature.chat';
    WHEN 'meet'     THEN v_toggle_key := 'feature.meet';
    ELSE RETURN FALSE;
    END CASE;

    v_toggle_enabled := v_toggle_key IS NULL OR COALESCE(
        (SELECT enabled FROM feature_toggles WHERE key = v_toggle_key),
        TRUE
    );

    v_is_guest := is_guest_account(p_user_id);

    -- The Guest Accounts program toggle is an independent runtime belt. A
    -- pre-existing guest identity and its derived entitlement rows must become
    -- inert immediately when the program is disabled; member access is
    -- intentionally unaffected by that toggle.
    IF v_is_guest AND NOT COALESCE(
        (SELECT enabled FROM feature_toggles WHERE key = 'feature.guest_accounts'),
        FALSE
    ) THEN
        RETURN FALSE;
    END IF;

    RETURN v_toggle_enabled AND COALESCE(
        (SELECT enabled FROM user_app_entitlements
          WHERE user_id = p_user_id AND app = p_app),
        NOT v_is_guest
    );
END;
$$;
SELECT apply_worker_ownership('check_user_app_entitlement(bigint,text)'::regprocedure);
