-- effective_capabilities.sql
-- Resolves per-account effective app access and feature flags for /jmap/session.
--
-- Logic: effective = global_toggle_on AND per_user_entitlement_allowed
--
-- Global toggles read from feature_toggles; absent row defaults to TRUE (the
-- toggle is presumed on for any app that has not yet been seeded, e.g. tasks).
--
-- Per-user entitlements read from user_app_entitlements; absent row = TRUE
-- (default-allow per B8 contract in schema/051_user_app_entitlements.sql).
--
-- Gate map:
--   mail      → always TRUE (no toggle; mail is always on for personal mailboxes)
--   calendar  → feature.caldav
--   contacts  → feature.carddav
--   tasks     → feature.tasks (may not be seeded; absent = TRUE)
--   drive     → feature.drive (V114 seeds this row FALSE)
--   chat      → feature.chat (V119 seeds this row FALSE)
--   meet      → feature.meet (V125 seeds this row FALSE)
--
-- Features map (Boolean flags for non-app features in the capabilities payload):
--   assist          → feature.assist
--   bundles         → feature.newsletter_bundles (seeded in B5.1; absent = TRUE)
--   device_lockdown → feature.device_lockdown (absent = FALSE; restriction, not grant)
--   external_labels → feature.external_sender_warn (seeded/default TRUE)
--
-- This function is STABLE (read-only; result depends only on DB state within
-- the current transaction). No jmap_*_state bump; no pg_notify.
--
-- p_mailbox_id: the mailbox id (primary mailbox of the authenticated user).
--               Ownership is scoped via mailboxes → users, satisfying R1 without
--               a direct message-table scan.
--

CREATE OR REPLACE FUNCTION effective_capabilities(
    p_mailbox_id BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_user_id     BIGINT;
    v_assist_toggle    BOOLEAN;
    v_bundles_toggle   BOOLEAN;
    v_lockdown_toggle  BOOLEAN;
    v_external_labels_toggle BOOLEAN;
    v_external_labels_user BOOLEAN;
    v_guest_accounts_toggle BOOLEAN;
    v_guest_invite_toggle BOOLEAN;
    v_mail_search_builder_toggle BOOLEAN;
    v_sender_control_center_toggle BOOLEAN;
    v_shared_mail_work_toggle BOOLEAN;
    v_shared_mail_comments_toggle BOOLEAN;
    v_shared_mail_drafts_toggle BOOLEAN;
    v_shared_mail_notifications_toggle BOOLEAN;
    v_shared_mail_analytics_toggle BOOLEAN;
    v_shared_mail_integrations_toggle BOOLEAN;
    v_apps         JSONB;
    v_features     JSONB;
BEGIN
    -- R1: derive user_id from the authenticated account's mailbox via the resolver seam.
    SELECT s.user_id INTO v_user_id
      FROM account_scope(p_mailbox_id) s;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account mailbox % not found', p_mailbox_id
            USING ERRCODE = 'BZ001',
                  HINT    = jsonb_build_object(
                                'type',       'not_found',
                                'account_id', p_mailbox_id
                            )::TEXT;
    END IF;

    -- ── Read non-app feature toggles (absent row = TRUE; lockdown = FALSE) ─────
    SELECT COALESCE(
        (SELECT enabled FROM feature_toggles WHERE key = 'feature.assist'), TRUE
    ) INTO v_assist_toggle;

    SELECT COALESCE(
        (SELECT enabled FROM feature_toggles WHERE key = 'feature.newsletter_bundles'), TRUE
    ) INTO v_bundles_toggle;

    -- ponytail: device_lockdown defaults FALSE (it is a restriction, not a feature grant)
    SELECT COALESCE(
        (SELECT enabled FROM feature_toggles WHERE key = 'feature.device_lockdown'), FALSE
    ) INTO v_lockdown_toggle;

    SELECT COALESCE(
        (SELECT enabled FROM feature_toggles WHERE key = 'feature.external_sender_warn'), TRUE
    ) INTO v_external_labels_toggle;

    SELECT COALESCE(external_sender_warning, TRUE)
      INTO v_external_labels_user
      FROM users
     WHERE id = v_user_id;

    -- Guest invite capabilities are security-sensitive grants: missing rows
    -- fail CLOSED. guest_invite is the effective AND used by the client.
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.guest_accounts'), FALSE)
      INTO v_guest_accounts_toggle;
    SELECT v_guest_accounts_toggle AND COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='approval.guest_invite'), FALSE)
      INTO v_guest_invite_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.mail_search_builder'), FALSE)
      INTO v_mail_search_builder_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.sender_control_center'), FALSE)
      INTO v_sender_control_center_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.shared_mail_work'), FALSE)
      INTO v_shared_mail_work_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.shared_mail_comments'), FALSE)
      INTO v_shared_mail_comments_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.shared_mail_drafts'), FALSE)
      INTO v_shared_mail_drafts_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.shared_mail_notifications'), FALSE)
      INTO v_shared_mail_notifications_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.shared_mail_analytics'), FALSE)
      INTO v_shared_mail_analytics_toggle;
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.shared_mail_integrations'), FALSE)
      INTO v_shared_mail_integrations_toggle;

    -- ── App access: delegate to check_app_entitlement (the B8.4 enforcement peer) ─
    -- so the session payload and per-request enforcement compute the SAME gate
    -- (global toggle AND per-user entitlement) from ONE place instead of a
    -- hand-copied duplicate that drifts. mail is always TRUE there too.
    v_apps := jsonb_build_object(
        'mail',      check_app_entitlement(p_mailbox_id, 'mail'),
        'calendar',  check_app_entitlement(p_mailbox_id, 'calendar'),
        'contacts',  check_app_entitlement(p_mailbox_id, 'contacts'),
        'tasks',     check_app_entitlement(p_mailbox_id, 'tasks'),
        'drive',     check_app_entitlement(p_mailbox_id, 'drive'),
        'chat',      check_app_entitlement(p_mailbox_id, 'chat'),
        'meet',      check_app_entitlement(p_mailbox_id, 'meet')
    );

    -- Features: non-app capabilities. external_labels is the one deliberate
    -- org-toggle ∧ per-user-preference result; the other rows are global only.
    v_features := jsonb_build_object(
        'assist',          v_assist_toggle,
        'bundles',         v_bundles_toggle,
        'device_lockdown', v_lockdown_toggle,
        'external_labels', v_external_labels_toggle AND COALESCE(v_external_labels_user, TRUE),
        'guest_accounts',  v_guest_accounts_toggle,
        'guest_invite',    v_guest_invite_toggle,
        'mail_search_builder', v_mail_search_builder_toggle,
        'sender_control_center', v_sender_control_center_toggle,
        'shared_mail_work', v_shared_mail_work_toggle,
        'shared_mail_comments', v_shared_mail_comments_toggle,
        'shared_mail_drafts', v_shared_mail_drafts_toggle,
        'shared_mail_notifications', v_shared_mail_notifications_toggle,
        'shared_mail_analytics', v_shared_mail_analytics_toggle,
        'shared_mail_integrations', v_shared_mail_integrations_toggle
    );

    RETURN jsonb_build_object('apps', v_apps, 'features', v_features);
END;
$$ LANGUAGE plpgsql STABLE;

-- Device-aware overload (#2a): the offline block needs the device id, which the
-- session handler resolves server-side (DeviceClaim.ID string → fingerprint_hash
-- → user_devices.id, F3). Returns the base capabilities payload plus an
-- `offline` block from offline_effective_policy. STABLE. deps: offline_effective_policy
CREATE OR REPLACE FUNCTION effective_capabilities(
    p_mailbox_id BIGINT,
    p_device_id  BIGINT
) RETURNS JSONB AS $$
    SELECT effective_capabilities(p_mailbox_id)
        || jsonb_build_object('offline',
             offline_effective_policy(p_mailbox_id, p_device_id));
$$ LANGUAGE sql STABLE;
