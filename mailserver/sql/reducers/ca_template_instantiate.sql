-- ca_template_instantiate.sql — CA-1 C2: instantiate a ca_templates row into a
-- new conditional_access_policies row.
--
-- Safety guarantees (logic-where-the-data-is):
--   • state is ALWAYS 'report_only' — never born enforcing.
--   • created_from_template set to the slug for provenance.
--   • exclude_users = distinct(p_admin_id ∪ system ca_break_glass_user_ids) so
--     the instantiating admin cannot lock themselves out, and break-glass remains
--     reachable even if the policy is later flipped to 'on'.
--   • For role-scoped templates, scope_target is resolved from the role group NAME
--     to its numeric id at instantiation time (not stored by name in the policy row).
--   • Audit row + PERFORM ca_notify_policy_change('ca_template_instantiate') in-txn
--     (F2 choke point — NOT a bespoke app_notify call).
--
-- BZ085: unknown slug (template not found). BZ084 is secure_account; CA-1 allocation starts at BZ085.
-- ponytail: ca_lockout_guard not called — report_only never blocks logins, so the
-- lockout condition cannot trigger; guard is for on+global+block/step_up flips only.
-- VOLATILE.

CREATE OR REPLACE FUNCTION ca_template_instantiate(
    p_slug     TEXT,
    p_admin_id BIGINT
) RETURNS BIGINT AS $$
DECLARE
    v_tpl        RECORD;
    v_bg         JSONB;
    v_excl_users JSONB;
    v_scope_tgt  TEXT;
    v_priority   INT;
    v_new_id     BIGINT;
    v_after      JSONB;
BEGIN
    -- (1) Look up template — raise BZ085 if absent.
    SELECT * INTO v_tpl FROM ca_templates WHERE slug = p_slug;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ca_template not found: %', p_slug
            USING ERRCODE = 'BZ085',
                  HINT    = 'pass a slug that exists in the ca_templates table';
    END IF;

    -- (2) Build exclude_users: distinct(author ∪ break-glass set).
    SELECT COALESCE(value, '[]'::jsonb) INTO v_bg
      FROM system_config WHERE key = 'ca_break_glass_user_ids';
    v_bg := COALESCE(v_bg, '[]'::jsonb);

    SELECT jsonb_agg(DISTINCT uid ORDER BY uid) INTO v_excl_users
    FROM (
        SELECT p_admin_id AS uid
        UNION
        SELECT (e)::bigint FROM jsonb_array_elements_text(v_bg) e
    ) s;
    v_excl_users := COALESCE(v_excl_users, to_jsonb(ARRAY[p_admin_id]));

    -- (3) Resolve scope_target: for role-scoped templates the stored value is a
    -- role group name; convert to numeric id at instantiation time (NEVER hard-code).
    -- ponytail: NULL join rather than RAISE on missing role — yields empty string,
    -- matching the behaviour of non-role templates; role-template validation is
    -- the caller's concern at the HTTP layer.
    IF v_tpl.scope_type = 'role' AND v_tpl.scope_target <> '' THEN
        SELECT id::text INTO v_scope_tgt
          FROM admin_role_groups WHERE name = v_tpl.scope_target;
        v_scope_tgt := COALESCE(v_scope_tgt, '');
    ELSE
        v_scope_tgt := v_tpl.scope_target;
    END IF;

    -- (4) Auto-assign priority: use template's suggested_priority unless taken
    -- (next available slot in the active+live set).
    IF NOT EXISTS (
        SELECT 1 FROM conditional_access_policies
        WHERE priority = v_tpl.suggested_priority
          AND state = 'on' AND deleted_at IS NULL
    ) THEN
        v_priority := v_tpl.suggested_priority;
    ELSE
        SELECT COALESCE(MAX(priority), 0) + 10 INTO v_priority
          FROM conditional_access_policies;
    END IF;

    -- (5) INSERT the new policy: born report_only, provenance set, exclusions applied.
    INSERT INTO conditional_access_policies
        (priority, name, description, state, scope_type, scope_target,
         conditions, actions, exclude_users, exclude_groups, created_from_template)
    VALUES (
        v_priority,
        v_tpl.name,
        v_tpl.description,
        'report_only',   -- NEVER born enforcing
        v_tpl.scope_type,
        COALESCE(v_scope_tgt, ''),
        v_tpl.conditions,
        v_tpl.actions,
        v_excl_users,
        '[]'::jsonb,     -- ponytail: no group exclusions at birth; admin adds if needed
        p_slug
    )
    RETURNING id INTO v_new_id;

    SELECT to_jsonb(c) - 'enabled' INTO v_after
      FROM conditional_access_policies c WHERE id = v_new_id;

    -- (6) Audit row (in-txn, per CA-0a pattern).
    PERFORM audit_write(p_admin_id, 'ca_template_instantiate',
            'conditional_access_policy', v_new_id, NULL, v_after, NULL, NULL, 'core');

    -- (7) F2: single choke point — NOT a bespoke app_notify call.
    PERFORM ca_notify_policy_change('ca_template_instantiate');

    RETURN v_new_id;
END;
$$ LANGUAGE plpgsql VOLATILE;
