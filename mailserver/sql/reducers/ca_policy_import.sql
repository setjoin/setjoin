-- ca_policy_import.sql — CA-1 C6: bulk policy-as-code import (merge / replace / prune).
--
-- Signature: ca_policy_import(p_doc JSONB, p_admin_id BIGINT, p_mode TEXT) RETURNS JSONB
--   p_mode ∈ 'merge' | 'replace' | 'prune'
--   Returns: {"applied": N, "created": N, "updated": N, "pruned": N}
--
-- Validation order (per policy item):
--   1. BZ088 — p_doc->>'schemaVersion' > v_supported_version (caller's doc is too new)
--   2. BZ090 — ca_validate_policy_document returns false (bad grant type or condition shape)
--   3. BZ091 — location_slug or strength_slug in the item doesn't resolve
--
-- Safety:
--   • Every imported policy is born 'report_only' — never enforcing on import.
--   • New rows are report_only. Updates preserve the existing state, so their
--     proposed scope/actions/exclusions pass ca_lockout_guard before mutation.
--   • 'prune' mode soft-deletes live (deleted_at IS NULL) policies whose name
--     is absent from the import doc. This is audited ("would-drop" logged).
--
-- Idempotency: upsert by name (UNIQUE NOT enforced by schema — we SELECT first).
--   Re-importing the same name updates in-place, preserving the policy id.
--   State is always forced to 'report_only' on create; on update the existing state
--   is preserved (caller must promote explicitly).
--
-- Audit + notify (CA-0a pattern):
--   One audit row per call (action='ca_policy_import', target_type='conditional_access_policy',
--   target_id=NULL) with after_state = the return summary.
--   PERFORM ca_notify_policy_change('ca_policy_import') — F2 choke point, NOT raw pg_notify.
--
-- BZ codes registered in docs/reducer-error-codes.md.
-- VOLATILE.

CREATE OR REPLACE FUNCTION ca_policy_import(
    p_doc      JSONB,
    p_admin_id BIGINT,
    p_mode     TEXT   -- 'merge' | 'replace' | 'prune'
) RETURNS JSONB AS $$
DECLARE
    -- Supported schemaVersion — bump here when a new version ships.
    v_supported_version CONSTANT INT := 1;

    v_schema_ver  INT;
    v_policies    JSONB;
    v_item        JSONB;
    v_name        TEXT;
    v_conditions  JSONB;
    v_actions     JSONB;
    v_loc_slug    TEXT;
    v_str_slug    TEXT;
    v_loc_id      BIGINT;
    v_str_id      BIGINT;
    v_existing_id BIGINT;
    v_existing_state TEXT;
    v_existing_scope_type TEXT;
    v_existing_exclude_users JSONB;
    v_existing_exclude_groups JSONB;
    v_priority    INT;
    v_n_created   INT := 0;
    v_n_updated   INT := 0;
    v_n_pruned    INT := 0;
    v_names       TEXT[];
    v_summary     JSONB;
BEGIN
    -- Universal CA lock order: reachability advisory fence before any policy
    -- row lock. ca_policy_upsert already enters through ca_lockout_guard first;
    -- taking FOR UPDATE before this fence would permit an advisory↔row deadlock.
    PERFORM ca_reachability_fence();

    -- ── (1) Schema version guard ────────────────────────────────────────────
    v_schema_ver := COALESCE((p_doc->>'schemaVersion')::int, 1);
    IF v_schema_ver > v_supported_version THEN
        RAISE EXCEPTION 'unsupported schemaVersion: % (max supported: %)',
            v_schema_ver, v_supported_version
            USING ERRCODE = 'BZ088',
                  HINT    = 'upgrade setjoin before importing this policy document';
    END IF;

    -- Mode guard (fail fast on bad mode rather than silently ignoring policies).
    -- BZ092 — distinct from BZ088 (schemaVersion) so callers can discriminate.
    IF p_mode NOT IN ('merge', 'replace', 'prune') THEN
        RAISE EXCEPTION 'invalid import mode: %', p_mode
            USING ERRCODE = 'BZ092',
                  HINT    = 'p_mode must be one of: merge, replace, prune';
    END IF;

    v_policies := COALESCE(p_doc->'policies', '[]'::jsonb);

    -- Collect the names from this doc (used for prune).
    SELECT ARRAY(
        SELECT elem->>'name'
          FROM jsonb_array_elements(v_policies) AS elem
         WHERE elem->>'name' IS NOT NULL
    ) INTO v_names;

    -- ── (2) Per-policy upsert ───────────────────────────────────────────────
    FOR v_item IN SELECT * FROM jsonb_array_elements(v_policies) LOOP
        v_name       := v_item->>'name';
        v_conditions := COALESCE(v_item->'conditions', '{}'::jsonb);
        v_actions    := COALESCE(v_item->'actions',    '{}'::jsonb);

        -- BZ090: validate grant/condition shape via the F6 SQL mirror.
        -- ponytail: reuse the existing CHECK-constraint validator rather than
        -- duplicating the allow-list here; raises BZ090 with the §10.1 HINT.
        IF NOT ca_validate_policy_document(v_conditions, v_actions)
           OR NOT ca_grant_discriminators_valid(v_actions) THEN
            RAISE EXCEPTION 'invalid grant or condition shape in policy %', COALESCE(v_name, '(unnamed)')
                USING ERRCODE = 'BZ090',
                      HINT    = jsonb_build_object(
                                    'type',            'ca_import_invalid_shape',
                                    'policy',          COALESCE(v_name,''),
                                    'allowed_actions', '["allow","block","step_up","notify","require_acr","require_strength","limited_web","require_terms","require_risk_remediation"]'::jsonb,
                                    'check',           'ca_validate_policy_document+ca_grant_discriminators_valid'
                                )::text;
        END IF;

        -- BZ091: resolve optional location_slug → id.
        -- ponytail: location_slug is a top-level field on the import item, not
        -- inside conditions (location_in is in the allow-list since V031; the handler
        -- embeds the resolved id into conditions). When a location_slug is present we
        -- validate the slug exists now so import fails loudly rather than silently
        -- dropping the reference.
        v_loc_slug := v_item->>'location_slug';
        IF v_loc_slug IS NOT NULL THEN
            SELECT id INTO v_loc_id
              FROM named_locations
             WHERE name = v_loc_slug AND deleted_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown named-location slug: %', v_loc_slug
                    USING ERRCODE = 'BZ091',
                          HINT    = jsonb_build_object(
                                        'type',         'ca_import_unknown_slug',
                                        'slug',         v_loc_slug,
                                        'table',        'named_locations',
                                        'match_column', 'name'
                                    )::text;
            END IF;
        END IF;

        -- BZ091: resolve optional strength_slug → id.
        v_str_slug := v_item->>'strength_slug';
        IF v_str_slug IS NOT NULL THEN
            SELECT id INTO v_str_id
              FROM auth_strengths
             WHERE slug = v_str_slug;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown auth-strength slug: %', v_str_slug
                    USING ERRCODE = 'BZ091',
                          HINT    = jsonb_build_object(
                                        'type',         'ca_import_unknown_slug',
                                        'slug',         v_str_slug,
                                        'table',        'auth_strengths',
                                        'match_column', 'slug'
                                    )::text;
            END IF;
        END IF;

        -- Upsert by name: if a live row with this name exists, update it;
        -- otherwise insert a new one born report_only.
        SELECT id, state, scope_type, exclude_users, exclude_groups
          INTO v_existing_id, v_existing_state, v_existing_scope_type,
               v_existing_exclude_users, v_existing_exclude_groups
          FROM conditional_access_policies
         WHERE name = v_name AND deleted_at IS NULL
         LIMIT 1
         FOR UPDATE;

        IF v_existing_id IS NULL THEN
            -- Auto-assign priority (from doc or next free slot).
            v_priority := COALESCE(
                (v_item->>'priority')::int,
                (SELECT COALESCE(MAX(priority), 0) + 10
                   FROM conditional_access_policies));

            INSERT INTO conditional_access_policies
                (priority, name, description, state, scope_type, scope_target,
                 conditions, actions, exclude_users, exclude_groups)
            VALUES (
                v_priority,
                v_name,
                COALESCE(v_item->>'description', ''),
                'report_only',     -- NEVER born enforcing
                COALESCE(v_item->>'scope_type', 'global'),
                COALESCE(v_item->>'scope_target', ''),
                v_conditions,
                v_actions,
                COALESCE(v_item->'exclude_users',  '[]'::jsonb),
                COALESCE(v_item->'exclude_groups', '[]'::jsonb)
            );
            v_n_created := v_n_created + 1;
        ELSE
            -- Update non-state fields; preserve existing state (promote is explicit).
            -- An existing on-policy stays on, so validate the complete proposed
            -- enforcement tuple before overwriting any field.
            PERFORM ca_lockout_guard(
                v_existing_state,
                COALESCE(v_item->>'scope_type', v_existing_scope_type),
                v_actions,
                COALESCE(v_item->'exclude_users', v_existing_exclude_users),
                COALESCE(v_item->'exclude_groups', v_existing_exclude_groups)
            );

            UPDATE conditional_access_policies SET
                description   = COALESCE(v_item->>'description', description),
                scope_type    = COALESCE(v_item->>'scope_type',  scope_type),
                scope_target  = COALESCE(v_item->>'scope_target', scope_target),
                conditions    = v_conditions,
                actions       = v_actions,
                exclude_users = COALESCE(v_item->'exclude_users',  exclude_users),
                exclude_groups= COALESCE(v_item->'exclude_groups', exclude_groups),
                updated_at    = now()
            WHERE id = v_existing_id;
            v_n_updated := v_n_updated + 1;
        END IF;
    END LOOP;

    -- ── (3) Prune: soft-delete live policies absent from this doc ───────────
    -- ponytail: 'replace' and 'prune' both prune. 'merge' leaves existing
    -- policies untouched. We log what prune drops (visible in audit trail).
    IF p_mode IN ('replace', 'prune') THEN
        UPDATE conditional_access_policies
           SET deleted_at = now(), updated_at = now()
         WHERE deleted_at IS NULL
           AND name <> ALL(v_names)
           AND name NOT IN (
               -- Protect the 5 baseline seeds from prune.
               SELECT name FROM conditional_access_policies WHERE id <= 5
           );
        GET DIAGNOSTICS v_n_pruned = ROW_COUNT;
    END IF;

    -- ── (4) One audit row for the entire import call ────────────────────────
    v_summary := jsonb_build_object(
        'applied', v_n_created + v_n_updated,
        'created', v_n_created,
        'updated', v_n_updated,
        'pruned',  v_n_pruned,
        'mode',    p_mode
    );

    PERFORM audit_write(p_admin_id, 'ca_policy_import',
            'conditional_access_policy', NULL, NULL, v_summary, NULL, NULL, 'core');

    -- ── (5) F2: single choke point — NOT a bespoke app_notify call ─────────
    PERFORM ca_notify_policy_change('ca_policy_import');

    RETURN v_summary;
END;
$$ LANGUAGE plpgsql VOLATILE;
