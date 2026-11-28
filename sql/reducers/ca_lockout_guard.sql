-- ca_lockout_guard.sql — CA-0a admin-lockout guard.
--
-- Refuses to persist an on + global + block/step_up policy that would leave NO
-- active admin reachable through exclusion. Server-enforced floor (logic-where-
-- the-data-is); the handler calls it before persisting.
--
-- Two-namespace join (load-bearing): "active admin" = unexpired admin_role_
-- assignments (keyed by role_group_id). A reachable safety principal must have
-- a permanent, non-JIT assignment: a finite expires_at or eligible activation
-- window can lapse without a database write, so neither is a durable escape
-- path. "Excluded" tests that admin's user_id
-- against exclude_users / ca_break_glass_user_ids AND that admin's
-- user_group_members.group_id set against exclude_groups (the USER-group
-- namespace, NOT role_group_id).
--
-- Guarantee is honestly scoped to the HTTP-login seam — IMAP/SMTP break-glass
-- enforcement is CA-F §F1.
--
-- SECURITY DEFINER: user_group_members has FORCE ROW LEVEL SECURITY (policy
-- ugm_self, V025). Running as setjoin_app (RLS-enforced role), the exclusion
-- subquery would see ZERO rows for the current user and false-raise BZ080 on
-- valid policies that exclude an admin group. SECURITY DEFINER runs this guard
-- as the DB owner (BYPASSRLS) so it reads all ugm rows correctly. This is safe:
-- the function writes no business data, accepts only scalar/jsonb inputs, and
-- its only side effect is the transaction-scoped authority advisory fence.
--
-- Error codes:
--   BZ080 / ca_admin_lockout — an on+global+block/step_up policy excludes no admin.
-- VOLATILE because every call acquires the transaction-scoped reachability
-- fence before any validation fast path.

-- CA reachability is a specialization of the existing V172 live-admin
-- authority fence. Reusing that fixed advisory-lock key gives every policy,
-- role-assignment, break-glass, and user-group writer one lock domain and one
-- global order; a second key would permit an authority-fence -> CA-fence versus
-- CA-fence -> authority-fence deadlock.
CREATE OR REPLACE FUNCTION ca_reachability_fence()
RETURNS VOID AS $$
BEGIN
    PERFORM admin_authority_fence();
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public;

-- ca_policy_effective_action is the shared first-action projection used by
-- session-control validation and read-only projections. Runtime precedence is:
-- top-level remediation special actions, then the first canonical/schema-v1
-- grant, then the legacy top-level action.
CREATE OR REPLACE FUNCTION ca_policy_effective_action(
    p_actions JSONB
) RETURNS TEXT AS $$
    SELECT CASE
        WHEN p_actions->>'action' IN ('require_terms', 'require_risk_remediation')
            THEN p_actions->>'action'
        WHEN jsonb_typeof(p_actions->'grants') = 'array'
            THEN CASE WHEN jsonb_array_length(p_actions->'grants') > 0
                THEN COALESCE(
                    NULLIF(p_actions->'grants'->0->>'type', ''),
                    NULLIF(p_actions->'grants'->0->>'action', '')
                )
            END
        ELSE NULLIF(p_actions->>'action', '')
    END;
$$ LANGUAGE sql IMMUTABLE;

-- ca_grant_discriminators_valid is the reducer-side compatibility seam for the
-- two persisted grant spellings. `type` is canonical; `action` remains accepted
-- for schema-v1 documents. A document carrying both must be byte-identical after
-- JSON string extraction. The action enum is intentionally lowercase and exact;
-- there is no trim/case fold that could silently change a persisted policy verb.
-- This is intentionally a pure shape predicate: callers retain ownership of the
-- wire-appropriate error (ca_lockout_guard uses 22023; import uses BZ090).
CREATE OR REPLACE FUNCTION ca_grant_discriminators_valid(
    p_actions JSONB
) RETURNS BOOLEAN AS $$
DECLARE
    v_grant  JSONB;
    v_type   TEXT;
    v_action TEXT;
BEGIN
    IF p_actions IS NULL OR NOT (p_actions ? 'grants') THEN
        RETURN TRUE;
    END IF;
    IF jsonb_typeof(p_actions->'grants') <> 'array'
       OR jsonb_array_length(p_actions->'grants') = 0 THEN
        RETURN FALSE;
    END IF;

    FOR v_grant IN SELECT * FROM jsonb_array_elements(p_actions->'grants') LOOP
        IF jsonb_typeof(v_grant) <> 'object' THEN
            RETURN FALSE;
        END IF;
        IF (v_grant ? 'type') AND jsonb_typeof(v_grant->'type') <> 'string' THEN
            RETURN FALSE;
        END IF;
        IF (v_grant ? 'action') AND jsonb_typeof(v_grant->'action') <> 'string' THEN
            RETURN FALSE;
        END IF;

        v_type := NULLIF(v_grant->>'type', '');
        v_action := NULLIF(v_grant->>'action', '');
        IF ((v_grant ? 'type') AND v_type IS NULL)
           OR ((v_grant ? 'action') AND v_action IS NULL) THEN
            RETURN FALSE;
        END IF;
        IF v_type IS NOT NULL AND v_action IS NOT NULL AND v_type <> v_action THEN
            RETURN FALSE;
        END IF;
        IF COALESCE(v_type, v_action) IS NULL
           OR COALESCE(v_type, v_action) IN ('require_terms', 'require_risk_remediation')
           OR COALESCE(v_type, v_action) <> ALL (
               ARRAY['allow','block','step_up','notify','require_acr','require_strength',
                     'limited_web','require_terms','require_risk_remediation']
           ) THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION ca_lockout_guard(
    p_state          TEXT,
    p_scope_type     TEXT,
    p_actions        JSONB,
    p_exclude_users  JSONB,
    p_exclude_groups JSONB
) RETURNS VOID AS $$
DECLARE
    v_break_glass     JSONB;
    v_reachable_count INT;
    v_has_dangerous   BOOLEAN := FALSE;
    v_grant           JSONB;
BEGIN
    -- Serialize the candidate policy tuple with every authority-side mutation.
    -- This must precede discriminator/state/scope fast paths: even an off or
    -- non-global policy write participates in the single lock-order contract.
    PERFORM ca_reachability_fence();

    -- Reject ambiguous/malformed grant discriminators before the state/scope
    -- fast path. An off/report-only document can later be promoted, so storing
    -- a split-brain action shape is never safe.
    IF NOT ca_grant_discriminators_valid(p_actions) THEN
        RAISE EXCEPTION 'invalid or conflicting conditional-access grant discriminator'
            USING ERRCODE = '22023',
                  HINT = 'use one non-empty grants[].type value, or a matching schema-v1 grants[].action value';
    END IF;

    -- Guard only fires for the worst write: on + global + block/step_up.
    -- Supports both legacy shape {"action":"block"} and grant-array shape
    -- {"operator":"all","grants":[{"action":"block"},...],"reason":"…"}.
    IF p_state <> 'on' OR p_scope_type <> 'global' THEN
        RETURN;
    END IF;

    -- Derive whether any effective action is block or step_up.
    -- Legacy top-level "action" key (NULL when absent → COALESCE to FALSE):
    v_has_dangerous := COALESCE((p_actions->>'action') IN ('block', 'step_up'), FALSE);
    -- Grant-array shape: `type` is canonical; retain schema-v1 `action` reads.
    IF NOT v_has_dangerous AND (p_actions ? 'grants') THEN
        FOR v_grant IN SELECT * FROM jsonb_array_elements(p_actions->'grants') LOOP
            IF COALESCE(NULLIF(v_grant->>'type', ''), v_grant->>'action')
               IN ('block', 'step_up') THEN
                v_has_dangerous := TRUE;
                EXIT;
            END IF;
        END LOOP;
    END IF;

    IF NOT v_has_dangerous THEN
        RETURN;
    END IF;

    SELECT COALESCE(value, '[]'::jsonb) INTO v_break_glass
      FROM system_config WHERE key = 'ca_break_glass_user_ids';
    v_break_glass := COALESCE(v_break_glass, '[]'::jsonb);

    -- Count active admins that REMAIN reachable (i.e. are excluded).
    SELECT COUNT(*) INTO v_reachable_count
    FROM (
        SELECT DISTINCT ara.user_id
        FROM admin_role_assignments ara
        JOIN users u ON u.id = ara.user_id AND u.enabled
        WHERE ara.expires_at IS NULL
          AND ara.eligible = FALSE
          AND admin_assignment_active(ara.eligible, ara.activated_until)
    ) admins
    WHERE
        -- excluded directly by user id
        admins.user_id IN (SELECT (e)::bigint FROM jsonb_array_elements_text(p_exclude_users) e)
        -- OR in the system break-glass set
        OR admins.user_id IN (SELECT (e)::bigint FROM jsonb_array_elements_text(v_break_glass) e)
        -- OR a member of an excluded USER group (two-namespace bridge)
        OR EXISTS (
            SELECT 1
            FROM user_group_members ugm
            WHERE ugm.user_id = admins.user_id
              AND ugm.group_id IN (
                  SELECT (e)::bigint FROM jsonb_array_elements_text(p_exclude_groups) e
              )
        );

    IF v_reachable_count = 0 THEN
        RAISE EXCEPTION 'global blocking policy would lock out all admins'
            USING ERRCODE = 'BZ080',
                  HINT = 'exclude a break-glass admin account (system_config.ca_break_glass_user_ids) or an admin group';
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public;

-- Recheck the complete final reachability state. Constraint triggers invoke
-- this at transaction end, rather than after each statement, so a safe
-- remove-then-add role or group replacement is not rejected at its transient
-- midpoint. Multiple affected rows may queue multiple calls; all calls observe
-- the same final transaction state and the advisory lock is re-entrant.
CREATE OR REPLACE FUNCTION ca_revalidate_active_lockout_policies()
RETURNS VOID AS $$
DECLARE
    v_policy conditional_access_policies%ROWTYPE;
BEGIN
    PERFORM ca_reachability_fence();

    FOR v_policy IN
        SELECT *
          FROM conditional_access_policies
         WHERE state = 'on'
           AND scope_type = 'global'
           AND deleted_at IS NULL
         ORDER BY id
    LOOP
        PERFORM ca_lockout_guard(
            v_policy.state,
            v_policy.scope_type,
            v_policy.actions,
            v_policy.exclude_users,
            v_policy.exclude_groups
        );
    END LOOP;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION trg_ca_reachability_fence()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM ca_reachability_fence();
    RETURN NULL;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION trg_ca_reachability_revalidate()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM ca_revalidate_active_lockout_policies();
    RETURN NULL;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public;

-- BEFORE STATEMENT obtains the fence before row locks. The assignment table
-- already has V172's authority-fence trigger; this named CA trigger deliberately
-- reacquires the same advisory lock to make the shared contract explicit.
DROP TRIGGER IF EXISTS trg_ca_reachability_assignments_fence ON public.admin_role_assignments;
CREATE TRIGGER trg_ca_reachability_assignments_fence
    BEFORE INSERT OR UPDATE OR DELETE ON public.admin_role_assignments
    FOR EACH STATEMENT EXECUTE FUNCTION trg_ca_reachability_fence();

DROP TRIGGER IF EXISTS trg_ca_reachability_break_glass_fence ON public.system_config;
CREATE TRIGGER trg_ca_reachability_break_glass_fence
    BEFORE INSERT OR UPDATE OR DELETE ON public.system_config
    FOR EACH STATEMENT EXECUTE FUNCTION trg_ca_reachability_fence();

DROP TRIGGER IF EXISTS trg_ca_reachability_user_groups_fence ON public.user_group_members;
CREATE TRIGGER trg_ca_reachability_user_groups_fence
    BEFORE INSERT OR UPDATE OR DELETE ON public.user_group_members
    FOR EACH STATEMENT EXECUTE FUNCTION trg_ca_reachability_fence();

DROP TRIGGER IF EXISTS trg_ca_reachability_users_fence ON public.users;
CREATE TRIGGER trg_ca_reachability_users_fence
    BEFORE UPDATE OF enabled OR DELETE ON public.users
    FOR EACH STATEMENT EXECUTE FUNCTION trg_ca_reachability_fence();

-- PostgreSQL constraint triggers are row-level. They are initially deferred so
-- validation sees the transaction's final authority graph, not a transient
-- remove-before-add midpoint.
DROP TRIGGER IF EXISTS trg_ca_reachability_assignments_validate ON public.admin_role_assignments;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_assignments_validate
    AFTER INSERT OR UPDATE OR DELETE ON public.admin_role_assignments
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION trg_ca_reachability_revalidate();

DROP TRIGGER IF EXISTS trg_ca_reachability_break_glass_validate ON public.system_config;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_break_glass_validate
    AFTER INSERT OR UPDATE OR DELETE ON public.system_config
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION trg_ca_reachability_revalidate();

DROP TRIGGER IF EXISTS trg_ca_reachability_user_groups_validate ON public.user_group_members;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_user_groups_validate
    AFTER INSERT OR UPDATE OR DELETE ON public.user_group_members
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION trg_ca_reachability_revalidate();

DROP TRIGGER IF EXISTS trg_ca_reachability_users_validate ON public.users;
CREATE CONSTRAINT TRIGGER trg_ca_reachability_users_validate
    AFTER UPDATE OF enabled OR DELETE ON public.users
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION trg_ca_reachability_revalidate();
