-- ════════════════════════════════════════════════════════════════════════
-- V045__ca_foundation.sql — CA-Foundation shared substrate (CA-F).
--
-- This migration is the first in a series that builds the plumbing every
-- Conditional Access phase assumes. Later CA-F tasks append to this file
-- (devices FK, oauth refresh family, access.policy_* perms, ca_notify).
-- Gated behaviour lands in later phases; this migration is structural.
--
-- Task 1 (this block): user_group_members
-- ─────────────────────────────────────────────────────────────────────
-- fetchUserGroups (authserver/internal/handlers/auth.go:1218) already
-- SELECTs user_group_members but the table was absent from the baseline.
-- CA group-scope policy conditions depend on it. Created here so the
-- authserver reference has a real table and later CA phases can scope
-- policies by group.
--
-- RLS: ENABLED + FORCE'd with policy ugm_self keyed on
--   current_setting('app.current_user_id', TRUE)::bigint
-- per DATABASE_SECURITY R1–R4 (user-data table, per-user policy).
-- The TRUE (missing_ok) flag makes an unset GUC return NULL → no rows
-- qualify → fail-closed (consistent with the pattern in V003/V004).
-- ════════════════════════════════════════════════════════════════════════

-- ── user_group_members: the group-membership source CA group-scope reads ──────
-- fetchUserGroups (authserver) and the post-auth policy pass SELECT this table;
-- it was referenced but never created in the baseline.
CREATE TABLE IF NOT EXISTS public.user_group_members (
    user_id    bigint                   NOT NULL
                 REFERENCES public.users(id) ON DELETE CASCADE,
    group_id   bigint                   NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, group_id)
);

-- Index on group_id so "who is in group G?" lookups are efficient (e.g.
-- future CA group-scope policy evaluation; the PK already covers user_id).
CREATE INDEX IF NOT EXISTS user_group_members_group_id_idx
    ON public.user_group_members (group_id);

-- ── RLS: ENABLED + FORCE'd ───────────────────────────────────────────────────
ALTER TABLE public.user_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_group_members FORCE  ROW LEVEL SECURITY;

-- ── Policy ugm_self: user sees only their own memberships ────────────────────
-- FOR ALL (read + write) to public. USING controls visibility (SELECT/DELETE);
-- WITH CHECK controls writes (INSERT/UPDATE). Both enforce the same predicate so
-- a user cannot insert or query another user's memberships.
-- current_setting(…, TRUE) is missing_ok: unset GUC → NULL → fail-closed
-- (no rows visible; no ''::bigint cast error — the same pattern as V003).
DROP POLICY IF EXISTS ugm_self ON public.user_group_members;
CREATE POLICY ugm_self ON public.user_group_members
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- ── canonical device model: user_devices -> devices (F3) ────────────────────
-- devices is the authoritative identity row (hmac_secret + enrollment lifecycle).
-- user_devices (push/offline) references it so a lockdown/approval reads ONE row.
-- Nullable + SET NULL: legacy user_devices rows predate enrollment; deleting a
-- devices row must not cascade-delete a push registration.
ALTER TABLE public.user_devices
    ADD COLUMN IF NOT EXISTS device_id bigint
    REFERENCES public.devices(id) ON DELETE SET NULL;

-- ── oauth_tokens refresh family (F4 substrate; inert until CA-3) ──────────────
ALTER TABLE public.oauth_tokens
    ADD COLUMN IF NOT EXISTS family_id uuid;

CREATE INDEX IF NOT EXISTS oauth_tokens_family_id_idx
    ON public.oauth_tokens(family_id) WHERE family_id IS NOT NULL;

-- ── access.policy_* permission registry rows (F5 / Task 12) ─────────────────
-- These two rows register the CA authority perms in the admin_permissions
-- catalog table (read by the role permission picker UI).  The Go-side canonical
-- list (shared/permissions/permissions.go AllPermissions) is the primary
-- authority; this seed keeps the DB catalog in sync.
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('access.policy_read',  'Access', 'Read conditional-access policies, excludes, and sign-in log', false),
  ('access.policy_write', 'Access', 'Mutate CA policies, excludes, and break-glass accounts (sensitive)', true)
ON CONFLICT (permission_key) DO NOTHING;

-- ── F6: ca_validate_policy_document — allow-list CHECK helper ────────────────
-- IMMUTABLE mirror of shared/threat/policyschema.go (allowedConditions /
-- allowedActions / allowedOperators). CA-0a wires this as a CHECK constraint
-- on its policy table so even a direct SQL write cannot persist an unknown
-- condition key / wrong-typed value / out-of-domain enum that would silently
-- widen a block policy to match-all (the fail-open regression, F6).
-- Keep in lockstep with the Go allow-list.
--
-- Allowed condition keys and their shapes (mirroring policyschema.go):
--   device_trust  → enum: managed|known|unknown|risky
--   ip_reputation → enum: low|medium|high|critical
--   geo_risk_tier → enum: low|medium|high|critical
--   user_group    → integer (numeric group ID)
--   auth_method   → string (single protocol string)
--   client_type   → enum: browser|native|imap|pop|smtp|activesync|legacy
--   time_of_day   → object with "start" + "end" string fields
CREATE OR REPLACE FUNCTION public.ca_validate_policy_document(
    p_conditions jsonb,
    p_grants     jsonb
) RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_key    text;
    v_val    jsonb;
    v_kind   text;
    v_enum   text[];
    v_action text;
    v_op     text;
    -- Allowed condition map: key → kind descriptor
    -- 'enum:a|b|c' = string restricted to the pipe-separated domain
    -- 'string'     = free-form string
    -- 'int'        = JSON number, must be integral
    -- 'time_range' = object with "start" + "end" string keys
    v_allowed jsonb := jsonb_build_object(
        'device_trust',  'enum:managed|known|unknown|risky',
        'ip_reputation', 'enum:low|medium|high|critical',
        'geo_risk_tier', 'enum:low|medium|high|critical',
        'user_group',    'int',
        'auth_method',   'string',
        'client_type',   'enum:browser|native|imap|pop|smtp|activesync|legacy',
        'time_of_day',   'time_range'
    );
BEGIN
    -- ── Validate conditions ───────────────────────────────────────────────
    IF p_conditions IS NOT NULL THEN
        FOR v_key, v_val IN SELECT * FROM jsonb_each(p_conditions) LOOP
            IF NOT (v_allowed ? v_key) THEN
                RETURN false;  -- unknown condition key
            END IF;

            v_kind := v_allowed ->> v_key;

            IF v_kind LIKE 'enum:%' THEN
                IF jsonb_typeof(v_val) <> 'string' THEN RETURN false; END IF;
                v_enum := string_to_array(substring(v_kind FROM 6), '|');
                IF NOT ((v_val #>> '{}') = ANY (v_enum)) THEN RETURN false; END IF;

            ELSIF v_kind = 'string' THEN
                IF jsonb_typeof(v_val) <> 'string' THEN RETURN false; END IF;

            ELSIF v_kind = 'int' THEN
                IF jsonb_typeof(v_val) <> 'number' THEN RETURN false; END IF;
                -- Require an integral value (no fractional part).
                IF (v_val #>> '{}') !~ '^-?[0-9]+$' THEN RETURN false; END IF;

            ELSIF v_kind = 'time_range' THEN
                IF jsonb_typeof(v_val) <> 'object'
                   OR jsonb_typeof(v_val -> 'start') <> 'string'
                   OR jsonb_typeof(v_val -> 'end')   <> 'string' THEN
                    RETURN false;
                END IF;
            END IF;
        END LOOP;
    END IF;

    -- ── Validate top-level grants action + operator ───────────────────────
    IF p_grants IS NOT NULL THEN
        v_action := p_grants ->> 'action';
        IF v_action IS NOT NULL
           AND v_action <> ALL (
               ARRAY['allow','block','step_up','notify','require_acr','require_strength']
           ) THEN
            RETURN false;
        END IF;

        v_op := p_grants ->> 'operator';
        IF v_op IS NOT NULL AND v_op <> ALL (ARRAY['all','one']) THEN
            RETURN false;
        END IF;
    END IF;

    RETURN true;
END;
$$;

-- ── F7: fail-closed posture default (admin-visible system_config) ──────────
-- The engine reads ca_fail_mode at startup; "closed" DENIES on an eval error
-- when an enforcing block policy exists (break-glass/exclude short-circuits
-- first). ON CONFLICT DO NOTHING: a manual admin override survives upgrades.
INSERT INTO public.system_config (key, value)
VALUES ('ca_fail_mode', '"closed"'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- ── schema_migrations row ────────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (45, now())
    ON CONFLICT (version) DO NOTHING;
