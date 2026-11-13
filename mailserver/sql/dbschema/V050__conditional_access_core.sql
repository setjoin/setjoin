-- ════════════════════════════════════════════════════════════════════════
-- V050__conditional_access_core.sql — CA-1 core schema (CA-1 B1).
--
-- Produces:
--   • named_locations — IP-range / country-set location objects for
--     location_in condition (CA-1 reducers reference this by id).
--   • auth_strengths — ordered authenticator-combination requirements
--     (phishing-resistant / passwordless / mfa built-in seeds).
--   • ca_templates — starter policy templates (block-legacy-auth,
--     mfa-for-admins, block-by-geo).
--   • conditional_access_policies ALTER:
--       - created_from_template text NOT NULL DEFAULT ''
--       - deleted_at timestamptz (soft-delete)
--       - scope_type CHECK widened to include 'role'
--       - priority partial-unique index rebuilt: WHERE state='on' AND deleted_at IS NULL
--   • Baseline seed (id 1–5) actions converted from bare {"action":"X"} to
--     grant-array form {"operator":"all","grants":[{"action":"X"},…],"reason":"…"}
--     so the engine can route through the nested-grants branch.
--
-- LOCKSTEP (CA-F rule): 'named_location' + 'auth_strength' condition keys are
-- added to the F6 SQL allow-list (ca_validate_policy_document) AND to the Go
-- allow-list (shared/threat/policyschema.go allowedConditions) in this same
-- migration so the write path accepts them.
--
-- ponytail: RLS on named_locations / auth_strengths / ca_templates follows the
-- admin-table model (no per-user RLS; access is gated by access.policy_* perms
-- at the application layer, same as conditional_access_policies itself).
-- ════════════════════════════════════════════════════════════════════════

-- ── named_locations ──────────────────────────────────────────────────────────
-- Stores named sets of IP ranges and/or country codes that CA conditions can
-- reference by id (location_in condition, CA-1+).
CREATE TABLE IF NOT EXISTS public.named_locations (
    id          bigserial PRIMARY KEY,
    name        text                     NOT NULL,
    description text                     NOT NULL DEFAULT '',
    -- ip_ranges: array of CIDR strings, e.g. ["10.0.0.0/8","192.168.0.0/16"]
    ip_ranges   jsonb                    NOT NULL DEFAULT '[]'::jsonb,
    -- countries: ISO 3166-1 alpha-2 codes, e.g. ["CN","RU"]
    countries   jsonb                    NOT NULL DEFAULT '[]'::jsonb,
    is_trusted  boolean                  NOT NULL DEFAULT false,
    created_at  timestamp with time zone NOT NULL DEFAULT now(),
    updated_at  timestamp with time zone NOT NULL DEFAULT now(),
    deleted_at  timestamp with time zone,
    CONSTRAINT named_locations_ip_ranges_is_array  CHECK (jsonb_typeof(ip_ranges)  = 'array'),
    CONSTRAINT named_locations_countries_is_array  CHECK (jsonb_typeof(countries)  = 'array')
);

CREATE UNIQUE INDEX IF NOT EXISTS named_locations_name_unique_idx
    ON public.named_locations (name) WHERE deleted_at IS NULL;

-- ── auth_strengths ────────────────────────────────────────────────────────────
-- Named authenticator-combination requirements (ordered alternatives):
--   requirement: JSON array of arrays — outer = OR alternatives (any row satisfies),
--                inner = AND combinators (all methods in the row must be present).
-- Example: [["webauthn"]] = must use WebAuthn.
-- Example: [["password","totp"],["password","push"],["webauthn"]] = MFA (multiple options).
CREATE TABLE IF NOT EXISTS public.auth_strengths (
    id          bigserial PRIMARY KEY,
    slug        text                     NOT NULL,
    name        text                     NOT NULL,
    description text                     NOT NULL DEFAULT '',
    requirement jsonb                    NOT NULL DEFAULT '[]'::jsonb,
    min_acr     text                     NOT NULL DEFAULT 'aal1',
    builtin     boolean                  NOT NULL DEFAULT false,
    created_at  timestamp with time zone NOT NULL DEFAULT now(),
    updated_at  timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT auth_strengths_requirement_is_array CHECK (jsonb_typeof(requirement) = 'array'),
    CONSTRAINT auth_strengths_min_acr_check        CHECK (min_acr IN ('aal1','aal2','aal3'))
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_strengths_slug_unique_idx
    ON public.auth_strengths (slug);

-- 3 built-in auth-strength seeds (builtin=true → not deletable by admins).
INSERT INTO public.auth_strengths (slug, name, description, requirement, min_acr, builtin) VALUES
  ('phishing-resistant',
   'Phishing-resistant MFA',
   'Hardware key or platform authenticator only (WebAuthn/FIDO2). Strongest available.',
   '[["webauthn"]]'::jsonb,
   'aal2',
   true),
  ('passwordless',
   'Passwordless',
   'Password-free sign-in via hardware key or push approval.',
   '[["webauthn"],["push"]]'::jsonb,
   'aal2',
   true),
  ('mfa',
   'Multi-factor authentication',
   'Any combination of password + second factor (TOTP, push, or WebAuthn).',
   '[["password","totp"],["password","push"],["webauthn"]]'::jsonb,
   'aal2',
   true)
ON CONFLICT (slug) DO NOTHING;

-- ── conditional_access_policies: soft-delete + template reference ─────────────
ALTER TABLE public.conditional_access_policies
    ADD COLUMN IF NOT EXISTS created_from_template text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS deleted_at            timestamptz;

-- ── scope_type CHECK: add 'role' ─────────────────────────────────────────────
-- Drop by name then recreate with the full value set (same pattern as V084).
ALTER TABLE public.conditional_access_policies
    DROP CONSTRAINT IF EXISTS conditional_access_policies_scope_type_check;

ALTER TABLE public.conditional_access_policies
    ADD CONSTRAINT conditional_access_policies_scope_type_check
        CHECK (scope_type = ANY (ARRAY['global'::text, 'user'::text, 'group'::text, 'role'::text]));

-- ── priority partial-unique index: rebuild with state+deleted_at predicate ────
-- Old: WHERE enabled (derived bool, kept for backcompat through CA-1).
-- New: WHERE state='on' AND deleted_at IS NULL — uses the authoritative column
--      (state, not the trigger-derived bool) and excludes soft-deleted rows.
DROP INDEX IF EXISTS public.ca_policies_priority_unique_idx;

CREATE UNIQUE INDEX ca_policies_priority_unique_idx
    ON public.conditional_access_policies (priority)
    WHERE state = 'on' AND deleted_at IS NULL;

-- ── Baseline seeds: convert to grant-array shape ──────────────────────────────
-- Old shape: {"action":"X","reason":"…","methods":[…],"channels":[…]}
-- New shape: {"operator":"all","grants":[{"action":"X"}[,{"action":"notify",…}]],"reason":"…"}
-- The CA engine routes through the nested-grants branch when "operator" is present.
-- The CA-F validator (ca_validate_policy_document) accepts nested grants with "action".
-- ponytail: per-row UPDATE rather than a generic transform — 5 known seeds, explicit is clear.

-- Seed 1: block critical countries
UPDATE public.conditional_access_policies
   SET actions = '{"operator":"all","grants":[{"action":"block"}],"reason":"Authentication from critical-risk country is blocked"}'::jsonb
 WHERE id = 1 AND actions ? 'action';

-- Seed 2: step-up high-risk + unknown device
UPDATE public.conditional_access_policies
   SET actions = '{"operator":"all","grants":[{"action":"step_up","methods":["totp","webauthn"]}],"reason":"MFA required for high-risk country sign-in with unknown device"}'::jsonb
 WHERE id = 2 AND actions ? 'action';

-- Seed 3: step-up risky device
UPDATE public.conditional_access_policies
   SET actions = '{"operator":"all","grants":[{"action":"step_up","methods":["totp","webauthn","push"]}],"reason":"MFA required for unrecognized device"}'::jsonb
 WHERE id = 3 AND actions ? 'action';

-- Seed 4: block medium IP risk + critical country
UPDATE public.conditional_access_policies
   SET actions = '{"operator":"all","grants":[{"action":"block"}],"reason":"Suspicious IP from critical-risk country"}'::jsonb
 WHERE id = 4 AND actions ? 'action';

-- Seed 5: notify high IP risk
UPDATE public.conditional_access_policies
   SET actions = '{"operator":"all","grants":[{"action":"notify","channels":["admin_alert","audit"]}],"reason":"High IP risk score detected"}'::jsonb
 WHERE id = 5 AND actions ? 'action';

-- ── ca_templates ──────────────────────────────────────────────────────────────
-- Starter policy templates an admin can instantiate. Stores conditions/actions
-- JSONB in the same shape as conditional_access_policies so the CA-1 import
-- reducer can INSERT directly.
CREATE TABLE IF NOT EXISTS public.ca_templates (
    id          bigserial PRIMARY KEY,
    slug        text                     NOT NULL,
    name        text                     NOT NULL,
    description text                     NOT NULL DEFAULT '',
    scope_type  text                     NOT NULL DEFAULT 'global',
    -- scope_target: for role-scoped templates, the role group name (resolved to id
    -- at instantiation time); empty for global templates.
    scope_target text                    NOT NULL DEFAULT '',
    conditions  jsonb                    NOT NULL DEFAULT '{}'::jsonb,
    actions     jsonb                    NOT NULL DEFAULT '{}'::jsonb,
    -- suggested_priority: hint for the UI; admin overrides on instantiation.
    suggested_priority integer           NOT NULL DEFAULT 100,
    created_at  timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT ca_templates_slug_key UNIQUE (slug),
    CONSTRAINT ca_templates_scope_type_check
        CHECK (scope_type = ANY (ARRAY['global'::text, 'user'::text, 'group'::text, 'role'::text]))
);

-- 3 starter templates
INSERT INTO public.ca_templates (slug, name, description, scope_type, scope_target, conditions, actions, suggested_priority) VALUES

  ('block-legacy-auth',
   'Block legacy authentication',
   'Block all authentication from legacy mail clients (IMAP/POP/SMTP basic auth). Requires modern auth for all access.',
   'global',
   '',
   '{"client_type":"legacy"}'::jsonb,
   '{"operator":"all","grants":[{"action":"block"}],"reason":"Legacy authentication protocols are blocked"}'::jsonb,
   10),

  ('mfa-for-admins',
   'Require MFA for admins',
   'Require multi-factor authentication for all members of the Super Admin role group.',
   'role',
   'Super Admin',
   '{}'::jsonb,
   '{"operator":"all","grants":[{"action":"step_up","methods":["totp","webauthn","push"]}],"reason":"MFA required for admin access"}'::jsonb,
   20),

  ('block-by-geo',
   'Block high-risk countries',
   'Block authentication originating from critical-risk countries.',
   'global',
   '',
   '{"geo_risk_tier":"critical"}'::jsonb,
   '{"operator":"all","grants":[{"action":"block"}],"reason":"Authentication from critical-risk country blocked"}'::jsonb,
   30)

ON CONFLICT (slug) DO NOTHING;

-- ── F6 lockstep: extend ca_validate_policy_document (keep allow-list in sync) ──
-- LOCKSTEP (CA-F rule): Go policyschema.go and this SQL mirror MUST stay in sync.
-- named_location and auth_strength are NOT included here: V030 adds the schema
-- tables but no engine matchers yet. Including them in the allow-list while
-- matchAll silently ignores them causes a fail-open: a block policy with
-- conditions:{"named_location":5} would match every principal. Both sides are
-- omitted until matchNamedLocation / matchAuthStrength land in policy.go.
-- The SQL function is IMMUTABLE CREATE OR REPLACE — safe to re-run.
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
    v_grant  jsonb;
    -- Allowed condition map: key → kind descriptor
    -- 'enum:a|b|c' = string restricted to the pipe-separated domain
    -- 'string'     = free-form string
    -- 'int'        = JSON number, must be integral
    -- 'time_range' = object with "start" + "end" string keys
    -- named_location / auth_strength: OMITTED — no engine matchers yet (see comment above).
    v_allowed jsonb := jsonb_build_object(
        'device_trust',    'enum:managed|known|unknown|risky',
        'ip_reputation',   'enum:low|medium|high|critical',
        'geo_risk_tier',   'enum:low|medium|high|critical',
        'user_group',      'int',
        'auth_method',     'string',
        'client_type',     'enum:browser|native|imap|pop|smtp|activesync|legacy',
        'time_of_day',     'time_range'
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

    -- ── Validate top-level grants action + operator; recurse into grants array ─
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

        -- Recurse into nested grants array
        IF p_grants ? 'grants' THEN
            IF jsonb_typeof(p_grants -> 'grants') <> 'array' THEN RETURN false; END IF;
            FOR v_grant IN SELECT * FROM jsonb_array_elements(p_grants -> 'grants') LOOP
                IF NOT ca_validate_policy_document(NULL, v_grant) THEN
                    RETURN false;
                END IF;
            END LOOP;
        END IF;
    END IF;

    RETURN true;
END;
$$;

-- ── schema_migrations row ────────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (50, now())
    ON CONFLICT (version) DO NOTHING;
