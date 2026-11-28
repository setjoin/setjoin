-- ════════════════════════════════════════════════════════════════════════
-- V051__ca_location_matcher.sql — CA-1 A2 lockstep: add location_in +
-- location_trusted to the F6 SQL allow-list (ca_validate_policy_document).
--
-- The Go side (shared/threat/policyschema.go allowedConditions) gains these
-- two keys in the same commit. The SQL function is IMMUTABLE CREATE OR REPLACE —
-- safe to re-run.
--
-- LOCKSTEP (CA-F rule): condition key additions are shipped in both the Go
-- allow-list (policyschema.go) AND this SQL mirror simultaneously.
-- ════════════════════════════════════════════════════════════════════════

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
    -- 'bool'       = JSON boolean (true/false)
    -- auth_strength: OMITTED — no engine matcher yet (CA-1 A3).
    v_allowed jsonb := jsonb_build_object(
        'device_trust',    'enum:managed|known|unknown|risky',
        'ip_reputation',   'enum:low|medium|high|critical',
        'geo_risk_tier',   'enum:low|medium|high|critical',
        'user_group',      'int',
        'auth_method',     'string',
        'client_type',     'enum:browser|native|imap|pop|smtp|activesync|legacy',
        'time_of_day',     'time_range',
        'location_in',     'int',
        'location_trusted','bool'
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

            ELSIF v_kind = 'bool' THEN
                IF jsonb_typeof(v_val) <> 'boolean' THEN RETURN false; END IF;
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
INSERT INTO public.schema_migrations (version, applied_at) VALUES (51, now())
    ON CONFLICT (version) DO NOTHING;
