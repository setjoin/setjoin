-- ════════════════════════════════════════════════════════════════════════
-- V046__ca_state_exclude_breakglass.sql — CA-0a forward migration.
--
-- Adds the tri-state policy `state` enum (off|report_only|on) that replaces the
-- bare `enabled` boolean's semantics, plus per-policy break-glass exclude lists
-- (exclude_users / exclude_groups), and seeds the system break-glass set.
--
-- `enabled` is KEPT for one phase as a trigger-mirrored shadow so the existing
-- unique partial index on (priority) WHERE enabled (V001:8374) and any un-migrated
-- reader keep working. CA-1 drops the bool.
--
-- HAZARD (Locked L2): ca_sync_enabled() is the SOLE writer of `enabled`; it
-- UNCONDITIONALLY overwrites NEW.enabled := (NEW.state='on'). Any caller that
-- writes `enabled` directly is SILENTLY OVERRIDDEN. After V026 NO caller may write
-- `enabled` — the handler and ca_policy_upsert write `state` ONLY.
--
-- F6 (wired here, substrate in V025): ca_validate_policy_document is attached as
-- a CHECK constraint so even a direct SQL write cannot persist an unknown condition
-- key or out-of-domain enum (the fail-open regression). The SQL function parameter
-- is p_grants; it maps to the `actions` column. The Go handler also calls
-- ValidatePolicyDocument() before the reducer so bad writes are rejected at
-- authoring time with HTTP 400 (defence in depth — handler is first; constraint
-- is the un-bypassable floor). Boundary: Go recurses nested grants; SQL validates
-- top-level — keep the two allow-lists in lockstep (per CA-F comment in V025).
--
-- F6 CHECK on existing rows: all 5 seed fixture policies (V001:12232-12236) use
-- only allow-listed condition keys (geo_risk_tier, device_trust, ip_reputation)
-- and valid actions (block, step_up, notify). Verified before V026 was authored;
-- the CHECK is added as a fully-validated (not NOT VALID) constraint. If this
-- ALTER fails on a real deployment it means a manually-inserted policy with an
-- unknown key exists in the DB — clean it up or use NOT VALID + VALIDATE separately.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE conditional_access_policies
  ADD COLUMN state          text  NOT NULL DEFAULT 'off'
       CHECK (state IN ('off','report_only','on')),
  ADD COLUMN exclude_users  jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN exclude_groups jsonb NOT NULL DEFAULT '[]'::jsonb;

-- Back-fill state from the legacy bool BEFORE the trigger exists (so the UPDATE
-- is a plain write, not a no-op the trigger would re-derive).
UPDATE conditional_access_policies SET state = CASE WHEN enabled THEN 'on' ELSE 'off' END;

-- Keep `enabled` in lock-step with `state`. SOLE writer of enabled (see HAZARD).
-- On INSERT: derive `state` from the incoming `enabled` first (back-compat for
-- legacy callers that only write `enabled`), then unconditionally write `enabled`
-- back from `state` so `enabled` is always the sole-derived column.
-- On UPDATE: `state` is authoritative — `enabled` is always overwritten from it
-- (SILENTLY OVERRIDES any direct write to `enabled`).
CREATE OR REPLACE FUNCTION ca_sync_enabled() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.state = 'off' AND NEW.enabled = TRUE THEN
    -- Legacy INSERT path: caller wrote enabled=TRUE without state; back-fill state.
    NEW.state := 'on';
  END IF;
  -- Always derive enabled from state (sole writer).
  NEW.enabled := (NEW.state = 'on');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ca_sync_enabled_trg
  BEFORE INSERT OR UPDATE ON conditional_access_policies
  FOR EACH ROW EXECUTE FUNCTION ca_sync_enabled();

-- Defence-in-depth: exclude lists must be JSON arrays.
ALTER TABLE conditional_access_policies
  ADD CONSTRAINT ca_exclude_users_is_array  CHECK (jsonb_typeof(exclude_users)  = 'array'),
  ADD CONSTRAINT ca_exclude_groups_is_array CHECK (jsonb_typeof(exclude_groups) = 'array');

-- F6 defence-in-depth: wire the CA-F substrate validator as a row-level CHECK so
-- even a direct SQL write cannot persist an unknown condition key / wrong-typed
-- value / out-of-domain enum. ca_validate_policy_document(p_conditions, p_grants)
-- is IMMUTABLE (V025); p_grants maps to the `actions` column (that is its column
-- name in this table). Returns false → check_violation (SQLSTATE 23514) which the
-- Go handler maps to HTTP 400.
ALTER TABLE conditional_access_policies
  ADD CONSTRAINT ca_policy_doc_valid
    CHECK (ca_validate_policy_document(conditions, actions));

-- Seed the system break-glass set (admin sets it to ≥1 dedicated MFA-strong admin
-- BEFORE authoring any `on` block policy — step zero). Idempotent.
INSERT INTO system_config (key, value, encrypted, description)
VALUES (
  'ca_break_glass_user_ids', '[]'::jsonb, false,
  'Conditional-access break-glass: user ids always excluded from every on+global+block policy (set BEFORE the first block policy; consulted by ca_lockout_guard + the engine)'
)
ON CONFLICT (key) DO NOTHING;

-- ── schema_migrations row ────────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (46, now())
    ON CONFLICT (version) DO NOTHING;
