-- ════════════════════════════════════════════════════════════════════════
-- admin_effective_authority.sql — resolve a user's effective admin authority
--
-- p_active_only (DEFAULT TRUE):
--   TRUE  → ACTIVE-ONLY (JIT-gated): "what the user CURRENTLY wields". A dormant-
--           eligible assignment grants NOTHING. This is what every actor-authority
--           caller wants (default).
--   FALSE → PRE-JIT (eligible-OR-active): "what the user COULD wield", used for
--           TARGET protection (a dormant-eligible higher admin stays protected).
--           Replaces the former verbatim-duplicate admin_effective_authority_potential.
--
-- Produces: perms (union of active role perms) + scope (broadest-reach domain)
--           + ou_reach (broadest-reach OU subtree paths).
--
-- SCOPE SEMANTICS — broadest reach, not narrowest:
--   NULL (global) wins if ANY active role is unscoped/global.
--   Otherwise the scope is MIN(eff_scope) across active rows — the smallest
--   domain id among active domain-scoped assignments.
--
-- OU_REACH SEMANTICS — same broadest-reach rule, on the OU axis:
--   NULL/empty (no OU narrowing → reaches the whole domain) if ANY active
--   assignment has scope_type IS NULL. Otherwise the array of the active
--   OU-scoped assignments' department subtree paths. The guard treats a
--   target whose ou_reach is NULL/empty, or not fully contained in the
--   actor's union of subtrees, as out-ranking an OU-confined actor.
--
--   This is INTENTIONALLY the OPPOSITE of Go permissions.Resolve's
--   narrowest-non-NULL-wins logic.  The two serve different questions:
--     • permissions.Resolve asks "what is the tightest scope I must ENFORCE?"
--       (narrowest wins → deny by default outside that scope).
--     • admin_effective_authority asks "what is the broadest reach this actor
--       EXPOSES?" (broadest wins → guards and manageable-flag queries want the
--       widest possible exposure so they can correctly answer "can this actor
--       touch that target?").
--
-- STABLE: genuinely read-only; safe for index-only planning, no locks.
-- ════════════════════════════════════════════════════════════════════════
-- Drop the old 1-arg signature so the unified 2-arg (defaulted) form replaces it;
-- CREATE OR REPLACE cannot add a parameter, only a sibling overload, and a 1-arg
-- call would then resolve to the old function instead of the defaulted new one.
DROP FUNCTION IF EXISTS admin_effective_authority(BIGINT);
CREATE OR REPLACE FUNCTION admin_effective_authority(
  p_user_id     BIGINT,
  p_active_only BOOLEAN DEFAULT TRUE
)
RETURNS TABLE(perms TEXT[], scope BIGINT, ou_reach TEXT[], is_unconfined BOOLEAN) AS $$
  WITH active AS (
    SELECT rg.permissions,
           COALESCE(ra.domain_override, rg.domain_scope) AS eff_scope,
           ra.scope_type,
           sd.path AS ou_path
      FROM admin_role_assignments ra
      JOIN admin_role_groups rg ON rg.id = ra.role_group_id
      LEFT JOIN departments sd ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
     WHERE ra.user_id = p_user_id
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       -- active-only callers (default) require the JIT gate; pre-JIT (target
       -- protection) callers pass FALSE to include dormant-eligible assignments.
       AND (NOT p_active_only OR admin_assignment_active(ra.eligible, ra.activated_until))
  )
  SELECT
    COALESCE((SELECT array_agg(DISTINCT p) FROM active, unnest(active.permissions) AS p), '{}')::text[],
    -- broadest reach: NULL (global) if ANY active role is global, else the narrowest domain
    CASE WHEN EXISTS (SELECT 1 FROM active WHERE eff_scope IS NULL)
         THEN NULL
         ELSE (SELECT MIN(eff_scope) FROM active) END,
    -- broadest OU reach: NULL (no narrowing → whole domain) if ANY active
    -- assignment is un-OU-scoped; else the active OU subtree paths.
    CASE WHEN EXISTS (SELECT 1 FROM active WHERE scope_type IS NULL)
         THEN NULL
         ELSE (SELECT array_agg(DISTINCT ou_path) FROM active WHERE ou_path IS NOT NULL) END,
    -- is_unconfined: TRUE iff the actor holds ANY active object-unrestricted
    -- (scope_type IS NULL) grant — i.e. one that reaches the whole (domain-
    -- limited) object space. NEVER inferred from a NULL/empty ou_reach array
    -- (the v1/v2 P0: a 'set'-confined actor has ou_reach NULL yet is confined).
    EXISTS (SELECT 1 FROM active WHERE scope_type IS NULL);
$$ LANGUAGE sql STABLE;
