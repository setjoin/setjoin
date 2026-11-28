-- admin_assignment_active: is this admin_role_assignments row currently GRANTING
-- permissions/reach? The single source of truth for the JIT eligibility gate, layered
-- ON TOP of the existing `expires_at` filter at every call site. Reads the rbac.jit
-- toggle INTERNALLY so the gate can never be forgotten at a site (D7). Toggle OFF
-- (default) ⇒ every row active (behaviorally inert). ON ⇒ an eligible row grants only
-- while its activation window is open.
CREATE OR REPLACE FUNCTION admin_assignment_active(p_eligible boolean, p_activated_until timestamptz)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'rbac.jit'), false)
      OR p_eligible = false
      OR (p_activated_until IS NOT NULL AND p_activated_until > now());
$$;
