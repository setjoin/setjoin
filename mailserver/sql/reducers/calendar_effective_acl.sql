-- calendar_effective_acl.sql — the headline (viewer, owner) visibility
-- resolver (spec 2026-06-27-sharing-delegation-design.md §5).
--
--   1. EXPLICIT GRANT — a calendar_acls row for (O's primary calendar, V)
--      returns that level (D5: explicit always wins; D6: the default unit is
--      the owner's PRIMARY calendar — secondary-calendar grants keep their
--      per-calendar meaning in the shared-read reducers, they do not decide
--      this per-owner answer).
--   2. sharing.defaults toggle OFF → 'none' (D11: the ladder is skipped
--      entirely; explicit-only = today's behavior, byte-identical).
--   3. DEFAULTS LADDER — sharing_default_resolve (most-specific-wins across
--      tiers, most-permissive within a tier, D4); fail-closed 'none' (D10).
--
-- viewer = owner short-circuits to 'admin' (owners reach their own calendars
-- through the owned path; this keeps the resolver total and safe).
CREATE OR REPLACE FUNCTION calendar_effective_acl(
  p_viewer_user_id BIGINT,
  p_owner_user_id  BIGINT
) RETURNS TEXT AS $$
DECLARE
  v_primary_cal BIGINT;
  v_level       TEXT;
BEGIN
  IF p_viewer_user_id = p_owner_user_id THEN
    RETURN 'admin';
  END IF;

  -- O's primary calendar: the default calendar on O's primary mailbox
  -- (calendars_default_idx guarantees at most one is_default per mailbox;
  -- fall back to the lowest id if none is flagged).
  SELECT c.id INTO v_primary_cal
    FROM calendars c
    JOIN mailboxes m ON m.id = c.mailbox_id
   WHERE m.user_id = p_owner_user_id AND m.is_primary
   ORDER BY c.is_default DESC, c.id
   LIMIT 1;

  IF v_primary_cal IS NOT NULL THEN
    SELECT permission INTO v_level FROM calendar_acls
     WHERE calendar_id = v_primary_cal AND user_id = p_viewer_user_id;
    IF v_level IS NOT NULL THEN
      RETURN v_level;
    END IF;
  END IF;

  -- D11: toggle OFF ⇒ explicit-only (the ladder never runs).
  IF NOT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'sharing.defaults'), FALSE) THEN
    RETURN 'none';
  END IF;

  RETURN sharing_default_resolve(p_viewer_user_id, p_owner_user_id, 'calendar');
END;
$$ LANGUAGE plpgsql STABLE;
