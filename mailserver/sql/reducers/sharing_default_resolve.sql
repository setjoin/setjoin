-- sharing_default_resolve.sql — the defaults-only resolution ladder (spec
-- 2026-06-27-sharing-delegation-design.md §5). PURE ladder math: no toggle
-- check here — calendar_effective_acl owns the D11 short-circuit (and the D5
-- explicit-grant step above it). Admin/preview surfaces may call this directly.
--
-- Tier precedence (D4, most-specific-wins):
--   user (owner_ref = O) ▸ group (O ∈ members) ▸ ou (O.department_id) ▸ org (O.domain_id)
-- Tie within one tier → most-permissive level (none < freebusy < read).
-- Audience membership of viewer V (D7 — 'everyone' is domain-scoped):
--   everyone → V.domain_id = audience_ref
--   ou       → V.department_id = audience_ref
--   group    → V's mailbox ∈ distribution_group_members(audience_ref)
-- No matching row → 'none' (无 — fail-closed, D10).
CREATE OR REPLACE FUNCTION sharing_default_resolve(
  p_viewer_user_id BIGINT,
  p_owner_user_id  BIGINT,
  p_resource       TEXT
) RETURNS TEXT AS $$
  SELECT COALESCE(
    (SELECT sd.level
       FROM sharing_defaults sd
       JOIN users o ON o.id = p_owner_user_id
       JOIN users v ON v.id = p_viewer_user_id
      WHERE sd.resource = p_resource
        -- O ∈ owner_scope
        AND (   (sd.owner_scope = 'user'  AND sd.owner_ref = o.id)
             OR (sd.owner_scope = 'group' AND EXISTS (
                   SELECT 1 FROM distribution_group_members dgm
                   JOIN mailboxes m ON m.id = dgm.mailbox_id
                  WHERE dgm.group_id = sd.owner_ref AND m.user_id = o.id))
             OR (sd.owner_scope = 'ou'    AND o.department_id = sd.owner_ref)
             OR (sd.owner_scope = 'org'   AND o.domain_id     = sd.owner_ref))
        -- V ∈ audience
        AND (   (sd.audience = 'everyone' AND v.domain_id     = sd.audience_ref)
             OR (sd.audience = 'ou'       AND v.department_id = sd.audience_ref)
             OR (sd.audience = 'group'    AND EXISTS (
                   SELECT 1 FROM distribution_group_members dgm
                   JOIN mailboxes m ON m.id = dgm.mailbox_id
                  WHERE dgm.group_id = sd.audience_ref AND m.user_id = v.id)))
      ORDER BY
        CASE sd.owner_scope WHEN 'user' THEN 1 WHEN 'group' THEN 2 WHEN 'ou' THEN 3 ELSE 4 END,
        CASE sd.level WHEN 'read' THEN 1 WHEN 'freebusy' THEN 2 ELSE 3 END
      LIMIT 1),
    'none');
$$ LANGUAGE sql STABLE;
