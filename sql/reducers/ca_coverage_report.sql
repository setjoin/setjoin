-- ca_coverage_report.sql — CA-1 C7: gap check + shadowed/unreachable-rule detector.
--
-- Returns JSONB: {
--   gaps:     [{kind, detail, severity}]  — uncovered client_type or scope
--   shadowed: [{policy_id, policy_name, priority,
--               shadowed_by_id, shadowed_by_name, shadowed_by_priority, reason}]
-- }
--
-- Gap semantics:
--   kind='client_type': no live policy with conditions->>'client_type' = detail
--     severity='danger'   for imap, smtp  (auth-protocol: high blast-radius)
--     severity='warning'  for web, mobile
--   kind='scope': no live policy with scope_type = detail
--     severity='warning'  for role, group
--
-- Shadow semantics:
--   Policy P (lower priority number Q) is "shadowed" by Q when:
--     Q.priority < P.priority  (Q evaluates first in first-match order)
--     Q.conditions is a subset of P.conditions (P.conditions @> Q.conditions)
--       → everywhere Q would fire, P also would fire — but Q wins, so P is unreachable
--     same grant action (first element of the grants array)
--   Advisory only — no mutation, no audit, no notify.
--
-- ponytail: STABLE + no parameters. PG JSONB operators (@>, ?, #>>) do all
--   the heavy lifting; no procedural loops needed for either check.
--
-- Read-only: no BZ codes, no audit, no notify (same pattern as ca_policy_impact).

CREATE OR REPLACE FUNCTION ca_coverage_report()
RETURNS JSONB AS $$
DECLARE
    v_gaps     JSONB;
    v_shadowed JSONB;
BEGIN
    -- ── Gap check ─────────────────────────────────────────────────────────────
    -- Live policy = state != 'off' AND deleted_at IS NULL
    -- ponytail: VALUES list + LEFT JOIN lets us check all protocols in one scan.
    SELECT jsonb_agg(
        jsonb_build_object(
            'kind',     proto.kind,
            'detail',   proto.detail,
            'severity', proto.severity
        ) ORDER BY proto.severity DESC, proto.detail
    )
    INTO v_gaps
    FROM (VALUES
        ('client_type', 'imap',   'danger'),
        ('client_type', 'smtp',   'danger'),
        ('client_type', 'web',    'warning'),
        ('client_type', 'mobile', 'warning'),
        ('scope',       'role',   'warning'),
        ('scope',       'group',  'warning')
    ) AS proto(kind, detail, severity)
    WHERE NOT EXISTS (
        SELECT 1 FROM conditional_access_policies p
        WHERE p.deleted_at IS NULL
          AND p.state <> 'off'
          AND CASE proto.kind
                WHEN 'client_type' THEN p.conditions->>'client_type' = proto.detail
                WHEN 'scope'       THEN p.scope_type = proto.detail
              END
    );

    -- ── Shadow detector ───────────────────────────────────────────────────────
    -- P is shadowed by Q when:
    --   Q.priority < P.priority (Q fires first)
    --   P.conditions @> Q.conditions (P conditions are a superset of Q's)
    --   same first grant action
    SELECT jsonb_agg(
        jsonb_build_object(
            'policy_id',            p.id,
            'policy_name',          p.name,
            'priority',             p.priority,
            'shadowed_by_id',       q.id,
            'shadowed_by_name',     q.name,
            'shadowed_by_priority', q.priority,
            'reason',               'conditions are a superset of the higher-priority policy'
        ) ORDER BY p.priority, q.priority
    )
    INTO v_shadowed
    FROM conditional_access_policies p
    JOIN conditional_access_policies q
      ON q.deleted_at IS NULL
     AND q.state <> 'off'
     AND q.priority < p.priority
     -- P.conditions is a superset of Q.conditions → P @> Q
     AND p.conditions @> q.conditions
     -- same runtime-equivalent first action across canonical and schema-v1 forms
     AND ca_policy_effective_action(p.actions)
       = ca_policy_effective_action(q.actions)
    WHERE p.deleted_at IS NULL
      AND p.state <> 'off';

    RETURN jsonb_build_object(
        'gaps',     COALESCE(v_gaps,     '[]'::jsonb),
        'shadowed', COALESCE(v_shadowed, '[]'::jsonb)
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public;
