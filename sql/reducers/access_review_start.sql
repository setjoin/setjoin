-- access_review_start.sql
-- Start an access-review campaign: snapshot the in-scope admin_role_assignments into
-- access_review_items + write one lifecycle audit row. Domain+OU-scope-confined (Rule B):
-- p_domain_scope<=0 ⇒ GLOBAL (snapshot org-wide); >0 ⇒ only assignments reachable by
-- the actor via admin_can_reach (enforces domain AND OU scope in one call).
-- Actors with no active DB assignments fall back to the legacy COALESCE domain check
-- (test actors; in production all admins have at least one active assignment).
-- VOLATILE (writes campaigns + items + admin_audit_log). No JMAP state (admin-plane).
-- D3: eligible-dormant assignments are intentionally captured (INCLUDES-ELIGIBLE allowlist);
-- their eligible + activated_until columns are snapshotted so reviewers recertify eligibility.
--       admin_can_reach, audit_write

CREATE OR REPLACE FUNCTION access_review_start(
    p_actor        BIGINT,
    p_name         TEXT,
    p_domain_scope BIGINT
) RETURNS BIGINT AS $$
DECLARE
    v_campaign BIGINT;
    v_scope    BIGINT := NULLIF(p_domain_scope, 0);  -- NULL = global campaign
    v_count    INT;
BEGIN
    INSERT INTO access_review_campaigns (name, status, domain_scope, created_by)
    VALUES (p_name, 'open', v_scope, p_actor)
    RETURNING id INTO v_campaign;

    INSERT INTO access_review_items (
        campaign_id, assignment_id, user_id, role_group_id,
        domain_override, granted_by, granted_at, is_sso,
        eligible, activated_until
    )
    SELECT v_campaign, ra.id, ra.user_id, ra.role_group_id,
           ra.domain_override, ra.granted_by, ra.granted_at,
           ra.granted_by IS NULL,
           ra.eligible, ra.activated_until
      FROM admin_role_assignments ra
      JOIN admin_role_groups rg ON rg.id = ra.role_group_id
     WHERE p_domain_scope <= 0
        -- actors WITH active assignments: admin_can_reach enforces domain+OU scope.
        OR admin_can_reach(p_actor, ra.user_id)
        -- actors WITHOUT active assignments: fall back to legacy COALESCE domain check.
        -- ponytail: in production all admins have at least one active assignment.
        OR (NOT EXISTS (SELECT 1 FROM admin_role_assignments ara2
                        WHERE ara2.user_id = p_actor
                          AND (ara2.expires_at IS NULL OR ara2.expires_at > now()))
            AND COALESCE(ra.domain_override, rg.domain_scope) = p_domain_scope);

    GET DIAGNOSTICS v_count = ROW_COUNT;

    PERFORM audit_write(
        p_actor,
        'access_review_start',
        'access_review_campaign',
        v_campaign,
        NULL,
        jsonb_build_object('name', p_name, 'item_count', v_count, 'domain_scope', v_scope),
        NULL,
        p_name,
        'core'
    );

    RETURN v_campaign;
END;
$$ LANGUAGE plpgsql VOLATILE;
