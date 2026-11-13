-- access_review_decide_bulk.sql
-- Apply one decision to many items in a single transaction (backs the bulk bar +
-- "Keep all remaining"). Same campaign existence/scope/open guards as _decide (raised
-- once). A bulk REVOKE skips SSO items (NOT(p_decision='revoke' AND is_sso)) so one SSO
-- row can't fail the batch. SoD: a self item (user_id = p_actor) is always skipped — an
-- actor may not certify their own access (mirrors _decide's BZ069). Returns
-- {applied, skipped}; writes ONE summary audit row. VOLATILE.

CREATE OR REPLACE FUNCTION access_review_decide_bulk(
    p_actor        BIGINT,
    p_campaign_id  BIGINT,
    p_item_ids     BIGINT[],
    p_decision     TEXT,
    p_domain_scope BIGINT
) RETURNS JSONB AS $$
DECLARE
    v_applied INT;
    v_total   INT := COALESCE(cardinality(p_item_ids), 0);
BEGIN
    PERFORM access_review_assert_open(p_campaign_id, p_domain_scope);

    UPDATE access_review_items
       SET decision = p_decision, decided_by = p_actor, decided_at = now()
     WHERE campaign_id = p_campaign_id
       AND id = ANY(p_item_ids)
       AND NOT (p_decision = 'revoke' AND is_sso)   -- bulk revoke skips SSO
       AND user_id <> p_actor                        -- SoD: never self-certify
       -- OU-scope: a scoped actor's bulk REVOKE skips items it can't reach (mirrors
       -- access_review_close's per-item DELETE gate + the single-decide guard, so the
       -- recorded revoke matches what close will actually apply). Global (scope<=0) bypass.
       AND (p_domain_scope <= 0 OR p_decision <> 'revoke' OR admin_can_reach(p_actor, user_id));
    GET DIAGNOSTICS v_applied = ROW_COUNT;

    PERFORM audit_write(
        p_actor,
        'access_review_decide_bulk',
        'access_review_campaign',
        p_campaign_id,
        NULL,
        jsonb_build_object('decision', p_decision, 'applied', v_applied,
                           'skipped', v_total - v_applied),
        NULL,
        NULL,
        'core'
    );

    RETURN jsonb_build_object('applied', v_applied, 'skipped', v_total - v_applied);
END;
$$ LANGUAGE plpgsql VOLATILE;
