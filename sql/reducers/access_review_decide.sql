-- access_review_decide.sql
-- Record a Keep/Revoke decision on one review item. Guards: campaign exists (BZ060→404),
-- in the actor's scope (BZ061→403), open (BZ062→409); a revoke of an SSO item is blocked
-- (BZ063→409); an actor may not certify their OWN access — separation of duties (BZ069→403).
-- A bad item id raises BZ060 (no silent 200). Writes a lifecycle audit row.
-- VOLATILE.

CREATE OR REPLACE FUNCTION access_review_decide(
    p_actor        BIGINT,
    p_campaign_id  BIGINT,
    p_item_id      BIGINT,
    p_decision     TEXT,
    p_note         TEXT,
    p_domain_scope BIGINT
) RETURNS VOID AS $$
DECLARE
    v_is_sso  BOOLEAN;
    v_user_id BIGINT;
BEGIN
    PERFORM access_review_assert_open(p_campaign_id, p_domain_scope);

    SELECT is_sso, user_id INTO v_is_sso, v_user_id FROM access_review_items
      WHERE id = p_item_id AND campaign_id = p_campaign_id;

    -- SoD: an actor may not certify their own access (self-review). The UI's cosmetic
    -- "self-review" tag is not enforcement — block it here. v_user_id NULL ⇒ bad item id,
    -- left to the UPDATE's BZ060 below (NULL = p_actor is never true).
    IF v_user_id = p_actor THEN
        RAISE EXCEPTION 'cannot review your own access (separation of duties)'
            USING ERRCODE='BZ069', HINT='{"type":"access_review_self_certify"}';
    END IF;

    IF p_decision = 'revoke' THEN
        IF v_is_sso THEN
            RAISE EXCEPTION 'revoke won''t persist — remove the IdP group mapping in Auth settings'
                USING ERRCODE='BZ063', HINT='{"type":"access_review_sso_revoke"}';
        END IF;
        -- OU-scope enforcement: a scoped actor may only revoke an item they can reach
        -- (domain AND OU AND set), mirroring access_review_close's per-item DELETE gate.
        -- Domain-only assert_open let a narrower OU-admin revoke items outside their OU in
        -- the same domain. Global actors (scope<=0) bypass. v_user_id NULL ⇒ bad item id,
        -- left to the UPDATE's BZ060 below.
        IF p_domain_scope > 0 AND v_user_id IS NOT NULL
           AND NOT admin_can_reach(p_actor, v_user_id) THEN
            RAISE EXCEPTION 'item out of scope'
                USING ERRCODE='BZ061', HINT='{"type":"access_review_forbidden"}';
        END IF;
    END IF;

    UPDATE access_review_items
       SET decision = p_decision, decided_by = p_actor, decided_at = now(), note = p_note
     WHERE id = p_item_id AND campaign_id = p_campaign_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such item'
            USING ERRCODE='BZ060', HINT='{"type":"access_review_not_found"}';
    END IF;

    PERFORM audit_write(
        p_actor,
        'access_review_decide',
        'access_review_item',
        p_item_id,
        NULL,
        jsonb_build_object('campaign_id', p_campaign_id, 'decision', p_decision),
        NULL,
        NULL,
        'core'
    );
END;
$$ LANGUAGE plpgsql VOLATILE;
