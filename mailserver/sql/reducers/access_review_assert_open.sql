-- access_review_assert_open.sql
-- Shared campaign authorization guard extracted from the three access_review
-- mutation reducers (decide, decide_bulk, close). Raises:
--   BZ060 — campaign not found
--   BZ061 — campaign out of scope for the actor
--   BZ062 — campaign is already closed
-- With p_lock=TRUE the campaign row is SELECT … FOR UPDATE, giving the
-- concurrent-close idempotency that access_review_close requires.
-- VOLATILE.

CREATE OR REPLACE FUNCTION access_review_assert_open(
    p_campaign_id  BIGINT,
    p_domain_scope BIGINT,
    p_lock         BOOLEAN DEFAULT FALSE
) RETURNS VOID AS $$
DECLARE
    v_status     TEXT;
    v_camp_scope BIGINT;
BEGIN
    IF p_lock THEN
        SELECT status, domain_scope INTO v_status, v_camp_scope
          FROM access_review_campaigns WHERE id = p_campaign_id FOR UPDATE;
    ELSE
        SELECT status, domain_scope INTO v_status, v_camp_scope
          FROM access_review_campaigns WHERE id = p_campaign_id;
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such campaign'
            USING ERRCODE='BZ060', HINT='{"type":"access_review_not_found"}';
    END IF;

    IF p_domain_scope > 0 AND v_camp_scope IS DISTINCT FROM p_domain_scope THEN
        RAISE EXCEPTION 'campaign out of scope'
            USING ERRCODE='BZ061', HINT='{"type":"access_review_forbidden"}';
    END IF;

    IF v_status <> 'open' THEN
        RAISE EXCEPTION 'campaign is closed'
            USING ERRCODE='BZ062', HINT='{"type":"access_review_closed"}';
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE;
