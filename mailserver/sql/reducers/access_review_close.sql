-- access_review_close.sql
-- Atomically finalize a campaign: for each revoke-decided item, delete the live
-- assignment (scoped + admin-granted only), audit the deleted row, set applied_at; then
-- mark the campaign closed. Lock-then-re-read makes concurrent close idempotent. VOLATILE.

CREATE OR REPLACE FUNCTION access_review_close(
    p_actor        BIGINT,
    p_campaign_id  BIGINT,
    p_ip           INET,
    p_domain_scope BIGINT
) RETURNS VOID AS $$
DECLARE
    v_item RECORD;
    v_del  admin_role_assignments%ROWTYPE;
BEGIN
    -- Lock the campaign row, THEN re-read status under the lock (idempotent close).
    PERFORM access_review_assert_open(p_campaign_id, p_domain_scope, TRUE);

    FOR v_item IN
        SELECT id, assignment_id FROM access_review_items
         WHERE campaign_id = p_campaign_id AND decision = 'revoke' AND assignment_id IS NOT NULL
    LOOP
        -- Scoped + SSO-safe delete: skip if now SSO-managed (granted_by NULL) or moved
        -- out of the actor's reach. Capture the row AS DELETED for the audit before_state.
        -- OU-scope enforcement: re-authorize the destructive DELETE with admin_can_reach
        -- (domain AND OU AND set — the same primitive access_review_start snapshotted with,
        -- and bulk_role_job_apply guards revokes with). A domain-only equality check let a
        -- narrower OU-admin close another OU-admin's campaign in the same domain and delete
        -- assignments outside their OU. Global actors (scope<=0) keep the bypass.
        DELETE FROM admin_role_assignments ra
         WHERE ra.id = v_item.assignment_id
           AND ra.granted_by IS NOT NULL
           AND (p_domain_scope <= 0 OR admin_can_reach(p_actor, ra.user_id))
        RETURNING ra.* INTO v_del;

        IF FOUND THEN
            UPDATE access_review_items SET applied_at = now() WHERE id = v_item.id;
            PERFORM audit_write(
                p_actor,
                'access_review_revoke',
                'admin_role_assignment',
                v_item.assignment_id,
                to_jsonb(v_del),
                NULL,
                p_ip,
                format('access review #%s item #%s', p_campaign_id, v_item.id),
                'core'
            );
        END IF;
    END LOOP;

    UPDATE access_review_campaigns
       SET status = 'closed', closed_by = p_actor, closed_at = now()
     WHERE id = p_campaign_id;

    -- Lifecycle audit for the close itself (siblings audit start/decide/revoke). A
    -- campaign closed with all-keep decisions otherwise left NO append-only trace of
    -- the close — a tamper-evidence gap.
    PERFORM audit_write(
        p_actor, 'access_review_close', 'access_review_campaign', p_campaign_id,
        NULL, jsonb_build_object('status', 'closed'), p_ip, NULL, 'core'
    );
END;
$$ LANGUAGE plpgsql VOLATILE;
