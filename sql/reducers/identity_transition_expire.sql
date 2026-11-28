CREATE OR REPLACE FUNCTION identity_transition_expire(
    p_actor BIGINT,
    p_transition_id UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_t identity_transitions%ROWTYPE;
    v_due BOOLEAN;
BEGIN
    SELECT * INTO v_t
      FROM identity_transitions
     WHERE id=p_transition_id
     FOR UPDATE;
    IF NOT FOUND OR NOT admin_can_reach(p_actor,v_t.user_id) THEN
        RAISE EXCEPTION 'identity transition not found'
            USING ERRCODE='BZ234';
    END IF;
    IF v_t.state NOT IN (
        'previewed','awaiting_approval','authorized','rollback_previewed'
    ) THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;
    v_due := CASE
        WHEN v_t.state='rollback_previewed'
            THEN v_t.rollback_preview_expires_at<=statement_timestamp()
                 OR EXISTS (
                     SELECT 1 FROM approval_requests ar
                      WHERE ar.id=v_t.rollback_approval_request_id
                        AND ar.status='pending'
                        AND ar.expires_at<=statement_timestamp()
                 )
        ELSE v_t.preview_expires_at<=statement_timestamp()
             OR EXISTS (
                 SELECT 1 FROM approval_requests ar
                  WHERE ar.id=v_t.approval_request_id
                    AND ar.status='pending'
                    AND ar.expires_at<=statement_timestamp()
             )
    END;
    IF NOT v_due THEN
        RETURN identity_transition_read(p_actor,p_transition_id);
    END IF;
    UPDATE approval_requests
       SET status='expired',decided_at=statement_timestamp()
     WHERE id IN (
         v_t.approval_request_id,v_t.rollback_approval_request_id
     ) AND status='pending';
    UPDATE identity_transition_elevations
       SET invalidated_at=statement_timestamp()
     WHERE transition_id=p_transition_id
       AND consumed_at IS NULL
       AND invalidated_at IS NULL;
    UPDATE identity_transition_challenges
       SET invalidated_at=statement_timestamp()
     WHERE transition_id=p_transition_id
       AND completed_at IS NULL
       AND invalidated_at IS NULL;
    PERFORM identity_transition_set_state(
        p_transition_id,v_t.state,'expired',NULL
    );
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,transition_id,
        action,reason,metadata
    ) VALUES(
        p_actor,v_t.user_id,v_t.source_id,v_t.link_id,v_t.id,
        'transition_expired','transition authorization expired',
        jsonb_build_object('fromState',v_t.state)
    );
    RETURN identity_transition_read(p_actor,p_transition_id);
END;
$$;
SELECT apply_worker_ownership(
    'identity_transition_expire(bigint,uuid)'::regprocedure
);
