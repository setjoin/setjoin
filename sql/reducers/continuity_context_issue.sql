CREATE OR REPLACE FUNCTION continuity_context_issue(
    p_mailbox_id bigint,
    p_boot_epoch uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
    v_control upgrade_control_state%ROWTYPE;
    v_watermark bigint;
    v_previous_wall timestamptz;
BEGIN
    IF p_mailbox_id IS NULL OR p_boot_epoch IS NULL OR
       NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint IS DISTINCT FROM p_mailbox_id OR
       NOT EXISTS (SELECT 1 FROM mailboxes WHERE id=p_mailbox_id AND enabled) THEN
        RAISE EXCEPTION 'continuity account scope is invalid'
            USING ERRCODE='BZ006',HINT='{"type":"account_not_found"}';
    END IF;

    SELECT GREATEST(
        m.jmap_email_state,m.jmap_mailbox_state,m.jmap_thread_state,m.jmap_tag_state,
        COALESCE((SELECT max(c.jmap_state) FROM calendars c WHERE c.mailbox_id=m.id),0),
        COALESCE((SELECT max(a.jmap_state) FROM addressbooks a WHERE a.mailbox_id=m.id),0),
        COALESCE((SELECT max(t.jmap_state) FROM tasks t WHERE t.mailbox_id=m.id),0)
    ) INTO STRICT v_watermark FROM mailboxes m WHERE m.id=p_mailbox_id;

    SELECT * INTO STRICT v_control FROM upgrade_control_state WHERE singleton FOR UPDATE;
    v_previous_wall := v_control.continuity_last_wall_clock;
    UPDATE upgrade_control_state
       SET continuity_last_wall_clock=GREATEST(
               COALESCE(continuity_last_wall_clock,'epoch'::timestamptz),statement_timestamp()),
           continuity_last_boot_epoch=p_boot_epoch,
           continuity_last_boot_at=CASE WHEN continuity_last_boot_epoch IS DISTINCT FROM p_boot_epoch
                                        THEN statement_timestamp() ELSE continuity_last_boot_at END
     WHERE singleton;

    RETURN jsonb_build_object(
        'installationId',v_control.installation_id::text,
        'timelineId',v_control.timeline_id::text,
        'timelineGeneration',v_control.timeline_generation::text,
        'stateWatermark',v_watermark::text,
        'serverTime',statement_timestamp(),
        'previousWallClock',v_previous_wall,
        'restoreDeclaredAt',v_control.continuity_restore_declared_at
    );
END;
$$;

REVOKE ALL ON FUNCTION continuity_context_issue(bigint,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION continuity_context_issue(bigint,uuid) TO setjoin_app,setjoin_worker;
SELECT apply_worker_ownership('continuity_context_issue(bigint,uuid)'::regprocedure);
