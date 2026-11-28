CREATE OR REPLACE FUNCTION continuity_client_witness_record(
    p_mailbox_id bigint,
    p_token_sha256 text,
    p_installation_id uuid,
    p_timeline_generation bigint,
    p_state_watermark bigint,
    p_issued_at timestamptz,
    p_boot_epoch uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
    v_control upgrade_control_state%ROWTYPE;
    v_local_watermark bigint;
    v_signal text;
    v_existing continuity_client_witnesses%ROWTYPE;
BEGIN
    IF p_mailbox_id IS NULL OR
       NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint IS DISTINCT FROM p_mailbox_id OR
       p_token_sha256 !~ '^[0-9a-f]{64}$' OR p_installation_id IS NULL OR
       p_timeline_generation IS NULL OR p_timeline_generation<=0 OR
       p_state_watermark IS NULL OR p_state_watermark<0 OR p_issued_at IS NULL OR
       p_issued_at>statement_timestamp()+interval '5 minutes' OR
       p_issued_at<statement_timestamp()-interval '180 days' OR p_boot_epoch IS NULL THEN
        RAISE EXCEPTION 'continuity witness is invalid'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_witness_invalid"}';
    END IF;
    SELECT * INTO STRICT v_control FROM upgrade_control_state WHERE singleton;
    IF p_installation_id<>v_control.installation_id THEN
        RAISE EXCEPTION 'continuity installation differs'
            USING ERRCODE='BZ245',HINT='{"type":"continuity_scope_mismatch"}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mailboxes WHERE id=p_mailbox_id AND enabled) THEN
        RAISE EXCEPTION 'continuity account not found'
            USING ERRCODE='BZ006',HINT='{"type":"account_not_found"}';
    END IF;
    SELECT GREATEST(
        m.jmap_email_state,m.jmap_mailbox_state,m.jmap_thread_state,m.jmap_tag_state,
        COALESCE((SELECT max(c.jmap_state) FROM calendars c WHERE c.mailbox_id=m.id),0),
        COALESCE((SELECT max(a.jmap_state) FROM addressbooks a WHERE a.mailbox_id=m.id),0),
        COALESCE((SELECT max(t.jmap_state) FROM tasks t WHERE t.mailbox_id=m.id),0)
    ) INTO STRICT v_local_watermark FROM mailboxes m WHERE m.id=p_mailbox_id;
    v_signal := CASE
        WHEN p_timeline_generation>v_control.timeline_generation OR
             (p_timeline_generation=v_control.timeline_generation AND p_state_watermark>v_local_watermark)
        THEN 'client_observed_newer_timeline' ELSE 'none' END;

    SELECT * INTO v_existing FROM continuity_client_witnesses
     WHERE mailbox_id=p_mailbox_id AND token_sha256=decode(p_token_sha256,'hex') FOR UPDATE;
    IF FOUND THEN
        RETURN jsonb_build_object('signalClass',v_existing.signal_class,'replayed',true,
                                  'localTimelineGeneration',v_control.timeline_generation::text,
                                  'localStateWatermark',v_local_watermark::text);
    END IF;
    INSERT INTO continuity_client_witnesses(
        mailbox_id,token_sha256,installation_id,timeline_generation,state_watermark,
        issued_at,boot_epoch,signal_class
    ) VALUES(
        p_mailbox_id,decode(p_token_sha256,'hex'),p_installation_id,p_timeline_generation,
        p_state_watermark,p_issued_at,p_boot_epoch,v_signal
    );
    IF v_signal='client_observed_newer_timeline' THEN
        PERFORM audit_write(
            (SELECT user_id FROM mailboxes WHERE id=p_mailbox_id),
            'continuity_client_observed_newer','mailbox',p_mailbox_id,NULL,
            jsonb_build_object('timelineGeneration',p_timeline_generation::text,
                               'stateWatermark',p_state_watermark::text,
                               'bootEpoch',p_boot_epoch::text),NULL,NULL,'core'
        );
        PERFORM app_notify('continuity_signal_changed',json_build_object(
            'mailbox_id',p_mailbox_id,'signal_class',v_signal)::text);
    END IF;
    RETURN jsonb_build_object('signalClass',v_signal,'replayed',false,
                              'localTimelineGeneration',v_control.timeline_generation::text,
                              'localStateWatermark',v_local_watermark::text);
END;
$$;

REVOKE ALL ON FUNCTION continuity_client_witness_record(bigint,text,uuid,bigint,bigint,timestamptz,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION continuity_client_witness_record(bigint,text,uuid,bigint,bigint,timestamptz,uuid) TO setjoin_app,setjoin_worker;
SELECT apply_worker_ownership('continuity_client_witness_record(bigint,text,uuid,bigint,bigint,timestamptz,uuid)'::regprocedure);
