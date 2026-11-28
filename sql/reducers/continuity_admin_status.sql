CREATE OR REPLACE FUNCTION continuity_admin_status(
    p_actor_user_id bigint,
    p_limit integer
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_control upgrade_control_state%ROWTYPE;
    v_signals jsonb;
BEGIN
    IF NOT mail_recovery_has_global_permission(p_actor_user_id) THEN
        RAISE EXCEPTION 'global system.recovery permission required'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'invalid continuity status limit'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;
    SELECT * INTO STRICT v_control FROM upgrade_control_state WHERE singleton;
    SELECT COALESCE(jsonb_agg(signal ORDER BY observed_at DESC),'[]'::jsonb)
      INTO v_signals
      FROM (
        SELECT witness.observed_at,jsonb_build_object(
            'mailboxId',witness.mailbox_id::text,
            'email',mailbox.email,
            'tokenSha256',encode(witness.token_sha256,'hex'),
            'timelineGeneration',witness.timeline_generation::text,
            'stateWatermark',witness.state_watermark::text,
            'bootEpoch',witness.boot_epoch,
            'issuedAt',witness.issued_at,
            'observedAt',witness.observed_at,
            'signalClass',witness.signal_class
        ) signal
          FROM continuity_client_witnesses witness
          JOIN mailboxes mailbox ON mailbox.id=witness.mailbox_id
          JOIN users affected ON affected.id=mailbox.user_id
         WHERE witness.signal_class='client_observed_newer_timeline'
           AND mailbox.enabled AND affected.enabled
         ORDER BY witness.observed_at DESC
         LIMIT p_limit
      ) bounded;
    RETURN jsonb_build_object(
        'installationId',v_control.installation_id,
        'localTimelineGeneration',v_control.timeline_generation::text,
        'lastWallClock',v_control.continuity_last_wall_clock,
        'lastBootEpoch',v_control.continuity_last_boot_epoch,
        'lastBootAt',v_control.continuity_last_boot_at,
        'restoreDeclaredAt',v_control.continuity_restore_declared_at,
        'signals',v_signals
    );
END;
$$;
REVOKE ALL ON FUNCTION continuity_admin_status(bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION continuity_admin_status(bigint,integer) TO setjoin_worker;
SELECT apply_worker_ownership('continuity_admin_status(bigint,integer)'::regprocedure);
