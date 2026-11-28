CREATE OR REPLACE FUNCTION mail_recovery_incident_open(
    p_actor_user_id bigint,
    p_incident_id uuid,
    p_mailbox_ids bigint[],
    p_evidence jsonb,
    p_minimum_timeline bigint,
    p_maximum_timeline bigint,
    p_expires_at timestamptz,
    p_reason text,
    p_approval_required boolean,
    p_step_up_binding bytea,
    p_idempotency_key uuid
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    v_installation_id uuid;
    v_mailbox_id bigint;
    v_evidence text;
    v_existing mail_recovery_incidents%ROWTYPE;
BEGIN
    IF NOT mail_recovery_feature_enabled() THEN
        RAISE EXCEPTION 'client recovery intake is disabled'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden","detail":"client recovery intake is disabled"}';
    END IF;
    IF NOT mail_recovery_has_global_permission(p_actor_user_id) THEN
        RAISE EXCEPTION 'global system.recovery permission required'
            USING ERRCODE='BZ003',HINT='{"type":"forbidden"}';
    END IF;
    IF p_incident_id IS NULL OR p_idempotency_key IS NULL OR p_mailbox_ids IS NULL OR
       cardinality(p_mailbox_ids) NOT BETWEEN 1 AND 100 OR
       cardinality(ARRAY(SELECT DISTINCT mailbox_id FROM unnest(p_mailbox_ids) mailbox_id))<>cardinality(p_mailbox_ids) OR
       jsonb_typeof(p_evidence)<>'object' OR p_minimum_timeline IS NULL OR p_minimum_timeline<=0 OR
       p_maximum_timeline IS NULL OR p_maximum_timeline<p_minimum_timeline OR
       p_expires_at IS NULL OR p_expires_at<=statement_timestamp() OR
       p_expires_at>statement_timestamp()+interval '7 days' OR
       length(btrim(COALESCE(p_reason,''))) NOT BETWEEN 8 AND 1024 OR p_reason~'[\r\n]' OR
       p_step_up_binding IS NULL OR octet_length(p_step_up_binding)<>32 THEN
        RAISE EXCEPTION 'invalid recovery incident request'
            USING ERRCODE='BZ251',HINT='{"type":"invalid_arguments"}';
    END IF;

    SELECT * INTO v_existing FROM mail_recovery_incidents
     WHERE opened_by=p_actor_user_id AND idempotency_key=p_idempotency_key;
    IF FOUND THEN
        RETURN jsonb_build_object('id',v_existing.id,'status',v_existing.status,
                                  'replayed',true,'expiresAt',v_existing.expires_at);
    END IF;

    SELECT installation_id INTO STRICT v_installation_id
      FROM upgrade_control_state WHERE singleton;

    FOREACH v_mailbox_id IN ARRAY p_mailbox_ids LOOP
        v_evidence:=p_evidence->>v_mailbox_id::text;
        IF v_evidence IS NULL OR v_evidence!~'^[0-9a-f]{64}$' OR NOT EXISTS(
            SELECT 1
              FROM continuity_client_witnesses witness
              JOIN mailboxes mailbox ON mailbox.id=witness.mailbox_id
              JOIN users affected ON affected.id=mailbox.user_id
             WHERE witness.mailbox_id=v_mailbox_id
               AND witness.token_sha256=decode(v_evidence,'hex')
               AND witness.installation_id=v_installation_id
               AND witness.signal_class='client_observed_newer_timeline'
               AND witness.timeline_generation BETWEEN p_minimum_timeline AND p_maximum_timeline
               AND mailbox.enabled AND affected.enabled
        ) THEN
            RAISE EXCEPTION 'credible newer-timeline evidence missing for mailbox %',v_mailbox_id
                USING ERRCODE='BZ251',HINT='{"type":"continuity_evidence_required"}';
        END IF;
    END LOOP;

    INSERT INTO mail_recovery_incidents(
        id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,
        step_up_binding,approval_required,expires_at,idempotency_key
    ) VALUES(
        p_incident_id,v_installation_id,p_minimum_timeline,p_maximum_timeline,
        btrim(p_reason),p_actor_user_id,p_step_up_binding,COALESCE(p_approval_required,false),
        p_expires_at,p_idempotency_key
    );
    INSERT INTO mail_recovery_incident_accounts(incident_id,mailbox_id,affected_user_id,evidence_token_sha256)
    SELECT p_incident_id,mailbox.id,mailbox.user_id,decode(p_evidence->>mailbox.id::text,'hex')
      FROM mailboxes mailbox WHERE mailbox.id=ANY(p_mailbox_ids);
    IF (SELECT count(*) FROM mail_recovery_incident_accounts WHERE incident_id=p_incident_id)<>cardinality(p_mailbox_ids) THEN
        RAISE EXCEPTION 'recovery mailbox scope changed'
            USING ERRCODE='BZ006',HINT='{"type":"account_not_found"}';
    END IF;
    PERFORM audit_write(p_actor_user_id,'mail_recovery_incident_open','mail_recovery_incident',NULL,NULL,
        jsonb_build_object('incidentId',p_incident_id,'mailboxCount',cardinality(p_mailbox_ids),
                           'minimumTimeline',p_minimum_timeline::text,'maximumTimeline',p_maximum_timeline::text,
                           'approvalRequired',COALESCE(p_approval_required,false),'expiresAt',p_expires_at),
        NULL,NULL,'core');
    PERFORM app_notify('mail_recovery_incident_changed',jsonb_build_object('incident_id',p_incident_id,'status','open')::text);
    RETURN jsonb_build_object('id',p_incident_id,'status','open','replayed',false,
                              'approvalRequired',COALESCE(p_approval_required,false),'expiresAt',p_expires_at);
END;
$$;
REVOKE ALL ON FUNCTION mail_recovery_incident_open(bigint,uuid,bigint[],jsonb,bigint,bigint,timestamptz,text,boolean,bytea,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mail_recovery_incident_open(bigint,uuid,bigint[],jsonb,bigint,bigint,timestamptz,text,boolean,bytea,uuid) TO setjoin_worker;
SELECT apply_worker_ownership('mail_recovery_incident_open(bigint,uuid,bigint[],jsonb,bigint,bigint,timestamptz,text,boolean,bytea,uuid)'::regprocedure);
