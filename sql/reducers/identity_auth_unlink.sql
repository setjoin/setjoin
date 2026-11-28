CREATE OR REPLACE FUNCTION identity_auth_unlink(
    p_actor BIGINT,
    p_link_id BIGINT,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_link user_identity_links%ROWTYPE;
    v_source identity_sources%ROWTYPE;
    v_recovery BOOLEAN;
    v_eviction_event UUID := gen_random_uuid();
BEGIN
    IF p_actor IS NULL THEN
        RAISE EXCEPTION 'invalid authenticated unlink'
            USING ERRCODE='BZ234';
    END IF;
    IF p_link_id IS NULL
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid authenticated unlink'
            USING ERRCODE='BZ241';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_actor::text,0
    ));
    SELECT * INTO v_link FROM user_identity_links
     WHERE id=p_link_id AND user_id=p_actor FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity link not found'
            USING ERRCODE='BZ234';
    END IF;
    IF v_link.state='detached' THEN
        RETURN jsonb_build_object('unlinked',true,'replayed',true,
                                  'linkId',v_link.id::text);
    END IF;
    IF v_link.state<>'active' OR 'provision'=ANY(v_link.purposes)
       OR EXISTS (
           SELECT 1 FROM user_lifecycle_authorities a
            WHERE a.user_id=p_actor AND a.link_id=v_link.id
       ) THEN
        RAISE EXCEPTION 'lifecycle or provisioning links require a transition'
            USING ERRCODE='BZ234',
                  HINT='{"type":"identity_transition_preflight"}';
    END IF;
    v_recovery := identity_recovery_available(p_actor,v_link.id);
    IF NOT v_recovery THEN
        RAISE EXCEPTION 'alternate authentication and recovery are required'
            USING ERRCODE='BZ237',
                  HINT='{"type":"identity_recovery_missing"}';
    END IF;
    SELECT * INTO v_source FROM identity_sources WHERE id=v_link.source_id;
    UPDATE user_identity_links
       SET state='detached',generation=generation+1,detached_by=p_actor,
           detached_at=statement_timestamp(),detached_reason=p_reason,
           updated_at=statement_timestamp()
     WHERE id=v_link.id
     RETURNING * INTO v_link;
    IF v_source.kind='oidc' THEN
        UPDATE users SET oidc_subject=NULL,oidc_issuer=NULL,
               updated_at=statement_timestamp()
         WHERE id=p_actor AND oidc_subject=v_link.external_subject;
    ELSIF v_source.kind='saml' THEN
        UPDATE users SET saml_name_id=NULL,saml_idp_entity_id=NULL,
               updated_at=statement_timestamp()
         WHERE id=p_actor AND saml_name_id=v_link.external_subject;
    END IF;
    UPDATE identity_entitlement_grants
       SET revoked_at=statement_timestamp(),updated_at=statement_timestamp()
     WHERE link_id=v_link.id AND revoked_at IS NULL;

    -- Removing an authentication route is also a session-boundary event.
    -- Revoke token families and every runtime session in this transaction so
    -- the detached link cannot leave refresh, HTTP, or websocket access alive.
    UPDATE oauth_tokens
       SET revoked_at=statement_timestamp(),revoked_by=p_actor
     WHERE user_id=p_actor AND revoked_at IS NULL;
    PERFORM revoke_user_sessions(
        p_actor,'all','identity_auth_unlink',p_actor,NULL,NULL
    );
    DELETE FROM sessions WHERE user_id=p_actor;
    DELETE FROM ws_subscriptions WHERE user_id=p_actor;

    INSERT INTO identity_session_eviction_intents(
        event_id,user_id,reason,room_name,identity,retry_until
    )
    SELECT v_eviction_event,p_actor,'identity_auth_unlink',
           m.room_name::text,'u:'||p_actor::text,
           statement_timestamp()+interval '5 minutes'
      FROM meeting_participants p
      JOIN meetings m ON m.id=p.meeting_id
     WHERE p.identity='u:'||p_actor::text
       AND p.left_at IS NULL
    ON CONFLICT DO NOTHING;
    INSERT INTO identity_session_eviction_intents(
        event_id,user_id,reason,room_name,identity,retry_until
    )
    SELECT v_eviction_event,p_actor,'identity_auth_unlink',
           a.room_name,a.identity,
           GREATEST(
               statement_timestamp()+interval '5 minutes',
               a.expires_at+interval '5 seconds'
           )
      FROM identity_media_admissions a
     WHERE a.user_id=p_actor
       AND a.expires_at>statement_timestamp()
    ON CONFLICT(event_id,room_name,identity) DO UPDATE
      SET retry_until=GREATEST(
          identity_session_eviction_intents.retry_until,
          EXCLUDED.retry_until
      );
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,action,reason,after_digest,metadata
    ) VALUES(
        p_actor,p_actor,v_source.id,v_link.id,'auth_unlinked',p_reason,
        digest(v_link.id::text||':'||v_link.generation::text,'sha256'),
        jsonb_build_object('kind',v_source.kind)
    );
    PERFORM app_notify('identity_link',
        jsonb_build_object('userId',p_actor::text,'action','unlinked')::text);
    RETURN jsonb_build_object(
        'unlinked',true,'replayed',false,'linkId',v_link.id::text,
        'sessionsRevoked',true,'evictionEventId',v_eviction_event::text
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_auth_unlink(bigint,bigint,text)'::regprocedure
);
