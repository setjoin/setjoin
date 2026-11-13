CREATE OR REPLACE FUNCTION identity_auth_link(
    p_actor BIGINT,
    p_user_id BIGINT,
    p_kind TEXT,
    p_provider TEXT,
    p_subject TEXT,
    p_provider_key TEXT,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_bound JSONB;
    v_source identity_sources%ROWTYPE;
    v_link user_identity_links%ROWTYPE;
BEGIN
    IF p_actor IS NULL OR p_actor<>p_user_id THEN
        RAISE EXCEPTION 'invalid authenticated identity link'
            USING ERRCODE='BZ234';
    END IF;
    IF p_kind NOT IN ('oidc','saml')
       OR p_subject IS NULL OR octet_length(p_subject) NOT BETWEEN 1 AND 2048
       OR p_subject ~ '[[:cntrl:]]'
       OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid authenticated identity link'
            USING ERRCODE='BZ241';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM users u WHERE u.id=p_user_id AND u.enabled
          AND NOT is_guest_account(u.id)
    ) THEN
        RAISE EXCEPTION 'identity link target is unavailable'
            USING ERRCODE='BZ234';
    END IF;
    v_bound := identity_source_provider_bind(p_kind,p_provider,p_provider_key);
    SELECT * INTO v_source FROM identity_sources
     WHERE id=(v_bound->>'sourceId')::bigint FOR UPDATE;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:'||p_user_id::text,0
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-subject:'||v_source.id::text||':'||
        encode(digest(p_subject,'sha256'),'hex'),0
    ));
    SELECT * INTO v_link FROM user_identity_links
     WHERE source_id=v_source.id AND external_subject=p_subject FOR UPDATE;
    IF FOUND THEN
        IF v_link.user_id<>p_user_id OR v_link.state='detached' THEN
            RAISE EXCEPTION 'federated subject belongs to another retained identity'
                USING ERRCODE='BZ230',
                      HINT='{"type":"identity_subject_conflict"}';
        END IF;
        IF v_link.state='active' AND 'authenticate'=ANY(v_link.purposes) THEN
            RETURN jsonb_build_object(
                'linked',true,'replayed',true,'linkId',v_link.id::text,
                'sourceId',v_source.id::text
            );
        END IF;
        UPDATE user_identity_links
           SET state='active',purposes=ARRAY['authenticate']::text[],
               generation=generation+1,last_seen_at=statement_timestamp(),
               updated_at=statement_timestamp()
         WHERE id=v_link.id
         RETURNING * INTO v_link;
    ELSE
        INSERT INTO user_identity_links(
            user_id,source_id,external_subject,purposes,state,link_method,
            evidence
        ) VALUES(
            p_user_id,v_source.id,p_subject,ARRAY['authenticate']::text[],
            'active','operator',
            jsonb_build_object('proof','federated_callback','providerKey',p_provider_key)
        ) RETURNING * INTO v_link;
    END IF;
    IF p_kind='oidc' THEN
        -- The legacy scalar is a rollback projection, not the normalized
        -- cardinality limit. Preserve its first complete pair when another
        -- OIDC provider is linked; normalized links may coexist up to the
        -- transactionally enforced eight-auth-link guard.
        UPDATE users SET
               oidc_subject=COALESCE(oidc_subject,p_subject),
               oidc_issuer=COALESCE(oidc_issuer,p_provider),
               updated_at=statement_timestamp()
         WHERE id=p_user_id
           AND (oidc_subject IS NULL
                OR (oidc_subject=p_subject AND oidc_issuer=p_provider));
    ELSE
        UPDATE users SET
               saml_name_id=COALESCE(saml_name_id,p_subject),
               saml_idp_entity_id=COALESCE(saml_idp_entity_id,p_provider),
               updated_at=statement_timestamp()
         WHERE id=p_user_id
           AND (saml_name_id IS NULL
                OR (saml_name_id=p_subject AND saml_idp_entity_id=p_provider));
    END IF;
    INSERT INTO identity_link_events(
        actor_user_id,user_id,source_id,link_id,action,reason,after_digest,metadata
    ) VALUES(
        p_actor,p_user_id,v_source.id,v_link.id,'auth_linked',p_reason,
        digest(v_link.id::text||':'||v_link.generation::text,'sha256'),
        jsonb_build_object('kind',p_kind,'providerKey',p_provider_key)
    );
    PERFORM app_notify('identity_link',
        jsonb_build_object('userId',p_user_id::text,'action','linked')::text);
    RETURN jsonb_build_object(
        'linked',true,'replayed',false,'linkId',v_link.id::text,
        'sourceId',v_source.id::text
    );
END;
$$;
SELECT apply_worker_ownership(
    'identity_auth_link(bigint,bigint,text,text,text,text,text)'::regprocedure
);
