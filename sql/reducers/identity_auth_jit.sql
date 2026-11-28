-- Atomically create a local-lifecycle person plus one authentication-only
-- source link. Soft address collision is a review fact, never linking proof.
CREATE OR REPLACE FUNCTION identity_auth_jit(
    p_kind TEXT,
    p_provider TEXT,
    p_subject TEXT,
    p_email TEXT,
    p_display_name TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source_key TEXT;
    v_source_id BIGINT;
    v_link_id BIGINT;
    v_link_generation BIGINT;
    v_user_id BIGINT;
    v_domain_id BIGINT;
    v_existing_user BIGINT;
    v_username TEXT;
    v_event_id BIGINT;
    v_source_generation BIGINT;
BEGIN
    IF p_kind NOT IN ('saml','oidc')
       OR p_provider IS NULL OR p_provider = ''
       OR p_subject IS NULL OR p_subject = ''
       OR p_email IS NULL OR p_email = ''
       OR octet_length(p_provider) > 2048
       OR octet_length(p_subject) > 2048
       OR p_provider ~ '[[:cntrl:]]'
       OR p_subject ~ '[[:cntrl:]]'
       OR p_email <> lower(btrim(p_email))
       OR position('@' IN p_email) = 0 THEN
        RAISE EXCEPTION 'invalid federated JIT identity'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid"}';
    END IF;

    v_source_key := p_kind || ':' ||
        substr(encode(digest(p_provider,'sha256'),'hex'),1,48);
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-source:' || v_source_key, 0
    ));

    INSERT INTO identity_sources (
        source_key, display_name, kind, capabilities, state
    ) VALUES (
        v_source_key,
        upper(p_kind) || ' authentication ' ||
            substr(encode(digest(p_provider,'sha256'),'hex'),1,12),
        p_kind,
        '{"authenticate":true,"provision_lifecycle":false,"stable_immutable_subject":true}'::jsonb,
        'active'
    )
    ON CONFLICT (source_key) DO NOTHING;

    SELECT id,generation INTO v_source_id,v_source_generation
      FROM identity_sources
     WHERE source_key = v_source_key AND kind = p_kind AND state = 'active'
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'federated identity source is unavailable'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","remediation":"activate the authentication source"}';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-subject:' || v_source_id::text || ':' ||
        encode(digest(p_subject,'sha256'),'hex'), 0
    ));
    SELECT l.user_id, l.id, l.generation
      INTO v_user_id, v_link_id, v_link_generation
      FROM user_identity_links l
     WHERE l.source_id = v_source_id AND l.external_subject = p_subject
       AND l.state = 'active' AND 'authenticate' = ANY(l.purposes)
     FOR UPDATE;
    IF FOUND THEN
        RETURN jsonb_build_object(
            'created',false,'userId',v_user_id::text,
            'linkId',v_link_id::text,
            'linkGeneration',v_link_generation::text,
            'sourceId',v_source_id::text,
            'sourceGeneration',v_source_generation::text
        );
    END IF;
    IF EXISTS (
        SELECT 1 FROM user_identity_links
         WHERE source_id=v_source_id AND external_subject=p_subject
    ) THEN
        RAISE EXCEPTION 'federated subject is retained as a tombstone'
            USING ERRCODE = 'BZ230',
                  HINT = '{"type":"identity_subject_conflict"}';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-email:' || p_email, 0
    ));
    SELECT u.id INTO v_existing_user
      FROM users u
     WHERE lower(u.email)=p_email
        OR lower(u.ad_upn)=p_email
        OR EXISTS (
            SELECT 1
              FROM aliases a
              JOIN mailboxes m ON m.id=a.mailbox_id
             WHERE m.user_id=u.id AND lower(a.email)=p_email
        )
     ORDER BY u.id
     LIMIT 1
     FOR UPDATE;
    IF FOUND THEN
        INSERT INTO identity_match_candidates (
            source_id, external_subject, candidate_user_id, evidence_class,
            evidence_digest, redacted_explanation, generation, expires_at
        ) VALUES (
            v_source_id,p_subject,v_existing_user,'soft',
            digest(v_source_id::text || ':' || p_subject || ':' ||
                   v_existing_user::text,'sha256'),
            'federated email matched an existing person; authenticated link approval required',
            v_source_generation,statement_timestamp()+interval '30 days'
        )
        ON CONFLICT (
            source_id, external_subject, candidate_user_id,
            evidence_class, generation
        ) WHERE status IN ('pending','deferred') DO NOTHING;
        RETURN jsonb_build_object(
            'state','blocked','code','BZ231',
            'sourceId',v_source_id::text,
            'remediation','complete authenticated linking; email is not proof'
        );
    END IF;

    SELECT id INTO v_domain_id
      FROM domains
     WHERE name=split_part(p_email,'@',2) AND is_local
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'federated email domain is not local'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"email"}';
    END IF;

    v_username := split_part(p_email,'@',1);
    INSERT INTO users (
        username,email,display_name,domain_id,sync_source,enabled,
        oidc_subject,oidc_issuer,saml_name_id,saml_idp_entity_id
    ) VALUES (
        v_username,p_email,COALESCE(NULLIF(p_display_name,''),v_username),
        v_domain_id,'sso',true,
        CASE WHEN p_kind='oidc' THEN p_subject END,
        CASE WHEN p_kind='oidc' THEN p_provider END,
        CASE WHEN p_kind='saml' THEN p_subject END,
        CASE WHEN p_kind='saml' THEN p_provider END
    ) RETURNING id INTO v_user_id;

    INSERT INTO mailboxes (
        user_id,domain_id,email,display_name,type,is_primary
    ) VALUES (
        v_user_id,v_domain_id,p_email,
        COALESCE(NULLIF(p_display_name,''),v_username),'personal',true
    );
    INSERT INTO user_identity_links (
        user_id,source_id,external_subject,purposes,state,link_method,evidence
    ) VALUES (
        v_user_id,v_source_id,p_subject,ARRAY['authenticate']::text[],
        'active','jit',jsonb_build_object(
            'providerDigest',encode(digest(p_provider,'sha256'),'hex')
        )
    ) RETURNING id INTO v_link_id;
    SELECT generation INTO v_link_generation
      FROM user_identity_links WHERE id=v_link_id;
    INSERT INTO user_lifecycle_authorities (user_id,authority_kind)
    VALUES (v_user_id,'local')
    ON CONFLICT (user_id) DO NOTHING;
    INSERT INTO identity_link_events (
        user_id,source_id,link_id,action,reason,after_digest,metadata
    ) VALUES (
        v_user_id,v_source_id,v_link_id,'auth_jit_created',
        'federated JIT created a new local-lifecycle person',
        digest(v_user_id::text || ':' || v_link_id::text,'sha256'),
        jsonb_build_object('kind',p_kind)
    ) RETURNING id INTO v_event_id;

    RETURN jsonb_build_object(
        'created',true,'userId',v_user_id::text,'linkId',v_link_id::text,
        'linkGeneration',v_link_generation::text,
        'sourceId',v_source_id::text,
        'sourceGeneration',v_source_generation::text,
        'eventId',v_event_id::text
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_auth_jit(text,text,text,text,text)'::regprocedure
);
