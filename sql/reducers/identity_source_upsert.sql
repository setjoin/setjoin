-- Identity source catalog authority. The HTTP layer supplies RBAC; this
-- reducer owns capability validation, generation CAS, audit evidence, and the
-- immutable source-key contract.
CREATE OR REPLACE FUNCTION identity_source_upsert(
    p_actor BIGINT,
    p_id BIGINT,
    p_source_key TEXT,
    p_display_name TEXT,
    p_kind TEXT,
    p_capabilities JSONB,
    p_state TEXT,
    p_config_envelope BYTEA,
    p_config_key_version BIGINT,
    p_mapping_version BIGINT,
    p_expected_generation BIGINT,
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_id BIGINT;
    v_generation BIGINT;
    v_key TEXT;
    v_stored_key TEXT;
    v_value JSONB;
    v_before_digest BYTEA;
BEGIN
    IF p_actor IS NULL
       OR p_source_key IS NULL
       OR p_display_name IS NULL
       OR p_kind IS NULL
       OR p_capabilities IS NULL
       OR p_state IS NULL
       OR p_config_key_version IS NULL
       OR p_mapping_version IS NULL
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity source request'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","remediation":"supply every required field and a bounded reason"}';
    END IF;

    IF p_kind NOT IN ('local','ad','ldap','scim','saml','oidc')
       OR p_state NOT IN ('draft','active','paused','error','retired')
       OR jsonb_typeof(p_capabilities) <> 'object'
       OR p_capabilities = '{}'::jsonb THEN
        RAISE EXCEPTION 'invalid identity source kind, state, or capabilities'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"capabilities"}';
    END IF;

    FOR v_key, v_value IN SELECT key, value FROM jsonb_each(p_capabilities)
    LOOP
        IF v_key NOT IN (
            'authenticate','provision_lifecycle','password_writeback',
            'profile_attributes','groups','delta_cursor','suspend_delete',
            'stable_immutable_subject'
        ) OR jsonb_typeof(v_value) <> 'boolean' THEN
            RAISE EXCEPTION 'unknown or non-boolean identity source capability'
                USING ERRCODE = 'BZ228',
                      HINT = jsonb_build_object(
                          'type', 'identity_source_invalid',
                          'field', 'capabilities/' || v_key,
                          'remediation', 'remove unknown keys and use boolean capability values'
                      )::text;
        END IF;
    END LOOP;

    IF NOT (p_capabilities ? 'authenticate')
       OR NOT (p_capabilities ? 'provision_lifecycle')
       OR NOT (p_capabilities ? 'stable_immutable_subject')
       OR (p_kind IN ('saml','oidc')
           AND COALESCE((p_capabilities ->> 'provision_lifecycle')::boolean, false))
       OR (p_kind = 'scim'
           AND COALESCE((p_capabilities ->> 'authenticate')::boolean, false))
       OR (p_kind = 'local'
           AND (NOT (p_capabilities ->> 'authenticate')::boolean
                OR NOT (p_capabilities ->> 'provision_lifecycle')::boolean
                OR NOT (p_capabilities ->> 'stable_immutable_subject')::boolean))
       OR (p_state = 'active'
           AND NOT (p_capabilities ->> 'stable_immutable_subject')::boolean
           AND p_kind <> 'local') THEN
        RAISE EXCEPTION 'identity source capability combination is unsafe'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"capabilities","remediation":"correct the kind/capability combination before activation"}';
    END IF;

    IF p_id IS NULL THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended('identity-source:' || p_source_key, 0)
        );
        IF p_expected_generation IS NOT NULL THEN
            RAISE EXCEPTION 'new identity source cannot carry an expected generation'
                USING ERRCODE = 'BZ229',
                      HINT = '{"type":"identity_generation_stale"}';
        END IF;

        INSERT INTO identity_sources (
            source_key, display_name, kind, capabilities, state,
            config_envelope, config_key_version, mapping_version,
            created_by, updated_by
        ) VALUES (
            p_source_key, p_display_name, p_kind, p_capabilities, p_state,
            p_config_envelope, p_config_key_version, p_mapping_version,
            p_actor, p_actor
        )
        RETURNING id, generation INTO v_id, v_generation;

        INSERT INTO identity_link_events (
            actor_user_id, source_id, action, reason, after_digest, metadata
        ) VALUES (
            p_actor, v_id, 'source_created', p_reason,
            digest(
                concat_ws(':', v_id::text, p_source_key, p_kind,
                          v_generation::text, p_state),
                'sha256'
            ),
            jsonb_build_object('generation', v_generation)
        );
    ELSE
        SELECT source_key INTO v_stored_key
          FROM identity_sources
         WHERE id=p_id;
        IF NOT FOUND OR v_stored_key<>p_source_key THEN
            RAISE EXCEPTION 'identity source id and key do not match'
                USING ERRCODE='BZ240',
                      HINT='{"type":"identity_idempotency_conflict","field":"sourceKey"}';
        END IF;
        PERFORM pg_advisory_xact_lock(
            hashtextextended('identity-source:' || v_stored_key, 0)
        );
        SELECT generation,
               digest(
                   concat_ws(':', id::text, source_key, kind,
                             generation::text, state, mapping_version::text),
                   'sha256'
               )
          INTO v_generation, v_before_digest
        FROM identity_sources
        WHERE id = p_id AND source_key=v_stored_key
        FOR UPDATE;

        IF NOT FOUND OR p_expected_generation IS NULL
           OR v_generation <> p_expected_generation THEN
            RAISE EXCEPTION 'identity source generation is stale'
                USING ERRCODE = 'BZ229',
                      HINT = jsonb_build_object(
                          'type', 'identity_generation_stale',
                          'expectedGeneration', p_expected_generation,
                          'actualGeneration', v_generation
                      )::text;
        END IF;

        UPDATE identity_sources
        SET display_name = p_display_name,
            kind = p_kind,
            capabilities = p_capabilities,
            state = p_state,
            config_envelope = p_config_envelope,
            config_key_version = p_config_key_version,
            mapping_version = p_mapping_version,
            generation = generation + 1,
            updated_by = p_actor,
            updated_at = statement_timestamp()
        WHERE id = p_id
          AND generation = p_expected_generation
        RETURNING id, generation INTO v_id, v_generation;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'identity source generation changed'
                USING ERRCODE = 'BZ229',
                      HINT = '{"type":"identity_generation_stale"}';
        END IF;

        INSERT INTO identity_link_events (
            actor_user_id, source_id, action, reason,
            before_digest, after_digest, metadata
        ) VALUES (
            p_actor, v_id, 'source_updated', p_reason,
            v_before_digest,
            digest(
                concat_ws(':', v_id::text, v_stored_key, p_kind,
                          v_generation::text, p_state, p_mapping_version::text),
                'sha256'
            ),
            jsonb_build_object(
                'generation',v_generation,
                'mappingVersion',p_mapping_version
            )
        );
    END IF;

    PERFORM app_notify(
        'config_changed',
        jsonb_build_object(
            'key', 'identity.source.' || v_id::text,
            'source_id', v_id,
            'generation', v_generation
        )::text
    );

    RETURN jsonb_build_object(
        'sourceId', v_id::text,
        'generation', v_generation::text,
        'state', p_state
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_upsert(bigint,bigint,text,text,text,jsonb,text,bytea,bigint,bigint,bigint,text)'::regprocedure
);
