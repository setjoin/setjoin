-- Apply one staged connector object. The immutable source subject is the only
-- automatic identity key; address fields may create review evidence but can
-- never take over an existing person.
CREATE OR REPLACE FUNCTION identity_source_entry_apply(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_batch_id UUID,
    p_object_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_entry identity_source_inbox%ROWTYPE;
    v_link user_identity_links%ROWTYPE;
    v_payload JSONB;
    v_operation TEXT;
    v_email TEXT;
    v_user_id BIGINT;
    v_user_generation BIGINT;
    v_result JSONB;
    v_event_id BIGINT;
    v_candidate_id UUID;
    v_department_id BIGINT;
    v_candidate_user_id BIGINT;
    v_existing_email_owner BIGINT;
    v_expected_user_id BIGINT;
    v_replace_all BOOLEAN;
BEGIN
    -- The master feature row is an authorization input, not merely a process
    -- startup hint. Hold it through the whole reducer so rollback/disable is
    -- linearizable with lifecycle mutation even if LISTEN was disconnected.
    PERFORM 1
      FROM feature_toggles
     WHERE key='feature.identity_model_v2'
       AND enabled
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity model writes are disabled'
            USING ERRCODE='BZ224',
                  HINT='{"type":"identity_source_inactive"}';
    END IF;

    SELECT * INTO v_source
    FROM identity_sources
    WHERE id = p_source_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source not found'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"sourceId"}';
    END IF;
    IF v_source.generation <> p_expected_generation
       OR v_source.state <> 'active' THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = jsonb_build_object(
                      'type','identity_generation_stale',
                      'expectedGeneration',p_expected_generation,
                      'actualGeneration',v_source.generation,
                      'sourceState',v_source.state
                  )::text;
    END IF;

    SELECT * INTO v_entry
    FROM identity_source_inbox
    WHERE source_id = p_source_id
      AND batch_id = p_batch_id
      AND object_key = p_object_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source inbox entry not found'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"objectKey"}';
    END IF;
    IF v_entry.source_generation <> p_expected_generation THEN
        RAISE EXCEPTION 'identity source entry generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale"}';
    END IF;
    IF v_entry.state <> 'pending' THEN
        RETURN jsonb_build_object(
            'state',v_entry.state,
            'sourceId',p_source_id::text,
            'batchId',p_batch_id,
            'objectKey',p_object_key,
            'replayed',true
        );
    END IF;

    UPDATE identity_source_inbox
       SET attempt_count = attempt_count + 1,
           next_attempt_at = statement_timestamp() + interval '1 minute'
     WHERE source_id = p_source_id
       AND batch_id = p_batch_id
       AND object_key = p_object_key;
    UPDATE identity_source_batches
       SET state = 'draining',
           started_at = COALESCE(started_at, statement_timestamp()),
           updated_at = statement_timestamp()
     WHERE source_id = p_source_id AND batch_id = p_batch_id;

    v_payload := v_entry.sanitized_payload;
    v_expected_user_id := NULLIF(v_payload->>'expectedUserId','')::bigint;
    IF v_expected_user_id = 0 THEN
        v_expected_user_id := NULL;
    END IF;
    v_replace_all := COALESCE((v_payload->>'replaceAll')::boolean, false);
    v_operation := COALESCE(NULLIF(v_payload->>'operation',''), 'upsert');
    v_email := lower(btrim(COALESCE(v_payload->>'email','')));
    IF v_operation NOT IN ('upsert','disable')
       OR (
           v_operation = 'upsert'
           AND (
               v_expected_user_id IS NULL
               OR v_payload ? 'email'
           )
           AND (v_email = '' OR position('@' IN v_email) = 0)
       ) THEN
        UPDATE identity_source_inbox
           SET last_error_code = 'BZ228'
         WHERE source_id = p_source_id AND batch_id = p_batch_id
           AND object_key = p_object_key;
        UPDATE identity_source_batches
           SET state = 'blocked', last_error_code = 'BZ228',
               updated_at = statement_timestamp()
         WHERE source_id = p_source_id AND batch_id = p_batch_id;
        RETURN jsonb_build_object('state','blocked','code','BZ228');
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'identity-subject:' || p_source_id::text || ':' ||
            encode(digest(v_entry.immutable_subject,'sha256'),'hex'),
            0
        )
    );

    SELECT * INTO v_link
    FROM user_identity_links
    WHERE source_id = p_source_id
      AND external_subject = v_entry.immutable_subject
    FOR UPDATE;

    IF v_expected_user_id IS NOT NULL
       AND (v_link.id IS NULL OR v_link.user_id <> v_expected_user_id) THEN
        RAISE EXCEPTION 'SCIM path does not match the immutable source subject'
            USING ERRCODE = 'BZ230',
                  HINT = '{"type":"identity_subject_conflict"}';
    END IF;

    IF FOUND AND v_link.state <> 'active' THEN
        UPDATE identity_source_inbox
           SET last_error_code = 'BZ230'
         WHERE source_id = p_source_id AND batch_id = p_batch_id
           AND object_key = p_object_key;
        UPDATE identity_source_batches
           SET state = 'blocked', last_error_code = 'BZ230',
               updated_at = statement_timestamp()
         WHERE source_id = p_source_id AND batch_id = p_batch_id;
        RETURN jsonb_build_object(
            'state','blocked','code','BZ230',
            'remediation','review retained subject tombstone'
        );
    END IF;

    IF v_link.id IS NULL THEN
        IF v_operation = 'disable' THEN
            UPDATE identity_source_inbox
               SET last_error_code = 'BZ230'
             WHERE source_id = p_source_id AND batch_id = p_batch_id
               AND object_key = p_object_key;
            UPDATE identity_source_batches
               SET state = 'blocked', last_error_code = 'BZ230',
                   updated_at = statement_timestamp()
             WHERE source_id = p_source_id AND batch_id = p_batch_id;
            RETURN jsonb_build_object(
                'state','blocked','code','BZ230',
                'remediation','review unknown disabled subject'
            );
        END IF;

        -- Serialize the soft-address collision check with other connector
        -- creates. The result remains evidence only.
        PERFORM pg_advisory_xact_lock(
            hashtextextended('identity-email:' || v_email, 0)
        );
        SELECT u.id INTO v_existing_email_owner
          FROM users u
         WHERE lower(u.email)=v_email
            OR lower(u.ad_upn)=v_email
            OR EXISTS (
                SELECT 1
                  FROM aliases a
                  JOIN mailboxes m ON m.id=a.mailbox_id
                 WHERE m.user_id=u.id AND lower(a.email)=v_email
            )
         ORDER BY u.id
         LIMIT 1
         FOR UPDATE;
        IF v_existing_email_owner IS NOT NULL THEN
            INSERT INTO identity_match_candidates (
                source_id, external_subject, candidate_user_id,
                evidence_class, evidence_digest, redacted_explanation,
                generation, expires_at
            ) VALUES (
                p_source_id, v_entry.immutable_subject, v_existing_email_owner,
                'soft',
                digest(p_source_id::text || ':' || v_entry.immutable_subject ||
                       ':' || v_existing_email_owner::text, 'sha256'),
                'address matched an existing person; immutable proof required',
                p_expected_generation, statement_timestamp() + interval '30 days'
            )
            -- The matching partial unique index is NULLS NOT DISTINCT. A
            -- column-list inference target does not match that index on
            -- PostgreSQL 17 (42P10), so use the unambiguous table-wide
            -- DO NOTHING form. Generated candidate IDs cannot collide.
            ON CONFLICT DO NOTHING
            RETURNING id INTO v_candidate_id;

            UPDATE identity_source_inbox
               SET last_error_code = 'BZ231'
             WHERE source_id = p_source_id AND batch_id = p_batch_id
               AND object_key = p_object_key;
            UPDATE identity_source_batches
               SET state = 'blocked', last_error_code = 'BZ231',
                   updated_at = statement_timestamp()
             WHERE source_id = p_source_id AND batch_id = p_batch_id;
            RETURN jsonb_build_object(
                'state','blocked','code','BZ231',
                'candidateId',v_candidate_id,
                'remediation','decide the soft-evidence conflict'
            );
        END IF;

        IF NULLIF(v_payload->>'department','') IS NOT NULL THEN
            INSERT INTO departments (name,path,ldap_ou)
            VALUES (
                v_payload->>'department',
                v_payload->>'department',
                v_payload->>'department'
            )
            ON CONFLICT (path) DO UPDATE SET
                name = EXCLUDED.name,
                ldap_ou = EXCLUDED.ldap_ou
            RETURNING id INTO v_department_id;
        END IF;

        v_result := provision_account(
            p_email => v_email,
            p_display_name => NULLIF(v_payload->>'displayName',''),
            p_enabled => COALESCE((v_payload->>'enabled')::boolean, true),
            p_sync_source => v_source.kind,
            p_first_name => NULLIF(v_payload->>'firstName',''),
            p_last_name => NULLIF(v_payload->>'lastName',''),
            p_job_title => NULLIF(v_payload->>'jobTitle',''),
            p_phone => NULLIF(v_payload->>'phone',''),
            p_department_id => v_department_id,
            -- The legacy scalar can project an AD objectGUID, but a normalized
            -- source may use binary msDS-ConsistencyGuid (stored as canonical
            -- base64). The source-scoped link is authoritative in both cases;
            -- never cast or invent a UUID for the consistency-GUID shape.
            p_ad_object_guid => CASE
                WHEN v_source.kind = 'ad'
                 AND v_entry.immutable_subject ~*
                     '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                THEN v_entry.immutable_subject::uuid
                ELSE NULL
            END,
            p_ad_usn_changed => CASE WHEN v_source.kind = 'ad'
                THEN NULLIF(v_payload->>'cursorValue','')::bigint ELSE NULL END,
            p_ad_upn => NULLIF(v_payload->>'upn',''),
            p_krb5_principal => NULLIF(v_payload->>'upn',''),
            p_scim_external_id => CASE WHEN v_source.kind = 'scim'
                THEN v_entry.immutable_subject ELSE NULL END
        );
        v_user_id := (v_result->>'user_id')::bigint;

        IF is_guest_account(v_user_id)
           OR NOT EXISTS (
               SELECT 1 FROM mailboxes
               WHERE user_id = v_user_id AND is_primary
           ) THEN
            RAISE EXCEPTION 'identity source entry targets an excluded account class'
                USING ERRCODE = 'BZ239',
                      HINT = '{"type":"identity_account_class_excluded"}';
        END IF;

        INSERT INTO user_identity_links (
            user_id, source_id, external_subject, purposes, state,
            link_method, evidence
        ) VALUES (
            v_user_id, p_source_id, v_entry.immutable_subject,
            ARRAY['provision']::text[], 'active', 'hard_anchor',
            jsonb_build_object(
                'class','immutable',
                'batchDigest',encode(v_entry.remote_cursor_digest,'hex')
            )
        )
        RETURNING * INTO v_link;

        INSERT INTO user_lifecycle_authorities (
            user_id, authority_kind, link_id
        ) VALUES (v_user_id, 'source', v_link.id)
        ON CONFLICT (user_id) DO UPDATE SET
            authority_kind = 'source',
            link_id = EXCLUDED.link_id,
            generation = user_lifecycle_authorities.generation + 1,
            established_by = NULL,
            established_at = statement_timestamp(),
            updated_at = statement_timestamp();
    ELSE
        v_user_id := v_link.user_id;
        PERFORM pg_advisory_xact_lock(
            hashtextextended('identity-person:' || v_user_id::text, 0)
        );
        SELECT generation INTO v_user_generation
        FROM user_lifecycle_authorities
        WHERE user_id = v_user_id
        FOR UPDATE;
        IF NOT FOUND OR NOT EXISTS (
            SELECT 1 FROM user_lifecycle_authorities
            WHERE user_id = v_user_id
              AND authority_kind = 'source'
              AND link_id = v_link.id
        ) THEN
            RAISE EXCEPTION 'identity lifecycle source does not own this person'
                USING ERRCODE = 'BZ233',
                      HINT = '{"type":"identity_lifecycle_conflict"}';
        END IF;
        IF is_guest_account(v_user_id)
           OR NOT EXISTS (
               SELECT 1 FROM mailboxes
               WHERE user_id = v_user_id AND is_primary
           ) THEN
            RAISE EXCEPTION 'identity source entry targets an excluded account class'
                USING ERRCODE = 'BZ239',
                      HINT = '{"type":"identity_account_class_excluded"}';
        END IF;

        IF v_operation = 'disable' THEN
            PERFORM identity_source_attributes_apply(
                p_source_id,p_expected_generation,v_link.id,
                p_batch_id,p_object_key,
                v_payload || '{"enabled":false}'::jsonb
            );
            UPDATE oauth_tokens
               SET revoked_at = statement_timestamp(),
                   revoked_by = NULL
             WHERE user_id = v_user_id
               AND revoked_at IS NULL;
            PERFORM revoke_user_sessions(
                v_user_id,
                'all',
                'identity_source_disable',
                NULL,
                NULL,
                NULL
            );
            DELETE FROM sessions WHERE user_id = v_user_id;
            DELETE FROM ws_subscriptions WHERE user_id = v_user_id;
        ELSE
            SELECT u.id INTO v_existing_email_owner
              FROM users u
             WHERE u.id<>v_user_id
               AND (
                    lower(u.email)=v_email
                    OR lower(u.ad_upn)=v_email
                    OR EXISTS (
                        SELECT 1
                          FROM aliases a
                          JOIN mailboxes m ON m.id=a.mailbox_id
                         WHERE m.user_id=u.id AND lower(a.email)=v_email
                    )
               )
             ORDER BY u.id
             LIMIT 1
             FOR UPDATE;
            IF v_existing_email_owner IS NOT NULL THEN
                INSERT INTO identity_match_candidates (
                    source_id, external_subject, candidate_user_id,
                    evidence_class, evidence_digest, redacted_explanation,
                    generation, expires_at
                ) VALUES (
                    p_source_id, v_entry.immutable_subject, v_existing_email_owner,
                    'soft',
                    digest(p_source_id::text || ':' || v_entry.immutable_subject ||
                           ':' || v_existing_email_owner::text, 'sha256'),
                    'renamed address collides with another person',
                    p_expected_generation, statement_timestamp() + interval '30 days'
                )
                ON CONFLICT DO NOTHING
                RETURNING id INTO v_candidate_id;
                UPDATE identity_source_inbox SET last_error_code = 'BZ230'
                 WHERE source_id = p_source_id AND batch_id = p_batch_id
                   AND object_key = p_object_key;
                UPDATE identity_source_batches
                   SET state = 'blocked', last_error_code = 'BZ230',
                       updated_at = statement_timestamp()
                 WHERE source_id = p_source_id AND batch_id = p_batch_id;
                RETURN jsonb_build_object(
                    'state','blocked','code','BZ230',
                    'candidateId',v_candidate_id
                );
            END IF;

            PERFORM identity_source_attributes_apply(
                p_source_id,p_expected_generation,v_link.id,
                p_batch_id,p_object_key,v_payload
            );
            IF v_source.kind='ad' THEN
                UPDATE users SET ad_usn_changed=COALESCE(
                    NULLIF(v_payload->>'cursorValue','')::bigint,ad_usn_changed
                ) WHERE id=v_user_id;
            END IF;
        END IF;

        UPDATE user_identity_links
           SET last_seen_at = statement_timestamp(),
               updated_at = statement_timestamp()
         WHERE id = v_link.id;
    END IF;

    -- New persons are created from this exact source, so seed the governed
    -- authority rows after the link exists. Existing persons were handled in
    -- the branch above.
    IF NOT EXISTS (
        SELECT 1 FROM identity_attribute_authority
         WHERE user_id=v_user_id AND source_id=p_source_id AND link_id=v_link.id
    ) THEN
        PERFORM identity_source_attributes_apply(
            p_source_id,p_expected_generation,v_link.id,
            p_batch_id,p_object_key,
            CASE WHEN v_operation='disable'
                 THEN v_payload || '{"enabled":false}'::jsonb
                 ELSE v_payload END
        );
    END IF;

    INSERT INTO identity_link_events (
        user_id, source_id, link_id, action, reason, after_digest, metadata
    ) VALUES (
        v_user_id, p_source_id, v_link.id, 'source_entry_applied',
        'connector inbox entry applied',
        digest(
            p_source_id::text || ':' || p_batch_id::text || ':' ||
            p_object_key || ':' || v_link.id::text,
            'sha256'
        ),
        jsonb_build_object(
            'batchId',p_batch_id,
            'objectKeyDigest',encode(digest(p_object_key,'sha256'),'hex'),
            'generation',p_expected_generation
        )
    ) RETURNING id INTO v_event_id;

    UPDATE identity_source_inbox
       SET state = 'applied', applied_event_id = v_event_id,
           applied_at = statement_timestamp(), last_error_code = NULL
     WHERE source_id = p_source_id AND batch_id = p_batch_id
       AND object_key = p_object_key;

    UPDATE identity_source_batches b
       SET applied_count = (
               SELECT count(*) FROM identity_source_inbox i
               WHERE i.source_id = b.source_id AND i.batch_id = b.batch_id
                 AND i.state = 'applied'
           ),
           quarantined_count = (
               SELECT count(*) FROM identity_source_inbox i
               WHERE i.source_id = b.source_id AND i.batch_id = b.batch_id
                 AND i.state = 'quarantined'
           ),
           state = 'draining', last_error_code = NULL,
           updated_at = statement_timestamp()
     WHERE b.source_id = p_source_id AND b.batch_id = p_batch_id;

    RETURN jsonb_build_object(
        'state','applied',
        'sourceId',p_source_id::text,
        'batchId',p_batch_id,
        'objectKey',p_object_key,
        'userId',v_user_id::text,
        'linkId',v_link.id::text,
        'eventId',v_event_id::text
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_entry_apply(bigint,bigint,uuid,text)'::regprocedure
);
