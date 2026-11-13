-- Compare one legacy person projection with the normalized I1 projection.
-- Digests and enum-only samples are persisted; raw subjects/addresses are not.
CREATE OR REPLACE FUNCTION identity_shadow_compare(
    p_user_id BIGINT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_user users%ROWTYPE;
    v_old_digest BYTEA;
    v_new_digest BYTEA;
    v_expected_links INTEGER := 0;
    v_matching_links INTEGER := 0;
    v_expected_authority TEXT;
    v_actual_authority TEXT;
    v_class TEXT;
    v_source_id BIGINT;
    v_link_id BIGINT;
    v_critical INTEGER := 0;
    v_ambiguities INTEGER := 0;
    v_scan_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'identity shadow comparison requires a person id'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"userId"}';
    END IF;

    SELECT * INTO v_user
    FROM users
    WHERE id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity person was not found'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"userId"}';
    END IF;

    SELECT digest(
        jsonb_build_object(
            'userId', v_user.id::text,
            'syncSource', v_user.sync_source,
            'hasADAnchor', v_user.ad_object_guid IS NOT NULL,
            'hasSCIMAnchor', v_user.scim_external_id IS NOT NULL,
            'hasOIDCPair', v_user.oidc_issuer IS NOT NULL AND v_user.oidc_subject IS NOT NULL,
            'hasSAMLPair', v_user.saml_idp_entity_id IS NOT NULL AND v_user.saml_name_id IS NOT NULL
        )::text,
        'sha256'
    ) INTO v_old_digest;

    SELECT digest(
        jsonb_build_object(
            'userId', v_user.id::text,
            'links', COALESCE((
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'sourceId', l.source_id::text,
                        'state', l.state,
                        'purposes', l.purposes,
                        'generation', l.generation::text
                    )
                    ORDER BY l.source_id, l.id
                )
                FROM user_identity_links l
                WHERE l.user_id = v_user.id
            ), '[]'::jsonb),
            'authority', (
                SELECT jsonb_build_object(
                    'kind', a.authority_kind,
                    'linkId', a.link_id::text,
                    'generation', a.generation::text
                )
                FROM user_lifecycle_authorities a
                WHERE a.user_id = v_user.id
            )
        )::text,
        'sha256'
    ) INTO v_new_digest;

    UPDATE identity_shadow_divergences
    SET state = 'resolved',
        last_seen_at = statement_timestamp(),
        expires_at = statement_timestamp() + interval '30 days'
    WHERE user_id = v_user.id
      AND state = 'open';

    -- Unsupported account classes and incomplete legacy pairs are explicit,
    -- operator-dispositioned ambiguity, never a person mismatch.
    IF is_guest_account(v_user.id)
       OR NOT EXISTS (
           SELECT 1 FROM mailboxes m
           WHERE m.user_id = v_user.id AND m.is_primary
       )
       OR (v_user.oidc_issuer IS NULL) <> (v_user.oidc_subject IS NULL)
       OR (v_user.saml_idp_entity_id IS NULL) <> (v_user.saml_name_id IS NULL)
       OR v_user.sync_source = 'ldap' THEN
        INSERT INTO identity_shadow_divergences (
            source_id, user_id, divergence_class,
            old_outcome_digest, new_outcome_digest,
            redacted_sample, last_seen_at
        ) VALUES (
            CASE
                WHEN v_user.sync_source = 'ldap' THEN (
                    SELECT id FROM identity_sources WHERE source_key = 'legacy:ldap'
                )
                ELSE NULL
            END,
            v_user.id,
            'expected_legacy_ambiguity',
            v_old_digest,
            v_new_digest,
            jsonb_build_object(
                'accountClassExcluded',
                    is_guest_account(v_user.id)
                    OR NOT EXISTS (
                        SELECT 1 FROM mailboxes m
                        WHERE m.user_id = v_user.id AND m.is_primary
                    ),
                'incompleteFederationPair',
                    (v_user.oidc_issuer IS NULL) <> (v_user.oidc_subject IS NULL)
                    OR (v_user.saml_idp_entity_id IS NULL) <> (v_user.saml_name_id IS NULL),
                'immutableAnchorDiscoveryRequired', v_user.sync_source = 'ldap'
            ),
            v_scan_at
        )
        ON CONFLICT (
            source_id, user_id, link_id, divergence_class
        )
        DO UPDATE SET
            old_outcome_digest = EXCLUDED.old_outcome_digest,
            new_outcome_digest = EXCLUDED.new_outcome_digest,
            last_seen_at = v_scan_at,
            seen_count = identity_shadow_divergences.seen_count + 1,
            state = CASE
                WHEN identity_shadow_divergences.state = 'explained'
                    THEN 'explained'
                ELSE 'open'
            END,
            redacted_sample = EXCLUDED.redacted_sample,
            explained_by = CASE
                WHEN identity_shadow_divergences.state = 'explained'
                    THEN identity_shadow_divergences.explained_by
                ELSE NULL
            END,
            explained_at = CASE
                WHEN identity_shadow_divergences.state = 'explained'
                    THEN identity_shadow_divergences.explained_at
                ELSE NULL
            END,
            expires_at = statement_timestamp() + interval '30 days';
        v_ambiguities := v_ambiguities + 1;
    END IF;

    -- Every complete hard legacy anchor must resolve to the same person.
    FOR v_class, v_source_id, v_link_id IN
        SELECT expected.anchor_class, expected.source_id, l.id
        FROM (
            SELECT 'ad'::text AS anchor_class, s.id AS source_id,
                   v_user.ad_object_guid::text AS subject
            FROM identity_sources s WHERE s.source_key = 'legacy:ad'
            UNION ALL
            SELECT 'scim', s.id, v_user.scim_external_id
            FROM identity_sources s WHERE s.source_key = 'legacy:scim'
            UNION ALL
            SELECT 'saml', s.id, v_user.saml_name_id
            FROM identity_sources s
            WHERE v_user.saml_idp_entity_id IS NOT NULL
              AND s.source_key = 'saml:' || substr(
                  encode(digest(v_user.saml_idp_entity_id, 'sha256'), 'hex'), 1, 48
              )
            UNION ALL
            SELECT 'oidc', s.id, v_user.oidc_subject
            FROM identity_sources s
            WHERE v_user.oidc_issuer IS NOT NULL
              AND s.source_key = 'oidc:' || substr(
                  encode(digest(v_user.oidc_issuer, 'sha256'), 'hex'), 1, 48
              )
        ) AS expected
        LEFT JOIN user_identity_links l
          ON l.source_id = expected.source_id
         AND l.external_subject = expected.subject
         AND l.user_id = v_user.id
         AND l.state = 'active'
        WHERE expected.subject IS NOT NULL
    LOOP
        v_expected_links := v_expected_links + 1;
        IF v_link_id IS NOT NULL THEN
            v_matching_links := v_matching_links + 1;
        ELSE
            INSERT INTO identity_shadow_divergences (
                source_id, user_id, divergence_class,
                old_outcome_digest, new_outcome_digest,
                redacted_sample, last_seen_at
            ) VALUES (
                v_source_id, v_user.id, 'person_mismatch',
                v_old_digest, v_new_digest,
                jsonb_build_object('anchorClass', v_class, 'normalizedLink', 'missing'),
                v_scan_at
            )
            ON CONFLICT (
                source_id, user_id, link_id, divergence_class
            )
            DO UPDATE SET
                old_outcome_digest = EXCLUDED.old_outcome_digest,
                new_outcome_digest = EXCLUDED.new_outcome_digest,
                last_seen_at = v_scan_at,
                seen_count = identity_shadow_divergences.seen_count + 1,
                state = CASE
                    WHEN identity_shadow_divergences.state = 'explained'
                        THEN 'explained'
                    ELSE 'open'
                END,
                redacted_sample = EXCLUDED.redacted_sample,
                explained_by = CASE
                    WHEN identity_shadow_divergences.state = 'explained'
                        THEN identity_shadow_divergences.explained_by
                    ELSE NULL
                END,
                explained_at = CASE
                    WHEN identity_shadow_divergences.state = 'explained'
                        THEN identity_shadow_divergences.explained_at
                    ELSE NULL
                END,
                expires_at = statement_timestamp() + interval '30 days';
            v_critical := v_critical + 1;
        END IF;
    END LOOP;

    v_expected_authority := CASE
        WHEN v_user.sync_source IN ('local','sso') THEN 'local'
        WHEN v_user.sync_source IN ('ad','scim') THEN 'source'
        WHEN v_user.sync_source = 'ldap' THEN NULL
    END;

    SELECT authority_kind INTO v_actual_authority
    FROM user_lifecycle_authorities
    WHERE user_id = v_user.id;

    IF v_expected_authority IS NOT NULL
       AND v_actual_authority IS DISTINCT FROM v_expected_authority THEN
        INSERT INTO identity_shadow_divergences (
            user_id, divergence_class,
            old_outcome_digest, new_outcome_digest,
            redacted_sample, last_seen_at
        ) VALUES (
            v_user.id, 'authority_mismatch',
            v_old_digest, v_new_digest,
            jsonb_build_object(
                'legacyAuthority', v_expected_authority,
                'normalizedAuthority', COALESCE(v_actual_authority, 'missing')
            ),
            v_scan_at
        )
        ON CONFLICT (
            source_id, user_id, link_id, divergence_class
        )
        DO UPDATE SET
            old_outcome_digest = EXCLUDED.old_outcome_digest,
            new_outcome_digest = EXCLUDED.new_outcome_digest,
            last_seen_at = v_scan_at,
            seen_count = identity_shadow_divergences.seen_count + 1,
            state = CASE
                WHEN identity_shadow_divergences.state = 'explained'
                    THEN 'explained'
                ELSE 'open'
            END,
            redacted_sample = EXCLUDED.redacted_sample,
            explained_by = CASE
                WHEN identity_shadow_divergences.state = 'explained'
                    THEN identity_shadow_divergences.explained_by
                ELSE NULL
            END,
            explained_at = CASE
                WHEN identity_shadow_divergences.state = 'explained'
                    THEN identity_shadow_divergences.explained_at
                ELSE NULL
            END,
            expires_at = statement_timestamp() + interval '30 days';
        v_critical := v_critical + 1;
    END IF;

    UPDATE identity_shadow_divergences
       SET state = 'resolved',
           explained_by = NULL,
           explained_at = NULL,
           expires_at = statement_timestamp() + interval '30 days'
     WHERE user_id = v_user.id
       AND state = 'explained'
       AND last_seen_at < v_scan_at;

    RETURN jsonb_build_object(
        'userId', v_user.id::text,
        'expectedLinks', v_expected_links,
        'matchingLinks', v_matching_links,
        'criticalDivergences', v_critical,
        'expectedAmbiguities', v_ambiguities
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_shadow_compare(bigint)'::regprocedure
);
