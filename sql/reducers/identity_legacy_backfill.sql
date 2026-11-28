-- Restart-safe, bounded I1 hard-anchor backfill. It is intentionally
-- worker-only and shadow-only: legacy rows remain untouched and the feature
-- toggle remains OFF.
CREATE OR REPLACE FUNCTION identity_legacy_backfill(
    p_after_user_id BIGINT,
    p_limit INTEGER
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_user RECORD;
    v_source_id BIGINT;
    v_link_id BIGINT;
    v_processed INTEGER := 0;
    v_linked INTEGER := 0;
    v_conflicts INTEGER := 0;
    v_last_user_id BIGINT := COALESCE(p_after_user_id, 0);
    v_source_key TEXT;
    v_subject TEXT;
    v_purposes TEXT[];
    v_items JSONB := '[]'::jsonb;
    v_user_linked INTEGER;
    v_user_conflicts INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 500 THEN
        RAISE EXCEPTION 'identity backfill limit must be between 1 and 500'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"limit","minimum":1,"maximum":500}';
    END IF;

    FOR v_user IN
        SELECT u.*
        FROM users u
        WHERE u.id > COALESCE(p_after_user_id, 0)
        ORDER BY u.id
        LIMIT p_limit
    LOOP
        v_processed := v_processed + 1;
        v_last_user_id := v_user.id;
        v_user_linked := 0;
        v_user_conflicts := 0;

        IF is_guest_account(v_user.id)
           OR NOT EXISTS (
               SELECT 1 FROM mailboxes m
               WHERE m.user_id = v_user.id AND m.is_primary
           ) THEN
            v_items := v_items || jsonb_build_array(jsonb_build_object(
                'userId',v_user.id::text,
                'state','skipped',
                'result',jsonb_build_object(
                    'reason','account_class_excluded',
                    'linksObserved',0,
                    'conflictsRecorded',0
                )
            ));
            CONTINUE;
        END IF;

        -- Local lifecycle requires no external link.
        IF v_user.sync_source IN ('local','sso') THEN
            INSERT INTO user_lifecycle_authorities (
                user_id, authority_kind, link_id
            ) VALUES (v_user.id, 'local', NULL)
            ON CONFLICT (user_id) DO NOTHING;
        END IF;

        FOR v_source_key, v_subject, v_purposes IN
            SELECT x.source_key, x.subject, x.purposes
            FROM (
                VALUES
                    (
                        'legacy:ad'::text,
                        v_user.ad_object_guid::text,
                        ARRAY['authenticate','provision']::text[]
                    ),
                    (
                        'legacy:scim'::text,
                        v_user.scim_external_id,
                        ARRAY['provision']::text[]
                    ),
                    (
                        CASE WHEN v_user.saml_idp_entity_id IS NULL THEN NULL
                             ELSE 'saml:' || substr(
                                 encode(digest(v_user.saml_idp_entity_id, 'sha256'), 'hex'),
                                 1, 48
                             )
                        END,
                        v_user.saml_name_id,
                        ARRAY['authenticate']::text[]
                    ),
                    (
                        CASE WHEN v_user.oidc_issuer IS NULL THEN NULL
                             ELSE 'oidc:' || substr(
                                 encode(digest(v_user.oidc_issuer, 'sha256'), 'hex'),
                                 1, 48
                             )
                        END,
                        v_user.oidc_subject,
                        ARRAY['authenticate']::text[]
                    )
            ) AS x(source_key, subject, purposes)
            WHERE x.source_key IS NOT NULL AND x.subject IS NOT NULL
        LOOP
            IF v_source_key LIKE 'saml:%' OR v_source_key LIKE 'oidc:%' THEN
                INSERT INTO identity_sources (
                    source_key, display_name, kind, capabilities, state
                ) VALUES (
                    v_source_key,
                    CASE WHEN v_source_key LIKE 'saml:%'
                         THEN 'Legacy SAML ' ELSE 'Legacy OIDC ' END
                        || substr(v_source_key, 6, 12),
                    CASE WHEN v_source_key LIKE 'saml:%' THEN 'saml' ELSE 'oidc' END,
                    '{"authenticate":true,"provision_lifecycle":false,"stable_immutable_subject":true}'::jsonb,
                    'active'
                )
                ON CONFLICT (source_key) DO NOTHING;
            END IF;

            SELECT id INTO v_source_id
            FROM identity_sources
            WHERE source_key = v_source_key;

            PERFORM pg_advisory_xact_lock(
                hashtextextended('identity-person:' || v_user.id::text, 0)
            );
            PERFORM pg_advisory_xact_lock(
                hashtextextended(
                    'identity-subject:' || v_source_id::text || ':'
                    || encode(digest(v_subject, 'sha256'), 'hex'),
                    0
                )
            );

            SELECT id INTO v_link_id
            FROM user_identity_links
            WHERE source_id = v_source_id
              AND external_subject = v_subject;

            IF FOUND AND EXISTS (
                SELECT 1 FROM user_identity_links
                WHERE id = v_link_id AND user_id <> v_user.id
            ) THEN
                INSERT INTO identity_match_candidates (
                    source_id, external_subject, candidate_user_id,
                    evidence_class, evidence_digest, redacted_explanation,
                    status, expires_at
                ) VALUES (
                    v_source_id, v_subject, v_user.id, 'conflict',
                    digest(
                        concat_ws(':', v_source_id::text, v_user.id::text,
                                  encode(digest(v_subject, 'sha256'), 'hex')),
                        'sha256'
                    ),
                    'Immutable subject is already reserved by another retained link',
                    'pending', statement_timestamp() + interval '30 days'
                )
                ON CONFLICT (
                    source_id, external_subject, candidate_user_id,
                    evidence_class, generation
                ) WHERE status IN ('pending','deferred')
                DO NOTHING;
                v_conflicts := v_conflicts + 1;
                v_user_conflicts := v_user_conflicts + 1;
                CONTINUE;
            END IF;

            INSERT INTO user_identity_links (
                user_id, source_id, external_subject, purposes,
                state, link_method, evidence
            ) VALUES (
                v_user.id, v_source_id, v_subject, v_purposes,
                'active', 'legacy_backfill',
                '{"legacy":true,"anchor":"protocol_immutable_subject"}'::jsonb
            )
            ON CONFLICT (source_id, external_subject) DO UPDATE
            SET last_seen_at = GREATEST(
                    user_identity_links.last_seen_at,
                    statement_timestamp()
                )
            WHERE user_identity_links.user_id = EXCLUDED.user_id
            RETURNING id INTO v_link_id;

            IF v_link_id IS NULL THEN
                CONTINUE;
            END IF;

            v_linked := v_linked + 1;
            v_user_linked := v_user_linked + 1;

            INSERT INTO identity_link_events (
                user_id, source_id, link_id, action, reason,
                after_digest, metadata
            ) VALUES (
                v_user.id, v_source_id, v_link_id, 'legacy_backfilled',
                'restart-safe deterministic hard-anchor backfill',
                digest(
                    concat_ws(':', v_user.id::text, v_source_id::text,
                              v_link_id::text),
                    'sha256'
                ),
                '{"legacy":true}'::jsonb
            )
            ON CONFLICT (link_id, action)
                WHERE action = 'legacy_backfilled' AND link_id IS NOT NULL
                DO NOTHING;

            IF (v_user.sync_source = 'ad' AND v_source_key = 'legacy:ad')
               OR (v_user.sync_source = 'scim' AND v_source_key = 'legacy:scim') THEN
                INSERT INTO user_lifecycle_authorities (
                    user_id, authority_kind, link_id
                ) VALUES (v_user.id, 'source', v_link_id)
                ON CONFLICT (user_id) DO UPDATE SET
                    authority_kind = 'source',
                    link_id = EXCLUDED.link_id,
                    generation = user_lifecycle_authorities.generation + 1,
                    established_by = NULL,
                    established_at = statement_timestamp(),
                    updated_at = statement_timestamp()
                WHERE user_lifecycle_authorities.authority_kind = 'local';
            END IF;
        END LOOP;
        v_items := v_items || jsonb_build_array(jsonb_build_object(
            'userId',v_user.id::text,
            'state',CASE WHEN v_user_conflicts > 0
                         THEN 'blocked' ELSE 'completed' END,
            'result',jsonb_build_object(
                'linksObserved',v_user_linked,
                'conflictsRecorded',v_user_conflicts
            )
        ));
    END LOOP;

    RETURN jsonb_build_object(
        'processed', v_processed,
        'linksObserved', v_linked,
        'conflictsRecorded', v_conflicts,
        'nextAfterUserId', v_last_user_id::text,
        'complete', v_processed < p_limit OR NOT EXISTS (
            SELECT 1 FROM users WHERE id > v_last_user_id
        ),
        'items', v_items
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_legacy_backfill(bigint,integer)'::regprocedure
);
