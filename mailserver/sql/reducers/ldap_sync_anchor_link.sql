-- ldap_sync_anchor_link — reducer-owned anchor establishment for the legacy
-- LDAP sync engine (med-ldapsync-identity-001, Astra waves12 HOLD item 1).
--
-- The engine previously hand-INSERTed into user_identity_links after
-- provisioning an account. Link establishment now runs HERE so the substrate's
-- own guards (account-class exclusion, lifecycle reverse guard, purpose
-- domain) and the append-only audit trail are enforced in the same
-- transaction as the write. The reducer only CONSUMES the 'legacy:ldap'
-- identity_sources row — creating or mutating source-catalog rows stays with
-- identity_source_upsert.
--
-- Outcomes (JSON, no exception):
--   linked:true / linkId            — link created or refreshed (idempotent
--                                     re-anchor of the SAME account).
--   linked:false / source_missing   — no 'legacy:ldap' catalog row; the
--                                     engine keeps working through its gated
--                                     email path.
--   linked:false / source_inactive  — catalog row exists but is not active;
--                                     establishment is pointless while paused.
--   linked:false / conflict         — the subject already anchors a DIFFERENT
--                                     account. The engine never steals an
--                                     anchor; a soft-evidence candidate row is
--                                     recorded for operator review.
-- Generation fencing: when p_expected_generation is non-null and the live
-- catalog row has moved past it, the reducer raises BZ229 — a mid-cycle
-- rebind/retire must surface as a sync error, not silently re-anchor against
-- a stale authority.
--
-- On success the reducer also (a) appends the 'legacy_backfilled'
-- identity_link_events audit row and (b) establishes source lifecycle
-- authority for the provisioned account — upgrading ONLY a 'local' authority,
-- never stealing another source's (same policy as identity_legacy_backfill).
CREATE OR REPLACE FUNCTION ldap_sync_anchor_link(
    p_user_id BIGINT,
    p_subject TEXT,
    p_expected_generation BIGINT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source identity_sources%ROWTYPE;
    v_link   user_identity_links%ROWTYPE;
    v_event_dupe BIGINT;
BEGIN
    IF p_user_id IS NULL OR p_user_id <= 0 THEN
        RAISE EXCEPTION 'ldap anchor link requires a user id'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"userId"}';
    END IF;
    IF NULLIF(btrim(p_subject), '') IS NULL THEN
        RAISE EXCEPTION 'ldap anchor link requires a non-empty subject'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"subject"}';
    END IF;

    SELECT * INTO v_source
      FROM identity_sources
     WHERE source_key = 'legacy:ldap'
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('linked', false, 'reason', 'source_missing');
    END IF;

    IF p_expected_generation IS NOT NULL
       AND v_source.generation <> p_expected_generation THEN
        RAISE EXCEPTION 'ldap anchor link generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = jsonb_build_object(
                      'type', 'identity_generation_stale',
                      'expectedGeneration', p_expected_generation,
                      'actualGeneration', v_source.generation)::TEXT;
    END IF;

    IF v_source.state <> 'active' THEN
        RETURN jsonb_build_object('linked', false, 'reason', 'source_inactive');
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-person:' || p_user_id::text, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-subject:' || v_source.id::text || ':'
        || encode(digest(p_subject, 'sha256'), 'hex'), 0));

    SELECT * INTO v_link
      FROM user_identity_links
     WHERE source_id = v_source.id
       AND external_subject = p_subject
       FOR UPDATE;

    IF FOUND AND v_link.user_id <> p_user_id THEN
        -- Never steal an anchor: record soft evidence for operator review and
        -- leave the existing link untouched.
        INSERT INTO identity_match_candidates (
            source_id, external_subject, candidate_user_id,
            evidence_class, evidence_digest, redacted_explanation,
            expires_at
        ) VALUES (
            v_source.id, p_subject, p_user_id, 'soft',
            digest(v_source.id::text || ':' || p_subject || ':'
                   || p_user_id::text, 'sha256'),
            'legacy ldap engine attempted to anchor a subject already owned by another account',
            statement_timestamp() + interval '30 days'
        )
        ON CONFLICT DO NOTHING;
        RETURN jsonb_build_object('linked', false, 'reason', 'conflict',
                                  'linkId', v_link.id);
    END IF;

    IF NOT FOUND THEN
        INSERT INTO user_identity_links (
            user_id, source_id, external_subject, purposes, state,
            link_method, evidence
        ) VALUES (
            p_user_id, v_source.id, p_subject,
            ARRAY['provision']::text[], 'active', 'legacy_backfill',
            '{"legacy":true,"anchor":"protocol_immutable_subject"}'::jsonb
        ) RETURNING * INTO v_link;
    ELSE
        UPDATE user_identity_links
           SET last_seen_at = GREATEST(user_identity_links.last_seen_at,
                                       statement_timestamp()),
               updated_at = statement_timestamp()
         WHERE id = v_link.id
        RETURNING * INTO v_link;
    END IF;

    SELECT a.id INTO v_event_dupe
      FROM identity_link_events a
     WHERE a.link_id = v_link.id
       AND a.action = 'legacy_backfilled'
     LIMIT 1;
    IF v_event_dupe IS NULL THEN
        INSERT INTO identity_link_events (
            user_id, source_id, link_id, action, reason,
            after_digest, metadata
        ) VALUES (
            p_user_id, v_source.id, v_link.id, 'legacy_backfilled',
            'legacy ldap engine provisioned this account',
            digest(concat_ws(':', p_user_id::text, v_source.id::text,
                             v_link.id::text), 'sha256'),
            '{"legacy":true}'::jsonb
        );
    END IF;

    -- Source lifecycle authority for the freshly provisioned account: upgrade
    -- ONLY an existing 'local' authority (never another source's claim).
    INSERT INTO user_lifecycle_authorities (user_id, authority_kind, link_id)
    VALUES (p_user_id, 'source', v_link.id)
    ON CONFLICT (user_id) DO UPDATE SET
        authority_kind = 'source',
        link_id = EXCLUDED.link_id,
        generation = user_lifecycle_authorities.generation + 1,
        established_by = NULL,
        established_at = statement_timestamp(),
        updated_at = statement_timestamp()
    WHERE user_lifecycle_authorities.authority_kind = 'local';

    RETURN jsonb_build_object('linked', true, 'linkId', v_link.id,
                              'sourceId', v_source.id,
                              'generation', v_source.generation);
END;
$$;

SELECT apply_worker_ownership(
    'ldap_sync_anchor_link(bigint,text,bigint)'::regprocedure
);
