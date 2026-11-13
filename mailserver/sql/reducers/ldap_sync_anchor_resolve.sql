-- ldap_sync_anchor_resolve — reducer-owned authority fence for the legacy LDAP
-- sync engine's anchor resolution (med-ldapsync-identity-001, Astra waves12
-- HOLD item 1).
--
-- The engine previously trusted ANY active user_identity_links row: an
-- authentication-only link, a link on a paused/retired source, or a link whose
-- subject no longer holds lifecycle authority could authorize disabling a
-- native account and revoking its sessions. Resolution now runs HERE, where
-- the authority inputs live, and returns a distinct outcome class instead of a
-- bare user id:
--
--   anchored  — the subject resolves to exactly one user AND every authority
--               input holds: source 'legacy:ldap' state 'active', link state
--               'active' with the 'provision' purpose, and lifecycle
--               authority for the linked user (an explicit
--               user_lifecycle_authorities row naming this link, or the
--               grandfathered legacy-provisioned family: users.sync_source
--               'ldap' with no OTHER identity source holding lifecycle
--               authority over the account).
--   missing   — the substrate knows nothing about the subject (no link row).
--               The engine may continue through its gated email path.
--   denied    — the subject is known but at least one authority input fails
--               (link suspended/detached/conflict, authentication-only
--               purposes, source paused/retired/draft/error, or lifecycle
--               authority held elsewhere). NOT a missing anchor: the engine
--               must NOT fall back to email matching, it must skip and audit.
--   no_source — the 'legacy:ldap' catalog row is absent entirely; the
--               substrate owns nothing and the engine falls back to its
--               grandfathered gated email path.
--   stale     — the caller pinned a source generation that is no longer
--               current (BZ229 semantics, outcome form): the engine must
--               surface the cycle for retry, never degrade to email.
--
-- Database errors surface as SQL errors and remain distinct from every
-- outcome above: an unreadable substrate is never "no anchor".
--
-- Outcome, not exception: denial is a normal authorization answer for a sync
-- engine that audits collisions, so denials return 'denied' + reason while
-- malformed input raises BZ228.
CREATE OR REPLACE FUNCTION ldap_sync_anchor_resolve(
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
    v_user_sync_source TEXT;
    v_other_owned BOOLEAN;
BEGIN
    IF NULLIF(btrim(p_subject), '') IS NULL THEN
        RAISE EXCEPTION 'ldap anchor resolve requires a non-empty subject'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"subject"}';
    END IF;

    SELECT * INTO v_source
      FROM identity_sources
     WHERE source_key = 'legacy:ldap'
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('resolution', 'no_source');
    END IF;

    IF p_expected_generation IS NOT NULL
       AND v_source.generation <> p_expected_generation THEN
        RETURN jsonb_build_object(
            'resolution', 'stale',
            'reason', 'source_generation',
            'sourceId', v_source.id,
            'generation', v_source.generation,
            'expectedGeneration', p_expected_generation);
    END IF;

    -- Subject existence FIRST: a subject the substrate does not know is
    -- 'missing' regardless of catalog state, so the engine's gated email path
    -- (and its own audits) keep governing exactly as before. Only a subject
    -- the substrate KNOWS is evaluated against the authority inputs below —
    -- and every denial then carries the linked user id for the audit trail.
    SELECT * INTO v_link
      FROM user_identity_links
     WHERE source_id = v_source.id
       AND external_subject = p_subject
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'resolution', 'missing',
            'sourceId', v_source.id,
            'generation', v_source.generation);
    END IF;

    IF v_source.state <> 'active' THEN
        RETURN jsonb_build_object(
            'resolution', 'denied',
            'reason', 'source_state',
            'sourceState', v_source.state,
            'sourceId', v_source.id,
            'linkId', v_link.id,
            'userId', v_link.user_id);
    END IF;

    IF v_link.state <> 'active' THEN
        RETURN jsonb_build_object(
            'resolution', 'denied',
            'reason', 'link_state',
            'linkState', v_link.state,
            'linkId', v_link.id,
            'userId', v_link.user_id);
    END IF;

    IF NOT ('provision' = ANY (v_link.purposes)) THEN
        RETURN jsonb_build_object(
            'resolution', 'denied',
            'reason', 'link_purposes',
            'purposes', to_jsonb(v_link.purposes),
            'linkId', v_link.id,
            'userId', v_link.user_id);
    END IF;

    SELECT sync_source INTO v_user_sync_source
      FROM users
     WHERE id = v_link.user_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'resolution', 'denied',
            'reason', 'user_missing',
            'linkId', v_link.id,
            'userId', v_link.user_id);
    END IF;

    SELECT EXISTS (
        SELECT 1
          FROM user_lifecycle_authorities a
          JOIN user_identity_links l2 ON l2.id = a.link_id
          JOIN identity_sources s2 ON s2.id = l2.source_id
         WHERE a.user_id = v_link.user_id
           AND a.authority_kind = 'source'
           AND s2.source_key <> 'legacy:ldap'
    ) INTO v_other_owned;

    IF NOT v_other_owned
       AND NOT EXISTS (
           SELECT 1
             FROM user_lifecycle_authorities a
            WHERE a.user_id = v_link.user_id
              AND a.authority_kind = 'source'
              AND a.link_id = v_link.id)
       AND v_user_sync_source IS DISTINCT FROM 'ldap' THEN
        RETURN jsonb_build_object(
            'resolution', 'denied',
            'reason', 'lifecycle_authority',
            'accountSyncSource', v_user_sync_source,
            'linkId', v_link.id,
            'userId', v_link.user_id);
    END IF;

    RETURN jsonb_build_object(
        'resolution', 'anchored',
        'userId', v_link.user_id,
        'linkId', v_link.id,
        'sourceId', v_source.id,
        'generation', v_source.generation);
END;
$$;

SELECT apply_worker_ownership(
    'ldap_sync_anchor_resolve(text,bigint)'::regprocedure
);
