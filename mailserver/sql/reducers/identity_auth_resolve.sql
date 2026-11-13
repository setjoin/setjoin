-- Resolve one exact federated issuer/subject pair. No address-like attribute is
-- considered, and detached tombstones never authenticate.
CREATE OR REPLACE FUNCTION identity_auth_resolve(
    p_kind TEXT,
    p_provider TEXT,
    p_subject TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source_key TEXT;
    v_user_id BIGINT;
    v_link_id BIGINT;
    v_link_generation BIGINT;
    v_email TEXT;
    v_source_id BIGINT;
    v_read_mode TEXT;
    v_source_generation BIGINT;
    v_serve BOOLEAN := false;
BEGIN
    IF p_kind NOT IN ('saml','oidc')
       OR p_provider IS NULL OR p_provider = ''
       OR p_subject IS NULL OR p_subject = ''
       OR octet_length(p_provider) > 2048
       OR octet_length(p_subject) > 2048
       OR p_provider ~ '[[:cntrl:]]'
       OR p_subject ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid federated identity pair'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid"}';
    END IF;

    v_source_key := p_kind || ':' ||
        substr(encode(digest(p_provider,'sha256'),'hex'),1,48);

    SELECT id,read_mode,generation
      INTO v_source_id,v_read_mode,v_source_generation
      FROM identity_sources
     WHERE source_key=v_source_key AND kind=p_kind AND state='active';
    SELECT u.id, l.id, l.generation, u.email
      INTO v_user_id, v_link_id, v_link_generation, v_email
      FROM identity_sources s
      JOIN user_identity_links l ON l.source_id = s.id
      JOIN users u ON u.id = l.user_id
     WHERE s.source_key = v_source_key
       AND s.kind = p_kind
       AND s.state = 'active'
       AND l.external_subject = p_subject
       AND l.state = 'active'
       AND 'authenticate' = ANY(l.purposes)
       AND u.enabled
       AND NOT is_guest_account(u.id);

    IF v_source_id IS NOT NULL THEN
        v_serve := v_read_mode='normalized'
          OR COALESCE((SELECT enabled FROM feature_toggles
                        WHERE key='feature.identity_normalized_reads'),false)
          OR (
              v_read_mode='canary' AND v_user_id IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM identity_read_cohort c
                  JOIN user_lifecycle_authorities authority
                    ON authority.user_id=c.user_id
                   WHERE c.source_id=v_source_id AND c.user_id=v_user_id
                     AND c.source_generation=v_source_generation
                     AND c.auth_link_id=v_link_id
                     AND c.auth_link_generation=v_link_generation
                     AND c.lifecycle_generation=authority.generation
              )
          );
    END IF;

    IF NOT FOUND THEN
        -- An unknown subject on a canary source must not fall through to the
        -- legacy address/UPN auto-link cascade. A cohort can only be evaluated
        -- after an exact subject resolves to a person, so the safe unknown
        -- result is a normalized miss (JIT or explicit linking), never a soft
        -- identity proof.
        RETURN jsonb_build_object(
            'found',false,'sourceKey',v_source_key,
            'sourceId',CASE WHEN v_source_id IS NULL
                            THEN NULL ELSE v_source_id::text END,
            'sourceGeneration',CASE WHEN v_source_id IS NULL
                                    THEN NULL ELSE v_source_generation::text END,
            'readMode',COALESCE(v_read_mode,'legacy'),
            'serveNormalized',v_serve OR v_read_mode='canary'
        );
    END IF;
    RETURN jsonb_build_object(
        'found',true,'sourceKey',v_source_key,
        'sourceId',v_source_id::text,
        'sourceGeneration',v_source_generation::text,
        'userId',v_user_id::text,'linkId',v_link_id::text,
        'linkGeneration',v_link_generation::text,'email',v_email,
        'readMode',v_read_mode,'serveNormalized',v_serve
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_auth_resolve(text,text,text)'::regprocedure
);
