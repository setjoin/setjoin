-- Record one real OIDC/SAML shadow comparison without retaining the provider
-- subject or assertion. Source-hour aggregates bound volume; per-link evidence
-- pins the exact link generation later admitted to a canary cohort.
CREATE OR REPLACE FUNCTION identity_auth_shadow_observe(
    p_kind TEXT,
    p_provider TEXT,
    p_subject TEXT,
    p_expected_source_id BIGINT,
    p_expected_source_generation BIGINT,
    p_expected_link_id BIGINT,
    p_expected_link_generation BIGINT,
    p_normalized_user_id BIGINT,
    p_legacy_user_id BIGINT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source public.identity_sources%ROWTYPE;
    v_link public.user_identity_links%ROWTYPE;
    v_bucket TIMESTAMPTZ := date_trunc('hour', statement_timestamp());
    v_match BOOLEAN;
    v_subject_digest BYTEA;
    v_old_digest BYTEA;
    v_new_digest BYTEA;
    v_divergence_user BIGINT;
BEGIN
    IF p_kind NOT IN ('oidc','saml')
       OR p_provider IS NULL OR p_provider=''
       OR p_subject IS NULL OR p_subject=''
       OR octet_length(p_provider)>2048
       OR octet_length(p_subject)>2048
       OR p_provider ~ '[[:cntrl:]]'
       OR p_subject ~ '[[:cntrl:]]'
       OR p_expected_source_id IS NULL
       OR p_expected_source_generation IS NULL THEN
        RAISE EXCEPTION 'invalid identity authentication shadow observation'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid"}';
    END IF;

    SELECT * INTO v_source
      FROM public.identity_sources
     WHERE id=p_expected_source_id
       AND source_key=p_kind||':'||
           substr(encode(digest(p_provider,'sha256'),'hex'),1,48)
       AND kind=p_kind
       AND state='active'
       AND generation=p_expected_source_generation
     FOR SHARE;
    IF NOT FOUND OR v_source.read_mode<>'shadow' THEN
        RETURN jsonb_build_object(
            'observed',false,'reason','source_generation_or_mode_changed'
        );
    END IF;

    SELECT * INTO v_link
      FROM public.user_identity_links
     WHERE source_id=v_source.id
       AND external_subject=p_subject
       AND state='active'
       AND 'authenticate'=ANY(purposes)
     FOR SHARE;

    IF FOUND THEN
        IF p_expected_link_id IS DISTINCT FROM v_link.id
           OR p_expected_link_generation IS DISTINCT FROM v_link.generation
           OR p_normalized_user_id IS DISTINCT FROM v_link.user_id THEN
            RETURN jsonb_build_object(
                'observed',false,'reason','link_generation_changed'
            );
        END IF;
    ELSIF p_expected_link_id IS NOT NULL
       OR p_expected_link_generation IS NOT NULL
       OR p_normalized_user_id IS NOT NULL THEN
        RETURN jsonb_build_object(
            'observed',false,'reason','link_generation_changed'
        );
    END IF;

    v_match := p_normalized_user_id IS NOT DISTINCT FROM p_legacy_user_id;
    v_subject_digest := digest(p_kind||':'||p_provider||':'||p_subject,'sha256');
    v_old_digest := digest(
        'legacy:'||COALESCE(p_legacy_user_id::text,'miss')||':'||
        encode(v_subject_digest,'hex'),'sha256'
    );
    v_new_digest := digest(
        'normalized:'||COALESCE(p_normalized_user_id::text,'miss')||':'||
        encode(v_subject_digest,'hex'),'sha256'
    );

    INSERT INTO public.identity_auth_shadow_hours(
        source_id,bucket_start,source_generation,matched_count,
        mismatched_count,first_observed_at,last_observed_at
    ) VALUES(
        v_source.id,v_bucket,v_source.generation,
        CASE WHEN v_match THEN 1 ELSE 0 END,
        CASE WHEN v_match THEN 0 ELSE 1 END,
        statement_timestamp(),statement_timestamp()
    )
    ON CONFLICT(source_id,bucket_start) DO UPDATE SET
        source_generation=EXCLUDED.source_generation,
        matched_count=public.identity_auth_shadow_hours.matched_count+
            EXCLUDED.matched_count,
        mismatched_count=public.identity_auth_shadow_hours.mismatched_count+
            EXCLUDED.mismatched_count,
        first_observed_at=least(
            public.identity_auth_shadow_hours.first_observed_at,
            EXCLUDED.first_observed_at
        ),
        last_observed_at=greatest(
            public.identity_auth_shadow_hours.last_observed_at,
            EXCLUDED.last_observed_at
        );

    IF v_link.id IS NOT NULL THEN
        INSERT INTO public.identity_auth_shadow_link_evidence(
            link_id,source_id,user_id,link_generation,match_count,
            mismatch_count,first_match_at,last_match_at,last_mismatch_at
        ) VALUES(
            v_link.id,v_source.id,v_link.user_id,v_link.generation,
            CASE WHEN v_match THEN 1 ELSE 0 END,
            CASE WHEN v_match THEN 0 ELSE 1 END,
            CASE WHEN v_match THEN statement_timestamp() END,
            CASE WHEN v_match THEN statement_timestamp() END,
            CASE WHEN NOT v_match THEN statement_timestamp() END
        )
        ON CONFLICT(link_id) DO UPDATE SET
            source_id=EXCLUDED.source_id,
            user_id=EXCLUDED.user_id,
            link_generation=EXCLUDED.link_generation,
            match_count=CASE
                WHEN public.identity_auth_shadow_link_evidence.link_generation
                     =EXCLUDED.link_generation
                THEN public.identity_auth_shadow_link_evidence.match_count+
                     EXCLUDED.match_count
                ELSE EXCLUDED.match_count END,
            mismatch_count=CASE
                WHEN public.identity_auth_shadow_link_evidence.link_generation
                     =EXCLUDED.link_generation
                THEN public.identity_auth_shadow_link_evidence.mismatch_count+
                     EXCLUDED.mismatch_count
                ELSE EXCLUDED.mismatch_count END,
            first_match_at=CASE
                WHEN public.identity_auth_shadow_link_evidence.link_generation
                     =EXCLUDED.link_generation
                THEN COALESCE(
                    public.identity_auth_shadow_link_evidence.first_match_at,
                    EXCLUDED.first_match_at
                )
                ELSE EXCLUDED.first_match_at END,
            last_match_at=CASE
                WHEN public.identity_auth_shadow_link_evidence.link_generation
                     =EXCLUDED.link_generation
                THEN greatest(
                    public.identity_auth_shadow_link_evidence.last_match_at,
                    EXCLUDED.last_match_at
                )
                ELSE EXCLUDED.last_match_at END,
            last_mismatch_at=CASE
                WHEN public.identity_auth_shadow_link_evidence.link_generation
                     =EXCLUDED.link_generation
                THEN greatest(
                    public.identity_auth_shadow_link_evidence.last_mismatch_at,
                    EXCLUDED.last_mismatch_at
                )
                ELSE EXCLUDED.last_mismatch_at END,
            updated_at=statement_timestamp();
    END IF;

    v_divergence_user := COALESCE(p_normalized_user_id,p_legacy_user_id);
    IF v_match THEN
        UPDATE public.identity_shadow_divergences
           SET state='resolved',
               last_seen_at=statement_timestamp(),
               expires_at=statement_timestamp()+interval '30 days'
         WHERE source_id=v_source.id
           AND user_id IS NOT DISTINCT FROM v_divergence_user
           AND divergence_class='person_mismatch'
           AND state='open';
    ELSE
        INSERT INTO public.identity_shadow_divergences(
            source_id,user_id,link_id,divergence_class,
            old_outcome_digest,new_outcome_digest,redacted_sample,last_seen_at
        ) VALUES(
            v_source.id,v_divergence_user,v_link.id,'person_mismatch',
            v_old_digest,v_new_digest,
            jsonb_build_object(
                'surface','authentication',
                'legacyOutcome',CASE WHEN p_legacy_user_id IS NULL
                    THEN 'miss' ELSE 'person' END,
                'normalizedOutcome',CASE WHEN p_normalized_user_id IS NULL
                    THEN 'miss' ELSE 'person' END
            ),
            statement_timestamp()
        )
        ON CONFLICT(source_id,user_id,link_id,divergence_class)
        DO UPDATE SET
            old_outcome_digest=EXCLUDED.old_outcome_digest,
            new_outcome_digest=EXCLUDED.new_outcome_digest,
            last_seen_at=EXCLUDED.last_seen_at,
            seen_count=public.identity_shadow_divergences.seen_count+1,
            state=CASE
                WHEN public.identity_shadow_divergences.state='explained'
                THEN 'explained' ELSE 'open' END,
            redacted_sample=EXCLUDED.redacted_sample,
            explained_by=CASE
                WHEN public.identity_shadow_divergences.state='explained'
                THEN public.identity_shadow_divergences.explained_by ELSE NULL END,
            explained_at=CASE
                WHEN public.identity_shadow_divergences.state='explained'
                THEN public.identity_shadow_divergences.explained_at ELSE NULL END,
            expires_at=statement_timestamp()+interval '30 days';
    END IF;

    DELETE FROM public.identity_auth_shadow_hours
     WHERE bucket_start<date_trunc(
         'hour',statement_timestamp()-interval '31 days'
     );

    RETURN jsonb_build_object(
        'observed',true,
        'matched',v_match,
        'sourceId',v_source.id::text,
        'sourceGeneration',v_source.generation::text,
        'linkId',CASE WHEN v_link.id IS NULL THEN NULL ELSE v_link.id::text END,
        'linkGeneration',CASE WHEN v_link.id IS NULL
            THEN NULL ELSE v_link.generation::text END
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_auth_shadow_observe(text,text,text,bigint,bigint,bigint,bigint,bigint,bigint)'::regprocedure
);
