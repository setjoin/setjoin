-- Record bounded, redacted candidate evidence. This reducer never links.
CREATE OR REPLACE FUNCTION identity_match_record(
    p_actor BIGINT,
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_external_subject TEXT,
    p_candidate_user_id BIGINT,
    p_evidence_class TEXT,
    p_evidence_digest BYTEA,
    p_redacted_explanation TEXT,
    p_expires_at TIMESTAMPTZ
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_candidate public.identity_match_candidates%ROWTYPE;
    v_source public.identity_sources%ROWTYPE;
BEGIN
    IF p_source_id IS NULL
       OR p_expected_generation IS NULL OR p_expected_generation <= 0
       OR p_external_subject IS NULL
       OR octet_length(p_external_subject) NOT BETWEEN 1 AND 2048
       OR p_external_subject ~ '[[:cntrl:]]'
       OR p_evidence_class NOT IN ('hard','composite','soft','conflict')
       OR p_evidence_digest IS NULL OR octet_length(p_evidence_digest) <> 32
       OR p_redacted_explanation IS NULL
       OR octet_length(p_redacted_explanation) NOT BETWEEN 1 AND 512
       OR p_redacted_explanation ~ '[[:cntrl:]]'
       OR p_expires_at IS NULL
       OR p_expires_at <= statement_timestamp() THEN
        RAISE EXCEPTION 'invalid identity match evidence'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","remediation":"supply bounded redacted evidence and a future expiry"}';
    END IF;

    IF p_actor IS NOT NULL
       AND NOT EXISTS (
           SELECT 1 FROM public.users u
            WHERE u.id = p_actor AND u.enabled
       ) THEN
        RAISE EXCEPTION 'identity match actor is unavailable'
            USING ERRCODE = 'BZ231',
                  HINT = '{"type":"identity_soft_match_forbidden","remediation":"authenticate as an enabled identity administrator"}';
    END IF;

    IF p_candidate_user_id IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'identity-person:' || p_candidate_user_id::text, 0
            )
        );
        IF is_guest_account(p_candidate_user_id)
           OR NOT EXISTS (
               SELECT 1 FROM public.mailboxes m
                WHERE m.user_id = p_candidate_user_id
                  AND m.is_primary
           )
           OR (p_actor IS NOT NULL
               AND NOT identity_admin_scope_allows(
                   p_actor, p_candidate_user_id, 'identity.write'
               )) THEN
            RAISE EXCEPTION 'identity candidate targets an excluded or unreachable account'
                USING ERRCODE = 'BZ239',
                      HINT = '{"type":"identity_account_class_excluded"}';
        END IF;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('identity-source:' || p_source_id::text, 0)
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'identity-subject:' || p_source_id::text || ':' ||
            encode(digest(p_external_subject, 'sha256'), 'hex'),
            0
        )
    );

    SELECT * INTO v_source
      FROM public.identity_sources s
     WHERE s.id = p_source_id
     FOR UPDATE;
    IF NOT FOUND OR v_source.generation <> p_expected_generation THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale","remediation":"refresh the source and record new evidence"}';
    END IF;

    INSERT INTO public.identity_match_candidates (
        source_id, external_subject, candidate_user_id,
        evidence_class, evidence_digest, redacted_explanation,
        generation, expires_at
    ) VALUES (
        p_source_id, p_external_subject, p_candidate_user_id,
        p_evidence_class, p_evidence_digest, p_redacted_explanation,
        p_expected_generation, p_expires_at
    )
    ON CONFLICT DO NOTHING
    RETURNING * INTO v_candidate;

    IF v_candidate.id IS NULL THEN
        SELECT * INTO v_candidate
          FROM public.identity_match_candidates c
         WHERE c.source_id = p_source_id
           AND c.external_subject = p_external_subject
           AND c.candidate_user_id IS NOT DISTINCT FROM p_candidate_user_id
           AND c.evidence_class = p_evidence_class
           AND c.generation = p_expected_generation
           AND c.status IN ('pending','deferred')
         ORDER BY c.created_at, c.id
         LIMIT 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'identity match candidate could not be replayed'
                USING ERRCODE = 'BZ230',
                      HINT = '{"type":"identity_subject_conflict","remediation":"refresh the source and inspect retained candidate evidence"}';
        END IF;
        IF v_candidate.evidence_digest <> p_evidence_digest THEN
            RAISE EXCEPTION 'open identity match evidence changed within one source generation'
                USING ERRCODE = 'BZ230',
                      HINT = '{"type":"identity_subject_conflict","remediation":"decide the retained candidate or advance source generation"}';
        END IF;
    ELSE
        INSERT INTO public.identity_link_events (
            actor_user_id, user_id, source_id, action, reason,
            after_digest, metadata
        ) VALUES (
            p_actor, p_candidate_user_id, p_source_id,
            'candidate_recorded', 'bounded identity match evidence recorded',
            p_evidence_digest,
            jsonb_build_object(
                'candidateId', v_candidate.id,
                'evidenceClass', p_evidence_class,
                'sourceGeneration', p_expected_generation::text
            )
        );
    END IF;

    RETURN jsonb_build_object(
        'id', v_candidate.id,
        'sourceId', v_candidate.source_id::text,
        'candidateUserId',
            CASE WHEN v_candidate.candidate_user_id IS NULL THEN NULL
                 ELSE v_candidate.candidate_user_id::text END,
        'evidenceClass', v_candidate.evidence_class,
        'state', v_candidate.status,
        'generation', v_candidate.generation::text,
        'expiresAt', v_candidate.expires_at
    );
END;
$$;

SELECT apply_worker_ownership(
    'identity_match_record(bigint,bigint,bigint,text,bigint,text,bytea,text,timestamptz)'::regprocedure
);
