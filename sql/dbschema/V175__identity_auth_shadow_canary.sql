-- V175 — make normalized authentication canaries evidence-backed and
-- generation-fenced.
--
-- OIDC/SAML sources are authentication-only and never produce directory sync
-- batches. The former canary gate nevertheless required seven source batches,
-- making every production-created authentication source permanently
-- ineligible. Record bounded, subject-free legacy-vs-normalized comparisons
-- from real login traffic, pin the exact observed auth link generation in the
-- cohort, and compose it with the member's lifecycle-authority evidence.

CREATE TABLE public.identity_auth_shadow_hours (
    source_id          BIGINT NOT NULL
        REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
    bucket_start       TIMESTAMPTZ NOT NULL,
    source_generation  BIGINT NOT NULL CHECK (source_generation>0),
    matched_count      BIGINT NOT NULL DEFAULT 0 CHECK (matched_count>=0),
    mismatched_count   BIGINT NOT NULL DEFAULT 0 CHECK (mismatched_count>=0),
    first_observed_at  TIMESTAMPTZ NOT NULL,
    last_observed_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(source_id,bucket_start),
    CONSTRAINT identity_auth_shadow_hours_bucket_check CHECK (
        bucket_start=date_trunc('hour',bucket_start)
    ),
    CONSTRAINT identity_auth_shadow_hours_order_check CHECK (
        last_observed_at>=first_observed_at
    ),
    CONSTRAINT identity_auth_shadow_hours_nonempty_check CHECK (
        matched_count+mismatched_count>0
    )
);

CREATE INDEX identity_auth_shadow_hours_gate_idx
    ON public.identity_auth_shadow_hours(
        source_id,source_generation,bucket_start
    );

CREATE TABLE public.identity_auth_shadow_link_evidence (
    link_id            BIGINT PRIMARY KEY
        REFERENCES public.user_identity_links(id) ON DELETE RESTRICT,
    source_id          BIGINT NOT NULL
        REFERENCES public.identity_sources(id) ON DELETE RESTRICT,
    user_id            BIGINT NOT NULL
        REFERENCES public.users(id) ON DELETE RESTRICT,
    link_generation    BIGINT NOT NULL CHECK (link_generation>0),
    match_count        BIGINT NOT NULL DEFAULT 0 CHECK (match_count>=0),
    mismatch_count     BIGINT NOT NULL DEFAULT 0 CHECK (mismatch_count>=0),
    first_match_at     TIMESTAMPTZ,
    last_match_at      TIMESTAMPTZ,
    last_mismatch_at   TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT identity_auth_shadow_link_match_pair_check CHECK (
        (first_match_at IS NULL)=(last_match_at IS NULL)
        AND (first_match_at IS NULL OR last_match_at>=first_match_at)
        AND (match_count=0)=(first_match_at IS NULL)
    ),
    CONSTRAINT identity_auth_shadow_link_nonempty_check CHECK (
        match_count+mismatch_count>0
    )
);

CREATE INDEX identity_auth_shadow_link_source_idx
    ON public.identity_auth_shadow_link_evidence(
        source_id,link_generation,user_id
    );

ALTER TABLE public.identity_auth_shadow_hours ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_auth_shadow_hours FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_auth_shadow_hours OWNER TO setjoin_owner;
ALTER TABLE public.identity_auth_shadow_link_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_auth_shadow_link_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_auth_shadow_link_evidence OWNER TO setjoin_owner;

ALTER TABLE public.identity_read_cohort
    ADD COLUMN auth_link_id BIGINT
        REFERENCES public.user_identity_links(id) ON DELETE RESTRICT,
    ADD COLUMN auth_link_generation BIGINT CHECK (auth_link_generation>0),
    ADD COLUMN lifecycle_generation BIGINT CHECK (lifecycle_generation>0),
    ADD CONSTRAINT identity_read_cohort_evidence_tuple_check CHECK (
        (auth_link_id IS NULL)
        =(auth_link_generation IS NULL)
        AND (auth_link_id IS NULL)
        =(lifecycle_generation IS NULL)
    );

-- Existing canary rows remain present for operator evidence but become
-- fail-closed because the resolver requires the new exact evidence tuple.
-- A fresh canary enable replaces the source cohort atomically.
UPDATE public.identity_read_cohort cohort
   SET auth_link_id=link.id,
       auth_link_generation=link.generation,
       lifecycle_generation=authority.generation
  FROM public.user_identity_links link,
       public.user_lifecycle_authorities authority
 WHERE link.source_id=cohort.source_id
   AND link.user_id=cohort.user_id
   AND link.state='active'
   AND 'authenticate'=ANY(link.purposes)
   AND authority.user_id=cohort.user_id
   AND (
       SELECT count(*)
         FROM public.user_identity_links exact_link
        WHERE exact_link.source_id=cohort.source_id
          AND exact_link.user_id=cohort.user_id
          AND exact_link.state='active'
          AND 'authenticate'=ANY(exact_link.purposes)
   )=1;

CREATE OR REPLACE FUNCTION public.identity_auth_shadow_observe(
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

SELECT public.apply_worker_ownership(
    'identity_auth_shadow_observe(text,text,text,bigint,bigint,bigint,bigint,bigint,bigint)'::regprocedure
);

CREATE OR REPLACE FUNCTION public.identity_upgrade_shadow(
    p_source_key TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_source_id BIGINT;
    v_source_kind TEXT;
    v_source_generation BIGINT;
    v_completed_batches INTEGER;
    v_window_start TIMESTAMPTZ;
    v_window_end TIMESTAMPTZ;
    v_open_batches INTEGER;
    v_window_hours NUMERIC;
    v_critical BIGINT;
    v_missing BIGINT;
    v_ambiguity BIGINT;
    v_eligible BOOLEAN;
BEGIN
    SELECT id,kind,generation
      INTO v_source_id,v_source_kind,v_source_generation
      FROM public.identity_sources
     WHERE source_key=p_source_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity source not found'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","field":"sourceKey"}';
    END IF;
    IF v_source_kind IN ('oidc','saml') THEN
        SELECT COALESCE(sum(matched_count),0)::integer,
               min(first_observed_at) FILTER (WHERE matched_count>0),
               max(last_observed_at) FILTER (WHERE matched_count>0)
          INTO v_completed_batches,v_window_start,v_window_end
          FROM public.identity_auth_shadow_hours
         WHERE source_id=v_source_id
           AND source_generation=v_source_generation;
        v_open_batches := 0;
    ELSE
        SELECT count(*)::integer,min(completed_at),max(completed_at)
          INTO v_completed_batches,v_window_start,v_window_end
          FROM public.identity_source_batches
         WHERE source_id=v_source_id AND state='completed';
        SELECT count(*)::integer
          INTO v_open_batches
          FROM public.identity_source_batches
         WHERE source_id=v_source_id AND state<>'completed';
    END IF;
    v_window_hours := CASE
        WHEN v_window_start IS NULL OR v_window_end IS NULL THEN 0
        ELSE round(extract(epoch FROM v_window_end-v_window_start)/3600,2)
    END;
    SELECT count(*) INTO v_critical
      FROM public.identity_shadow_divergences
     WHERE source_id=v_source_id AND state='open'
       AND divergence_class IN (
           'person_mismatch','authority_mismatch','access_mismatch'
       );
    SELECT count(*) INTO v_missing
      FROM public.identity_shadow_divergences
     WHERE source_id=v_source_id AND state='open'
       AND divergence_class='missing_projection';
    SELECT count(*) INTO v_ambiguity
      FROM public.identity_shadow_divergences
     WHERE source_id=v_source_id AND state='open'
       AND divergence_class='expected_legacy_ambiguity';
    v_eligible := v_completed_batches>=7
        AND v_open_batches=0
        AND COALESCE(
            v_window_end-v_window_start>=interval '24 hours',
            false
        )
        AND v_critical=0 AND v_missing=0 AND v_ambiguity=0;
    RETURN jsonb_build_object(
        'sourceKey',p_source_key,
        'eligible',v_eligible,
        'observationKind',CASE WHEN v_source_kind IN ('oidc','saml')
            THEN 'authentication' ELSE 'directory' END,
        'completedSyncs',least(v_completed_batches,7),
        'completedObservations',least(v_completed_batches,7),
        'requiredSyncs',7,
        'windowStartedAt',v_window_start,
        'windowHours',v_window_hours,
        'requiredWindowHours',24,
        'criticalDivergences',v_critical,
        'missingProjections',v_missing,
        'undispositionedAmbiguities',v_ambiguity,
        'nextAction',CASE
            WHEN v_critical>0 THEN 'pause canary and resolve critical divergences'
            WHEN v_missing>0 THEN 'repair rollback projections'
            WHEN v_ambiguity>0 THEN 'disposition or exclude every expected ambiguity'
            WHEN v_open_batches>0 THEN 'let the current source sync reach terminal state'
            WHEN v_completed_batches<7 AND v_source_kind IN ('oidc','saml')
                THEN 'complete seven real authentication shadow comparisons'
            WHEN v_completed_batches<7 THEN 'complete seven consecutive full syncs'
            WHEN v_window_hours<24 AND v_source_kind IN ('oidc','saml')
                THEN 'continue authentication shadow comparisons across 24 hours'
            WHEN v_window_hours<24
                THEN 'continue completed source sync coverage across 24 hours'
            ELSE 'canary plan is permitted' END
    );
END;
$$;

SELECT public.apply_worker_ownership(
    'identity_upgrade_shadow(text)'::regprocedure
);

CREATE OR REPLACE FUNCTION public.identity_upgrade_canary(
    p_actor BIGINT,
    p_source_key TEXT,
    p_expected_generation BIGINT,
    p_enable BOOLEAN,
    p_user_ids BIGINT[],
    p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_s public.identity_sources%ROWTYPE;
    v_shadow JSONB;
BEGIN
    IF p_actor IS NULL OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid identity canary request'
            USING ERRCODE='BZ228';
    END IF;
    SELECT * INTO v_s FROM public.identity_sources
     WHERE source_key=p_source_key FOR UPDATE;
    IF NOT FOUND OR v_s.generation<>p_expected_generation THEN
        RAISE EXCEPTION 'identity source generation is stale'
            USING ERRCODE='BZ229';
    END IF;
    IF p_enable AND v_s.kind NOT IN ('oidc','saml') THEN
        RAISE EXCEPTION 'identity read canary requires an authentication source'
            USING ERRCODE='BZ234',
                  HINT='{"type":"identity_transition_preflight"}';
    END IF;
    IF p_enable THEN
        v_shadow := public.identity_upgrade_shadow(p_source_key);
    END IF;
    IF p_enable AND NOT (v_shadow->>'eligible')::boolean THEN
        RAISE EXCEPTION 'source has not completed the shadow gate'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_preview_stale"}';
    END IF;
    IF p_enable AND (
        p_user_ids IS NULL OR cardinality(p_user_ids) NOT BETWEEN 1 AND 500
        OR cardinality(p_user_ids)<>(
            SELECT count(DISTINCT u.user_id)::integer
              FROM unnest(p_user_ids) u(user_id)
        )
        OR EXISTS (
            SELECT 1 FROM unnest(p_user_ids) u(user_id)
             WHERE (
                 SELECT count(*) FROM public.user_identity_links l
                  WHERE l.source_id=v_s.id AND l.user_id=u.user_id
                    AND l.state='active'
                    AND 'authenticate'=ANY(l.purposes)
             )<>1
        )
        OR EXISTS (
            SELECT 1
              FROM unnest(p_user_ids) u(user_id)
              JOIN public.user_identity_links auth_link
                ON auth_link.source_id=v_s.id
               AND auth_link.user_id=u.user_id
               AND auth_link.state='active'
               AND 'authenticate'=ANY(auth_link.purposes)
              LEFT JOIN public.identity_auth_shadow_link_evidence evidence
                ON evidence.link_id=auth_link.id
               AND evidence.link_generation=auth_link.generation
             WHERE evidence.link_id IS NULL
                OR evidence.match_count<1
                OR evidence.last_match_at IS NULL
                OR (
                    evidence.last_mismatch_at IS NOT NULL
                    AND evidence.last_mismatch_at>evidence.last_match_at
                )
        )
    ) THEN
        RAISE EXCEPTION 'canary cohort must contain unique observed active linked users'
            USING ERRCODE='BZ234',
                  HINT='{"type":"identity_transition_preflight"}';
    END IF;
    IF p_enable AND EXISTS (
        SELECT 1
          FROM unnest(p_user_ids) u(user_id)
          JOIN public.user_identity_links auth_link
            ON auth_link.source_id=v_s.id
           AND auth_link.user_id=u.user_id
           AND auth_link.state='active'
           AND 'authenticate'=ANY(auth_link.purposes)
          LEFT JOIN public.user_lifecycle_authorities authority
            ON authority.user_id=u.user_id
          LEFT JOIN public.user_identity_links lifecycle_link
            ON lifecycle_link.id=authority.link_id
          LEFT JOIN public.identity_sources lifecycle_source
            ON lifecycle_source.id=lifecycle_link.source_id
         WHERE authority.user_id IS NULL
            OR (
                authority.authority_kind='source'
                AND (
                    lifecycle_source.id IS NULL
                    OR lifecycle_source.kind NOT IN ('ad','ldap','scim')
                    OR NOT COALESCE((
                        public.identity_upgrade_shadow(
                            lifecycle_source.source_key
                        )->>'eligible'
                    )::boolean,false)
                )
            )
            OR (
                authority.authority_kind='local'
                AND (
                    NOT public.identity_recovery_available(
                        u.user_id,auth_link.id
                    )
                    OR EXISTS (
                        SELECT 1
                          FROM public.identity_shadow_divergences d
                         WHERE d.user_id=u.user_id
                           AND d.state='open'
                           AND d.divergence_class IN (
                               'person_mismatch','authority_mismatch',
                               'access_mismatch','missing_projection'
                           )
                    )
                )
            )
    ) THEN
        RAISE EXCEPTION 'canary cohort lifecycle evidence is not ready'
            USING ERRCODE='BZ235',
                  HINT='{"type":"identity_lifecycle_shadow_required"}';
    END IF;
    UPDATE public.identity_sources
       SET read_mode=CASE WHEN p_enable THEN 'canary' ELSE 'shadow' END,
           generation=generation+1,
           updated_by=p_actor,
           updated_at=statement_timestamp()
     WHERE id=v_s.id;
    DELETE FROM public.identity_read_cohort WHERE source_id=v_s.id;
    IF p_enable THEN
        INSERT INTO public.identity_read_cohort(
            source_id,user_id,source_generation,added_by,reason,
            auth_link_id,auth_link_generation,lifecycle_generation
        )
        SELECT v_s.id,u.user_id,p_expected_generation+1,p_actor,p_reason,
               auth_link.id,auth_link.generation,authority.generation
          FROM (
              SELECT DISTINCT unnest(p_user_ids) AS user_id
          ) u
          JOIN public.user_identity_links auth_link
            ON auth_link.source_id=v_s.id
           AND auth_link.user_id=u.user_id
           AND auth_link.state='active'
           AND 'authenticate'=ANY(auth_link.purposes)
          JOIN public.user_lifecycle_authorities authority
            ON authority.user_id=u.user_id;
    END IF;
    INSERT INTO public.identity_link_events(
        actor_user_id,source_id,action,reason,metadata
    ) VALUES(
        p_actor,v_s.id,'source_updated',p_reason,
        jsonb_build_object(
            'readMode',CASE WHEN p_enable THEN 'canary' ELSE 'shadow' END
        )
    );
    RETURN jsonb_build_object(
        'sourceKey',p_source_key,
        'readMode',CASE WHEN p_enable THEN 'canary' ELSE 'shadow' END,
        'generation',(p_expected_generation+1)::text,
        'cohortSize',CASE WHEN p_enable THEN cardinality(p_user_ids) ELSE 0 END
    );
END;
$$;

SELECT public.apply_worker_ownership(
    'identity_upgrade_canary(bigint,text,bigint,boolean,bigint[],text)'::regprocedure
);

CREATE OR REPLACE FUNCTION public.identity_auth_resolve(
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
       OR p_provider IS NULL OR p_provider=''
       OR p_subject IS NULL OR p_subject=''
       OR octet_length(p_provider)>2048
       OR octet_length(p_subject)>2048
       OR p_provider ~ '[[:cntrl:]]'
       OR p_subject ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid federated identity pair'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid"}';
    END IF;
    v_source_key := p_kind||':'||
        substr(encode(digest(p_provider,'sha256'),'hex'),1,48);
    SELECT id,read_mode,generation
      INTO v_source_id,v_read_mode,v_source_generation
      FROM public.identity_sources
     WHERE source_key=v_source_key AND kind=p_kind AND state='active';
    SELECT u.id,l.id,l.generation,u.email
      INTO v_user_id,v_link_id,v_link_generation,v_email
      FROM public.identity_sources s
      JOIN public.user_identity_links l ON l.source_id=s.id
      JOIN public.users u ON u.id=l.user_id
     WHERE s.source_key=v_source_key
       AND s.kind=p_kind
       AND s.state='active'
       AND l.external_subject=p_subject
       AND l.state='active'
       AND 'authenticate'=ANY(l.purposes)
       AND u.enabled
       AND NOT public.is_guest_account(u.id);
    IF v_source_id IS NOT NULL THEN
        v_serve := v_read_mode='normalized'
          OR COALESCE((
              SELECT enabled FROM public.feature_toggles
               WHERE key='feature.identity_normalized_reads'
          ),false)
          OR (
              v_read_mode='canary' AND v_user_id IS NOT NULL
              AND EXISTS (
                  SELECT 1
                    FROM public.identity_read_cohort c
                    JOIN public.user_lifecycle_authorities authority
                      ON authority.user_id=c.user_id
                   WHERE c.source_id=v_source_id
                     AND c.user_id=v_user_id
                     AND c.source_generation=v_source_generation
                     AND c.auth_link_id=v_link_id
                     AND c.auth_link_generation=v_link_generation
                     AND c.lifecycle_generation=authority.generation
              )
          );
    END IF;
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'found',false,
            'sourceKey',v_source_key,
            'sourceId',CASE WHEN v_source_id IS NULL
                THEN NULL ELSE v_source_id::text END,
            'sourceGeneration',CASE WHEN v_source_id IS NULL
                THEN NULL ELSE v_source_generation::text END,
            'readMode',COALESCE(v_read_mode,'legacy'),
            'serveNormalized',v_serve OR v_read_mode='canary'
        );
    END IF;
    RETURN jsonb_build_object(
        'found',true,
        'sourceKey',v_source_key,
        'sourceId',v_source_id::text,
        'sourceGeneration',v_source_generation::text,
        'userId',v_user_id::text,
        'linkId',v_link_id::text,
        'linkGeneration',v_link_generation::text,
        'email',v_email,
        'readMode',v_read_mode,
        'serveNormalized',v_serve
    );
END;
$$;

SELECT public.apply_worker_ownership(
    'identity_auth_resolve(text,text,text)'::regprocedure
);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (175, now())
  ON CONFLICT (version) DO NOTHING;
