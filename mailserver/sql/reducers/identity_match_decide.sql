-- Couple permission and scope on one live assignment. An unbound candidate is
-- source-wide and therefore requires a globally unscoped assignment.
CREATE OR REPLACE FUNCTION identity_admin_scope_allows(
    p_actor BIGINT,
    p_candidate_user_id BIGINT,
    p_permission TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM public.admin_role_assignments ra
          JOIN public.admin_role_groups rg ON rg.id = ra.role_group_id
          LEFT JOIN public.departments sd
            ON ra.scope_type = 'ou' AND sd.id = ra.scope_id
         WHERE ra.user_id = p_actor
           AND p_permission = ANY(rg.permissions)
           AND (ra.expires_at IS NULL
                OR ra.expires_at > statement_timestamp())
           AND admin_assignment_active(ra.eligible, ra.activated_until)
           AND (
               (
                   p_candidate_user_id IS NULL
                   AND ra.scope_type IS NULL
                   AND COALESCE(ra.domain_override, rg.domain_scope) IS NULL
               )
               OR
               (
                   p_candidate_user_id IS NOT NULL
                   AND (
                       COALESCE(ra.domain_override, rg.domain_scope) IS NULL
                       OR EXISTS (
                           SELECT 1 FROM public.users target
                            WHERE target.id = p_candidate_user_id
                              AND COALESCE(
                                  guest_account_host_domain(target.id),
                                  target.domain_id
                              ) = COALESCE(
                                  ra.domain_override, rg.domain_scope
                              )
                       )
                   )
                   AND (
                       ra.scope_type IS NULL
                       OR (
                           ra.scope_type = 'ou'
                           AND EXISTS (
                               SELECT 1
                                 FROM public.users target
                                 JOIN public.departments td
                                   ON td.id = target.department_id
                                WHERE target.id = p_candidate_user_id
                                  AND (
                                      td.path = sd.path
                                      OR starts_with(
                                          td.path, sd.path || '/'
                                      )
                                  )
                           )
                       )
                       OR (
                           ra.scope_type = 'set'
                           AND admin_set_reaches(
                               ra.scope_id, p_candidate_user_id
                           )
                       )
                   )
               )
           )
    );
$$;

SELECT apply_worker_ownership(
    'identity_admin_scope_allows(bigint,bigint,text)'::regprocedure
);

-- Resolve exactly one candidate. No bulk path exists. The reducer owns all
-- link/create/reject/defer semantics, generation checks, account-class checks,
-- protected-target refusal, audit, and idempotent replay.
CREATE OR REPLACE FUNCTION identity_match_decide(
    p_actor BIGINT,
    p_candidate_id UUID,
    p_expected_generation BIGINT,
    p_decision TEXT,
    p_person_id BIGINT,
    p_reason TEXT,
    p_idempotency_key UUID
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_candidate public.identity_match_candidates%ROWTYPE;
    v_initial_candidate_user_id BIGINT;
    v_source public.identity_sources%ROWTYPE;
    v_link public.user_identity_links%ROWTYPE;
    v_authority public.user_lifecycle_authorities%ROWTYPE;
    v_person_id BIGINT;
    v_request_digest BYTEA;
    v_existing_request RECORD;
    v_provision_lifecycle BOOLEAN;
    v_purposes TEXT[];
    v_protected BOOLEAN;
    v_event_id BIGINT;
    v_result JSONB;
BEGIN
    IF p_actor IS NULL
       OR p_candidate_id IS NULL
       OR p_expected_generation IS NULL OR p_expected_generation <= 0
       OR p_decision NOT IN ('link','create','reject','defer')
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
       OR p_reason ~ '[[:cntrl:]]'
       OR p_idempotency_key IS NULL
       OR (p_decision = 'link' AND (p_person_id IS NULL OR p_person_id <= 0))
       OR (p_decision <> 'link' AND p_person_id IS NOT NULL) THEN
        RAISE EXCEPTION 'invalid identity conflict decision'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","remediation":"supply one decision, exact generation, stable IDs, reason, and idempotency key"}';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.users u
         WHERE u.id = p_actor AND u.enabled
    ) THEN
        RAISE EXCEPTION 'identity conflict actor is unavailable'
            USING ERRCODE = 'BZ231',
                  HINT = '{"type":"identity_soft_match_forbidden","remediation":"authenticate as an enabled identity administrator"}';
    END IF;

    v_request_digest := digest(jsonb_build_object(
        'operation', 'conflict_decide',
        'candidateId', p_candidate_id,
        'expectedGeneration', p_expected_generation::text,
        'decision', p_decision,
        'personId', CASE WHEN p_person_id IS NULL THEN NULL
                         ELSE p_person_id::text END,
        'reason', p_reason
    )::text, 'sha256');

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-conflict-idempotency:' || p_actor::text || ':' ||
        p_idempotency_key::text, 0
    ));
    SELECT d.request_digest, d.result
      INTO v_existing_request
      FROM public.identity_match_decisions d
     WHERE d.decided_by = p_actor
       AND d.idempotency_key = p_idempotency_key;
    IF FOUND THEN
        IF v_existing_request.request_digest <> v_request_digest THEN
            RAISE EXCEPTION 'identity conflict idempotency key was reused'
                USING ERRCODE = 'BZ240',
                      HINT = '{"type":"identity_idempotency_conflict","operation":"conflict_decide"}';
        END IF;
        RETURN v_existing_request.result || '{"replayed":true}'::jsonb;
    END IF;

    SELECT c.candidate_user_id
      INTO v_initial_candidate_user_id
      FROM public.identity_match_candidates c
     WHERE c.id = p_candidate_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity conflict not found'
            USING ERRCODE = 'BZ230',
                  HINT = '{"type":"identity_subject_conflict"}';
    END IF;
    IF NOT identity_admin_scope_allows(
        p_actor, v_initial_candidate_user_id, 'identity.write'
    ) THEN
        RAISE EXCEPTION 'identity conflict not found'
            USING ERRCODE = 'BZ230',
                  HINT = '{"type":"identity_subject_conflict"}';
    END IF;

    v_person_id := CASE WHEN p_decision = 'link'
                        THEN p_person_id
                        ELSE v_initial_candidate_user_id END;
    IF v_person_id IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'identity-person:' || v_person_id::text, 0
        ));
    END IF;

    SELECT * INTO v_candidate
      FROM public.identity_match_candidates c
     WHERE c.id = p_candidate_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity conflict not found'
            USING ERRCODE = 'BZ230',
                  HINT = '{"type":"identity_subject_conflict"}';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-source:' || v_candidate.source_id::text, 0
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'identity-subject:' || v_candidate.source_id::text || ':' ||
        encode(digest(v_candidate.external_subject, 'sha256'), 'hex'), 0
    ));

    SELECT * INTO v_candidate
      FROM public.identity_match_candidates c
     WHERE c.id = p_candidate_id
     FOR UPDATE;
    SELECT * INTO v_source
      FROM public.identity_sources s
     WHERE s.id = v_candidate.source_id
     FOR UPDATE;

    IF v_candidate.generation <> p_expected_generation
       OR v_source.generation <> v_candidate.generation THEN
        RAISE EXCEPTION 'identity conflict generation is stale'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale","remediation":"refresh the conflict before deciding"}';
    END IF;
    IF v_candidate.expires_at <= statement_timestamp() THEN
        RAISE EXCEPTION 'identity conflict evidence has expired'
            USING ERRCODE = 'BZ229',
                  HINT = '{"type":"identity_generation_stale","remediation":"run discovery again to create fresh evidence"}';
    END IF;
    IF v_candidate.status NOT IN ('pending','deferred') THEN
        RAISE EXCEPTION 'identity conflict is already decided'
            USING ERRCODE = 'BZ238',
                  HINT = '{"type":"identity_transition_illegal","remediation":"inspect the existing decision"}';
    END IF;

    IF v_candidate.candidate_user_id IS NOT NULL
       AND NOT admin_can_reach(p_actor, v_candidate.candidate_user_id) THEN
        RAISE EXCEPTION 'identity conflict not found'
            USING ERRCODE = 'BZ230',
                  HINT = '{"type":"identity_subject_conflict"}';
    END IF;

    IF p_decision = 'link' THEN
        IF v_source.state <> 'active' THEN
            RAISE EXCEPTION 'identity source is not active'
                USING ERRCODE = 'BZ229',
                      HINT = '{"type":"identity_generation_stale","remediation":"activate or refresh the source before linking"}';
        END IF;
        IF v_candidate.evidence_class = 'soft' THEN
            RAISE EXCEPTION 'soft evidence cannot authorize an identity link'
                USING ERRCODE = 'BZ231',
                      HINT = '{"type":"identity_soft_match_forbidden","remediation":"supply immutable proof or choose create, reject, or defer"}';
        END IF;
        IF v_candidate.candidate_user_id IS NULL
           OR v_candidate.candidate_user_id <> p_person_id
           OR NOT admin_can_reach(p_actor, p_person_id)
           OR is_guest_account(p_person_id)
           OR NOT EXISTS (
               SELECT 1 FROM public.mailboxes m
                WHERE m.user_id = p_person_id AND m.is_primary
           ) THEN
            RAISE EXCEPTION 'selected person is not the evidenced member candidate'
                USING ERRCODE = 'BZ239',
                      HINT = '{"type":"identity_account_class_excluded"}';
        END IF;

        v_protected := EXISTS (
            SELECT 1
              FROM public.admin_role_assignments ara
              JOIN public.admin_role_groups arg
                ON arg.id = ara.role_group_id
             WHERE ara.user_id = p_person_id
               AND (ara.expires_at IS NULL
                    OR ara.expires_at > statement_timestamp())
               AND admin_assignment_active(
                   ara.eligible, ara.activated_until
               )
               AND EXISTS (
                   SELECT 1 FROM public.admin_permissions ap
                    WHERE ap.permission_key = ANY(arg.permissions)
                      AND ap.is_sensitive
               )
        ) OR EXISTS (
            SELECT 1
              FROM public.system_config cfg,
                   LATERAL jsonb_array_elements_text(cfg.value) x(raw)
             WHERE cfg.key = 'ca_break_glass_user_ids'
               AND x.raw::bigint = p_person_id
        );
        IF v_protected THEN
            RAISE EXCEPTION 'protected identity takeover requires an approved transition'
                USING ERRCODE = 'BZ236',
                      HINT = '{"type":"identity_approval_invalid","remediation":"start a protected identity transition with independent approval"}';
        END IF;

        SELECT * INTO v_link
          FROM public.user_identity_links l
         WHERE l.source_id = v_source.id
           AND l.external_subject = v_candidate.external_subject
         FOR UPDATE;
        IF FOUND AND (
            v_link.user_id <> p_person_id
            OR v_link.state <> 'active'
        ) THEN
            RAISE EXCEPTION 'identity subject is reserved by another retained link'
                USING ERRCODE = 'BZ230',
                      HINT = '{"type":"identity_subject_conflict","remediation":"use the duplicate-correction procedure; tombstones are not reassigned"}';
        END IF;

        v_provision_lifecycle := COALESCE(
            (v_source.capabilities->>'provision_lifecycle')::boolean,
            (v_source.capabilities->>'provisionLifecycle')::boolean,
            false
        );
        v_purposes := CASE
            WHEN v_provision_lifecycle
                 AND COALESCE(
                     (v_source.capabilities->>'authenticate')::boolean,
                     false
                 )
                THEN ARRAY['authenticate','provision']::text[]
            WHEN v_provision_lifecycle
                THEN ARRAY['provision']::text[]
            ELSE ARRAY['authenticate']::text[]
        END;

        IF v_link.id IS NULL THEN
            INSERT INTO public.user_identity_links (
                user_id, source_id, external_subject, purposes,
                state, link_method, evidence
            ) VALUES (
                p_person_id, v_source.id, v_candidate.external_subject,
                v_purposes, 'active', 'operator',
                jsonb_build_object(
                    'candidateId', v_candidate.id,
                    'evidenceClass', v_candidate.evidence_class,
                    'evidenceDigest',
                        encode(v_candidate.evidence_digest, 'hex')
                )
            )
            RETURNING * INTO v_link;
        END IF;

        IF v_provision_lifecycle THEN
            SELECT * INTO v_authority
              FROM public.user_lifecycle_authorities ula
             WHERE ula.user_id = p_person_id
             FOR UPDATE;
            IF NOT FOUND OR (
                v_authority.authority_kind = 'source'
                AND v_authority.link_id <> v_link.id
            ) THEN
                RAISE EXCEPTION 'another source owns person lifecycle'
                    USING ERRCODE = 'BZ233',
                          HINT = '{"type":"identity_lifecycle_conflict","remediation":"use a previewed source migration"}';
            END IF;
            UPDATE public.user_lifecycle_authorities
               SET authority_kind = 'source',
                   link_id = v_link.id,
                   generation = generation + 1,
                   established_by = p_actor,
                   established_at = statement_timestamp(),
                   updated_at = statement_timestamp()
             WHERE user_id = p_person_id
               AND (authority_kind <> 'source'
                    OR link_id IS DISTINCT FROM v_link.id);
        END IF;
        v_person_id := p_person_id;

        INSERT INTO public.identity_link_events (
            actor_user_id, user_id, source_id, link_id,
            action, reason, correlation_id, after_digest, metadata
        ) VALUES (
            p_actor, v_person_id, v_source.id, v_link.id,
            'link_activated', p_reason, p_idempotency_key,
            digest(jsonb_build_object(
                'userId', v_person_id::text,
                'sourceId', v_source.id::text,
                'linkId', v_link.id::text,
                'purposes', v_purposes
            )::text, 'sha256'),
            jsonb_build_object(
                'candidateId', v_candidate.id,
                'evidenceClass', v_candidate.evidence_class
            )
        ) RETURNING id INTO v_event_id;
    ELSIF p_decision = 'create' THEN
        -- No production connector currently emits an unbound candidate with a
        -- batch/object binding. Keep this mode fail-closed until an insert-only
        -- provisioning reducer and exact current inbox reference exist; the
        -- generic provision_account upsert may resolve legacy anchors.
        RAISE EXCEPTION 'conflict create requires a current insert-only source object'
            USING ERRCODE = 'BZ234',
                  HINT = '{"type":"identity_transition_preflight","remediation":"rerun discovery and use an explicitly batch-bound create workflow"}';
    ELSE
        v_person_id := v_candidate.candidate_user_id;
    END IF;

    UPDATE public.identity_match_candidates
       SET status = CASE p_decision
                        WHEN 'link' THEN 'linked'
                        WHEN 'reject' THEN 'rejected'
                        ELSE 'deferred'
                    END,
           candidate_user_id = COALESCE(v_person_id, candidate_user_id),
           decided_by = p_actor,
           decided_at = statement_timestamp(),
           decision_idempotency_key = p_idempotency_key,
           decision_request_digest = v_request_digest,
           decision_reason = p_reason
     WHERE id = v_candidate.id;

    INSERT INTO public.identity_link_events (
        actor_user_id, user_id, source_id, link_id,
        action, reason, correlation_id, before_digest, after_digest, metadata
    ) VALUES (
        p_actor, v_person_id, v_source.id,
        CASE WHEN v_link.id IS NULL THEN NULL ELSE v_link.id END,
        'conflict_decided', p_reason, p_idempotency_key,
        v_candidate.evidence_digest,
        digest(jsonb_build_object(
            'candidateId', v_candidate.id,
            'decision', p_decision,
            'personId', CASE WHEN v_person_id IS NULL THEN NULL
                             ELSE v_person_id::text END
        )::text, 'sha256'),
        jsonb_build_object(
            'candidateId', v_candidate.id,
            'decision', p_decision,
            'evidenceClass', v_candidate.evidence_class
        )
    );

    v_result := jsonb_build_object(
        'id', v_candidate.id,
        'state', CASE p_decision
                     WHEN 'link' THEN 'linked'
                     WHEN 'reject' THEN 'rejected'
                     ELSE 'deferred'
                 END,
        'generation', v_candidate.generation::text,
        'personId', CASE WHEN v_person_id IS NULL THEN NULL
                         ELSE v_person_id::text END,
        'linkId', CASE WHEN v_link.id IS NULL THEN NULL
                       ELSE v_link.id::text END,
        'replayed', false
    );
    INSERT INTO public.identity_match_decisions (
        candidate_id, decided_by, idempotency_key, request_digest,
        decision, reason, person_id, link_id, result
    ) VALUES (
        v_candidate.id, p_actor, p_idempotency_key, v_request_digest,
        p_decision, p_reason, v_person_id,
        CASE WHEN v_link.id IS NULL THEN NULL ELSE v_link.id END,
        v_result
    );
    RETURN v_result;
END;
$$;

SELECT apply_worker_ownership(
    'identity_match_decide(bigint,uuid,bigint,text,bigint,text,uuid)'::regprocedure
);
