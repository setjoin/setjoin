-- Stable, redacted People detail read model. Raw external subjects, credential
-- material, assertions, and source payloads are deliberately absent.
CREATE OR REPLACE FUNCTION identity_person_read(
    p_actor BIGINT,
    p_user_id BIGINT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_result JSONB;
BEGIN
    IF p_actor IS NULL OR p_user_id IS NULL OR p_user_id <= 0
       OR NOT EXISTS (
           SELECT 1 FROM public.users a
            WHERE a.id = p_actor AND a.enabled
       )
       OR NOT identity_admin_scope_allows(
           p_actor, p_user_id, 'users.read'
       )
       OR is_guest_account(p_user_id)
       OR NOT EXISTS (
           SELECT 1 FROM public.mailboxes m
            WHERE m.user_id = p_user_id AND m.is_primary
       ) THEN
        RETURN NULL;
    END IF;

    SELECT jsonb_build_object(
        'userId', u.id::text,
        'email', u.email,
        'displayName', u.display_name,
        'enabled', u.enabled,
        'relationship', 'member',
        'protected', (
            EXISTS (
                SELECT 1
                  FROM public.admin_role_assignments ara
                  JOIN public.admin_role_groups arg
                    ON arg.id = ara.role_group_id
                 WHERE ara.user_id = u.id
                   AND (ara.expires_at IS NULL
                        OR ara.expires_at > statement_timestamp())
                   AND admin_assignment_active(
                       ara.eligible, ara.activated_until
                   )
                   AND EXISTS (
                       SELECT 1
                         FROM public.admin_permissions ap
                        WHERE ap.permission_key = ANY(arg.permissions)
                          AND ap.is_sensitive
                   )
            )
            OR EXISTS (
                SELECT 1
                  FROM public.system_config cfg,
                       LATERAL jsonb_array_elements_text(cfg.value) x(raw)
                 WHERE cfg.key = 'ca_break_glass_user_ids'
                   AND x.raw::bigint = u.id
            )
        ),
        'lifecycleAuthority', jsonb_build_object(
            'kind', ula.authority_kind,
            'generation', ula.generation::text,
            'linkId', CASE WHEN ula.link_id IS NULL THEN NULL
                           ELSE ula.link_id::text END,
            'sourceKey', lifecycle_source.source_key
        ),
        'recovery', jsonb_build_object(
            'hasLocalPassword',
                u.password_hash IS NOT NULL AND u.password_hash <> '',
            'passkeyCount', (
                SELECT count(*) FROM public.passkey_credentials pc
                 WHERE pc.user_id = u.id
            ),
            'activeAuthenticationLinks', (
                SELECT count(*) FROM public.user_identity_links auth_link
                 WHERE auth_link.user_id = u.id
                   AND auth_link.state = 'active'
                   AND 'authenticate' = ANY(auth_link.purposes)
            )
        ),
        'links', COALESCE((
            SELECT jsonb_agg(link_row.row ORDER BY link_row.id)
              FROM (
                SELECT l.id,
                       jsonb_build_object(
                           'id', l.id::text,
                           'sourceKey', s.source_key,
                           'sourceKind', s.kind,
                           'purposes', l.purposes,
                           'state', l.state,
                           'generation', l.generation::text,
                           'linkMethod', l.link_method,
                           'subjectFingerprint',
                               substr(encode(digest(l.external_subject, 'sha256'), 'hex'), 1, 16),
                           'firstSeenAt', l.first_seen_at,
                           'lastSeenAt', l.last_seen_at,
                           'detachedAt', l.detached_at
                       ) AS row
                  FROM public.user_identity_links l
                  JOIN public.identity_sources s ON s.id = l.source_id
                 WHERE l.user_id = u.id
                 ORDER BY l.id
                 LIMIT 100
              ) link_row
        ), '[]'::jsonb),
        'fieldAuthority', COALESCE((
            SELECT jsonb_agg(authority_row.row ORDER BY authority_row.field)
              FROM (
                SELECT aa.field,
                       jsonb_build_object(
                           'field', aa.field,
                           'authorityKind', aa.authority_kind,
                           'sourceKey', aas.source_key,
                           'linkId', CASE WHEN aa.link_id IS NULL THEN NULL
                                          ELSE aa.link_id::text END,
                           'generation', aa.generation::text,
                           'localOverrideState', aa.local_override_state
                       ) AS row
                  FROM public.identity_attribute_authority aa
                  LEFT JOIN public.identity_sources aas ON aas.id = aa.source_id
                 WHERE aa.user_id = u.id
                 ORDER BY aa.field
                 LIMIT 64
              ) authority_row
        ), '[]'::jsonb),
        'entitlementProvenance', COALESCE((
            SELECT jsonb_agg(grant_row.row ORDER BY grant_row.id)
              FROM (
                SELECT eg.id,
                       jsonb_build_object(
                           'id', eg.id::text,
                           'targetKind', eg.target_kind,
                           'targetId', eg.target_id::text,
                           'entitlementKind', eg.entitlement_kind,
                           'entitlementId', eg.entitlement_id::text,
                           'provenanceKind', eg.provenance_kind,
                           'sourceKey', egs.source_key,
                           'linkId', CASE WHEN eg.link_id IS NULL THEN NULL
                                          ELSE eg.link_id::text END,
                           'sourceGeneration', eg.generation::text,
                           'validUntil', eg.valid_until,
                           'revokedAt', eg.revoked_at
                       ) AS row
                  FROM public.identity_entitlement_grants eg
                  LEFT JOIN public.identity_sources egs
                    ON egs.id = eg.source_id
                 WHERE eg.user_id = u.id
                 ORDER BY eg.id
                 LIMIT 500
              ) grant_row
        ), '[]'::jsonb),
        'transitionHistory', COALESCE((
            SELECT jsonb_agg(history.row ORDER BY history.created_at DESC)
              FROM (
                SELECT t.created_at,
                       jsonb_build_object(
                           'id', t.id,
                           'kind', t.kind,
                           'state', t.state,
                           'protected', t.protected,
                           'generation', t.transition_generation::text,
                           'createdAt', t.created_at,
                           'updatedAt', t.updated_at,
                           'completedAt', t.completed_at,
                           'failureCode', t.failure_code
                       ) AS row
                  FROM public.identity_transitions t
                 WHERE t.user_id = u.id
                 ORDER BY t.created_at DESC, t.id DESC
                 LIMIT 50
              ) history
        ), '[]'::jsonb),
        'linkHistory', COALESCE((
            SELECT jsonb_agg(history.row ORDER BY history.occurred_at DESC)
              FROM (
                SELECT e.occurred_at,
                       jsonb_build_object(
                           'id', e.id::text,
                           'occurredAt', e.occurred_at,
                           'action', e.action,
                           'sourceKey', es.source_key,
                           'linkId', CASE WHEN e.link_id IS NULL THEN NULL
                                          ELSE e.link_id::text END,
                           'reason', e.reason,
                           'correlationId', e.correlation_id
                       ) AS row
                  FROM public.identity_link_events e
                  LEFT JOIN public.identity_sources es ON es.id = e.source_id
                 WHERE e.user_id = u.id
                 ORDER BY e.occurred_at DESC, e.id DESC
                 LIMIT 100
              ) history
        ), '[]'::jsonb)
    ) INTO v_result
      FROM public.users u
      JOIN public.user_lifecycle_authorities ula ON ula.user_id = u.id
      LEFT JOIN public.user_identity_links lifecycle_link
        ON lifecycle_link.id = ula.link_id
      LEFT JOIN public.identity_sources lifecycle_source
        ON lifecycle_source.id = lifecycle_link.source_id
     WHERE u.id = p_user_id;

    RETURN v_result;
END;
$$;

SELECT apply_worker_ownership(
    'identity_person_read(bigint,bigint)'::regprocedure
);
