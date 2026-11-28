CREATE OR REPLACE FUNCTION identity_inventory_export()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_people BIGINT;
    v_report JSONB;
BEGIN
    SELECT count(*) INTO v_people FROM public.users;
    IF v_people > 10000 THEN
        RAISE EXCEPTION 'identity inventory exceeds the synchronous export limit'
            USING ERRCODE='BZ228',
                  HINT='{"type":"identity_source_invalid","remediation":"use a bounded filtered export or support bundle"}';
    END IF;
    v_report := jsonb_build_object(
        'manifestVersion','1',
        'schemaVersion',(SELECT max(version) FROM public.schema_migrations),
        'generatedAt',statement_timestamp(),
        'redactionPolicy','identity-inventory-v1',
        'sources',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'sourceKey',s.source_key,'kind',s.kind,'state',s.state,
                'generation',s.generation::text,'readMode',s.read_mode,
                'activeLinks',(SELECT count(*) FROM public.user_identity_links l
                    WHERE l.source_id=s.id AND l.state='active'),
                'openConflicts',(SELECT count(*) FROM public.identity_match_candidates c
                    WHERE c.source_id=s.id AND c.status IN ('pending','deferred'))
            ) ORDER BY s.source_key)
              FROM public.identity_sources s
        ),'[]'::jsonb),
        'people',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'userId',u.id::text,
                'enabled',u.enabled,
                'accountClass',CASE
                    WHEN is_guest_account(u.id) THEN 'guest'
                    WHEN NOT EXISTS (SELECT 1 FROM public.mailboxes m
                        WHERE m.user_id=u.id AND m.is_primary) THEN 'unclassified'
                    ELSE 'member' END,
                'lifecycleAuthority',a.authority_kind,
                'activeLinks',(SELECT count(*) FROM public.user_identity_links l
                    WHERE l.user_id=u.id AND l.state='active'),
                'detachedLinks',(SELECT count(*) FROM public.user_identity_links l
                    WHERE l.user_id=u.id AND l.state='detached')
            ) ORDER BY u.id)
              FROM public.users u
              LEFT JOIN public.user_lifecycle_authorities a ON a.user_id=u.id
        ),'[]'::jsonb),
        'conflicts',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'id',c.id,'sourceKey',s.source_key,
                'evidenceClass',c.evidence_class,'state',c.status,
                'generation',c.generation::text,'createdAt',c.created_at,
                'expiresAt',c.expires_at
            ) ORDER BY c.created_at,c.id)
              FROM public.identity_match_candidates c
              JOIN public.identity_sources s ON s.id=c.source_id
        ),'[]'::jsonb),
        'redactionCounts',jsonb_build_object(
            'emailsOmitted',v_people,
            'externalSubjectsOmitted',(SELECT count(*) FROM public.user_identity_links),
            'candidateSubjectsOmitted',(SELECT count(*) FROM public.identity_match_candidates),
            'secretsOmitted',(SELECT count(*) FROM public.identity_sources
                WHERE config_envelope IS NOT NULL)
        )
    );
    RETURN v_report || jsonb_build_object(
        'sha256',encode(digest(convert_to(v_report::text,'UTF8'),'sha256'),'hex')
    );
END;
$$;

SELECT apply_worker_ownership('identity_inventory_export()'::regprocedure);
