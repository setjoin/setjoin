CREATE OR REPLACE FUNCTION identity_upgrade_canary(
 p_actor BIGINT,p_source_key TEXT,p_expected_generation BIGINT,
 p_enable BOOLEAN,p_user_ids BIGINT[],p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
 v_s identity_sources%ROWTYPE;
 v_shadow JSONB;
BEGIN
 IF p_actor IS NULL OR p_reason IS NULL
    OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
    OR p_reason ~ '[[:cntrl:]]' THEN
   RAISE EXCEPTION 'invalid identity canary request' USING ERRCODE='BZ228';
 END IF;
 SELECT * INTO v_s FROM identity_sources WHERE source_key=p_source_key FOR UPDATE;
 IF NOT FOUND OR v_s.generation<>p_expected_generation THEN
   RAISE EXCEPTION 'identity source generation is stale' USING ERRCODE='BZ229';
 END IF;
 IF p_enable AND v_s.kind NOT IN ('oidc','saml') THEN
   RAISE EXCEPTION 'identity read canary requires an authentication source'
     USING ERRCODE='BZ234',
           HINT='{"type":"identity_transition_preflight"}';
 END IF;
 IF p_enable THEN
   v_shadow := identity_upgrade_shadow(p_source_key);
 END IF;
 IF p_enable AND NOT (v_shadow->>'eligible')::boolean THEN
   RAISE EXCEPTION 'source has not completed the shadow gate'
     USING ERRCODE='BZ235',HINT='{"type":"identity_preview_stale"}';
 END IF;
 IF p_enable AND (
      p_user_ids IS NULL OR cardinality(p_user_ids) NOT BETWEEN 1 AND 500
      OR cardinality(p_user_ids) <> (
          SELECT count(DISTINCT u.user_id)::integer
          FROM unnest(p_user_ids) u(user_id)
      )
      OR EXISTS (
          SELECT 1 FROM unnest(p_user_ids) u(user_id)
          WHERE (
              SELECT count(*) FROM user_identity_links l
               WHERE l.source_id=v_s.id AND l.user_id=u.user_id
                 AND l.state='active' AND 'authenticate'=ANY(l.purposes)
          )<>1
      )
      OR EXISTS (
          SELECT 1
            FROM unnest(p_user_ids) u(user_id)
            JOIN user_identity_links auth_link
              ON auth_link.source_id=v_s.id
             AND auth_link.user_id=u.user_id
             AND auth_link.state='active'
             AND 'authenticate'=ANY(auth_link.purposes)
            LEFT JOIN identity_auth_shadow_link_evidence evidence
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
        JOIN user_identity_links auth_link
          ON auth_link.source_id=v_s.id
         AND auth_link.user_id=u.user_id
         AND auth_link.state='active'
         AND 'authenticate'=ANY(auth_link.purposes)
        LEFT JOIN user_lifecycle_authorities authority
          ON authority.user_id=u.user_id
        LEFT JOIN user_identity_links lifecycle_link
          ON lifecycle_link.id=authority.link_id
        LEFT JOIN identity_sources lifecycle_source
          ON lifecycle_source.id=lifecycle_link.source_id
       WHERE authority.user_id IS NULL
          OR (
              authority.authority_kind='source'
              AND (
                  lifecycle_source.id IS NULL
                  OR lifecycle_source.kind NOT IN ('ad','ldap','scim')
                  OR NOT COALESCE((
                      identity_upgrade_shadow(lifecycle_source.source_key)
                      ->>'eligible'
                  )::boolean,false)
              )
          )
          OR (
              authority.authority_kind='local'
              AND (
                  NOT identity_recovery_available(u.user_id,auth_link.id)
                  OR EXISTS (
                      SELECT 1 FROM identity_shadow_divergences d
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
 UPDATE identity_sources SET read_mode=CASE WHEN p_enable THEN 'canary' ELSE 'shadow' END,
   generation=generation+1,updated_by=p_actor,updated_at=statement_timestamp()
  WHERE id=v_s.id;
 DELETE FROM identity_read_cohort WHERE source_id=v_s.id;
 IF p_enable THEN
   INSERT INTO identity_read_cohort(
       source_id,user_id,source_generation,added_by,reason,
       auth_link_id,auth_link_generation,lifecycle_generation
   )
   SELECT v_s.id,u.user_id,p_expected_generation+1,p_actor,p_reason,
          auth_link.id,auth_link.generation,authority.generation
     FROM (SELECT DISTINCT unnest(p_user_ids) AS user_id) u
     JOIN user_identity_links auth_link
       ON auth_link.source_id=v_s.id
      AND auth_link.user_id=u.user_id
      AND auth_link.state='active'
      AND 'authenticate'=ANY(auth_link.purposes)
     JOIN user_lifecycle_authorities authority
       ON authority.user_id=u.user_id;
 END IF;
 INSERT INTO identity_link_events(actor_user_id,source_id,action,reason,metadata)
 VALUES(p_actor,v_s.id,'source_updated',p_reason,
   jsonb_build_object('readMode',CASE WHEN p_enable THEN 'canary' ELSE 'shadow' END));
 RETURN jsonb_build_object('sourceKey',p_source_key,
   'readMode',CASE WHEN p_enable THEN 'canary' ELSE 'shadow' END,
   'generation',(p_expected_generation+1)::text,
   'cohortSize',CASE WHEN p_enable THEN cardinality(p_user_ids) ELSE 0 END);
END $$;
SELECT apply_worker_ownership(
 'identity_upgrade_canary(bigint,text,bigint,boolean,bigint[],text)'::regprocedure
);
