CREATE OR REPLACE FUNCTION identity_upgrade_rollback(
 p_actor BIGINT,p_reason TEXT
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
 v_sources_changed INTEGER;
 v_cohort_members_cleared INTEGER;
BEGIN
 IF p_actor IS NULL OR p_reason IS NULL
    OR octet_length(p_reason) NOT BETWEEN 1 AND 1024
    OR p_reason ~ '[[:cntrl:]]' THEN
   RAISE EXCEPTION 'invalid identity rollback request' USING ERRCODE='BZ228';
 END IF;
 SELECT count(*)::integer INTO v_sources_changed
   FROM identity_sources WHERE read_mode<>'shadow';
 SELECT count(*)::integer INTO v_cohort_members_cleared
   FROM identity_read_cohort;
 UPDATE feature_toggles SET enabled=false,updated_at=statement_timestamp()
  WHERE key IN ('feature.identity_normalized_reads','feature.identity_transitions',
                'feature.identity_model_v2');
 UPDATE identity_sources SET read_mode='shadow',generation=generation+1,
   updated_by=p_actor,updated_at=statement_timestamp()
  WHERE read_mode<>'shadow';
 DELETE FROM identity_read_cohort;
 INSERT INTO identity_link_events(
   actor_user_id,action,reason,metadata
 ) VALUES(
   p_actor,'source_updated',p_reason,
   jsonb_build_object(
     'operation','global_rollback',
     'sourcesChanged',v_sources_changed,
     'cohortMembersCleared',v_cohort_members_cleared,
     'identityModelEnabled',false,
     'normalizedReadsEnabled',false,
     'transitionsEnabled',false
   )
 );
 PERFORM app_notify('config_changed',
   '{"key":"feature.identity_model_v2","enabled":false}'::text);
 RETURN identity_upgrade_status() || jsonb_build_object(
   'rolledBack',true,'schemaPreserved',true,'effectsStillDraining',true,
   'pendingEffects',(SELECT count(*) FROM identity_transition_effects
                      WHERE state<>'completed')
 );
END $$;
SELECT apply_worker_ownership(
 'identity_upgrade_rollback(bigint,text)'::regprocedure
);
