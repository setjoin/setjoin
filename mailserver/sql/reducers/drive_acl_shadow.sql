-- drive_acl_shadow.sql -- bounded compatibility observation and cutover rail.

CREATE OR REPLACE FUNCTION drive_acl_shadow_start(
  p_actor_user_id bigint,p_space_id bigint
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  v_space drive_spaces%ROWTYPE;
  v_started_at timestamptz;
BEGIN
  IF NOT public.drive_has_admin_perm(p_actor_user_id,'drive.manage') THEN
    RAISE EXCEPTION 'Drive ACL shadow start forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  SELECT * INTO v_space FROM public.drive_spaces WHERE id=p_space_id FOR UPDATE;
  IF NOT FOUND OR v_space.chat_channel_id IS NOT NULL OR v_space.meeting_id IS NOT NULL THEN
    RAISE EXCEPTION 'bound or missing Drive space cannot enter ACL shadow'
      USING ERRCODE='BZ256',HINT='{"type":"drive_acl_bound_space"}';
  END IF;
  IF EXISTS(SELECT 1 FROM public.drive_acl_grants WHERE space_id=p_space_id)
     OR EXISTS(SELECT 1 FROM public.drive_acl_breaks WHERE space_id=p_space_id) THEN
    RAISE EXCEPTION 'Drive ACL shadow requires a compatibility-only space'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","detail":"ACL inputs already exist"}';
  END IF;
  UPDATE public.drive_spaces SET acl_mode='shadow' WHERE id=p_space_id;
  v_started_at:=clock_timestamp();
  INSERT INTO public.drive_acl_shadow_state(space_id,started_at,expires_at)
  VALUES(p_space_id,v_started_at,v_started_at+interval '28 days')
  ON CONFLICT(space_id) DO UPDATE SET
    started_at=EXCLUDED.started_at,expires_at=EXCLUDED.expires_at,
    comparisons=0,matches=0,widenings=0,narrowings=0,last_compared_at=NULL;
  DELETE FROM public.drive_acl_shadow_mismatches WHERE space_id=p_space_id;
  DELETE FROM public.drive_acl_cutover_evidence WHERE space_id=p_space_id;
  RETURN public.drive_acl_shadow_readiness(p_actor_user_id,p_space_id);
END;
$$;
SELECT apply_worker_ownership('drive_acl_shadow_start(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_shadow_compare(
  p_user_id bigint,p_node_id bigint
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  v_space_id bigint; v_mode text; v_chat bigint; v_meeting bigint;
  v_expires timestamptz; v_legacy text[]; v_canonical text[];
  v_widening boolean; v_narrowing boolean; v_kind text;
  v_legacy_digest text; v_canonical_digest text;
BEGIN
  SELECT n.space_id,s.acl_mode,s.chat_channel_id,s.meeting_id
    INTO v_space_id,v_mode,v_chat,v_meeting
    FROM public.drive_nodes n JOIN public.drive_spaces s ON s.id=n.space_id
   WHERE n.id=p_node_id;
  IF NOT FOUND OR v_mode<>'shadow' OR v_chat IS NOT NULL OR v_meeting IS NOT NULL THEN
    RETURN 'not_shadow';
  END IF;
  SELECT expires_at INTO v_expires FROM public.drive_acl_shadow_state
   WHERE space_id=v_space_id FOR UPDATE;
  IF NOT FOUND OR v_expires<=now() THEN
    RETURN 'expired';
  END IF;
  IF EXISTS(SELECT 1 FROM public.drive_acl_grants WHERE space_id=v_space_id)
     OR EXISTS(SELECT 1 FROM public.drive_acl_breaks WHERE space_id=v_space_id) THEN
    RAISE EXCEPTION 'Drive ACL shadow inputs changed'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","detail":"shadow no longer compatibility-only"}';
  END IF;

  v_legacy:=public.drive_legacy_node_capabilities(p_user_id,p_node_id);
  v_canonical:=public.drive_effective_capabilities(p_user_id,p_node_id);
  v_widening:=EXISTS(SELECT 1 FROM unnest(v_canonical) c WHERE NOT c=ANY(v_legacy));
  v_narrowing:=EXISTS(SELECT 1 FROM unnest(v_legacy) c WHERE NOT c=ANY(v_canonical));

  UPDATE public.drive_acl_shadow_state SET
    comparisons=comparisons+1,
    matches=matches+CASE WHEN NOT v_widening AND NOT v_narrowing THEN 1 ELSE 0 END,
    widenings=widenings+CASE WHEN v_widening THEN 1 ELSE 0 END,
    narrowings=narrowings+CASE WHEN v_narrowing THEN 1 ELSE 0 END,
    last_compared_at=clock_timestamp()
   WHERE space_id=v_space_id;

  IF NOT v_widening AND NOT v_narrowing THEN
    UPDATE public.drive_acl_shadow_mismatches SET resolved_at=clock_timestamp()
     WHERE space_id=v_space_id AND user_id=p_user_id AND node_id=p_node_id
       AND resolved_at IS NULL;
    RETURN 'match';
  END IF;
  v_kind:=CASE WHEN v_widening AND v_narrowing THEN 'both'
               WHEN v_widening THEN 'widening' ELSE 'narrowing' END;
  v_legacy_digest:=encode(digest(array_to_string(v_legacy,E'\x1f'),'sha256'),'hex');
  v_canonical_digest:=encode(digest(array_to_string(v_canonical,E'\x1f'),'sha256'),'hex');
  IF EXISTS(SELECT 1 FROM public.drive_acl_shadow_mismatches
             WHERE space_id=v_space_id AND user_id=p_user_id AND node_id=p_node_id)
     OR (SELECT count(*) FROM public.drive_acl_shadow_mismatches
          WHERE space_id=v_space_id)<1000 THEN
    INSERT INTO public.drive_acl_shadow_mismatches(
      space_id,user_id,node_id,mismatch_kind,legacy_digest,canonical_digest
    ) VALUES(v_space_id,p_user_id,p_node_id,v_kind,v_legacy_digest,v_canonical_digest)
    ON CONFLICT(space_id,user_id,node_id) DO UPDATE SET
      mismatch_kind=EXCLUDED.mismatch_kind,
      legacy_digest=EXCLUDED.legacy_digest,
      canonical_digest=EXCLUDED.canonical_digest,
      occurrence_count=drive_acl_shadow_mismatches.occurrence_count+1,
      last_seen_at=clock_timestamp(),resolved_at=NULL;
  END IF;
  RETURN v_kind;
END;
$$;
SELECT apply_worker_ownership('drive_acl_shadow_compare(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_shadow_classify(
  p_actor_user_id bigint,p_space_id bigint,p_user_id bigint,p_node_id bigint,
  p_classification text,p_reason text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT public.drive_has_admin_perm(p_actor_user_id,'drive.manage') THEN
    RAISE EXCEPTION 'Drive ACL mismatch classification forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  IF p_classification NOT IN (
    'legacy_defect','canonical_defect','fixture_defect','reviewed_semantic_change'
  ) OR p_reason IS NULL OR length(p_reason) NOT BETWEEN 8 AND 1000 THEN
    RAISE EXCEPTION 'invalid Drive ACL mismatch classification'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid"}';
  END IF;
  UPDATE public.drive_acl_shadow_mismatches SET
    classification=p_classification,classified_by=p_actor_user_id,
    classified_at=clock_timestamp(),classification_reason=p_reason
   WHERE space_id=p_space_id AND user_id=p_user_id AND node_id=p_node_id
     AND resolved_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'open Drive ACL mismatch not found'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict"}';
  END IF;
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_shadow_classify(bigint,bigint,bigint,bigint,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_cutover_evidence_record(
  p_actor_user_id bigint,p_space_id bigint,p_deterministic_passed boolean,
  p_ubuntu_passed boolean,p_evidence_digest text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE
  v_zero boolean;
  v_recorded_at timestamptz;
BEGIN
  IF NOT public.drive_has_admin_perm(p_actor_user_id,'drive.manage') THEN
    RAISE EXCEPTION 'Drive ACL evidence record forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  IF p_evidence_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid Drive ACL evidence digest'
      USING ERRCODE='BZ252',HINT='{"type":"drive_acl_invalid","field":"evidenceDigest"}';
  END IF;
  v_zero:=NOT EXISTS(SELECT 1 FROM public.drive_acl_shadow_mismatches
                      WHERE space_id=p_space_id AND resolved_at IS NULL);
  v_recorded_at:=clock_timestamp();
  INSERT INTO public.drive_acl_cutover_evidence(
    space_id,deterministic_passed,ubuntu_passed,zero_open_mismatches,
    evidence_digest,recorded_by,recorded_at,expires_at
  ) VALUES(p_space_id,p_deterministic_passed,p_ubuntu_passed,v_zero,
           p_evidence_digest,p_actor_user_id,v_recorded_at,
           v_recorded_at+interval '7 days')
  ON CONFLICT(space_id) DO UPDATE SET
    deterministic_passed=EXCLUDED.deterministic_passed,
    ubuntu_passed=EXCLUDED.ubuntu_passed,
    zero_open_mismatches=EXCLUDED.zero_open_mismatches,
    evidence_digest=EXCLUDED.evidence_digest,recorded_by=EXCLUDED.recorded_by,
    recorded_at=EXCLUDED.recorded_at,expires_at=EXCLUDED.expires_at;
END;
$$;
SELECT apply_worker_ownership(
  'drive_acl_cutover_evidence_record(bigint,bigint,boolean,boolean,text)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_cutover(
  p_actor_user_id bigint,p_space_id bigint,p_expected_epoch bigint
) RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_epoch bigint;
BEGIN
  IF NOT public.drive_has_admin_perm(p_actor_user_id,'drive.manage') THEN
    RAISE EXCEPTION 'Drive ACL cutover forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  PERFORM 1 FROM public.drive_spaces s
   JOIN public.drive_acl_shadow_state sh ON sh.space_id=s.id
   WHERE s.id=p_space_id AND s.acl_mode='shadow' AND sh.expires_at>now() FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Drive ACL shadow window is absent or expired'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"shadowWindow"}';
  END IF;
  SELECT epoch INTO v_epoch FROM public.drive_acl_generations
   WHERE space_id=p_space_id FOR UPDATE;
  IF v_epoch<>p_expected_epoch THEN
    RAISE EXCEPTION 'Drive ACL epoch conflict'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"epoch"}';
  END IF;
  IF NOT COALESCE((SELECT enabled FROM public.feature_toggles
                    WHERE key='feature.drive_node_acl_reads'),false)
     OR NOT EXISTS(
       SELECT 1 FROM public.drive_acl_cutover_evidence e
        WHERE e.space_id=p_space_id AND e.expires_at>now()
          AND e.deterministic_passed AND e.ubuntu_passed AND e.zero_open_mismatches
     ) OR EXISTS(SELECT 1 FROM public.drive_acl_shadow_mismatches
                  WHERE space_id=p_space_id AND resolved_at IS NULL)
     OR (SELECT comparisons=0 FROM public.drive_acl_shadow_state WHERE space_id=p_space_id) THEN
    RAISE EXCEPTION 'Drive ACL cutover evidence is incomplete'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","field":"evidence"}';
  END IF;
  UPDATE public.drive_spaces SET acl_mode='acl' WHERE id=p_space_id;
  RETURN v_epoch;
END;
$$;
SELECT apply_worker_ownership('drive_acl_cutover(bigint,bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_rollback(
  p_actor_user_id bigint,p_space_id bigint
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT public.drive_has_admin_perm(p_actor_user_id,'drive.manage') THEN
    RAISE EXCEPTION 'Drive ACL rollback forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  PERFORM 1 FROM public.drive_spaces WHERE id=p_space_id AND acl_mode='acl' FOR UPDATE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM public.drive_acl_grants
                          WHERE space_id=p_space_id AND state='active')
     OR EXISTS(SELECT 1 FROM public.drive_acl_breaks WHERE space_id=p_space_id)
     OR EXISTS(SELECT 1 FROM public.drive_spaces
                WHERE id=p_space_id AND acl_irreversible_at IS NOT NULL) THEN
    RAISE EXCEPTION 'Drive ACL rollback would widen access'
      USING ERRCODE='BZ254',HINT='{"type":"drive_acl_conflict","detail":"rollback would widen access"}';
  END IF;
  UPDATE public.drive_spaces SET acl_mode='shadow' WHERE id=p_space_id;
END;
$$;
SELECT apply_worker_ownership('drive_acl_rollback(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION drive_acl_shadow_readiness(
  p_actor_user_id bigint,p_space_id bigint
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_result jsonb;
BEGIN
  IF NOT public.drive_has_admin_perm(p_actor_user_id,'drive.manage') THEN
    RAISE EXCEPTION 'Drive ACL readiness forbidden'
      USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
  END IF;
  SELECT jsonb_build_object(
    'spaceId',s.id::text,'mode',s.acl_mode,
    'epoch',g.epoch::text,'startedAt',sh.started_at,'expiresAt',sh.expires_at,
    'comparisons',sh.comparisons::text,'matches',sh.matches::text,
    'widenings',sh.widenings::text,'narrowings',sh.narrowings::text,
    'openMismatches',(SELECT count(*)::text FROM public.drive_acl_shadow_mismatches m
                       WHERE m.space_id=s.id AND m.resolved_at IS NULL),
    'evidenceReady',COALESCE(e.deterministic_passed AND e.ubuntu_passed
                              AND e.zero_open_mismatches AND e.expires_at>now(),false)
  ) INTO v_result
  FROM public.drive_spaces s
  JOIN public.drive_acl_generations g ON g.space_id=s.id
  LEFT JOIN public.drive_acl_shadow_state sh ON sh.space_id=s.id
  LEFT JOIN public.drive_acl_cutover_evidence e ON e.space_id=s.id
  WHERE s.id=p_space_id;
  RETURN v_result;
END;
$$;
SELECT apply_worker_ownership('drive_acl_shadow_readiness(bigint,bigint)'::regprocedure);
